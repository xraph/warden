package warden

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store"
)

// Engine is the central authorization engine. It coordinates RBAC, ReBAC,
// and ABAC evaluation, manages the store, and fires extension hooks.
type Engine struct {
	store       store.Store
	evaluator   Evaluator
	graphWalker GraphWalker
	cache       Cache
	plugins     *plugin.Registry
	logger      log.Logger
	config      Config
}

// NewEngine creates a new Warden engine with the given options.
func NewEngine(opts ...Option) (*Engine, error) {
	e := &Engine{
		evaluator:   DefaultEvaluator(),
		graphWalker: DefaultGraphWalker(10),
		logger:      log.NewNoopLogger(),
		config:      DefaultConfig(),
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.store == nil {
		return nil, errors.New("warden: store is required")
	}
	// Update graph walker max depth from config.
	if e.config.MaxGraphDepth > 0 {
		e.graphWalker = DefaultGraphWalker(e.config.MaxGraphDepth)
	}
	return e, nil
}

// Store returns the underlying composite store.
func (e *Engine) Store() store.Store { return e.store }

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.config }

// Plugins returns the plugin registry (may be nil).
func (e *Engine) Plugins() *plugin.Registry { return e.plugins }

// Health checks the health of the engine by pinging its store.
func (e *Engine) Health(ctx context.Context) error {
	return e.store.Ping(ctx)
}

// Start performs any startup initialization.
func (e *Engine) Start(_ context.Context) error { return nil }

// Stop performs graceful shutdown.
func (e *Engine) Stop(_ context.Context) error { return nil }

// Check performs an authorization check. This is the hot path.
// Optional CallOption values override scope for this single call.
func (e *Engine) Check(ctx context.Context, req *CheckRequest, opts ...CallOption) (*CheckResult, error) {
	start := time.Now()

	// Validate required fields.
	if req.Subject.ID == "" {
		return nil, fmt.Errorf("warden: subject ID is required")
	}
	if req.Action.Name == "" {
		return nil, fmt.Errorf("warden: action name is required")
	}
	if req.Resource.Type == "" {
		return nil, fmt.Errorf("warden: resource type is required for permission check")
	}

	scope := scopeFromContext(ctx)
	if req.TenantID != "" {
		scope.tenantID = req.TenantID
	}

	// Apply call-time options (highest priority).
	co := resolveCallOptions(opts)
	if co.tenantID != "" {
		scope.tenantID = co.tenantID
	}
	if co.appID != "" {
		scope.appID = co.appID
	}

	e.logger.Debug("warden: check",
		log.String("subject_kind", string(req.Subject.Kind)),
		log.String("subject_id", req.Subject.ID),
		log.String("action", req.Action.Name),
		log.String("resource_type", req.Resource.Type),
		log.String("scope_app_id", scope.appID),
		log.String("scope_tenant_id", scope.tenantID),
	)

	// 1. Cache hit?
	if e.cache != nil {
		if cached, ok := e.cache.Get(ctx, scope.tenantID, req); ok {
			cached.EvalTimeNs = time.Since(start).Nanoseconds()
			return cached, nil
		}
	}

	// 1b. Extension hook: before check.
	if e.plugins != nil {
		e.plugins.EmitBeforeCheck(ctx, req)
	}

	var rbacResult, rebacResult, abacResult *CheckResult
	var err error

	// 2. RBAC: resolve roles → check permissions.
	if e.config.rbacEnabled() {
		rbacResult, err = e.evaluateRBAC(ctx, scope, req)
		if err != nil {
			return nil, fmt.Errorf("warden rbac: %w", err)
		}
	}

	// 3. ReBAC: check relation tuples → walk graph.
	if e.config.rebacEnabled() {
		rebacResult, err = e.evaluateReBAC(ctx, scope, req)
		if err != nil {
			return nil, fmt.Errorf("warden rebac: %w", err)
		}
	}

	// 4. ABAC: evaluate active policies with conditions.
	if e.config.abacEnabled() {
		abacResult, err = e.evaluateABAC(ctx, scope, req)
		if err != nil {
			return nil, fmt.Errorf("warden abac: %w", err)
		}
	}

	// 5. Merge: explicit deny > allow > default deny.
	result := e.mergeDecisions(req, rbacResult, rebacResult, abacResult)
	result.EvalTimeNs = time.Since(start).Nanoseconds()

	// 6. Cache the result.
	if e.cache != nil {
		e.cache.Set(ctx, scope.tenantID, req, result)
	}

	// 7. Extension hook: after check.
	if e.plugins != nil {
		e.plugins.EmitAfterCheck(ctx, req, result)
	}

	// 8. Write check log entry (fire-and-forget).
	if e.config.checkLogEnabled() {
		go e.writeCheckLog(ctx, scope, req, result)
	}

	return result, nil
}

// Enforce returns an error if the authorization check is denied.
// Optional CallOption values override scope for this single call.
func (e *Engine) Enforce(ctx context.Context, req *CheckRequest, opts ...CallOption) error {
	result, err := e.Check(ctx, req, opts...)
	if err != nil {
		return fmt.Errorf("warden check: %w", err)
	}
	if !result.Allowed {
		return fmt.Errorf("%w: %s — %s", ErrAccessDenied, result.Decision, result.Reason)
	}
	return nil
}

// CanI is a shorthand for a simple authorization check.
// Optional CallOption values override scope for this single call.
func (e *Engine) CanI(ctx context.Context, subjectKind SubjectKind, subjectID, action, resourceType, resourceID string, opts ...CallOption) (bool, error) {
	result, err := e.Check(ctx, &CheckRequest{
		Subject:  Subject{Kind: subjectKind, ID: subjectID},
		Action:   Action{Name: action},
		Resource: Resource{Type: resourceType, ID: resourceID},
	}, opts...)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

func (e *Engine) writeCheckLog(ctx context.Context, scope tenantScope, req *CheckRequest, result *CheckResult) {
	entry := &checklog.Entry{
		ID:           id.NewCheckLogID(),
		TenantID:     scope.tenantID,
		AppID:        scope.appID,
		SubjectKind:  string(req.Subject.Kind),
		SubjectID:    req.Subject.ID,
		Action:       req.Action.Name,
		ResourceType: req.Resource.Type,
		ResourceID:   req.Resource.ID,
		Decision:     string(result.Decision),
		Reason:       result.Reason,
		EvalTimeNs:   result.EvalTimeNs,
		CreatedAt:    time.Now(),
	}
	if err := e.store.CreateCheckLog(context.WithoutCancel(ctx), entry); err != nil {
		e.logger.Error("warden: failed to write check log", log.Error(err))
	}
}

func (e *Engine) evaluateRBAC(ctx context.Context, scope tenantScope, req *CheckRequest) (*CheckResult, error) {
	// 1. Get roles assigned to subject (global + resource-scoped).
	globalRoles, err := e.store.ListRolesForSubject(ctx, scope.tenantID, string(req.Subject.Kind), req.Subject.ID)
	if err != nil {
		return nil, err
	}
	resourceRoles, err := e.store.ListRolesForSubjectOnResource(ctx, scope.tenantID, string(req.Subject.Kind), req.Subject.ID, req.Resource.Type, req.Resource.ID)
	if err != nil {
		return nil, err
	}
	allRoles := make([]id.RoleID, 0, len(globalRoles)+len(resourceRoles))
	allRoles = append(allRoles, globalRoles...)
	allRoles = append(allRoles, resourceRoles...)

	if len(allRoles) == 0 {
		e.logger.Debug("warden: rbac no roles found",
			log.String("tenant_id", scope.tenantID),
			log.String("subject_kind", string(req.Subject.Kind)),
			log.String("subject_id", req.Subject.ID),
		)
		return &CheckResult{Decision: DecisionDenyNoRoles, Reason: fmt.Sprintf("subject %s:%s has no assigned roles in tenant %q", req.Subject.Kind, req.Subject.ID, scope.tenantID)}, nil
	}

	// 2. Walk parent chain for inherited roles.
	allRoles = e.resolveInheritedRoles(ctx, allRoles)

	// 3. Check if any role grants "resource:action" permission (glob matching).
	permName := req.Resource.Type + ":" + req.Action.Name

	e.logger.Debug("warden: rbac evaluating",
		log.Int("role_count", len(allRoles)),
		log.String("perm_required", permName),
		log.String("tenant_id", scope.tenantID),
	)

	for _, roleID := range allRoles {
		perms, err := e.store.ListRolePermissions(ctx, roleID)
		if err != nil {
			e.logger.Warn("warden: rbac ListRolePermissions error",
				log.String("role_id", roleID.String()),
				log.Error(err),
			)
			continue
		}

		e.logger.Debug("warden: rbac checking role",
			log.String("role_id", roleID.String()),
			log.Int("perm_count", len(perms)),
		)

		for _, permID := range perms {
			perm, err := e.store.GetPermission(ctx, permID)
			if err != nil || perm == nil {
				e.logger.Warn("warden: rbac GetPermission error",
					log.String("perm_id", permID.String()),
					log.Error(err),
				)
				continue
			}
			storedPerm := perm.Resource + ":" + perm.Action
			matched := matchPermission(storedPerm, permName)

			e.logger.Debug("warden: rbac checking perm",
				log.String("stored_perm", storedPerm),
				log.String("required_perm", permName),
				log.Bool("match", matched),
			)

			if matched {
				return &CheckResult{
					Allowed:  true,
					Decision: DecisionAllow,
					MatchedBy: []MatchInfo{{
						Source: "rbac",
						RuleID: roleID.String(),
						Detail: "role grants " + storedPerm,
					}},
				}, nil
			}
		}
	}

	return &CheckResult{Decision: DecisionDenyNoPerms, Reason: fmt.Sprintf("no role grants permission %q for subject %s:%s", permName, req.Subject.Kind, req.Subject.ID)}, nil
}

func (e *Engine) resolveInheritedRoles(ctx context.Context, roleIDs []id.RoleID) []id.RoleID {
	seen := make(map[string]struct{}, len(roleIDs))
	result := make([]id.RoleID, 0, len(roleIDs)*2)

	for _, rid := range roleIDs {
		e.walkRoleParents(ctx, rid, seen, &result, 0)
	}
	return result
}

func (e *Engine) walkRoleParents(ctx context.Context, roleID id.RoleID, seen map[string]struct{}, result *[]id.RoleID, depth int) {
	key := roleID.String()
	if _, ok := seen[key]; ok {
		return
	}
	if depth > 20 {
		return // Safety limit.
	}
	seen[key] = struct{}{}
	*result = append(*result, roleID)

	r, err := e.store.GetRole(ctx, roleID)
	if err != nil || r == nil || r.ParentID == nil {
		return
	}
	e.walkRoleParents(ctx, *r.ParentID, seen, result, depth+1)
}

func (e *Engine) evaluateReBAC(ctx context.Context, scope tenantScope, req *CheckRequest) (*CheckResult, error) {
	// Direct relation check.
	direct, err := e.store.CheckDirectRelation(ctx, scope.tenantID, req.Resource.Type, req.Resource.ID, req.Action.Name, string(req.Subject.Kind), req.Subject.ID)
	if err != nil {
		return nil, err
	}
	if direct {
		return &CheckResult{
			Allowed:   true,
			Decision:  DecisionAllow,
			MatchedBy: []MatchInfo{{Source: "rebac", Detail: "direct relation"}},
		}, nil
	}

	// Walk graph for transitive permissions.
	if e.graphWalker != nil {
		allowed, path, err := e.graphWalker.Walk(ctx, e.store, scope.tenantID, req)
		if err != nil && !errors.Is(err, ErrGraphDepthExceeded) {
			return nil, err
		}
		if allowed {
			return &CheckResult{
				Allowed:   true,
				Decision:  DecisionAllow,
				MatchedBy: []MatchInfo{{Source: "rebac", Detail: "transitive: " + path}},
			}, nil
		}
	}

	return &CheckResult{Decision: DecisionDenyRelation, Reason: fmt.Sprintf("no relation grants %s:%s %s access to %s:%s", req.Subject.Kind, req.Subject.ID, req.Action.Name, req.Resource.Type, req.Resource.ID)}, nil
}

func (e *Engine) evaluateABAC(ctx context.Context, scope tenantScope, req *CheckRequest) (*CheckResult, error) {
	policies, err := e.store.ListActivePolicies(ctx, scope.tenantID)
	if err != nil {
		return nil, err
	}
	return e.evaluator.Evaluate(ctx, policies, req)
}

func (e *Engine) mergeDecisions(req *CheckRequest, rbac, rebac, abac *CheckResult) *CheckResult {
	// Explicit deny (from ABAC) always wins.
	if abac != nil && abac.Decision == DecisionDenyExplicit {
		return abac
	}

	// Any allow from any model grants access.
	for _, r := range []*CheckResult{rbac, rebac, abac} {
		if r != nil && r.Allowed {
			return r
		}
	}

	// Default deny — pick most informative reason.
	for _, r := range []*CheckResult{rbac, rebac, abac} {
		if r != nil && r.Reason != "" {
			return r
		}
	}

	return &CheckResult{Decision: DecisionDenyDefault, Reason: fmt.Sprintf("no rule allows %s:%s to %s on %s:%s", req.Subject.Kind, req.Subject.ID, req.Action.Name, req.Resource.Type, req.Resource.ID)}
}
