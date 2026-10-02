package warden

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// Engine is the central authorization engine. It coordinates RBAC, ReBAC,
// and ABAC evaluation, manages the store, and fires extension hooks.
type Engine struct {
	store       store.Store
	evaluator   Evaluator
	graphWalker GraphWalker
	exprEval    ExpressionEvaluator
	cache       Cache
	plugins     *plugin.Registry
	logger      log.Logger
	config      Config
	metrics     Metrics

	checkLogWriter *checkLogWriter
	maintCancel    context.CancelFunc

	// nowFn is the clock RunMaintenance uses to decide what has expired.
	// Unexported so tests in this package can substitute a fixed clock
	// without expanding the public API.
	nowFn func() time.Time
}

// ExpressionEvaluator is an optional engine hook that evaluates resource-type
// permission expressions (the SpiceDB-style `viewer or editor or parent->read`
// expressions stored on ResourceType.Permissions[].Expression).
//
// The DSL package implements this; wire it via WithExpressionEvaluator. When
// nil, resource-type expressions are inert (the relation graph walker still
// handles direct + transitive relations).
type ExpressionEvaluator interface {
	EvalPermission(ctx context.Context, tenantID, namespacePath, resourceType, permName, subjectKind, subjectID, resourceID string) (matched bool, err error)
}

// NewEngine creates a new Warden engine with the given options.
func NewEngine(opts ...Option) (*Engine, error) {
	e := &Engine{
		evaluator: DefaultEvaluator(),
		logger:    log.NewNoopLogger(),
		config:    DefaultConfig(),
		metrics:   NoopMetrics{},
		nowFn:     time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.store == nil {
		return nil, errors.New("warden: store is required")
	}
	if err := e.config.Validate(); err != nil {
		return nil, fmt.Errorf("warden: invalid config: %w", err)
	}

	// Wire the configured logger into the default evaluator, constructed
	// before WithLogger ran. A caller-supplied Evaluator (WithEvaluator) is
	// left alone.
	if ls, ok := e.evaluator.(interface{ setLogger(log.Logger) }); ok {
		ls.setLogger(e.logger)
	}

	// Build the graph walker from config now that MaxGraphDepth/Visited/
	// Fanout and the metrics sink are all resolved, unless the caller
	// supplied their own via WithGraphWalker.
	if e.graphWalker == nil {
		e.graphWalker = NewGraphWalker(e.config.MaxGraphDepth, e.config.MaxGraphVisited, e.config.MaxGraphFanout, e.metrics)
	}

	// Auto-build the memory cache from Config.CacheTTL when the caller
	// didn't supply one explicitly via WithCache.
	if e.cache == nil && e.config.CacheTTL > 0 {
		e.cache = NewMemoryCache(WithCacheTTL(e.config.CacheTTL), WithCacheMaxSize(e.config.CacheMaxSize))
	}
	if e.cache != nil {
		if e.plugins == nil {
			e.plugins = plugin.NewRegistry(e.logger)
		}
		e.plugins.Register(newCacheInvalidator(e.cache))
	}
	if e.plugins != nil {
		e.plugins.SetMetrics(e.metrics)
	}

	if e.config.checkLogEnabled() {
		e.checkLogWriter = newCheckLogWriter(e.store, e.config.CheckLogQueueSize, e.logger, e.metrics)
	}

	return e, nil
}

// expansionWalker is the walker ExpandRelation runs, and whether it is the
// one Check runs (Expansion.ExactWalk): the engine's own when it is the
// built-in BFS walker, so an expansion has exactly Check's budget;
// otherwise, when WithGraphWalker installed another kind, a built-in
// walker with Config's budget, as NewEngine would have built, and false.
func (e *Engine) expansionWalker() (w *bfsGraphWalker, exact bool) {
	if w, ok := e.graphWalker.(*bfsGraphWalker); ok {
		return w, true
	}
	return newBFSGraphWalker(e.config.MaxGraphDepth, e.config.MaxGraphVisited, e.config.MaxGraphFanout, nil), false
}

// Store returns the underlying composite store.
func (e *Engine) Store() store.Store { return e.store }

// SetExpressionEvaluator overrides the resource-type expression evaluator
// at runtime. Used by the extension to wire dsl.NewEngineEvaluator after
// engine construction, since the evaluator depends on the engine's store.
func (e *Engine) SetExpressionEvaluator(ev ExpressionEvaluator) { e.exprEval = ev }

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.config }

// CheckLogLoss reports how many checks the engine ran whose entries may not
// have been recorded since this engine started. Failed checks count too,
// because a failed check's entry goes through the same writer. A write that
// times out after the store committed also counts as failed. ok is false when
// check logging is off.
func (e *Engine) CheckLogLoss() (CheckLogLoss, bool) {
	if e.checkLogWriter == nil {
		return CheckLogLoss{}, false
	}
	return e.checkLogWriter.loss(), true
}

// Plugins returns the plugin registry (may be nil).
func (e *Engine) Plugins() *plugin.Registry { return e.plugins }

// Health checks the health of the engine by pinging its store.
func (e *Engine) Health(ctx context.Context) error {
	return e.store.Ping(ctx)
}

// Start performs startup initialization: logs a summary of the engine's
// check-log/cache/maintenance configuration and, when
// Config.MaintenanceInterval > 0, starts the background maintenance loop
// (RunMaintenance on that interval) that Stop later cancels.
func (e *Engine) Start(_ context.Context) error {
	e.logger.Info("warden: engine starting",
		log.Bool("check_log_enabled", e.config.checkLogEnabled()),
		log.String("check_log_retention", e.config.CheckLogRetention.String()),
		log.Int("check_log_queue_size", e.config.CheckLogQueueSize),
		log.Bool("cache_enabled", e.cache != nil),
		log.String("maintenance_interval", e.config.MaintenanceInterval.String()),
	)
	if e.config.MaintenanceInterval > 0 {
		mctx, cancel := context.WithCancel(context.Background())
		e.maintCancel = cancel
		e.StartMaintenance(mctx)
	}
	return nil
}

// Stop performs graceful shutdown: cancels the maintenance loop, drains the
// check log writer (best-effort, bounded by ctx), and notifies Shutdown
// plugin hooks.
func (e *Engine) Stop(ctx context.Context) error {
	if e.maintCancel != nil {
		e.maintCancel()
	}
	var err error
	if e.checkLogWriter != nil {
		err = e.checkLogWriter.Stop(ctx)
	}
	if e.plugins != nil {
		e.plugins.EmitShutdown(ctx)
	}
	return err
}

// InvalidateSubject clears every cached Check result for one subject. A
// no-op when no Cache is configured.
func (e *Engine) InvalidateSubject(ctx context.Context, tenantID string, subjectKind SubjectKind, subjectID string) {
	if e.cache == nil {
		return
	}
	e.cache.InvalidateSubject(ctx, tenantID, subjectKind, subjectID)
	e.metrics.CacheInvalidated("subject")
}

// InvalidateTenant clears every cached Check result for a tenant. A no-op
// when no Cache is configured.
func (e *Engine) InvalidateTenant(ctx context.Context, tenantID string) {
	if e.cache == nil {
		return
	}
	e.cache.InvalidateTenant(ctx, tenantID)
	e.metrics.CacheInvalidated("tenant")
}

// Check performs an authorization check. This is the hot path.
// Optional CallOption values override scope for this single call.
func (e *Engine) Check(ctx context.Context, req *CheckRequest, opts ...CallOption) (*CheckResult, error) {
	start := time.Now()

	scope, co, err := e.prepareCheck(ctx, req, opts)
	if err != nil {
		return nil, err
	}

	e.logger.Debug("warden: check",
		log.String("subject_kind", string(req.Subject.Kind)),
		log.String("subject_id", req.Subject.ID),
		log.String("action", req.Action.Name),
		log.String("resource_type", req.Resource.Type),
		log.String("scope_app_id", scope.appID),
		log.String("scope_tenant_id", scope.tenantID),
	)

	if e.plugins != nil && !co.dryRun {
		e.plugins.EmitBeforeCheck(ctx, req)
	}

	// 1. Cache hit? Hooks and the check log still fire on a hit: only the
	// RBAC/ReBAC/ABAC evaluation itself is skipped. A dry run skips the
	// lookup entirely, because a cached answer carries no reasoning and its
	// EvalTimeNs is a cache lookup rather than an evaluation.
	if e.cache != nil && !co.dryRun {
		if cached, ok := e.cache.Get(ctx, scope.tenantID, scope.namespacePath, req); ok {
			result := *cached
			result.EvalTimeNs = time.Since(start).Nanoseconds()
			e.metrics.CheckEvaluated(result.Decision, decisionSource(&result), time.Since(start), true)
			e.emitAfterCheck(ctx, req, &result)
			e.writeCheckLog(ctx, scope, req, &result, true, "")
			return &result, nil
		}
	}

	// 2 to 4. RBAC, ReBAC, ABAC.
	run := e.runModels(ctx, scope, req)
	if run.err != nil {
		return e.failCheck(ctx, scope, req, run.err, co.dryRun)
	}
	rbacResult, rebacResult, abacResult := run.rbac, run.rebac, run.abac

	// 5. Merge: explicit deny > allow > default deny.
	result := e.mergeDecisions(req, rbacResult, rebacResult, abacResult)
	if !result.Allowed && rebacResult != nil && rebacResult.truncated {
		// The graph walk hit its depth or budget limit before it could
		// answer, so this denial does not mean "no relation exists". Say
		// so in the reason, which is what the check log records, so an
		// auditor can tell the two apart. The decision itself stays a
		// deny: an unfinished walk never grants.
		result.Reason = truncatedWalkNote + joinReason(result.Reason)
	}
	result.EvalTimeNs = time.Since(start).Nanoseconds()

	e.metrics.CheckEvaluated(result.Decision, decisionSource(result), time.Since(start), false)

	// 6. Cache the result.
	if e.cache != nil && !co.dryRun {
		e.cache.Set(ctx, scope.tenantID, scope.namespacePath, req, result)
	}

	// 7. Extension hooks: per-obligation, then after check.
	if !co.dryRun {
		e.emitAfterCheck(ctx, req, result)
	}

	// 8. Write check log entry (via the bounded batching writer, never a
	// per-call goroutine).
	if !co.dryRun {
		e.writeCheckLog(ctx, scope, req, result, false, "")
	}

	return result, nil
}

// prepareCheck validates req and resolves its scope and call options, as
// the first part of Check. Explain shares it.
func (e *Engine) prepareCheck(ctx context.Context, req *CheckRequest, opts []CallOption) (tenantScope, callOptions, error) {
	// Validate required fields.
	if req.Subject.ID == "" {
		return tenantScope{}, callOptions{}, fmt.Errorf("warden: subject ID is required")
	}
	if req.Action.Name == "" {
		return tenantScope{}, callOptions{}, fmt.Errorf("warden: action name is required")
	}
	if req.Resource.Type == "" {
		return tenantScope{}, callOptions{}, fmt.Errorf("warden: resource type is required for permission check")
	}

	return e.resolveScope(ctx, req.TenantID, req.NamespacePath, opts)
}

// resolveScope resolves one call's scope and call options, the scope-only
// part of prepareCheck, which SubjectRoles shares. Precedence runs from the
// context, to the request's own tenant and namespace (each only when
// non-empty), to the call options, which win. SubjectRoles has no request
// and passes "" for both, which skips that middle layer.
func (e *Engine) resolveScope(ctx context.Context, reqTenantID, reqNamespacePath string, opts []CallOption) (tenantScope, callOptions, error) {
	scope := scopeFromContext(ctx)
	if reqTenantID != "" {
		scope.tenantID = reqTenantID
	}
	if reqNamespacePath != "" {
		scope.namespacePath = reqNamespacePath
	}

	// Apply call-time options (highest priority).
	co := resolveCallOptions(opts)
	if co.tenantID != "" {
		scope.tenantID = co.tenantID
	}
	if co.appID != "" {
		scope.appID = co.appID
	}
	if co.namespacePathSet {
		scope.namespacePath = co.namespacePath
	}

	if e.config.requireTenant() && scope.tenantID == "" {
		return tenantScope{}, callOptions{}, ErrTenantRequired
	}

	// Computed once, after every scope override has been applied, and
	// reused by every evaluator below instead of each recomputing it.
	scope.namespaces = AncestorNamespaces(scope.namespacePath)

	return scope, co, nil
}

// modelRun is one pass through the models, in Check's order.
type modelRun struct {
	rbac, rebac, abac *CheckResult
	rbacRoles         []*role.Role
	// failed names the model whose store read failed ("rbac", "rebac",
	// "abac"); err is the wrapped error Check returns. Empty on success.
	failed string
	err    error
}

// runModels runs RBAC, ReBAC and ABAC exactly as Check always has: ReBAC
// only when RBAC did not allow or EvaluateAllModels is on, ABAC whenever
// enabled, and nothing after a failure.
func (e *Engine) runModels(ctx context.Context, scope tenantScope, req *CheckRequest) modelRun {
	var run modelRun
	var err error

	// 2. RBAC: resolve roles → check permissions.
	if e.config.rbacEnabled() {
		run.rbac, run.rbacRoles, err = e.evaluateRBAC(ctx, scope, req)
		if err != nil {
			run.failed, run.err = "rbac", fmt.Errorf("warden rbac: %w", err)
			return run
		}
	}

	// 3. ReBAC: check relation tuples → walk graph. Skipped once RBAC has
	// already allowed the request, unless EvaluateAllModels is set: the
	// graph walk is the most expensive of the three evaluators.
	if e.config.rebacEnabled() && (run.rbac == nil || !run.rbac.Allowed || e.config.EvaluateAllModels) {
		run.rebac, err = e.evaluateReBAC(ctx, scope, req)
		if err != nil {
			run.failed, run.err = "rebac", fmt.Errorf("warden rebac: %w", err)
			return run
		}
	}

	// 4. ABAC: evaluate active policies with conditions. Always runs (even
	// after an RBAC/ReBAC allow) because an explicit deny policy must be
	// able to override an allow from another model.
	if e.config.abacEnabled() {
		run.abac, err = e.evaluateABAC(ctx, scope, req, rolesToSlugs(run.rbacRoles))
		if err != nil {
			run.failed, run.err = "abac", fmt.Errorf("warden abac: %w", err)
			return run
		}
	}

	return run
}

func (e *Engine) emitAfterCheck(ctx context.Context, req *CheckRequest, result *CheckResult) {
	if e.plugins == nil {
		return
	}
	for _, ob := range result.Obligations {
		e.plugins.EmitPolicyObligationFired(ctx, policyIDFromMatched(result.MatchedBy), ob, req, result)
	}
	e.plugins.EmitAfterCheck(ctx, req, result)
}

// failCheck records a check-evaluation failure (as a check log entry with
// Decision "error") and returns the error unchanged, so every Check error
// path still leaves an audit trail. A dry run leaves none, the same as its
// success path.
func (e *Engine) failCheck(ctx context.Context, scope tenantScope, req *CheckRequest, err error, dryRun bool) (*CheckResult, error) {
	// No StoreError here. Every store call that fails is already counted
	// at its call site under its own op label, and a failure that did not
	// come from the store (a policy condition, say) is not a store error.
	// A blanket count in this function counted store failures twice and
	// everything else wrongly.
	if !dryRun {
		e.writeCheckLog(ctx, scope, req, nil, false, err.Error())
	}
	return nil, err
}

// decisionSource returns the evaluator that produced result's decision
// ("rbac", "rebac", "abac"), or "none" when nothing matched.
func decisionSource(result *CheckResult) string {
	if result == nil || len(result.MatchedBy) == 0 {
		return "none"
	}
	return result.MatchedBy[0].Source
}

// Enforce returns an error if the authorization check is denied.
// Optional CallOption values override scope for this single call.
func (e *Engine) Enforce(ctx context.Context, req *CheckRequest, opts ...CallOption) error {
	result, err := e.Check(ctx, req, opts...)
	if err != nil {
		return fmt.Errorf("warden check: %w", err)
	}
	if !result.Allowed {
		return fmt.Errorf("%w: %s: %s", ErrAccessDenied, result.Decision, result.Reason)
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

// writeCheckLog builds a check log entry and hands it to the bounded
// batching writer. cached marks a cache-hit entry; evalErr, when non-empty,
// marks an evaluation-error entry (Decision "error"). Never blocks: a full
// writer queue drops the entry and increments Metrics.CheckLogDropped.
func (e *Engine) writeCheckLog(ctx context.Context, scope tenantScope, req *CheckRequest, result *CheckResult, cached bool, evalErr string) {
	if !e.config.checkLogEnabled() || e.checkLogWriter == nil {
		return
	}
	e.checkLogWriter.Enqueue(e.buildCheckLogEntry(ctx, scope, req, result, cached, evalErr))
}

func (e *Engine) buildCheckLogEntry(ctx context.Context, scope tenantScope, req *CheckRequest, result *CheckResult, cached bool, evalErr string) *checklog.Entry {
	decision := "error"
	reason := ""
	var matchedBy []checklog.MatchRef
	var obligations []string
	var evalTimeNs int64
	if result != nil {
		decision = string(result.Decision)
		reason = result.Reason
		matchedBy = toMatchRefs(result.MatchedBy)
		obligations = result.Obligations
		evalTimeNs = result.EvalTimeNs
	}
	if evalErr != "" {
		decision = "error"
	}

	traceID := log.TraceIDFromContext(ctx)
	if traceID == "" {
		if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
			traceID = sc.TraceID().String()
		}
	}

	return &checklog.Entry{
		ID:            id.NewCheckLogID(),
		TenantID:      scope.tenantID,
		NamespacePath: scope.namespacePath,
		AppID:         scope.appID,
		SubjectKind:   string(req.Subject.Kind),
		SubjectID:     req.Subject.ID,
		Action:        req.Action.Name,
		ResourceType:  req.Resource.Type,
		ResourceID:    req.Resource.ID,
		Decision:      decision,
		Reason:        reason,
		MatchedBy:     matchedBy,
		Obligations:   obligations,
		EvalTimeNs:    evalTimeNs,
		RequestIP:     requestIPFromContext(ctx),
		RequestID:     log.RequestIDFromContext(ctx),
		TraceID:       traceID,
		Cached:        cached,
		Error:         evalErr,
		CreatedAt:     time.Now(),
	}
}

func toMatchRefs(in []MatchInfo) []checklog.MatchRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]checklog.MatchRef, len(in))
	for i, m := range in {
		out[i] = checklog.MatchRef{Source: m.Source, RuleID: m.RuleID, Detail: m.Detail}
	}
	return out
}

// resolveAssignedRoles resolves the full set of roles held by the request's
// subject: direct (global + resource-scoped) assignments, plus every role
// reached by walking ParentSlug inheritance, as full Role objects, so
// callers can read both permissions (RBAC) and slugs (role-scoped ABAC
// matching, see matchesSubject) from the same resolution.
func (e *Engine) resolveAssignedRoles(ctx context.Context, scope tenantScope, req *CheckRequest) ([]*role.Role, error) {
	globalRoleIDs, err := e.globalRoleIDs(ctx, scope, req.Subject.Kind, req.Subject.ID)
	if err != nil {
		return nil, err
	}
	resourceRoleIDs, err := e.store.ListRolesForSubjectOnResource(ctx, scope.tenantID, scope.namespaces, string(req.Subject.Kind), req.Subject.ID, req.Resource.Type, req.Resource.ID)
	if err != nil {
		e.metrics.StoreError("list_roles_for_subject_on_resource")
		return nil, err
	}

	allIDs := make([]id.RoleID, 0, len(globalRoleIDs)+len(resourceRoleIDs))
	allIDs = append(allIDs, globalRoleIDs...)
	allIDs = append(allIDs, resourceRoleIDs...)
	if len(allIDs) == 0 {
		return nil, nil
	}

	direct, err := e.getRoles(ctx, scope, allIDs)
	if err != nil {
		return nil, err
	}

	return e.resolveInheritedRoleObjects(ctx, direct), nil
}

// globalRoleIDs lists the roles assigned to a subject at scope's namespace
// or an ancestor, with no resource and unexpired: the global half of
// resolveAssignedRoles, which SubjectRoles shares through globalRoles.
func (e *Engine) globalRoleIDs(ctx context.Context, scope tenantScope, kind SubjectKind, subjectID string) ([]id.RoleID, error) {
	globalRoleIDs, err := e.store.ListRolesForSubject(ctx, scope.tenantID, scope.namespaces, string(kind), subjectID)
	if err != nil {
		e.metrics.StoreError("list_roles_for_subject")
		return nil, err
	}
	return globalRoleIDs, nil
}

// getRoles loads role objects by ID, counting a store failure under
// "get_roles". Callers skip it for an empty ID list, as resolveAssignedRoles
// always has.
func (e *Engine) getRoles(ctx context.Context, scope tenantScope, roleIDs []id.RoleID) ([]*role.Role, error) {
	direct, err := e.store.GetRoles(ctx, scope.tenantID, roleIDs)
	if err != nil {
		e.metrics.StoreError("get_roles")
		return nil, err
	}
	return direct, nil
}

// resolveInheritedRoleObjects walks ParentSlug inheritance breadth-first,
// one level at a time, deduplicating both by role ID (a role already
// resolved at an earlier level is never re-walked) and by (namespace,slug)
// within a level (two roles at the same level sharing a parent slug only
// trigger one GetRoleBySlug call). depth is capped at 20 to bound a cyclic
// parent chain.
func (e *Engine) resolveInheritedRoleObjects(ctx context.Context, initial []*role.Role) []*role.Role {
	seen := make(map[string]struct{}, len(initial))
	var result []*role.Role

	level := initial
	// depth <= 20 (not <) matches the original recursive walker's cap
	// ("if depth > 20 { return }" before appending), which permits 21
	// levels total (depth 0 through 20 inclusive) before the safety limit
	// bites, a chain shallower than that must resolve every level.
	for depth := 0; len(level) > 0 && depth <= 20; depth++ {
		var nextLevel []*role.Role
		parentCache := make(map[string]*role.Role)

		for _, r := range level {
			if r == nil {
				continue
			}
			key := r.ID.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, r)

			if r.ParentSlug == "" {
				continue
			}
			pkey := r.NamespacePath + "\x00" + r.ParentSlug
			parent, ok := parentCache[pkey]
			if !ok {
				var perr error
				parent, perr = e.store.GetRoleBySlug(ctx, r.TenantID, r.NamespacePath, r.ParentSlug)
				if perr != nil || parent == nil {
					parentCache[pkey] = nil
					continue
				}
				parentCache[pkey] = parent
			}
			if parent == nil {
				continue
			}
			if _, ok := seen[parent.ID.String()]; ok {
				continue
			}
			nextLevel = append(nextLevel, parent)
		}
		level = nextLevel
	}
	return result
}

// rolesToSlugs extracts role slugs for role-scoped ABAC matching
// (policy.SubjectMatch.Role).
func rolesToSlugs(roles []*role.Role) []string {
	if len(roles) == 0 {
		return nil
	}
	slugs := make([]string, 0, len(roles))
	for _, r := range roles {
		if r == nil {
			continue
		}
		slugs = append(slugs, r.Slug)
	}
	return slugs
}

func (e *Engine) evaluateRBAC(ctx context.Context, scope tenantScope, req *CheckRequest) (*CheckResult, []*role.Role, error) {
	roles, err := e.resolveAssignedRoles(ctx, scope, req)
	if err != nil {
		return nil, nil, err
	}
	if len(roles) == 0 {
		return &CheckResult{Decision: DecisionDenyNoRoles, Reason: fmt.Sprintf("subject %s:%s has no assigned roles in tenant %q", req.Subject.Kind, req.Subject.ID, scope.tenantID)}, nil, nil
	}

	roleIDs := make([]id.RoleID, len(roles))
	for i, r := range roles {
		roleIDs[i] = r.ID
	}

	// One JOIN-backed call for every role's grants, instead of the
	// previous ListRolePermissions-per-role loop.
	permsByRole, err := e.store.ListRolePermissionsForRoles(ctx, scope.tenantID, roleIDs)
	if err != nil {
		e.metrics.StoreError("list_role_permissions_for_roles")
		return nil, roles, err
	}

	permName := req.Resource.Type + ":" + req.Action.Name

	for _, r := range roles {
		for _, perm := range permsByRole[r.ID] {
			if perm == nil {
				continue
			}
			storedPerm := perm.Resource + ":" + perm.Action
			if matchPermission(storedPerm, permName) {
				return &CheckResult{
					Allowed:  true,
					Decision: DecisionAllow,
					MatchedBy: []MatchInfo{{
						Source: "rbac",
						RuleID: r.ID.String(),
						Detail: "role grants " + storedPerm,
					}},
				}, roles, nil
			}
		}
	}

	return &CheckResult{Decision: DecisionDenyNoPerms, Reason: fmt.Sprintf("no role grants permission %q for subject %s:%s", permName, req.Subject.Kind, req.Subject.ID)}, roles, nil
}

func (e *Engine) evaluateReBAC(ctx context.Context, scope tenantScope, req *CheckRequest) (*CheckResult, error) {
	// Direct relation check. Relations cascade like roles/policies: a tuple at
	// an ancestor namespace is in scope for a check at a descendant namespace.
	direct, err := e.store.CheckDirectRelation(ctx, scope.tenantID, scope.namespaces, req.Resource.Type, req.Resource.ID, req.Action.Name, string(req.Subject.Kind), req.Subject.ID)
	if err != nil {
		e.metrics.StoreError("check_direct_relation")
		return nil, err
	}
	if direct {
		return &CheckResult{
			Allowed:   true,
			Decision:  DecisionAllow,
			MatchedBy: []MatchInfo{{Source: "rebac", Detail: "direct relation"}},
		}, nil
	}

	// Resource-type expression: if the request's resource type defines the
	// permission as an expression (`read = viewer or editor or parent->read`),
	// evaluate it. A failed expression is logged and treated as no match;
	// its message rides on every result returned below so Explain can
	// report it.
	exprErr := ""
	if e.exprEval != nil {
		matched, err := e.exprEval.EvalPermission(ctx, scope.tenantID, scope.namespacePath,
			req.Resource.Type, req.Action.Name,
			string(req.Subject.Kind), req.Subject.ID, req.Resource.ID)
		if err != nil {
			e.logger.Warn("warden: rebac expression eval error", log.Error(err))
			exprErr = err.Error()
		} else if matched {
			return &CheckResult{
				Allowed:   true,
				Decision:  DecisionAllow,
				MatchedBy: []MatchInfo{{Source: "rebac", Detail: "expression: " + req.Action.Name}},
			}, nil
		}
	}

	// Walk graph for transitive permissions.
	truncated := false
	if e.graphWalker != nil {
		allowed, path, err := e.graphWalker.Walk(ctx, e.store, scope.tenantID, scope.namespacePath, req)
		if err != nil {
			switch {
			case errors.Is(err, ErrGraphDepthExceeded), errors.Is(err, ErrGraphBudgetExceeded):
				truncated = true
			default:
				e.metrics.StoreError("graph_walk")
				return nil, err
			}
		}
		if allowed {
			return &CheckResult{
				Allowed:   true,
				Decision:  DecisionAllow,
				MatchedBy: []MatchInfo{{Source: "rebac", Detail: "transitive: " + path}},
				exprErr:   exprErr,
			}, nil
		}
	}

	return &CheckResult{
		Decision:  DecisionDenyRelation,
		Reason:    fmt.Sprintf("no relation grants %s:%s %s access to %s:%s", req.Subject.Kind, req.Subject.ID, req.Action.Name, req.Resource.Type, req.Resource.ID),
		truncated: truncated,
		exprErr:   exprErr,
	}, nil
}

func (e *Engine) evaluateABAC(ctx context.Context, scope tenantScope, req *CheckRequest, roleSlugs []string) (*CheckResult, error) {
	if !e.config.rbacEnabled() {
		// RBAC didn't already resolve roles for us, so resolve them here.
		// This keeps role-scoped policies (policy.SubjectMatch.Role)
		// working even when RBAC evaluation itself is disabled.
		//
		// A failed lookup fails the check. Carrying on with an empty role
		// list would make every role-scoped deny policy stop matching, so
		// an outage in the role tables would quietly open exactly the
		// access those policies exist to close.
		roles, err := e.resolveAssignedRoles(ctx, scope, req)
		if err != nil {
			return nil, fmt.Errorf("resolve roles for role-scoped policies: %w", err)
		}
		roleSlugs = rolesToSlugs(roles)
	}

	// Policies cascade: include policies at the request's namespace and every ancestor.
	policies, err := e.store.ListActivePolicies(ctx, scope.tenantID, scope.namespaces)
	if err != nil {
		e.metrics.StoreError("list_active_policies")
		return nil, err
	}
	return e.evaluator.Evaluate(ctx, policies, req, roleSlugs)
}

func (e *Engine) mergeDecisions(req *CheckRequest, rbac, rebac, abac *CheckResult) *CheckResult {
	// Obligations from every matched policy (allow OR deny) flow through to
	// the final result regardless of which decision wins. Side-effect
	// signals are independent of the allow/deny outcome.
	obligations := mergeObligations(rbac, rebac, abac)

	// Explicit deny (from ABAC) always wins.
	if abac != nil && abac.Decision == DecisionDenyExplicit {
		out := *abac
		out.Obligations = obligations
		return &out
	}

	// Any allow from any model grants access.
	for _, r := range []*CheckResult{rbac, rebac, abac} {
		if r != nil && r.Allowed {
			out := *r
			out.Obligations = obligations
			return &out
		}
	}

	// Default deny: pick the most informative reason.
	for _, r := range []*CheckResult{rbac, rebac, abac} {
		if r != nil && r.Reason != "" {
			out := *r
			out.Obligations = obligations
			return &out
		}
	}

	return &CheckResult{
		Decision:    DecisionDenyDefault,
		Reason:      fmt.Sprintf("no rule allows %s:%s to %s on %s:%s", req.Subject.Kind, req.Subject.ID, req.Action.Name, req.Resource.Type, req.Resource.ID),
		Obligations: obligations,
	}
}

func mergeObligations(results ...*CheckResult) []string {
	var all []string
	for _, r := range results {
		if r == nil {
			continue
		}
		all = append(all, r.Obligations...)
	}
	return dedupeStrings(all)
}

// policyIDFromMatched returns the first ABAC policy ID in matchedBy, or
// the zero value if none is present. Used to attach provenance to
// PolicyObligationFired events; consumers needing full provenance can
// iterate result.MatchedBy directly.
func policyIDFromMatched(matchedBy []MatchInfo) id.PolicyID {
	for _, m := range matchedBy {
		if m.Source != "abac" {
			continue
		}
		if pid, err := id.ParsePolicyID(m.RuleID); err == nil {
			return pid
		}
	}
	return id.PolicyID{}
}

// truncatedWalkNote prefixes the reason of a denial that followed a graph
// walk stopped by MaxGraphDepth, MaxGraphVisited or MaxGraphFanout.
const truncatedWalkNote = "graph traversal budget exceeded (relation walk truncated, a relation may exist beyond the limit); "

func joinReason(r string) string {
	if r == "" {
		return "no rule allows the request"
	}
	return r
}
