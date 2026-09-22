package plugin

import (
	"context"
	"fmt"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
)

// MetricsRecorder is the minimal metrics surface the registry needs. It
// mirrors (and is satisfied by) warden.Metrics' HookError method without
// importing the root package, which would create an import cycle.
type MetricsRecorder interface {
	HookError(hook, plugin string)
}

type noopMetricsRecorder struct{}

func (noopMetricsRecorder) HookError(string, string) {}

// Named entry types pair a hook with the plugin name for logging.

type beforeCheckEntry struct {
	name string
	hook BeforeCheck
}
type afterCheckEntry struct {
	name string
	hook AfterCheck
}
type roleCreatedEntry struct {
	name string
	hook RoleCreated
}
type roleUpdatedEntry struct {
	name string
	hook RoleUpdated
}
type roleDeletedEntry struct {
	name string
	hook RoleDeleted
}
type permissionCreatedEntry struct {
	name string
	hook PermissionCreated
}
type permissionDeletedEntry struct {
	name string
	hook PermissionDeleted
}
type permissionAttachedEntry struct {
	name string
	hook PermissionAttached
}
type permissionDetachedEntry struct {
	name string
	hook PermissionDetached
}
type roleAssignedEntry struct {
	name string
	hook RoleAssigned
}
type roleUnassignedEntry struct {
	name string
	hook RoleUnassigned
}
type relationWrittenEntry struct {
	name string
	hook RelationWritten
}
type relationDeletedEntry struct {
	name string
	hook RelationDeleted
}
type policyCreatedEntry struct {
	name string
	hook PolicyCreated
}
type policyUpdatedEntry struct {
	name string
	hook PolicyUpdated
}
type policyDeletedEntry struct {
	name string
	hook PolicyDeleted
}
type policyObligationFiredEntry struct {
	name string
	hook PolicyObligationFired
}
type shutdownEntry struct {
	name string
	hook Shutdown
}
type auditEntry struct {
	name string
	hook Audit
}

// Registry holds registered plugins and dispatches lifecycle events.
// It type-caches plugins at registration time so emit calls iterate
// only over plugins implementing the relevant hook.
//
// Every dispatch is panic-recovered per hook: one misbehaving plugin can
// neither crash the calling goroutine nor stop other plugins in the same
// Emit call from running.
type Registry struct {
	plugins []Plugin
	logger  log.Logger
	metrics MetricsRecorder

	beforeCheck        []beforeCheckEntry
	afterCheck         []afterCheckEntry
	roleCreated        []roleCreatedEntry
	roleUpdated        []roleUpdatedEntry
	roleDeleted        []roleDeletedEntry
	permissionCreated  []permissionCreatedEntry
	permissionDeleted  []permissionDeletedEntry
	permissionAttached []permissionAttachedEntry
	permissionDetached []permissionDetachedEntry
	roleAssigned       []roleAssignedEntry
	roleUnassigned     []roleUnassignedEntry
	relationWritten    []relationWrittenEntry
	relationDeleted    []relationDeletedEntry
	policyCreated      []policyCreatedEntry
	policyUpdated      []policyUpdatedEntry
	policyDeleted      []policyDeletedEntry
	policyObligation   []policyObligationFiredEntry
	shutdown           []shutdownEntry
	audit              []auditEntry
}

// NewRegistry creates a plugin registry with the given logger.
func NewRegistry(logger log.Logger) *Registry {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Registry{logger: logger, metrics: noopMetricsRecorder{}}
}

// SetMetrics installs a metrics sink for hook-error counting. Passing nil
// is a no-op (the registry keeps its current sink, defaulting to a noop).
func (r *Registry) SetMetrics(m MetricsRecorder) {
	if m != nil {
		r.metrics = m
	}
}

// Register adds a plugin and type-asserts it into all applicable
// hook caches. Plugins are notified in registration order.
//
// If the plugin implements none of the known hook interfaces, Register
// logs a Warn: a plugin that only implements Plugin does nothing, which
// is almost always a wiring mistake (wrong interface signature, typo'd
// method name, etc).
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
	name := p.Name()

	if len(r.Validate(p)) == 0 {
		r.logger.Warn("plugin implements no known hook interface", log.String("plugin", name))
	}

	if h, ok := p.(BeforeCheck); ok {
		r.beforeCheck = append(r.beforeCheck, beforeCheckEntry{name, h})
	}
	if h, ok := p.(AfterCheck); ok {
		r.afterCheck = append(r.afterCheck, afterCheckEntry{name, h})
	}
	if h, ok := p.(RoleCreated); ok {
		r.roleCreated = append(r.roleCreated, roleCreatedEntry{name, h})
	}
	if h, ok := p.(RoleUpdated); ok {
		r.roleUpdated = append(r.roleUpdated, roleUpdatedEntry{name, h})
	}
	if h, ok := p.(RoleDeleted); ok {
		r.roleDeleted = append(r.roleDeleted, roleDeletedEntry{name, h})
	}
	if h, ok := p.(PermissionCreated); ok {
		r.permissionCreated = append(r.permissionCreated, permissionCreatedEntry{name, h})
	}
	if h, ok := p.(PermissionDeleted); ok {
		r.permissionDeleted = append(r.permissionDeleted, permissionDeletedEntry{name, h})
	}
	if h, ok := p.(PermissionAttached); ok {
		r.permissionAttached = append(r.permissionAttached, permissionAttachedEntry{name, h})
	}
	if h, ok := p.(PermissionDetached); ok {
		r.permissionDetached = append(r.permissionDetached, permissionDetachedEntry{name, h})
	}
	if h, ok := p.(RoleAssigned); ok {
		r.roleAssigned = append(r.roleAssigned, roleAssignedEntry{name, h})
	}
	if h, ok := p.(RoleUnassigned); ok {
		r.roleUnassigned = append(r.roleUnassigned, roleUnassignedEntry{name, h})
	}
	if h, ok := p.(RelationWritten); ok {
		r.relationWritten = append(r.relationWritten, relationWrittenEntry{name, h})
	}
	if h, ok := p.(RelationDeleted); ok {
		r.relationDeleted = append(r.relationDeleted, relationDeletedEntry{name, h})
	}
	if h, ok := p.(PolicyCreated); ok {
		r.policyCreated = append(r.policyCreated, policyCreatedEntry{name, h})
	}
	if h, ok := p.(PolicyUpdated); ok {
		r.policyUpdated = append(r.policyUpdated, policyUpdatedEntry{name, h})
	}
	if h, ok := p.(PolicyDeleted); ok {
		r.policyDeleted = append(r.policyDeleted, policyDeletedEntry{name, h})
	}
	if h, ok := p.(PolicyObligationFired); ok {
		r.policyObligation = append(r.policyObligation, policyObligationFiredEntry{name, h})
	}
	if h, ok := p.(Shutdown); ok {
		r.shutdown = append(r.shutdown, shutdownEntry{name, h})
	}
	if h, ok := p.(Audit); ok {
		r.audit = append(r.audit, auditEntry{name, h})
	}
}

// Validate returns the names of every known hook interface p implements.
// An empty slice means p implements nothing beyond the base Plugin
// interface.
func (r *Registry) Validate(p Plugin) []string {
	var names []string
	if _, ok := p.(BeforeCheck); ok {
		names = append(names, "BeforeCheck")
	}
	if _, ok := p.(AfterCheck); ok {
		names = append(names, "AfterCheck")
	}
	if _, ok := p.(RoleCreated); ok {
		names = append(names, "RoleCreated")
	}
	if _, ok := p.(RoleUpdated); ok {
		names = append(names, "RoleUpdated")
	}
	if _, ok := p.(RoleDeleted); ok {
		names = append(names, "RoleDeleted")
	}
	if _, ok := p.(PermissionCreated); ok {
		names = append(names, "PermissionCreated")
	}
	if _, ok := p.(PermissionDeleted); ok {
		names = append(names, "PermissionDeleted")
	}
	if _, ok := p.(PermissionAttached); ok {
		names = append(names, "PermissionAttached")
	}
	if _, ok := p.(PermissionDetached); ok {
		names = append(names, "PermissionDetached")
	}
	if _, ok := p.(RoleAssigned); ok {
		names = append(names, "RoleAssigned")
	}
	if _, ok := p.(RoleUnassigned); ok {
		names = append(names, "RoleUnassigned")
	}
	if _, ok := p.(RelationWritten); ok {
		names = append(names, "RelationWritten")
	}
	if _, ok := p.(RelationDeleted); ok {
		names = append(names, "RelationDeleted")
	}
	if _, ok := p.(PolicyCreated); ok {
		names = append(names, "PolicyCreated")
	}
	if _, ok := p.(PolicyUpdated); ok {
		names = append(names, "PolicyUpdated")
	}
	if _, ok := p.(PolicyDeleted); ok {
		names = append(names, "PolicyDeleted")
	}
	if _, ok := p.(PolicyObligationFired); ok {
		names = append(names, "PolicyObligationFired")
	}
	if _, ok := p.(Shutdown); ok {
		names = append(names, "Shutdown")
	}
	if _, ok := p.(Audit); ok {
		names = append(names, "Audit")
	}
	return names
}

// Plugins returns all registered plugins.
func (r *Registry) Plugins() []Plugin { return r.plugins }

// call invokes fn, recovering from a panic and counting/logging both
// panics and returned errors as a hook error. Used by every Emit* method
// below so one misbehaving plugin can't crash the caller or block the rest
// of the dispatch loop.
func (r *Registry) call(hook, pluginName string, fn func() error) {
	defer func() {
		if rec := recover(); rec != nil {
			r.metrics.HookError(hook, pluginName)
			r.logger.Error("plugin hook panicked",
				log.String("hook", hook),
				log.String("plugin", pluginName),
				log.String("panic", fmt.Sprintf("%v", rec)),
			)
		}
	}()
	if err := fn(); err != nil {
		r.metrics.HookError(hook, pluginName)
		r.logHookError(hook, pluginName, err)
	}
}

// ──────────────────────────────────────────────────
// Check event emitters
// ──────────────────────────────────────────────────

// EmitBeforeCheck notifies all plugins that implement BeforeCheck.
func (r *Registry) EmitBeforeCheck(ctx context.Context, req any) {
	for _, e := range r.beforeCheck {
		r.call("OnBeforeCheck", e.name, func() error { return e.hook.OnBeforeCheck(ctx, req) })
	}
}

// EmitAfterCheck notifies all plugins that implement AfterCheck.
func (r *Registry) EmitAfterCheck(ctx context.Context, req, result any) {
	for _, e := range r.afterCheck {
		r.call("OnAfterCheck", e.name, func() error { return e.hook.OnAfterCheck(ctx, req, result) })
	}
}

// ──────────────────────────────────────────────────
// Role event emitters
// ──────────────────────────────────────────────────

// EmitRoleCreated notifies all plugins that implement RoleCreated.
func (r *Registry) EmitRoleCreated(ctx context.Context, rl *role.Role) {
	for _, e := range r.roleCreated {
		r.call("OnRoleCreated", e.name, func() error { return e.hook.OnRoleCreated(ctx, rl) })
	}
}

// EmitRoleUpdated notifies all plugins that implement RoleUpdated.
func (r *Registry) EmitRoleUpdated(ctx context.Context, rl *role.Role) {
	for _, e := range r.roleUpdated {
		r.call("OnRoleUpdated", e.name, func() error { return e.hook.OnRoleUpdated(ctx, rl) })
	}
}

// EmitRoleDeleted notifies all plugins that implement RoleDeleted.
func (r *Registry) EmitRoleDeleted(ctx context.Context, roleID id.RoleID) {
	for _, e := range r.roleDeleted {
		r.call("OnRoleDeleted", e.name, func() error { return e.hook.OnRoleDeleted(ctx, roleID) })
	}
}

// ──────────────────────────────────────────────────
// Permission event emitters
// ──────────────────────────────────────────────────

// EmitPermissionCreated notifies all plugins that implement PermissionCreated.
func (r *Registry) EmitPermissionCreated(ctx context.Context, p *permission.Permission) {
	for _, e := range r.permissionCreated {
		r.call("OnPermissionCreated", e.name, func() error { return e.hook.OnPermissionCreated(ctx, p) })
	}
}

// EmitPermissionDeleted notifies all plugins that implement PermissionDeleted.
func (r *Registry) EmitPermissionDeleted(ctx context.Context, permID id.PermissionID) {
	for _, e := range r.permissionDeleted {
		r.call("OnPermissionDeleted", e.name, func() error { return e.hook.OnPermissionDeleted(ctx, permID) })
	}
}

// EmitPermissionAttached notifies all plugins that implement PermissionAttached.
func (r *Registry) EmitPermissionAttached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) {
	for _, e := range r.permissionAttached {
		r.call("OnPermissionAttached", e.name, func() error { return e.hook.OnPermissionAttached(ctx, roleID, permID) })
	}
}

// EmitPermissionDetached notifies all plugins that implement PermissionDetached.
func (r *Registry) EmitPermissionDetached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) {
	for _, e := range r.permissionDetached {
		r.call("OnPermissionDetached", e.name, func() error { return e.hook.OnPermissionDetached(ctx, roleID, permID) })
	}
}

// ──────────────────────────────────────────────────
// Assignment event emitters
// ──────────────────────────────────────────────────

// EmitRoleAssigned notifies all plugins that implement RoleAssigned.
func (r *Registry) EmitRoleAssigned(ctx context.Context, a *assignment.Assignment) {
	for _, e := range r.roleAssigned {
		r.call("OnRoleAssigned", e.name, func() error { return e.hook.OnRoleAssigned(ctx, a) })
	}
}

// EmitRoleUnassigned notifies all plugins that implement RoleUnassigned.
func (r *Registry) EmitRoleUnassigned(ctx context.Context, a *assignment.Assignment) {
	for _, e := range r.roleUnassigned {
		r.call("OnRoleUnassigned", e.name, func() error { return e.hook.OnRoleUnassigned(ctx, a) })
	}
}

// ──────────────────────────────────────────────────
// Relation event emitters
// ──────────────────────────────────────────────────

// EmitRelationWritten notifies all plugins that implement RelationWritten.
func (r *Registry) EmitRelationWritten(ctx context.Context, t *relation.Tuple) {
	for _, e := range r.relationWritten {
		r.call("OnRelationWritten", e.name, func() error { return e.hook.OnRelationWritten(ctx, t) })
	}
}

// EmitRelationDeleted notifies all plugins that implement RelationDeleted.
func (r *Registry) EmitRelationDeleted(ctx context.Context, relID id.RelationID) {
	for _, e := range r.relationDeleted {
		r.call("OnRelationDeleted", e.name, func() error { return e.hook.OnRelationDeleted(ctx, relID) })
	}
}

// ──────────────────────────────────────────────────
// Policy event emitters
// ──────────────────────────────────────────────────

// EmitPolicyCreated notifies all plugins that implement PolicyCreated.
func (r *Registry) EmitPolicyCreated(ctx context.Context, p *policy.Policy) {
	for _, e := range r.policyCreated {
		r.call("OnPolicyCreated", e.name, func() error { return e.hook.OnPolicyCreated(ctx, p) })
	}
}

// EmitPolicyUpdated notifies all plugins that implement PolicyUpdated.
func (r *Registry) EmitPolicyUpdated(ctx context.Context, p *policy.Policy) {
	for _, e := range r.policyUpdated {
		r.call("OnPolicyUpdated", e.name, func() error { return e.hook.OnPolicyUpdated(ctx, p) })
	}
}

// EmitPolicyDeleted notifies all plugins that implement PolicyDeleted.
func (r *Registry) EmitPolicyDeleted(ctx context.Context, polID id.PolicyID) {
	for _, e := range r.policyDeleted {
		r.call("OnPolicyDeleted", e.name, func() error { return e.hook.OnPolicyDeleted(ctx, polID) })
	}
}

// EmitPolicyObligationFired notifies all plugins that implement
// PolicyObligationFired. Called once per obligation produced by the
// engine after merging RBAC / ReBAC / ABAC results.
func (r *Registry) EmitPolicyObligationFired(ctx context.Context, polID id.PolicyID, obligation string, req, result any) {
	for _, e := range r.policyObligation {
		r.call("OnPolicyObligationFired", e.name, func() error {
			return e.hook.OnPolicyObligationFired(ctx, polID, obligation, req, result)
		})
	}
}

// ──────────────────────────────────────────────────
// Audit emitter
// ──────────────────────────────────────────────────

// EmitAudit notifies all plugins that implement Audit. Called for every
// mutation, in addition to whichever typed Emit* also fires for it.
func (r *Registry) EmitAudit(ctx context.Context, ev Event) {
	for _, e := range r.audit {
		r.call("OnAudit", e.name, func() error { return e.hook.OnAudit(ctx, ev) })
	}
}

// ──────────────────────────────────────────────────
// Shutdown emitter
// ──────────────────────────────────────────────────

// EmitShutdown notifies all plugins that implement Shutdown.
func (r *Registry) EmitShutdown(ctx context.Context) {
	for _, e := range r.shutdown {
		r.call("OnShutdown", e.name, func() error { return e.hook.OnShutdown(ctx) })
	}
}

// logHookError logs a warning when a lifecycle hook returns an error.
// Errors from hooks are never propagated — they must not block the pipeline.
func (r *Registry) logHookError(hook, pluginName string, err error) {
	r.logger.Warn("plugin hook error",
		log.String("hook", hook),
		log.String("plugin", pluginName),
		log.String("error", err.Error()),
	)
}
