package plugin

import (
	"context"
	"log/slog"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
)

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
type shutdownEntry struct {
	name string
	hook Shutdown
}

// Registry holds registered plugins and dispatches lifecycle events.
// It type-caches plugins at registration time so emit calls iterate
// only over plugins implementing the relevant hook.
type Registry struct {
	plugins []Plugin
	logger  *slog.Logger

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
	shutdown           []shutdownEntry
}

// NewRegistry creates a plugin registry with the given logger.
func NewRegistry(logger *slog.Logger) *Registry {
	return &Registry{logger: logger}
}

// Register adds a plugin and type-asserts it into all applicable
// hook caches. Plugins are notified in registration order.
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
	name := p.Name()

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
	if h, ok := p.(Shutdown); ok {
		r.shutdown = append(r.shutdown, shutdownEntry{name, h})
	}
}

// Plugins returns all registered plugins.
func (r *Registry) Plugins() []Plugin { return r.plugins }

// ──────────────────────────────────────────────────
// Check event emitters
// ──────────────────────────────────────────────────

// EmitBeforeCheck notifies all plugins that implement BeforeCheck.
func (r *Registry) EmitBeforeCheck(ctx context.Context, req any) {
	for _, e := range r.beforeCheck {
		if err := e.hook.OnBeforeCheck(ctx, req); err != nil {
			r.logHookError("OnBeforeCheck", e.name, err)
		}
	}
}

// EmitAfterCheck notifies all plugins that implement AfterCheck.
func (r *Registry) EmitAfterCheck(ctx context.Context, req, result any) {
	for _, e := range r.afterCheck {
		if err := e.hook.OnAfterCheck(ctx, req, result); err != nil {
			r.logHookError("OnAfterCheck", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Role event emitters
// ──────────────────────────────────────────────────

// EmitRoleCreated notifies all plugins that implement RoleCreated.
func (r *Registry) EmitRoleCreated(ctx context.Context, rl *role.Role) {
	for _, e := range r.roleCreated {
		if err := e.hook.OnRoleCreated(ctx, rl); err != nil {
			r.logHookError("OnRoleCreated", e.name, err)
		}
	}
}

// EmitRoleUpdated notifies all plugins that implement RoleUpdated.
func (r *Registry) EmitRoleUpdated(ctx context.Context, rl *role.Role) {
	for _, e := range r.roleUpdated {
		if err := e.hook.OnRoleUpdated(ctx, rl); err != nil {
			r.logHookError("OnRoleUpdated", e.name, err)
		}
	}
}

// EmitRoleDeleted notifies all plugins that implement RoleDeleted.
func (r *Registry) EmitRoleDeleted(ctx context.Context, roleID id.RoleID) {
	for _, e := range r.roleDeleted {
		if err := e.hook.OnRoleDeleted(ctx, roleID); err != nil {
			r.logHookError("OnRoleDeleted", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Permission event emitters
// ──────────────────────────────────────────────────

// EmitPermissionCreated notifies all plugins that implement PermissionCreated.
func (r *Registry) EmitPermissionCreated(ctx context.Context, p *permission.Permission) {
	for _, e := range r.permissionCreated {
		if err := e.hook.OnPermissionCreated(ctx, p); err != nil {
			r.logHookError("OnPermissionCreated", e.name, err)
		}
	}
}

// EmitPermissionDeleted notifies all plugins that implement PermissionDeleted.
func (r *Registry) EmitPermissionDeleted(ctx context.Context, permID id.PermissionID) {
	for _, e := range r.permissionDeleted {
		if err := e.hook.OnPermissionDeleted(ctx, permID); err != nil {
			r.logHookError("OnPermissionDeleted", e.name, err)
		}
	}
}

// EmitPermissionAttached notifies all plugins that implement PermissionAttached.
func (r *Registry) EmitPermissionAttached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) {
	for _, e := range r.permissionAttached {
		if err := e.hook.OnPermissionAttached(ctx, roleID, permID); err != nil {
			r.logHookError("OnPermissionAttached", e.name, err)
		}
	}
}

// EmitPermissionDetached notifies all plugins that implement PermissionDetached.
func (r *Registry) EmitPermissionDetached(ctx context.Context, roleID id.RoleID, permID id.PermissionID) {
	for _, e := range r.permissionDetached {
		if err := e.hook.OnPermissionDetached(ctx, roleID, permID); err != nil {
			r.logHookError("OnPermissionDetached", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Assignment event emitters
// ──────────────────────────────────────────────────

// EmitRoleAssigned notifies all plugins that implement RoleAssigned.
func (r *Registry) EmitRoleAssigned(ctx context.Context, a *assignment.Assignment) {
	for _, e := range r.roleAssigned {
		if err := e.hook.OnRoleAssigned(ctx, a); err != nil {
			r.logHookError("OnRoleAssigned", e.name, err)
		}
	}
}

// EmitRoleUnassigned notifies all plugins that implement RoleUnassigned.
func (r *Registry) EmitRoleUnassigned(ctx context.Context, a *assignment.Assignment) {
	for _, e := range r.roleUnassigned {
		if err := e.hook.OnRoleUnassigned(ctx, a); err != nil {
			r.logHookError("OnRoleUnassigned", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Relation event emitters
// ──────────────────────────────────────────────────

// EmitRelationWritten notifies all plugins that implement RelationWritten.
func (r *Registry) EmitRelationWritten(ctx context.Context, t *relation.Tuple) {
	for _, e := range r.relationWritten {
		if err := e.hook.OnRelationWritten(ctx, t); err != nil {
			r.logHookError("OnRelationWritten", e.name, err)
		}
	}
}

// EmitRelationDeleted notifies all plugins that implement RelationDeleted.
func (r *Registry) EmitRelationDeleted(ctx context.Context, relID id.RelationID) {
	for _, e := range r.relationDeleted {
		if err := e.hook.OnRelationDeleted(ctx, relID); err != nil {
			r.logHookError("OnRelationDeleted", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Policy event emitters
// ──────────────────────────────────────────────────

// EmitPolicyCreated notifies all plugins that implement PolicyCreated.
func (r *Registry) EmitPolicyCreated(ctx context.Context, p *policy.Policy) {
	for _, e := range r.policyCreated {
		if err := e.hook.OnPolicyCreated(ctx, p); err != nil {
			r.logHookError("OnPolicyCreated", e.name, err)
		}
	}
}

// EmitPolicyUpdated notifies all plugins that implement PolicyUpdated.
func (r *Registry) EmitPolicyUpdated(ctx context.Context, p *policy.Policy) {
	for _, e := range r.policyUpdated {
		if err := e.hook.OnPolicyUpdated(ctx, p); err != nil {
			r.logHookError("OnPolicyUpdated", e.name, err)
		}
	}
}

// EmitPolicyDeleted notifies all plugins that implement PolicyDeleted.
func (r *Registry) EmitPolicyDeleted(ctx context.Context, polID id.PolicyID) {
	for _, e := range r.policyDeleted {
		if err := e.hook.OnPolicyDeleted(ctx, polID); err != nil {
			r.logHookError("OnPolicyDeleted", e.name, err)
		}
	}
}

// ──────────────────────────────────────────────────
// Shutdown emitter
// ──────────────────────────────────────────────────

// EmitShutdown notifies all plugins that implement Shutdown.
func (r *Registry) EmitShutdown(ctx context.Context) {
	for _, e := range r.shutdown {
		if err := e.hook.OnShutdown(ctx); err != nil {
			r.logHookError("OnShutdown", e.name, err)
		}
	}
}

// logHookError logs a warning when a lifecycle hook returns an error.
// Errors from hooks are never propagated — they must not block the pipeline.
func (r *Registry) logHookError(hook, pluginName string, err error) {
	r.logger.Warn("plugin hook error",
		slog.String("hook", hook),
		slog.String("plugin", pluginName),
		slog.String("error", err.Error()),
	)
}
