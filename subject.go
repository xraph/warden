package warden

import (
	"context"
	"fmt"

	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/role"
)

// SubjectRoles reports the roles a subject holds at a namespace, as Check
// resolves them for a check on no particular resource: the roles assigned
// at that namespace or an ancestor (expired assignments excluded), then
// every parent reached through ParentSlug. direct lists the assigned roles;
// all lists direct plus inherited, in the order Check resolves them.
// Resource-scoped assignments are not included: they grant only for a check
// on their own resource.
func (e *Engine) SubjectRoles(ctx context.Context, kind SubjectKind, subjectID string, opts ...CallOption) (direct, all []*role.Role, err error) {
	scope, _, err := e.resolveScope(ctx, "", "", opts)
	if err != nil {
		return nil, nil, err
	}
	direct, err = e.globalRoles(ctx, scope, kind, subjectID)
	if err != nil {
		return nil, nil, fmt.Errorf("warden subject roles: %w", err)
	}
	return direct, e.resolveInheritedRoleObjects(ctx, direct), nil
}

// globalRoles loads the roles assigned to a subject at scope's namespace or
// an ancestor, with no resource: the global path of resolveAssignedRoles
// (ListRolesForSubject, then GetRoles), without the resource-scoped IDs.
func (e *Engine) globalRoles(ctx context.Context, scope tenantScope, kind SubjectKind, subjectID string) ([]*role.Role, error) {
	roleIDs, err := e.globalRoleIDs(ctx, scope, kind, subjectID)
	if err != nil {
		return nil, err
	}
	if len(roleIDs) == 0 {
		return nil, nil
	}
	return e.getRoles(ctx, scope, roleIDs)
}

// PolicySelectsSubject reports whether a policy's subject matchers select a
// subject holding roleSlugs. It is the evaluator's own test: an empty
// Subjects list selects everyone; otherwise any matcher whose non-empty
// Kind, ID and Role all agree. Selecting is not applying: the policy's
// actions, resources, window and conditions still decide each check.
func PolicySelectsSubject(pol *policy.Policy, kind SubjectKind, subjectID string, roleSlugs []string) bool {
	if len(pol.Subjects) == 0 {
		return true // No subject filter means all subjects.
	}
	for _, sm := range pol.Subjects {
		if sm.Kind != "" && sm.Kind != string(kind) {
			continue
		}
		if sm.ID != "" && sm.ID != subjectID {
			continue
		}
		if sm.Role != "" && !contains(roleSlugs, sm.Role) {
			continue
		}
		return true
	}
	return false
}
