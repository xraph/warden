package pages

import "github.com/xraph/warden/role"

// RoleRow is a view model that pairs a Role with pre-fetched relationship
// counts for display in the roles list table.
type RoleRow struct {
	Role            *role.Role
	PermissionCount int
	ParentSlug      string // copy of Role.ParentSlug; empty if no parent
	ParentName      string // resolved display name; empty if no parent
	ParentID        string // stringified parent typeid for link building; empty if no parent
	RelationCount   int64
}

// extractRoles pulls the raw Role pointers out of a RoleRow slice.
func extractRoles(rows []RoleRow) []*role.Role {
	out := make([]*role.Role, len(rows))
	for i, r := range rows {
		out[i] = r.Role
	}
	return out
}
