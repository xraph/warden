// handlers_roles.go: the role surface.
//
// Roles carry more than the templ dashboard ever showed: a namespace, the
// system and default flags, a member cap, and parent-slug inheritance.
// Slugs are unique per (tenant, namespace), which is why the namespace is
// on every read and every write.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// RoleSummary is one row of the roles list.
type RoleSummary struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	Description   string `json:"description,omitempty"`
	ParentSlug    string `json:"parentSlug,omitempty"`
	IsSystem      bool   `json:"isSystem"`
	IsDefault     bool   `json:"isDefault"`
	MaxMembers    int    `json:"maxMembers,omitempty"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// PermissionSummary is one row of the permissions list, and one grant on a
// role's detail page. The same shape serves both so the role page can link
// each grant to its own permission row.
type PermissionSummary struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	Name          string `json:"name"`
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	Description   string `json:"description,omitempty"`
	IsSystem      bool   `json:"isSystem"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// RoleDetail is one role with everything its page shows.
type RoleDetail struct {
	RoleSummary
	Permissions []PermissionSummary `json:"permissions"`
	Children    []RoleSummary       `json:"children"`
	CreatedBy   string              `json:"createdBy,omitempty"`
	UpdatedBy   string              `json:"updatedBy,omitempty"`
}

// RolesListInput filters the roles list.
//
// NamespacePath is a pointer because nil and the empty string are different
// queries: nil means every namespace, "" means the tenant root.
type RolesListInput struct {
	PageRequest
	NamespacePath *string `json:"namespacePath,omitempty"`
	Search        string  `json:"search,omitempty"`
	IsSystem      *bool   `json:"isSystem,omitempty"`
	IsDefault     *bool   `json:"isDefault,omitempty"`
}

// RolesListResponse is the paged reply.
type RolesListResponse struct {
	PageMeta
	Items []RoleSummary `json:"items"`
}

// RoleDetailInput names one role.
type RoleDetailInput struct {
	ID string `json:"id"`
}

func projectRole(r *role.Role) RoleSummary {
	return RoleSummary{
		ID:            r.ID.String(),
		NamespacePath: r.NamespacePath,
		Name:          r.Name,
		Slug:          r.Slug,
		Description:   r.Description,
		ParentSlug:    r.ParentSlug,
		IsSystem:      r.IsSystem,
		IsDefault:     r.IsDefault,
		MaxMembers:    r.MaxMembers,
		CreatedAt:     r.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     r.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func projectPermission(p *permission.Permission) PermissionSummary {
	return PermissionSummary{
		ID:            p.ID.String(),
		NamespacePath: p.NamespacePath,
		Name:          p.Name,
		Resource:      p.Resource,
		Action:        p.Action,
		Description:   p.Description,
		IsSystem:      p.IsSystem,
		CreatedAt:     p.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// parseRoleID turns a wire id into a typed one, reporting a malformed id as
// BAD_REQUEST rather than NOT_FOUND. They are different facts: one is a
// caller bug, the other sends somebody looking for a missing row.
func parseRoleID(raw string) (id.RoleID, error) {
	rid, err := id.ParseRoleID(raw)
	if err != nil {
		return id.Nil, &dashcontract.Error{
			Code:    dashcontract.CodeBadRequest,
			Message: "not a role id: " + raw,
		}
	}
	return rid, nil
}

func rolesListHandler(deps Deps) func(context.Context, RolesListInput, dashcontract.Principal) (RolesListResponse, error) {
	return func(ctx context.Context, in RolesListInput, p dashcontract.Principal) (RolesListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return RolesListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return RolesListResponse{}, err
		}
		limit, offset := in.Clamp()
		filter := &role.ListFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Search:        in.Search,
			IsSystem:      in.IsSystem,
			IsDefault:     in.IsDefault,
			Limit:         limit,
			Offset:        offset,
		}
		s := deps.Engine.Store()
		rows, err := s.ListRoles(ctx, filter)
		if err != nil {
			return RolesListResponse{}, mapWardenError(err)
		}
		total, err := s.CountRoles(ctx, filter)
		if err != nil {
			return RolesListResponse{}, mapWardenError(err)
		}
		out := RolesListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]RoleSummary, 0, len(rows)),
		}
		for _, r := range rows {
			out.Items = append(out.Items, projectRole(r))
		}
		return out, nil
	}
}

func rolesDetailHandler(deps Deps) func(context.Context, RoleDetailInput, dashcontract.Principal) (RoleDetail, error) {
	return func(ctx context.Context, in RoleDetailInput, p dashcontract.Principal) (RoleDetail, error) {
		if err := requireEngine(deps); err != nil {
			return RoleDetail{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return RoleDetail{}, err
		}
		rid, err := parseRoleID(in.ID)
		if err != nil {
			return RoleDetail{}, err
		}
		s := deps.Engine.Store()
		r, err := s.GetRole(ctx, tenantID, rid)
		if err != nil {
			return RoleDetail{}, mapWardenError(err)
		}
		out := RoleDetail{
			RoleSummary: projectRole(r),
			Permissions: []PermissionSummary{},
			Children:    []RoleSummary{},
			CreatedBy:   r.CreatedBy,
			UpdatedBy:   r.UpdatedBy,
		}
		grants, err := s.ListRolePermissions(ctx, tenantID, rid)
		if err != nil {
			return RoleDetail{}, mapWardenError(err)
		}
		for _, g := range grants {
			out.Permissions = append(out.Permissions, projectPermission(g))
		}
		// Children are found by parent SLUG, not by id, because slugs are
		// what inheritance is declared with.
		children, err := s.ListChildRoles(ctx, tenantID, r.Slug)
		if err != nil {
			return RoleDetail{}, mapWardenError(err)
		}
		for _, c := range children {
			out.Children = append(out.Children, projectRole(c))
		}
		return out, nil
	}
}
