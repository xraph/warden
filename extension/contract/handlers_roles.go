// handlers_roles.go: the role surface.
//
// Roles carry more than the templ dashboard ever showed: a namespace, the
// system and default flags, a member cap, and parent-slug inheritance.
// Slugs are unique per (tenant, namespace), which is why the namespace is
// on every read and every write.
package contract

import (
	"context"
	"errors"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"

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
		// what inheritance is declared with. ListChildRoles takes no
		// namespace, but the engine resolves a parent only within the
		// child's own namespace (and the foreign key is tenant, namespace,
		// parent slug), so a same-slug role in another namespace is a
		// child of a different parent. Keep only this role's namespace.
		children, err := s.ListChildRoles(ctx, tenantID, r.Slug)
		if err != nil {
			return RoleDetail{}, mapWardenError(err)
		}
		for _, c := range children {
			if c.NamespacePath != r.NamespacePath {
				continue
			}
			out.Children = append(out.Children, projectRole(c))
		}
		return out, nil
	}
}

// AckResponse is what a command returns when the only thing worth reporting
// is which row it touched. ID is empty for a delete.
type AckResponse struct {
	ID string `json:"id,omitempty"`
}

// RoleCreateInput creates a role. Non-pointer fields because a create has
// no "leave this alone": every field is either given or defaulted.
type RoleCreateInput struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	NamespacePath string `json:"namespacePath,omitempty"`
	Description   string `json:"description,omitempty"`
	ParentSlug    string `json:"parentSlug,omitempty"`
	MaxMembers    int    `json:"maxMembers,omitempty"`
	IsDefault     bool   `json:"isDefault,omitempty"`
}

// RoleUpdateInput patches a role.
//
// Every optional field is a pointer, and the distinction is load-bearing:
// nil means "leave this alone", and a pointer to the zero value means "set
// it to empty". A non-pointer field cannot express the difference, and the
// UI would silently erase values the operator never touched.
type RoleUpdateInput struct {
	ID          string  `json:"id"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	ParentSlug  *string `json:"parentSlug,omitempty"`
	MaxMembers  *int    `json:"maxMembers,omitempty"`
	IsDefault   *bool   `json:"isDefault,omitempty"`
}

// RoleDeleteInput names the role to remove.
type RoleDeleteInput struct {
	ID string `json:"id"`
}

// badRequest is the shape for anything a person can fix by retyping.
func badRequest(msg string) error {
	return &dashcontract.Error{Code: dashcontract.CodeBadRequest, Message: msg}
}

// validateNamespace refuses a malformed namespace before it is written. A
// row with an invalid namespace is reachable by no namespaced query, so
// writing one loses it silently.
//
// The brief for this task named deps.Engine.Config().MaxNamespaceDepth as
// the depth cap to read, with an instruction to verify that field exists
// before relying on it. It does not: warden.Config (config.go) carries no
// MaxNamespaceDepth field, only the package-level constant
// warden.MaxNamespaceDepth. warden.ValidateNamespacePath already documents
// 0 as "use that default cap", so this passes 0 through rather than
// referencing a field that would not compile.
func validateNamespace(path string) error {
	if err := warden.ValidateNamespacePath(path, 0); err != nil {
		return badRequest(err.Error())
	}
	return nil
}

func rolesCreateHandler(deps Deps) func(context.Context, RoleCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RoleCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		if in.Name == "" || in.Slug == "" {
			return AckResponse{}, badRequest("a role needs a name and a slug")
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		if in.ParentSlug == in.Slug && in.ParentSlug != "" {
			return AckResponse{}, badRequest("a role cannot be its own parent")
		}
		ctx = withActor(ctx, p)
		actor := actorFor(p)
		r := &role.Role{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Name:          in.Name,
			Slug:          in.Slug,
			Description:   in.Description,
			ParentSlug:    in.ParentSlug,
			MaxMembers:    in.MaxMembers,
			IsDefault:     in.IsDefault,
			CreatedBy:     actor.ID,
			UpdatedBy:     actor.ID,
		}
		// A parent that does not exist would be stored as a dangling slug
		// that inheritance resolution silently skips. The REST handler
		// refuses it, and so does this one.
		if err := checkParent(ctx, deps.Engine.Store(), tenantID, r, in.ParentSlug); err != nil {
			return AckResponse{}, err
		}
		if err := deps.Engine.Store().CreateRole(ctx, r); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRoleCreated(ctx, r)
		}
		emitAudit(ctx, deps, p, "role.created", tenantID, r.ID.String(), r, nil)
		return AckResponse{ID: r.ID.String()}, nil
	}
}

func rolesUpdateHandler(deps Deps) func(context.Context, RoleUpdateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RoleUpdateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		rid, err := parseRoleID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()

		// Read, patch, write. UpdateRole persists the whole struct, so
		// building a fresh one from the request would erase every field
		// the request omitted.
		r, err := s.GetRole(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if err := guardSystemRole(r); err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		before := *r
		if in.Name != nil {
			if *in.Name == "" {
				return AckResponse{}, badRequest("a role's name cannot be empty")
			}
			r.Name = *in.Name
		}
		if in.Description != nil {
			r.Description = *in.Description
		}
		if in.MaxMembers != nil {
			if err := guardCapLowering(ctx, s, tenantID, &before, *in.MaxMembers, time.Now()); err != nil {
				return AckResponse{}, err
			}
			r.MaxMembers = *in.MaxMembers
		}
		if in.IsDefault != nil {
			r.IsDefault = *in.IsDefault
		}
		if in.ParentSlug != nil {
			if err := checkParent(ctx, s, tenantID, r, *in.ParentSlug); err != nil {
				return AckResponse{}, err
			}
			r.ParentSlug = *in.ParentSlug
		}
		r.UpdatedBy = actorFor(p).ID
		r.UpdatedAt = time.Now()
		if err := s.UpdateRole(ctx, r); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRoleUpdated(ctx, r)
		}
		emitAudit(ctx, deps, p, "role.updated", tenantID, r.ID.String(), r, &before)
		return AckResponse{ID: r.ID.String()}, nil
	}
}

// checkParent refuses a parent that does not exist in the role's namespace
// or that would create a cycle, with role.CheckParent's refusal as
// BAD_REQUEST: the operator can fix it by choosing another parent. The REST
// role handlers call the same check. A store failure is INTERNAL.
func checkParent(ctx context.Context, s store.Store, tenantID string, r *role.Role, parentSlug string) error {
	err := role.CheckParent(ctx, s, tenantID, r, parentSlug)
	var cycle *role.CycleError
	var missing *role.ParentNotFoundError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &cycle), errors.As(err, &missing):
		return badRequest(err.Error())
	default:
		return mapWardenError(err)
	}
}

// PermissionRef names one permission by its natural key.
//
// The junction is keyed by (namespacePath, name), not by id, because that
// is what the DSL declares and what survives a re-apply. An empty
// NamespacePath means the tenant root, which is a real namespace rather
// than an absent value.
type PermissionRef struct {
	Name          string `json:"name"`
	NamespacePath string `json:"namespacePath,omitempty"`
}

// RolePermissionInput attaches or detaches one grant.
type RolePermissionInput struct {
	RoleID                  string `json:"roleId"`
	PermissionName          string `json:"permissionName"`
	PermissionNamespacePath string `json:"permissionNamespacePath,omitempty"`
}

// RoleSetPermissionsInput replaces a role's whole grant set.
//
// An empty Permissions slice is a real instruction: it revokes everything.
// That is why the field is not a pointer; there is no "leave the set alone"
// case for an intent whose only job is to replace it.
type RoleSetPermissionsInput struct {
	RoleID      string          `json:"roleId"`
	Permissions []PermissionRef `json:"permissions"`
}

// loadWritableRole fetches a role and refuses if it is a system role. Every
// junction command starts here.
func loadWritableRole(ctx context.Context, deps Deps, tenantID, rawID string) (*role.Role, error) {
	rid, err := parseRoleID(rawID)
	if err != nil {
		return nil, err
	}
	r, err := deps.Engine.Store().GetRole(ctx, tenantID, rid)
	if err != nil {
		return nil, mapWardenError(err)
	}
	if err := guardSystemRole(r); err != nil {
		return nil, err
	}
	return r, nil
}

// resolvePermissionRef confirms a named permission exists in this tenant
// before it is used as a junction key, through permission.LookupRef, which
// the REST attach also calls.
//
// It also returns the permission's id, which the typed attach and detach
// hooks carry.
func resolvePermissionRef(ctx context.Context, deps Deps, tenantID string, ref PermissionRef) (permission.Ref, id.PermissionID, error) {
	if ref.Name == "" {
		return permission.Ref{}, id.Nil, badRequest("a permission reference needs a name")
	}
	key := permission.Ref{NamespacePath: ref.NamespacePath, Name: ref.Name}
	pm, err := permission.LookupRef(ctx, deps.Engine.Store(), tenantID, key)
	if err != nil {
		return permission.Ref{}, id.Nil, mapWardenError(err)
	}
	return key, pm.ID, nil
}

// grantEntity is the audit payload for one attach or detach, shaped like the
// REST handlers' so a consumer parses both the same way.
func grantEntity(roleID id.RoleID, ref permission.Ref) map[string]string {
	return map[string]string{
		"role_id":                   roleID.String(),
		"permission_namespace_path": ref.NamespacePath,
		"permission_name":           ref.Name,
	}
}

func refsForAudit(refs []permission.Ref) []map[string]string {
	out := make([]map[string]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]string{"namespace_path": r.NamespacePath, "name": r.Name})
	}
	return out
}

func grantsForAudit(grants []*permission.Permission) []map[string]string {
	out := make([]map[string]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, map[string]string{"namespace_path": g.NamespacePath, "name": g.Name})
	}
	return out
}

func rolesAttachPermissionHandler(deps Deps) func(context.Context, RolePermissionInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RolePermissionInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		r, err := loadWritableRole(ctx, deps, tenantID, in.RoleID)
		if err != nil {
			return AckResponse{}, err
		}
		ref, permID, err := resolvePermissionRef(ctx, deps, tenantID, PermissionRef{
			Name: in.PermissionName, NamespacePath: in.PermissionNamespacePath,
		})
		if err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		if err := deps.Engine.Store().AttachPermission(ctx, tenantID, r.ID, ref); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPermissionAttached(ctx, r.ID, permID)
		}
		emitAudit(ctx, deps, p, "permission.attached", tenantID, r.ID.String(), grantEntity(r.ID, ref), nil)
		return AckResponse{ID: r.ID.String()}, nil
	}
}

func rolesDetachPermissionHandler(deps Deps) func(context.Context, RolePermissionInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RolePermissionInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		r, err := loadWritableRole(ctx, deps, tenantID, in.RoleID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()

		// Confirm the grant is actually there (role.HeldGrant says why). The
		// REST detach runs the same check.
		ref := permission.Ref{NamespacePath: in.PermissionNamespacePath, Name: in.PermissionName}
		held, err := role.HeldGrant(ctx, s, tenantID, r, ref)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := s.DetachPermission(ctx, tenantID, r.ID, ref); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPermissionDetached(ctx, r.ID, held.ID)
		}
		emitAudit(ctx, deps, p, "permission.detached", tenantID, r.ID.String(), grantEntity(r.ID, ref), nil)
		return AckResponse{ID: r.ID.String()}, nil
	}
}

func rolesSetPermissionsHandler(deps Deps) func(context.Context, RoleSetPermissionsInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RoleSetPermissionsInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		r, err := loadWritableRole(ctx, deps, tenantID, in.RoleID)
		if err != nil {
			return AckResponse{}, err
		}
		// Resolve every reference BEFORE writing any of them. All or
		// nothing: silently dropping an unknown name would leave the role
		// with a set the operator did not choose.
		refs := make([]permission.Ref, 0, len(in.Permissions))
		ids := make(map[permission.Ref]id.PermissionID, len(in.Permissions))
		for _, ref := range in.Permissions {
			resolved, permID, err := resolvePermissionRef(ctx, deps, tenantID, ref)
			if err != nil {
				return AckResponse{}, err
			}
			refs = append(refs, resolved)
			ids[resolved] = permID
		}
		// The previous set feeds the audit event's Before and decides which
		// typed attach and detach hooks to fire.
		previous, err := deps.Engine.Store().ListRolePermissions(ctx, tenantID, r.ID)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := deps.Engine.Store().SetRolePermissions(ctx, tenantID, r.ID, refs); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			had := make(map[permission.Ref]struct{}, len(previous))
			for _, g := range previous {
				ref := permission.Ref{NamespacePath: g.NamespacePath, Name: g.Name}
				had[ref] = struct{}{}
				if _, keep := ids[ref]; !keep {
					pl.EmitPermissionDetached(ctx, r.ID, g.ID)
				}
			}
			for ref, permID := range ids {
				if _, was := had[ref]; !was {
					pl.EmitPermissionAttached(ctx, r.ID, permID)
				}
			}
		}
		emitAudit(ctx, deps, p, "role.permissions_set", tenantID, r.ID.String(),
			map[string]any{"role_id": r.ID.String(), "permissions": refsForAudit(refs)},
			map[string]any{"role_id": r.ID.String(), "permissions": grantsForAudit(previous)})
		return AckResponse{ID: r.ID.String()}, nil
	}
}

func rolesDeleteHandler(deps Deps) func(context.Context, RoleDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RoleDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		rid, err := parseRoleID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		// Read first so the system guard has something to check, and so a
		// delete of another tenant's role is NOT_FOUND rather than silent.
		r, err := s.GetRole(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if err := guardSystemRole(r); err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		if err := s.DeleteRole(ctx, tenantID, rid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRoleDeleted(ctx, rid)
		}
		emitAudit(ctx, deps, p, "role.deleted", tenantID, rid.String(), nil, r)
		return AckResponse{}, nil
	}
}
