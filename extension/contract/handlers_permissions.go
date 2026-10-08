// handlers_permissions.go: the permission surface.
//
// One thing about permissions matters more than the rest: the RBAC
// evaluator matches a request against Resource + ":" + Action, and never
// against Name. So Name is a label, and a permission whose name disagrees
// with its resource and action is invisible to every check that looks for
// it by name while appearing correct in every list. This file refuses to
// write that state.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// PermissionDetail is one permission plus the roles that grant it, which is
// the question an operator opens this page to answer.
type PermissionDetail struct {
	PermissionSummary
	GrantedBy []RoleSummary `json:"grantedBy"`
}

// PermissionsListInput filters the permissions list.
type PermissionsListInput struct {
	PageRequest
	NamespacePath *string `json:"namespacePath,omitempty"`
	Resource      string  `json:"resource,omitempty"`
	Action        string  `json:"action,omitempty"`
	Search        string  `json:"search,omitempty"`
	IsSystem      *bool   `json:"isSystem,omitempty"`
}

// PermissionsListResponse is the paged reply.
type PermissionsListResponse struct {
	PageMeta
	Items []PermissionSummary `json:"items"`
}

// PermissionDetailInput names one permission.
type PermissionDetailInput struct {
	ID string `json:"id"`
}

// PermissionCreateInput creates a permission. Name may be omitted, in which
// case it is derived as resource:action.
type PermissionCreateInput struct {
	Name          string `json:"name,omitempty"`
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	NamespacePath string `json:"namespacePath,omitempty"`
	Description   string `json:"description,omitempty"`
}

// PermissionUpdateInput patches a permission. Resource and action are
// absent deliberately: changing either would change what the permission
// means without changing which roles grant it, silently altering every
// check that resolves through it. Delete and recreate instead.
type PermissionUpdateInput struct {
	ID          string  `json:"id"`
	Description *string `json:"description,omitempty"`
}

// PermissionDeleteInput names the permission to remove.
type PermissionDeleteInput struct {
	ID string `json:"id"`
}

func parsePermissionID(raw string) (id.PermissionID, error) {
	pid, err := id.ParsePermissionID(raw)
	if err != nil {
		return id.Nil, badRequest("not a permission id: " + raw)
	}
	return pid, nil
}

// derivedName is what the RBAC evaluator will actually match on.
func derivedName(resource, action string) string { return resource + ":" + action }

func permissionsListHandler(deps Deps) func(context.Context, PermissionsListInput, dashcontract.Principal) (PermissionsListResponse, error) {
	return func(ctx context.Context, in PermissionsListInput, p dashcontract.Principal) (PermissionsListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return PermissionsListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PermissionsListResponse{}, err
		}
		limit, offset := in.Clamp()
		filter := &permission.ListFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Resource:      in.Resource,
			Action:        in.Action,
			Search:        in.Search,
			IsSystem:      in.IsSystem,
			Limit:         limit,
			Offset:        offset,
		}
		s := deps.Engine.Store()
		rows, err := s.ListPermissions(ctx, filter)
		if err != nil {
			return PermissionsListResponse{}, mapWardenError(err)
		}
		total, err := s.CountPermissions(ctx, filter)
		if err != nil {
			return PermissionsListResponse{}, mapWardenError(err)
		}
		out := PermissionsListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]PermissionSummary, 0, len(rows)),
		}
		for _, pm := range rows {
			out.Items = append(out.Items, projectPermission(pm))
		}
		return out, nil
	}
}

func permissionsDetailHandler(deps Deps) func(context.Context, PermissionDetailInput, dashcontract.Principal) (PermissionDetail, error) {
	return func(ctx context.Context, in PermissionDetailInput, p dashcontract.Principal) (PermissionDetail, error) {
		if err := requireEngine(deps); err != nil {
			return PermissionDetail{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PermissionDetail{}, err
		}
		pid, err := parsePermissionID(in.ID)
		if err != nil {
			return PermissionDetail{}, err
		}
		pm, err := deps.Engine.Store().GetPermission(ctx, tenantID, pid)
		if err != nil {
			return PermissionDetail{}, mapWardenError(err)
		}
		holders, err := rolesGranting(ctx, deps, tenantID, pm)
		if err != nil {
			return PermissionDetail{}, err
		}
		return PermissionDetail{
			PermissionSummary: projectPermission(pm),
			GrantedBy:         holders,
		}, nil
	}
}

// rolesGranting lists every role in the tenant whose grants include pm,
// through role.GrantingRoles, which the REST delete's guard also walks.
func rolesGranting(ctx context.Context, deps Deps, tenantID string, pm *permission.Permission) ([]RoleSummary, error) {
	holders, err := role.GrantingRoles(ctx, deps.Engine.Store(), tenantID, pm)
	if err != nil {
		return nil, mapWardenError(err)
	}
	out := make([]RoleSummary, 0, len(holders))
	for _, r := range holders {
		out = append(out, projectRole(r))
	}
	return out, nil
}

func permissionsCreateHandler(deps Deps) func(context.Context, PermissionCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PermissionCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		if in.Resource == "" || in.Action == "" {
			return AckResponse{}, badRequest("a permission needs a resource and an action")
		}
		if err := permission.CheckAction(in.Action); err != nil {
			return AckResponse{}, badRequest(err.Error())
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		want := derivedName(in.Resource, in.Action)
		name := in.Name
		if name == "" {
			name = want
		}
		// The evaluator matches on resource:action, so a name that says
		// something else is a permission nothing can find by name.
		if name != want {
			return AckResponse{}, badRequest(
				"name " + name + " disagrees with " + want +
					": checks match on resource and action, so this permission would be unreachable by name")
		}
		ctx = withActor(ctx, p)
		actor := actorFor(p)
		pm := &permission.Permission{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Name:          name,
			Resource:      in.Resource,
			Action:        in.Action,
			Description:   in.Description,
			CreatedBy:     actor.ID,
			UpdatedBy:     actor.ID,
		}
		if err := deps.Engine.Store().CreatePermission(ctx, pm); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPermissionCreated(ctx, pm)
		}
		emitAudit(ctx, deps, p, "permission.created", tenantID, pm.ID.String(), pm, nil)
		return AckResponse{ID: pm.ID.String()}, nil
	}
}

func permissionsUpdateHandler(deps Deps) func(context.Context, PermissionUpdateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PermissionUpdateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		pid, err := parsePermissionID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		pm, err := s.GetPermission(ctx, tenantID, pid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if err := guardSystemPermission(pm); err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		before := *pm
		if in.Description != nil {
			pm.Description = *in.Description
		}
		pm.UpdatedBy = actorFor(p).ID
		pm.UpdatedAt = time.Now()
		if err := s.UpdatePermission(ctx, pm); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// There is no typed OnPermissionUpdated hook, so the audit event
		// is the only signal, and it is enough: the cache invalidator
		// flushes the tenant on any audit event.
		emitAudit(ctx, deps, p, "permission.updated", tenantID, pm.ID.String(), pm, &before)
		return AckResponse{ID: pm.ID.String()}, nil
	}
}

func permissionsDeleteHandler(deps Deps) func(context.Context, PermissionDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PermissionDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		pid, err := parsePermissionID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		pm, err := s.GetPermission(ctx, tenantID, pid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if err := guardSystemPermission(pm); err != nil {
			return AckResponse{}, err
		}
		// DeletePermission also removes the junction rows granting it, so
		// deleting one silently strips it from every role that had it.
		// Refuse and name the roles, so the operator detaches on purpose.
		// REST DELETE /v1/permissions/:id runs the same check.
		if err := role.CheckPermissionUngranted(ctx, s, tenantID, pm); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := s.DeletePermission(ctx, tenantID, pid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPermissionDeleted(ctx, pid)
		}
		emitAudit(ctx, deps, p, "permission.deleted", tenantID, pid.String(), nil, pm)
		return AckResponse{}, nil
	}
}
