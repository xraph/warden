package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
)

func (a *API) registerRoleRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("roles"))

	if err := g.POST("/roles", a.createRole,
		forge.WithSummary("Create role"),
		forge.WithDescription("Creates a new role."),
		forge.WithOperationID("wardenCreateRole"),
		forge.WithRequestSchema(CreateRoleRequest{}),
		forge.WithCreatedResponse(&role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/roles/:roleId", a.getRole,
		forge.WithSummary("Get role"),
		forge.WithDescription("Returns details of a specific role."),
		forge.WithOperationID("wardenGetRole"),
		forge.WithRequestSchema(GetRoleRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Role details", &role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.PUT("/roles/:roleId", a.updateRole,
		forge.WithSummary("Update role"),
		forge.WithDescription("Updates an existing role."),
		forge.WithOperationID("wardenUpdateRole"),
		forge.WithRequestSchema(UpdateRoleRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Updated role", &role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.DELETE("/roles/:roleId", a.deleteRole,
		forge.WithSummary("Delete role"),
		forge.WithDescription("Deletes a role."),
		forge.WithOperationID("wardenDeleteRole"),
		forge.WithRequestSchema(GetRoleRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/roles", a.listRoles,
		forge.WithSummary("List roles"),
		forge.WithDescription("Lists roles with optional filters."),
		forge.WithOperationID("wardenListRoles"),
		forge.WithRequestSchema(ListRolesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Role list", []*role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.POST("/roles/:roleId/permissions", a.attachPermissionToRole,
		forge.WithSummary("Attach permission to role"),
		forge.WithDescription("Attaches a permission to a role."),
		forge.WithOperationID("wardenAttachPermission"),
		forge.WithRequestSchema(AttachPermissionRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.DELETE("/roles/:roleId/permissions/:permissionId", a.detachPermissionFromRole,
		forge.WithSummary("Detach permission from role"),
		forge.WithDescription("Detaches a permission from a role."),
		forge.WithOperationID("wardenDetachPermission"),
		forge.WithRequestSchema(DetachPermissionRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	)
}

func (a *API) createRole(ctx forge.Context, req *CreateRoleRequest) (*role.Role, error) {
	{
		verr := forge.NewValidationErrors()
		if req.Name == "" {
			verr.AddWithCode("name", "name is required", "REQUIRED", nil)
		}
		if req.Slug == "" {
			verr.AddWithCode("slug", "slug is required", "REQUIRED", nil)
		}
		if verr.HasErrors() {
			return nil, verr
		}
	}

	if err := warden.ValidateNamespacePath(req.NamespacePath, 0); err != nil {
		return nil, forge.BadRequest(err.Error())
	}

	now := time.Now()
	appID, tenantID := scopeFromForgeContext(ctx)
	r := &role.Role{
		ID:            id.NewRoleID(),
		TenantID:      tenantID,
		NamespacePath: req.NamespacePath,
		AppID:         appID,
		Name:          req.Name,
		Slug:          req.Slug,
		Description:   req.Description,
		IsSystem:      req.IsSystem,
		IsDefault:     req.IsDefault,
		MaxMembers:    req.MaxMembers,
		Metadata:      req.Metadata,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if req.ParentSlug != "" {
		// Pre-validate the parent exists for a friendlier error than an FK violation.
		// Parents must live in the same namespace as the child role.
		if _, err := a.eng.Store().GetRoleBySlug(ctx.Context(), tenantID, r.NamespacePath, req.ParentSlug); err != nil {
			return nil, forge.BadRequest(fmt.Sprintf("parent role %q not found in tenant %q ns %q", req.ParentSlug, tenantID, r.NamespacePath))
		}
		r.ParentSlug = req.ParentSlug
	}

	if err := a.eng.Store().CreateRole(ctx.Context(), r); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRoleCreated(ctx.Context(), r)
	}

	return r, ctx.JSON(http.StatusCreated, r)
}

func (a *API) getRole(ctx forge.Context, _ *GetRoleRequest) (*role.Role, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}

	r, err := a.eng.Store().GetRole(ctx.Context(), roleID)
	if err != nil {
		return nil, mapError(err)
	}

	return r, ctx.JSON(http.StatusOK, r)
}

func (a *API) updateRole(ctx forge.Context, req *UpdateRoleRequest) (*role.Role, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}

	r, err := a.eng.Store().GetRole(ctx.Context(), roleID)
	if err != nil {
		return nil, mapError(err)
	}

	if req.Name != "" {
		r.Name = req.Name
	}
	if req.Description != "" {
		r.Description = req.Description
	}
	if req.MaxMembers != nil {
		r.MaxMembers = *req.MaxMembers
	}
	if req.IsDefault != nil {
		r.IsDefault = *req.IsDefault
	}
	if req.ParentSlug != nil {
		newParent := *req.ParentSlug
		if newParent != "" && newParent != r.ParentSlug {
			if _, err := a.eng.Store().GetRoleBySlug(ctx.Context(), r.TenantID, r.NamespacePath, newParent); err != nil {
				return nil, forge.BadRequest(fmt.Sprintf("parent role %q not found in tenant %q ns %q", newParent, r.TenantID, r.NamespacePath))
			}
		}
		r.ParentSlug = newParent
	}
	if req.Metadata != nil {
		r.Metadata = req.Metadata
	}
	r.UpdatedAt = time.Now()

	if err := a.eng.Store().UpdateRole(ctx.Context(), r); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRoleUpdated(ctx.Context(), r)
	}

	return r, ctx.JSON(http.StatusOK, r)
}

func (a *API) deleteRole(ctx forge.Context, _ *GetRoleRequest) (*struct{}, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}

	if err := a.eng.Store().DeleteRole(ctx.Context(), roleID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRoleDeleted(ctx.Context(), roleID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listRoles(ctx forge.Context, req *ListRolesRequest) (*RoleListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &role.ListFilter{
		TenantID: tenantID,
		Search:   req.Search,
		Limit:    defaultLimit(req.Limit),
		Offset:   req.Offset,
	}

	roles, err := a.eng.Store().ListRoles(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return &RoleListResponse{Body: roles}, nil
}

// resolvePermRef converts an attach/detach request's mixed-form permission
// reference into a permission.Ref. PermissionName wins when both are set;
// PermissionID is resolved via GetPermission for the legacy code path.
func (a *API) resolvePermRef(ctx forge.Context, tenantID, permIDStr, permName, permNamespace string) (permission.Ref, *id.PermissionID, error) {
	if permName != "" {
		return permission.Ref{NamespacePath: permNamespace, Name: permName}, nil, nil
	}
	if permIDStr == "" {
		return permission.Ref{}, nil, forge.BadRequest("permission_id or permission_name is required")
	}
	pid, err := id.ParsePermissionID(permIDStr)
	if err != nil {
		return permission.Ref{}, nil, forge.BadRequest(fmt.Sprintf("invalid permission ID: %v", err))
	}
	p, err := a.eng.Store().GetPermission(ctx.Context(), pid)
	if err != nil || p == nil {
		return permission.Ref{}, nil, forge.NotFound(fmt.Sprintf("permission %q not found", permIDStr))
	}
	if p.TenantID != tenantID {
		return permission.Ref{}, nil, forge.NotFound(fmt.Sprintf("permission %q not found in tenant", permIDStr))
	}
	return permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name}, &pid, nil
}

func (a *API) attachPermissionToRole(ctx forge.Context, req *AttachPermissionRequest) (*struct{}, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}
	_, tenantID := scopeFromForgeContext(ctx)

	ref, legacyID, perr := a.resolvePermRef(ctx, tenantID, req.PermissionID, req.PermissionName, req.PermissionNamespacePath)
	if perr != nil {
		return nil, perr
	}

	if err := a.eng.Store().AttachPermission(ctx.Context(), roleID, ref); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil && legacyID != nil {
		a.eng.Plugins().EmitPermissionAttached(ctx.Context(), roleID, *legacyID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) detachPermissionFromRole(ctx forge.Context, req *DetachPermissionRequest) (*struct{}, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}
	_, tenantID := scopeFromForgeContext(ctx)

	permIDStr := ctx.Param("permissionId")
	if permIDStr == "" {
		permIDStr = req.PermissionID
	}
	ref, legacyID, perr := a.resolvePermRef(ctx, tenantID, permIDStr, req.PermissionName, req.PermissionNamespacePath)
	if perr != nil {
		return nil, perr
	}

	if err := a.eng.Store().DetachPermission(ctx.Context(), roleID, ref); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil && legacyID != nil {
		a.eng.Plugins().EmitPermissionDetached(ctx.Context(), roleID, *legacyID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}
