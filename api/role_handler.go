package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
)

func (a *API) registerRoleRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("roles"))

	if err := g.POST("/roles", a.createRole,
		forge.WithSummary("Create role"),
		forge.WithDescription("Creates a new role."),
		forge.WithOperationID("createRole"),
		forge.WithRequestSchema(CreateRoleRequest{}),
		forge.WithCreatedResponse(&role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/roles/:roleId", a.getRole,
		forge.WithSummary("Get role"),
		forge.WithDescription("Returns details of a specific role."),
		forge.WithOperationID("getRole"),
		forge.WithResponseSchema(http.StatusOK, "Role details", &role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.PUT("/roles/:roleId", a.updateRole,
		forge.WithSummary("Update role"),
		forge.WithDescription("Updates an existing role."),
		forge.WithOperationID("updateRole"),
		forge.WithRequestSchema(UpdateRoleRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Updated role", &role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.DELETE("/roles/:roleId", a.deleteRole,
		forge.WithSummary("Delete role"),
		forge.WithDescription("Deletes a role."),
		forge.WithOperationID("deleteRole"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/roles", a.listRoles,
		forge.WithSummary("List roles"),
		forge.WithDescription("Lists roles with optional filters."),
		forge.WithOperationID("listRoles"),
		forge.WithRequestSchema(ListRolesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Role list", []*role.Role{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.POST("/roles/:roleId/permissions", a.attachPermissionToRole,
		forge.WithSummary("Attach permission to role"),
		forge.WithDescription("Attaches a permission to a role."),
		forge.WithOperationID("attachPermission"),
		forge.WithRequestSchema(AttachPermissionRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.DELETE("/roles/:roleId/permissions/:permissionId", a.detachPermissionFromRole,
		forge.WithSummary("Detach permission from role"),
		forge.WithDescription("Detaches a permission from a role."),
		forge.WithOperationID("detachPermission"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	)
}

func (a *API) createRole(ctx forge.Context, req *CreateRoleRequest) (*role.Role, error) {
	if req.Name == "" {
		return nil, forge.BadRequest("name is required")
	}
	if req.Slug == "" {
		return nil, forge.BadRequest("slug is required")
	}

	now := time.Now()
	r := &role.Role{
		ID:          id.NewRoleID(),
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		IsSystem:    req.IsSystem,
		IsDefault:   req.IsDefault,
		MaxMembers:  req.MaxMembers,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if req.ParentID != "" {
		pid, err := id.ParseRoleID(req.ParentID)
		if err != nil {
			return nil, forge.BadRequest(fmt.Sprintf("invalid parent_id: %v", err))
		}
		r.ParentID = &pid
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

func (a *API) listRoles(ctx forge.Context, req *ListRolesRequest) ([]*role.Role, error) {
	filter := &role.ListFilter{
		Search: req.Search,
		Limit:  defaultLimit(req.Limit),
		Offset: req.Offset,
	}

	roles, err := a.eng.Store().ListRoles(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return roles, ctx.JSON(http.StatusOK, roles)
}

func (a *API) attachPermissionToRole(ctx forge.Context, req *AttachPermissionRequest) (*struct{}, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}

	permID, err := id.ParsePermissionID(req.PermissionID)
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid permission ID: %v", err))
	}

	if err := a.eng.Store().AttachPermission(ctx.Context(), roleID, permID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPermissionAttached(ctx.Context(), roleID, permID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) detachPermissionFromRole(ctx forge.Context, _ *struct{}) (*struct{}, error) {
	roleID, err := id.ParseRoleID(ctx.Param("roleId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role ID: %v", err))
	}

	permID, err := id.ParsePermissionID(ctx.Param("permissionId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid permission ID: %v", err))
	}

	if err := a.eng.Store().DetachPermission(ctx.Context(), roleID, permID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPermissionDetached(ctx.Context(), roleID, permID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}
