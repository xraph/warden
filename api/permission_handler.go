package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
)

func (a *API) registerPermissionRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("permissions"))

	manage := a.authorize("manage", "warden:permission")
	read := a.authorize("read", "warden:permission")

	if err := g.POST("/permissions", a.createPermission,
		forge.WithSummary("Create permission"),
		forge.WithDescription("Creates a new permission."),
		forge.WithOperationID("createPermission"),
		forge.WithRequestSchema(CreatePermissionRequest{}),
		forge.WithCreatedResponse(&permission.Permission{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.GET("/permissions/:permissionId", a.getPermission,
		forge.WithSummary("Get permission"),
		forge.WithOperationID("getPermission"),
		forge.WithResponseSchema(http.StatusOK, "Permission details", &permission.Permission{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	); err != nil {
		return err
	}

	if err := g.DELETE("/permissions/:permissionId", a.deletePermission,
		forge.WithSummary("Delete permission"),
		forge.WithOperationID("deletePermission"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	return g.GET("/permissions", a.listPermissions,
		forge.WithSummary("List permissions"),
		forge.WithOperationID("listPermissions"),
		forge.WithRequestSchema(ListPermissionsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Permission list", []*permission.Permission{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	)
}

func (a *API) createPermission(ctx forge.Context, req *CreatePermissionRequest) (*permission.Permission, error) {
	{
		verr := forge.NewValidationErrors()
		if req.Name == "" {
			verr.AddWithCode("name", "name is required", "REQUIRED", nil)
		}
		if req.Resource == "" {
			verr.AddWithCode("resource", "resource is required", "REQUIRED", nil)
		}
		if req.Action == "" {
			verr.AddWithCode("action", "action is required", "REQUIRED", nil)
		}
		if verr.HasErrors() {
			return nil, verr
		}
	}
	if err := permission.CheckAction(req.Action); err != nil {
		return nil, forge.BadRequest(err.Error())
	}

	appID, tenantID := scopeFromForgeContext(ctx)
	actor, _ := warden.ActorFromContext(ctx.Context())
	now := time.Now()
	p := &permission.Permission{
		ID:          id.NewPermissionID(),
		TenantID:    tenantID,
		AppID:       appID,
		Name:        req.Name,
		Resource:    req.Resource,
		Action:      req.Action,
		Description: req.Description,
		Metadata:    req.Metadata,
		CreatedBy:   actor.ID,
		UpdatedBy:   actor.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := a.eng.Store().CreatePermission(ctx.Context(), p); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPermissionCreated(ctx.Context(), p)
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: now, Action: "permission.created",
			TenantID: tenantID, EntityID: p.ID.String(), Entity: p,
		})
	}

	return nil, ctx.JSON(http.StatusCreated, p)
}

func (a *API) getPermission(ctx forge.Context, _ *GetPermissionRequest) (*permission.Permission, error) {
	permID, err := id.ParsePermissionID(ctx.Param("permissionId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid permission ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)

	p, err := a.eng.Store().GetPermission(ctx.Context(), tenantID, permID)
	if err != nil {
		return nil, mapError(err)
	}

	return p, nil
}

func (a *API) deletePermission(ctx forge.Context, _ *GetPermissionRequest) (*struct{}, error) {
	permID, err := id.ParsePermissionID(ctx.Param("permissionId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid permission ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)
	before, getErr := a.eng.Store().GetPermission(ctx.Context(), tenantID, permID)

	if err := a.eng.Store().DeletePermission(ctx.Context(), tenantID, permID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPermissionDeleted(ctx.Context(), permID)
		actor, _ := warden.ActorFromContext(ctx.Context())
		ev := plugin.Event{
			Actor: actor, At: time.Now(), Action: "permission.deleted",
			TenantID: tenantID, EntityID: permID.String(),
		}
		if getErr == nil {
			ev.Before = before
		}
		a.eng.Plugins().EmitAudit(ctx.Context(), ev)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listPermissions(ctx forge.Context, req *ListPermissionsRequest) (*PermissionListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &permission.ListFilter{
		TenantID: tenantID,
		Resource: req.Resource,
		Action:   req.Action,
		Search:   req.Search,
		Limit:    defaultLimit(req.Limit),
		Offset:   req.Offset,
	}

	perms, err := a.eng.Store().ListPermissions(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return &PermissionListResponse{Body: perms}, nil
}
