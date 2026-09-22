package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/resourcetype"
)

func (a *API) registerResourceTypeRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("resource-types"))

	manage := a.authorize("manage", "warden:resourcetype")
	read := a.authorize("read", "warden:resourcetype")

	if err := g.POST("/resource-types", a.createResourceType,
		forge.WithSummary("Create resource type"),
		forge.WithDescription("Creates a new resource type definition."),
		forge.WithOperationID("createResourceType"),
		forge.WithRequestSchema(CreateResourceTypeRequest{}),
		forge.WithCreatedResponse(&resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.GET("/resource-types/:resourceTypeId", a.getResourceType,
		forge.WithSummary("Get resource type"),
		forge.WithOperationID("getResourceType"),
		forge.WithResponseSchema(http.StatusOK, "Resource type details", &resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	); err != nil {
		return err
	}

	if err := g.DELETE("/resource-types/:resourceTypeId", a.deleteResourceType,
		forge.WithSummary("Delete resource type"),
		forge.WithOperationID("deleteResourceType"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	return g.GET("/resource-types", a.listResourceTypes,
		forge.WithSummary("List resource types"),
		forge.WithOperationID("listResourceTypes"),
		forge.WithRequestSchema(ListResourceTypesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Resource type list", []*resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	)
}

func (a *API) createResourceType(ctx forge.Context, req *CreateResourceTypeRequest) (*resourcetype.ResourceType, error) {
	{
		verr := forge.NewValidationErrors()
		if req.Name == "" {
			verr.AddWithCode("name", "name is required", "REQUIRED", nil)
		}
		if verr.HasErrors() {
			return nil, verr
		}
	}

	appID, tenantID := scopeFromForgeContext(ctx)
	actor, _ := warden.ActorFromContext(ctx.Context())
	now := time.Now()
	rt := &resourcetype.ResourceType{
		ID:          id.NewResourceTypeID(),
		TenantID:    tenantID,
		AppID:       appID,
		Name:        req.Name,
		Description: req.Description,
		Metadata:    req.Metadata,
		CreatedBy:   actor.ID,
		UpdatedBy:   actor.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	for _, r := range req.Relations {
		rt.Relations = append(rt.Relations, resourcetype.RelationDef{
			Name:            r.Name,
			AllowedSubjects: r.AllowedSubjects,
		})
	}
	for _, p := range req.Permissions {
		rt.Permissions = append(rt.Permissions, resourcetype.PermissionDef{
			Name:       p.Name,
			Expression: p.Expression,
		})
	}

	if err := a.eng.Store().CreateResourceType(ctx.Context(), rt); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: now, Action: "resourcetype.created",
			TenantID: tenantID, EntityID: rt.ID.String(), Entity: rt,
		})
	}

	return nil, ctx.JSON(http.StatusCreated, rt)
}

func (a *API) getResourceType(ctx forge.Context, _ *GetResourceTypeRequest) (*resourcetype.ResourceType, error) {
	rtID, err := id.ParseResourceTypeID(ctx.Param("resourceTypeId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid resource type ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)

	rt, err := a.eng.Store().GetResourceType(ctx.Context(), tenantID, rtID)
	if err != nil {
		return nil, mapError(err)
	}

	return rt, nil
}

func (a *API) deleteResourceType(ctx forge.Context, _ *GetResourceTypeRequest) (*struct{}, error) {
	rtID, err := id.ParseResourceTypeID(ctx.Param("resourceTypeId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid resource type ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)
	before, getErr := a.eng.Store().GetResourceType(ctx.Context(), tenantID, rtID)

	if err := a.eng.Store().DeleteResourceType(ctx.Context(), tenantID, rtID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		actor, _ := warden.ActorFromContext(ctx.Context())
		ev := plugin.Event{
			Actor: actor, At: time.Now(), Action: "resourcetype.deleted",
			TenantID: tenantID, EntityID: rtID.String(),
		}
		if getErr == nil {
			ev.Before = before
		}
		a.eng.Plugins().EmitAudit(ctx.Context(), ev)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listResourceTypes(ctx forge.Context, req *ListResourceTypesRequest) (*ResourceTypeListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &resourcetype.ListFilter{
		TenantID: tenantID,
		Search:   req.Search,
		Limit:    defaultLimit(req.Limit),
		Offset:   req.Offset,
	}

	rts, err := a.eng.Store().ListResourceTypes(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return &ResourceTypeListResponse{Body: rts}, nil
}
