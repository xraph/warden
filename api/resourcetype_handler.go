package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/resourcetype"
)

func (a *API) registerResourceTypeRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("resource-types"))

	if err := g.POST("/resource-types", a.createResourceType,
		forge.WithSummary("Create resource type"),
		forge.WithDescription("Creates a new resource type definition."),
		forge.WithOperationID("createResourceType"),
		forge.WithRequestSchema(CreateResourceTypeRequest{}),
		forge.WithCreatedResponse(&resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/resource-types/:resourceTypeId", a.getResourceType,
		forge.WithSummary("Get resource type"),
		forge.WithOperationID("getResourceType"),
		forge.WithResponseSchema(http.StatusOK, "Resource type details", &resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.DELETE("/resource-types/:resourceTypeId", a.deleteResourceType,
		forge.WithSummary("Delete resource type"),
		forge.WithOperationID("deleteResourceType"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.GET("/resource-types", a.listResourceTypes,
		forge.WithSummary("List resource types"),
		forge.WithOperationID("listResourceTypes"),
		forge.WithRequestSchema(ListResourceTypesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Resource type list", []*resourcetype.ResourceType{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) createResourceType(ctx forge.Context, req *CreateResourceTypeRequest) (*resourcetype.ResourceType, error) {
	if req.Name == "" {
		return nil, forge.BadRequest("name is required")
	}

	now := time.Now()
	rt := &resourcetype.ResourceType{
		ID:          id.NewResourceTypeID(),
		Name:        req.Name,
		Description: req.Description,
		Metadata:    req.Metadata,
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

	return rt, ctx.JSON(http.StatusCreated, rt)
}

func (a *API) getResourceType(ctx forge.Context, _ *GetResourceTypeRequest) (*resourcetype.ResourceType, error) {
	rtID, err := id.ParseResourceTypeID(ctx.Param("resourceTypeId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid resource type ID: %v", err))
	}

	rt, err := a.eng.Store().GetResourceType(ctx.Context(), rtID)
	if err != nil {
		return nil, mapError(err)
	}

	return rt, ctx.JSON(http.StatusOK, rt)
}

func (a *API) deleteResourceType(ctx forge.Context, _ *GetResourceTypeRequest) (*struct{}, error) {
	rtID, err := id.ParseResourceTypeID(ctx.Param("resourceTypeId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid resource type ID: %v", err))
	}

	if err := a.eng.Store().DeleteResourceType(ctx.Context(), rtID); err != nil {
		return nil, mapError(err)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listResourceTypes(ctx forge.Context, req *ListResourceTypesRequest) ([]*resourcetype.ResourceType, error) {
	filter := &resourcetype.ListFilter{
		Search: req.Search,
		Limit:  defaultLimit(req.Limit),
		Offset: req.Offset,
	}

	rts, err := a.eng.Store().ListResourceTypes(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return rts, ctx.JSON(http.StatusOK, rts)
}
