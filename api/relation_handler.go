package api

import (
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
)

func (a *API) registerRelationRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("relations"))

	if err := g.POST("/relations", a.writeRelation,
		forge.WithSummary("Write relation"),
		forge.WithDescription("Creates a relation tuple."),
		forge.WithOperationID("writeRelation"),
		forge.WithRequestSchema(WriteRelationRequest{}),
		forge.WithCreatedResponse(&relation.Tuple{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.POST("/relations/delete", a.deleteRelation,
		forge.WithSummary("Delete relation"),
		forge.WithDescription("Deletes a relation tuple by its fields."),
		forge.WithOperationID("deleteRelation"),
		forge.WithRequestSchema(DeleteRelationRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.GET("/relations", a.listRelations,
		forge.WithSummary("List relations"),
		forge.WithOperationID("listRelations"),
		forge.WithRequestSchema(ListRelationsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Relation list", []*relation.Tuple{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) writeRelation(ctx forge.Context, req *WriteRelationRequest) (*relation.Tuple, error) {
	if req.ObjectType == "" || req.ObjectID == "" || req.Relation == "" || req.SubjectType == "" || req.SubjectID == "" {
		return nil, forge.BadRequest("object_type, object_id, relation, subject_type, and subject_id are required")
	}

	now := time.Now()
	t := &relation.Tuple{
		ID:              id.NewRelationID(),
		ObjectType:      req.ObjectType,
		ObjectID:        req.ObjectID,
		Relation:        req.Relation,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		SubjectRelation: req.SubjectRelation,
		CreatedAt:       now,
	}

	if err := a.eng.Store().CreateRelation(ctx.Context(), t); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRelationWritten(ctx.Context(), t)
	}

	return t, ctx.JSON(http.StatusCreated, t)
}

func (a *API) deleteRelation(ctx forge.Context, req *DeleteRelationRequest) (*struct{}, error) {
	if req.ObjectType == "" || req.ObjectID == "" || req.Relation == "" || req.SubjectType == "" || req.SubjectID == "" {
		return nil, forge.BadRequest("object_type, object_id, relation, subject_type, and subject_id are required")
	}

	if err := a.eng.Store().DeleteRelationTuple(ctx.Context(), "", req.ObjectType, req.ObjectID, req.Relation, req.SubjectType, req.SubjectID); err != nil {
		return nil, mapError(err)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listRelations(ctx forge.Context, req *ListRelationsRequest) ([]*relation.Tuple, error) {
	filter := &relation.ListFilter{
		ObjectType:  req.ObjectType,
		ObjectID:    req.ObjectID,
		Relation:    req.Relation,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Limit:       defaultLimit(req.Limit),
		Offset:      req.Offset,
	}

	tuples, err := a.eng.Store().ListRelations(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return tuples, ctx.JSON(http.StatusOK, tuples)
}
