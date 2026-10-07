package api

import (
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
)

func (a *API) registerRelationRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("relations"))

	manage := a.authorize("manage", "warden:relation")
	read := a.authorize("read", "warden:relation")

	if err := g.POST("/relations", a.writeRelation,
		forge.WithSummary("Write relation"),
		forge.WithDescription("Creates a relation tuple."),
		forge.WithOperationID("writeRelation"),
		forge.WithRequestSchema(WriteRelationRequest{}),
		forge.WithCreatedResponse(&relation.Tuple{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
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
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	return g.GET("/relations", a.listRelations,
		forge.WithSummary("List relations"),
		forge.WithOperationID("listRelations"),
		forge.WithRequestSchema(ListRelationsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Relation list", []*relation.Tuple{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	)
}

func validateRelationFields(objectType, objectID, rel, subjectType, subjectID string) error {
	verr := forge.NewValidationErrors()
	if objectType == "" {
		verr.AddWithCode("object_type", "object_type is required", "REQUIRED", nil)
	}
	if objectID == "" {
		verr.AddWithCode("object_id", "object_id is required", "REQUIRED", nil)
	}
	if rel == "" {
		verr.AddWithCode("relation", "relation is required", "REQUIRED", nil)
	}
	if subjectType == "" {
		verr.AddWithCode("subject_type", "subject_type is required", "REQUIRED", nil)
	}
	if subjectID == "" {
		verr.AddWithCode("subject_id", "subject_id is required", "REQUIRED", nil)
	}
	if verr.HasErrors() {
		return verr
	}
	return nil
}

func (a *API) writeRelation(ctx forge.Context, req *WriteRelationRequest) (*relation.Tuple, error) {
	if err := validateRelationFields(req.ObjectType, req.ObjectID, req.Relation, req.SubjectType, req.SubjectID); err != nil {
		return nil, err
	}

	appID, tenantID := scopeFromForgeContext(ctx)
	actor, _ := warden.ActorFromContext(ctx.Context())
	now := time.Now()
	t := &relation.Tuple{
		ID:              id.NewRelationID(),
		TenantID:        tenantID,
		AppID:           appID,
		ObjectType:      req.ObjectType,
		ObjectID:        req.ObjectID,
		Relation:        req.Relation,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		SubjectRelation: req.SubjectRelation,
		CreatedBy:       actor.ID,
		CreatedAt:       now,
	}

	// The resource type governing the object type, if there is one, must
	// declare the relation and allow the subject (the dashboard's
	// relations.create runs the same check). REST writes every tuple at the
	// tenant root, so only a root declaration can govern it. The read and
	// the write are not atomic.
	if err := resourcetype.CheckTupleDeclared(ctx.Context(), a.eng.Store(), t); err != nil {
		return nil, mapError(err)
	}
	if err := a.eng.Store().CreateRelation(ctx.Context(), t); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRelationWritten(ctx.Context(), t)
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: now, Action: "relation.written",
			TenantID: tenantID, EntityID: t.ID.String(), Entity: t,
		})
	}

	return nil, ctx.JSON(http.StatusCreated, t)
}

func (a *API) deleteRelation(ctx forge.Context, req *DeleteRelationRequest) (*struct{}, error) {
	if err := validateRelationFields(req.ObjectType, req.ObjectID, req.Relation, req.SubjectType, req.SubjectID); err != nil {
		return nil, err
	}

	_, tenantID := scopeFromForgeContext(ctx)
	// Read the matching tuples first so each one is audited by its own ID,
	// the same shape the dashboard's relations.delete uses. The filter is
	// the delete's key exactly. That key leaves out subject_relation, so one
	// delete can remove several tuples (group:eng and group:eng#member).
	//
	// The read and the delete are two calls, not one transaction: a tuple
	// with this key written between them is removed without an audit event
	// of its own. As with the role and policy deletes, a failed read does
	// not stop the delete; the audit then falls back to one event naming
	// the key.
	//
	// The typed hook clears the check cache for each tuple the read named.
	// DeleteRelationTuple does not say how many rows it removed, so when
	// the read named none (it failed, or found nothing) the handler clears
	// this tenant's cached decisions itself after a successful delete. A
	// spurious clear costs a few cache misses in one tenant; a missed one
	// leaves a revoked subject allowed until the entry expires.
	ns := req.NamespacePath
	matched, listErr := a.eng.Store().ListRelations(ctx.Context(), &relation.ListFilter{
		TenantID:      tenantID,
		NamespacePath: &ns,
		ObjectType:    req.ObjectType,
		ObjectID:      req.ObjectID,
		Relation:      req.Relation,
		SubjectType:   req.SubjectType,
		SubjectID:     req.SubjectID,
	})

	if err := a.eng.Store().DeleteRelationTuple(ctx.Context(), tenantID, req.NamespacePath, req.ObjectType, req.ObjectID, req.Relation, req.SubjectType, req.SubjectID); err != nil {
		return nil, mapError(err)
	}
	if len(matched) == 0 {
		a.eng.InvalidateTenant(ctx.Context(), tenantID)
	}

	if a.eng.Plugins() != nil {
		actor, _ := warden.ActorFromContext(ctx.Context())
		now := time.Now()
		for _, t := range matched {
			a.eng.Plugins().EmitRelationDeleted(ctx.Context(), t.ID)
		}
		if listErr != nil {
			a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
				Actor: actor, At: now, Action: "relation.deleted",
				TenantID: tenantID, EntityID: relationDeleteKey(req),
			})
		}
		for _, t := range matched {
			a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
				Actor: actor, At: now, Action: "relation.deleted",
				TenantID: tenantID, EntityID: t.ID.String(), Before: t,
			})
		}
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

// relationDeleteKey names the tuples a REST delete covers, for the audit
// event of a delete whose read failed: the namespace, the object, relation
// and subject, and any subject relation, since the delete's key leaves it
// out and removes group:eng and group:eng#member alike.
func relationDeleteKey(req *DeleteRelationRequest) string {
	where := "tenant root"
	if req.NamespacePath != "" {
		where = "namespace " + req.NamespacePath
	}
	return where + ": " + req.ObjectType + ":" + req.ObjectID + "#" + req.Relation +
		"@" + req.SubjectType + ":" + req.SubjectID + " (any subject relation)"
}

func (a *API) listRelations(ctx forge.Context, req *ListRelationsRequest) (*RelationListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &relation.ListFilter{
		TenantID:    tenantID,
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

	return &RelationListResponse{Body: tuples}, nil
}
