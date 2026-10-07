// handlers_relations.go: the relation surface.
//
// A tuple is object#relation@subject, Zanzibar style:
// document:readme#viewer@user:bob.
//
// Two things about tuples that differ from everything else in this contract.
//
// They are create-and-delete only. relation.Store exposes no update, so
// changing a tuple means deleting one and writing another. There is no
// patch input here and no edit form on the page.
//
// Their namespace cascades at check time but not in the list. Like roles
// and policies, a tuple stored at a namespace is in scope for a check in
// that namespace and in every namespace below it: the engine passes
// AncestorNamespaces(checkNamespace) to every tuple lookup a check makes,
// in the direct check, the expression evaluator and the graph walker alike
// (see evaluateReBAC in engine.go and TestReBAC_NamespaceCascade). The list
// filter, by contrast, is an exact match on purpose, so it shows what is
// stored in one namespace. A namespace's listing therefore does NOT show a
// parent's tuples that also apply there, and a page must say so rather
// than let the listing read as everything in effect.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// RelationSummary is one tuple.
type RelationSummary struct {
	ID              string `json:"id"`
	NamespacePath   string `json:"namespacePath"`
	ObjectType      string `json:"objectType"`
	ObjectID        string `json:"objectId"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subjectType"`
	SubjectID       string `json:"subjectId"`
	SubjectRelation string `json:"subjectRelation,omitempty"`
	CreatedBy       string `json:"createdBy,omitempty"`
	CreatedAt       string `json:"createdAt"`
}

// RelationsListInput filters the tuple list. Every field the store's filter
// offers is here, because tracing a tuple means narrowing on whichever end
// you happen to know.
type RelationsListInput struct {
	PageRequest
	NamespacePath   *string `json:"namespacePath,omitempty"`
	ObjectType      string  `json:"objectType,omitempty"`
	ObjectID        string  `json:"objectId,omitempty"`
	Relation        string  `json:"relation,omitempty"`
	SubjectType     string  `json:"subjectType,omitempty"`
	SubjectID       string  `json:"subjectId,omitempty"`
	SubjectRelation string  `json:"subjectRelation,omitempty"`
}

// RelationsListResponse is the paged reply.
type RelationsListResponse struct {
	PageMeta
	Items []RelationSummary `json:"items"`
}

// RelationCreateInput writes one tuple. Every part of the triple is
// required: a tuple missing any of them matches nothing and is reachable by
// no filter, so it is silent junk rather than a partial grant.
type RelationCreateInput struct {
	NamespacePath   string `json:"namespacePath,omitempty"`
	ObjectType      string `json:"objectType"`
	ObjectID        string `json:"objectId"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subjectType"`
	SubjectID       string `json:"subjectId"`
	SubjectRelation string `json:"subjectRelation,omitempty"`
}

// RelationDeleteInput names the tuple to remove, by id.
//
// The store also offers DeleteRelationTuple, which takes the whole natural
// key. By-id is used here because the list hands the page an id, and an id
// cannot be half-right the way a seven-part key can.
type RelationDeleteInput struct {
	ID string `json:"id"`
}

func parseRelationID(raw string) (id.RelationID, error) {
	rid, err := id.ParseRelationID(raw)
	if err != nil {
		return id.Nil, badRequest("not a relation id: " + raw)
	}
	return rid, nil
}

func projectTuple(tp *relation.Tuple) RelationSummary {
	return RelationSummary{
		ID:              tp.ID.String(),
		NamespacePath:   tp.NamespacePath,
		ObjectType:      tp.ObjectType,
		ObjectID:        tp.ObjectID,
		Relation:        tp.Relation,
		SubjectType:     tp.SubjectType,
		SubjectID:       tp.SubjectID,
		SubjectRelation: tp.SubjectRelation,
		CreatedBy:       tp.CreatedBy,
		CreatedAt:       tp.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func relationsListHandler(deps Deps) func(context.Context, RelationsListInput, dashcontract.Principal) (RelationsListResponse, error) {
	return func(ctx context.Context, in RelationsListInput, p dashcontract.Principal) (RelationsListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return RelationsListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return RelationsListResponse{}, err
		}
		limit, offset := in.Clamp()
		filter := &relation.ListFilter{
			TenantID:        tenantID,
			NamespacePath:   in.NamespacePath,
			ObjectType:      in.ObjectType,
			ObjectID:        in.ObjectID,
			Relation:        in.Relation,
			SubjectType:     in.SubjectType,
			SubjectID:       in.SubjectID,
			SubjectRelation: in.SubjectRelation,
			Limit:           limit,
			Offset:          offset,
		}
		s := deps.Engine.Store()
		rows, err := s.ListRelations(ctx, filter)
		if err != nil {
			return RelationsListResponse{}, mapWardenError(err)
		}
		total, err := s.CountRelations(ctx, filter)
		if err != nil {
			return RelationsListResponse{}, mapWardenError(err)
		}
		out := RelationsListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]RelationSummary, 0, len(rows)),
		}
		for _, tp := range rows {
			out.Items = append(out.Items, projectTuple(tp))
		}
		return out, nil
	}
}

func relationsCreateHandler(deps Deps) func(context.Context, RelationCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RelationCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		// An ordered slice rather than a map, so the first missing part
		// reported is the same one on every run.
		for _, part := range []struct{ field, value string }{
			{"objectType", in.ObjectType},
			{"objectId", in.ObjectID},
			{"relation", in.Relation},
			{"subjectType", in.SubjectType},
			{"subjectId", in.SubjectID},
		} {
			if part.value == "" {
				return AckResponse{}, badRequest("a relation needs " + part.field)
			}
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		tp := &relation.Tuple{
			TenantID:        tenantID,
			NamespacePath:   in.NamespacePath,
			ObjectType:      in.ObjectType,
			ObjectID:        in.ObjectID,
			Relation:        in.Relation,
			SubjectType:     in.SubjectType,
			SubjectID:       in.SubjectID,
			SubjectRelation: in.SubjectRelation,
			CreatedBy:       actorFor(p).ID,
		}
		// The resource type governing the object type, if there is one,
		// must declare the relation and allow the subject. The read and the
		// write are not atomic: a schema change landing between them is not
		// seen by this write.
		if err := resourcetype.CheckTupleDeclared(ctx, deps.Engine.Store(), tp); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if err := deps.Engine.Store().CreateRelation(ctx, tp); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// Same emissions as the REST handler (api/relation_handler.go). The
		// typed hook and the audit event each drive the cache invalidator, so
		// skipping them leaves a stale answer for the new subject until the
		// cached decision ages out.
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRelationWritten(ctx, tp)
		}
		emitAudit(ctx, deps, p, "relation.written", tenantID, tp.ID.String(), tp, nil)
		return AckResponse{ID: tp.ID.String()}, nil
	}
}

func relationsDeleteHandler(deps Deps) func(context.Context, RelationDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in RelationDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		rid, err := parseRelationID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		// Read first: it makes another tenant's tuple NOT_FOUND before
		// anything is deleted or audited, and gives the audit event the tuple
		// that is about to disappear rather than a bare ID.
		//
		// The read and the delete are two calls, not one transaction. A
		// tuple has no update path, so the row cannot change between them;
		// if a concurrent request deletes it first, DeleteRelation returns
		// ErrRelationNotFound below and this request audits nothing.
		before, err := s.GetRelation(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := s.DeleteRelation(ctx, tenantID, rid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// Load-bearing: the typed hook clears the decision cache and the
		// audit event flushes the tenant. Without them a subject who no
		// longer holds the relation keeps a cached ALLOW.
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRelationDeleted(ctx, rid)
		}
		emitAudit(ctx, deps, p, "relation.deleted", tenantID, rid.String(), nil, before)
		return AckResponse{}, nil
	}
}
