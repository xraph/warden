// handlers_resourcetypes.go: the ReBAC schema surface.
//
// A resource type declares its relations (viewer, editor, parent) and the
// permissions derived from them (read = viewer or editor or parent->read).
//
// Those expressions are a real language with a real parser, dsl.CompileExpr,
// which returns diagnostics carrying Pos{Line, Col}. Nothing calls it on a
// write. api/resourcetype_handler.go copies Expression straight through, and
// the store stores whatever it is handed. An invalid expression therefore
// saves without complaint and fails at CHECK time, where evaluateReBAC logs
// a warning and treats it as no match. The permission silently never grants,
// and nothing an operator can see says why.
//
// So this file validates on write, twice. First the expression must parse.
// Second, every relation it names must be one the type declares, which the
// parser cannot know and which is the other way to write an expression that
// can never match.
package contract

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/dsl"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// ResourceTypeSummary is one row of the resource types list. It carries
// counts rather than the definitions themselves: a row showing every
// relation and expression of every type is a wall of text, and the detail
// page is where the definitions live.
type ResourceTypeSummary struct {
	ID              string `json:"id"`
	NamespacePath   string `json:"namespacePath"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	RelationCount   int    `json:"relationCount"`
	PermissionCount int    `json:"permissionCount"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
}

// RelationDefDTO mirrors resourcetype.RelationDef on the wire.
type RelationDefDTO struct {
	Name            string   `json:"name"`
	AllowedSubjects []string `json:"allowedSubjects"`
}

// PermissionDefDTO mirrors resourcetype.PermissionDef on the wire.
type PermissionDefDTO struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

// ResourceTypeDetail is one type with its full definitions. Both slices are
// always non-nil so the JSON carries [] rather than null: a page doing
// data.relations.length on null throws.
type ResourceTypeDetail struct {
	ResourceTypeSummary
	Relations   []RelationDefDTO   `json:"relations"`
	Permissions []PermissionDefDTO `json:"permissions"`
	CreatedBy   string             `json:"createdBy,omitempty"`
	UpdatedBy   string             `json:"updatedBy,omitempty"`
}

// ExpressionDiagnostic is one problem found in a permission expression.
// Line and Col are 1-based and relative to the expression text, which is
// what lets an editor mark the exact column.
type ExpressionDiagnostic struct {
	Permission string `json:"permission"`
	Line       int    `json:"line"`
	Col        int    `json:"col"`
	Message    string `json:"message"`
}

// diagnosticsDetailKey is where the diagnostics ride on a BAD_REQUEST's
// Details map.
const diagnosticsDetailKey = "diagnostics"

// ResourceTypesListInput filters the resource types list.
type ResourceTypesListInput struct {
	PageRequest
	NamespacePath *string `json:"namespacePath,omitempty"`
	Search        string  `json:"search,omitempty"`
}

// ResourceTypesListResponse is the paged reply.
type ResourceTypesListResponse struct {
	PageMeta
	Items []ResourceTypeSummary `json:"items"`
}

// ResourceTypeDetailInput names one resource type.
type ResourceTypeDetailInput struct {
	ID string `json:"id"`
}

// ResourceTypeCreateInput creates a resource type.
type ResourceTypeCreateInput struct {
	Name          string             `json:"name"`
	NamespacePath string             `json:"namespacePath,omitempty"`
	Description   string             `json:"description,omitempty"`
	Relations     []RelationDefDTO   `json:"relations,omitempty"`
	Permissions   []PermissionDefDTO `json:"permissions,omitempty"`
}

// ResourceTypeUpdateInput patches a resource type.
//
// Every field but the id is a pointer. nil means "leave it alone"; a
// pointer to an empty slice means "remove them all". Name and namespace are
// absent on purpose: tuples name a type by its name, so renaming one strands
// every tuple that used the old name.
type ResourceTypeUpdateInput struct {
	ID          string              `json:"id"`
	Description *string             `json:"description,omitempty"`
	Relations   *[]RelationDefDTO   `json:"relations,omitempty"`
	Permissions *[]PermissionDefDTO `json:"permissions,omitempty"`
}

// ResourceTypeDeleteInput names the resource type to remove.
type ResourceTypeDeleteInput struct {
	ID string `json:"id"`
}

func parseResourceTypeID(raw string) (id.ResourceTypeID, error) {
	rid, err := id.ParseResourceTypeID(raw)
	if err != nil {
		return id.Nil, badRequest("not a resource type id: " + raw)
	}
	return rid, nil
}

func projectResourceType(rt *resourcetype.ResourceType) ResourceTypeSummary {
	return ResourceTypeSummary{
		ID:              rt.ID.String(),
		NamespacePath:   rt.NamespacePath,
		Name:            rt.Name,
		Description:     rt.Description,
		RelationCount:   len(rt.Relations),
		PermissionCount: len(rt.Permissions),
		CreatedAt:       rt.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       rt.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func relationDefsToDTO(defs []resourcetype.RelationDef) []RelationDefDTO {
	out := make([]RelationDefDTO, 0, len(defs))
	for _, d := range defs {
		subjects := make([]string, len(d.AllowedSubjects))
		copy(subjects, d.AllowedSubjects)
		out = append(out, RelationDefDTO{Name: d.Name, AllowedSubjects: subjects})
	}
	return out
}

func permissionDefsToDTO(defs []resourcetype.PermissionDef) []PermissionDefDTO {
	out := make([]PermissionDefDTO, 0, len(defs))
	for _, d := range defs {
		out = append(out, PermissionDefDTO{Name: d.Name, Expression: d.Expression})
	}
	return out
}

func relationDefsFromDTO(dtos []RelationDefDTO) []resourcetype.RelationDef {
	out := make([]resourcetype.RelationDef, 0, len(dtos))
	for _, d := range dtos {
		subjects := make([]string, len(d.AllowedSubjects))
		copy(subjects, d.AllowedSubjects)
		out = append(out, resourcetype.RelationDef{Name: d.Name, AllowedSubjects: subjects})
	}
	return out
}

func permissionDefsFromDTO(dtos []PermissionDefDTO) []resourcetype.PermissionDef {
	out := make([]resourcetype.PermissionDef, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, resourcetype.PermissionDef{Name: d.Name, Expression: d.Expression})
	}
	return out
}

// relationRef is one relation an expression depends on, with where it sits.
type relationRef struct {
	name string
	pos  dsl.Pos
}

// referencedRelations walks a parsed expression and returns every relation
// the current type must declare for the expression to be able to match.
//
// A bare identifier is a direct relation lookup on this type. A traversal
// (parent->read) needs only its first step declared here: every later step
// is a relation or permission on whichever type the first hop lands on,
// which this type's own definition cannot know.
func referencedRelations(e dsl.Expr) []relationRef {
	switch v := e.(type) {
	case *dsl.RefExpr:
		return []relationRef{{name: v.Name, pos: v.Pos}}
	case *dsl.TraverseExpr:
		if len(v.Steps) == 0 {
			return nil
		}
		return []relationRef{{name: v.Steps[0], pos: v.Pos}}
	case *dsl.OrExpr:
		return append(referencedRelations(v.Left), referencedRelations(v.Right)...)
	case *dsl.AndExpr:
		return append(referencedRelations(v.Left), referencedRelations(v.Right)...)
	case *dsl.NotExpr:
		return referencedRelations(v.Inner)
	}
	return nil
}

// validateDefinitions refuses a relation and permission set that cannot work.
//
// It checks names, then parses every expression with dsl.CompileExpr, then
// checks that every relation an expression references is declared. All the
// problems found are reported together, in declaration order, so an operator
// fixes them in one pass. They ride on the returned error's Details under
// "diagnostics" as []ExpressionDiagnostic, each with a line and column, and
// the message names each offending permission.
func validateDefinitions(relations []RelationDefDTO, permissions []PermissionDefDTO) error {
	declared := make(map[string]struct{}, len(relations))
	for _, r := range relations {
		if r.Name == "" {
			return badRequest("a relation needs a name")
		}
		if _, dup := declared[r.Name]; dup {
			return badRequest("relation " + r.Name + " is declared twice")
		}
		declared[r.Name] = struct{}{}
	}
	permNames := make(map[string]struct{}, len(permissions))
	for _, p := range permissions {
		if p.Name == "" {
			return badRequest("a permission needs a name")
		}
		if _, dup := permNames[p.Name]; dup {
			return badRequest("permission " + p.Name + " is declared twice")
		}
		permNames[p.Name] = struct{}{}
	}

	var diags []ExpressionDiagnostic
	for _, p := range permissions {
		expr, parseDiags := dsl.CompileExpr("<"+p.Name+">", p.Expression)
		if len(parseDiags) > 0 {
			for _, d := range parseDiags {
				diags = append(diags, ExpressionDiagnostic{
					Permission: p.Name, Line: d.Pos.Line, Col: d.Pos.Col, Message: d.Msg,
				})
			}
			// The tree of a failed parse holds placeholders, so its
			// references are not worth checking.
			continue
		}
		for _, ref := range referencedRelations(expr) {
			if _, ok := declared[ref.name]; ok {
				continue
			}
			msg := "relation " + ref.name + " is not declared on this type"
			if _, isPerm := permNames[ref.name]; isPerm {
				// Not "an expression can only reference relations": the last
				// step of a traversal (parent->read) can name a permission on
				// the hopped type. What cannot is a bare name or a
				// traversal's first step, because the evaluator looks those
				// up as relation tuples and never as permissions.
				msg = ref.name + " is a permission, not a relation. A bare name, like the first step of a traversal, " +
					"is looked up as a relation, not evaluated as a permission"
			}
			diags = append(diags, ExpressionDiagnostic{
				Permission: p.Name, Line: ref.pos.Line, Col: ref.pos.Col, Message: msg,
			})
		}
	}
	if len(diags) == 0 {
		return nil
	}

	parts := make([]string, 0, len(diags))
	for _, d := range diags {
		parts = append(parts, fmt.Sprintf("permission %s at %d:%d: %s", d.Permission, d.Line, d.Col, d.Message))
	}
	return &dashcontract.Error{
		Code:    dashcontract.CodeBadRequest,
		Message: "invalid permission expression: " + strings.Join(parts, "; "),
		Details: map[string]any{diagnosticsDetailKey: diags},
	}
}

func resourceTypesListHandler(deps Deps) func(context.Context, ResourceTypesListInput, dashcontract.Principal) (ResourceTypesListResponse, error) {
	return func(ctx context.Context, in ResourceTypesListInput, p dashcontract.Principal) (ResourceTypesListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return ResourceTypesListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return ResourceTypesListResponse{}, err
		}
		limit, offset := in.Clamp()
		filter := &resourcetype.ListFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Search:        in.Search,
			Limit:         limit,
			Offset:        offset,
		}
		s := deps.Engine.Store()
		rows, err := s.ListResourceTypes(ctx, filter)
		if err != nil {
			return ResourceTypesListResponse{}, mapWardenError(err)
		}
		total, err := s.CountResourceTypes(ctx, filter)
		if err != nil {
			return ResourceTypesListResponse{}, mapWardenError(err)
		}
		out := ResourceTypesListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]ResourceTypeSummary, 0, len(rows)),
		}
		for _, rt := range rows {
			out.Items = append(out.Items, projectResourceType(rt))
		}
		return out, nil
	}
}

func resourceTypesDetailHandler(deps Deps) func(context.Context, ResourceTypeDetailInput, dashcontract.Principal) (ResourceTypeDetail, error) {
	return func(ctx context.Context, in ResourceTypeDetailInput, p dashcontract.Principal) (ResourceTypeDetail, error) {
		if err := requireEngine(deps); err != nil {
			return ResourceTypeDetail{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return ResourceTypeDetail{}, err
		}
		rid, err := parseResourceTypeID(in.ID)
		if err != nil {
			return ResourceTypeDetail{}, err
		}
		rt, err := deps.Engine.Store().GetResourceType(ctx, tenantID, rid)
		if err != nil {
			return ResourceTypeDetail{}, mapWardenError(err)
		}
		return ResourceTypeDetail{
			ResourceTypeSummary: projectResourceType(rt),
			Relations:           relationDefsToDTO(rt.Relations),
			Permissions:         permissionDefsToDTO(rt.Permissions),
			CreatedBy:           rt.CreatedBy,
			UpdatedBy:           rt.UpdatedBy,
		}, nil
	}
}

func resourceTypesCreateHandler(deps Deps) func(context.Context, ResourceTypeCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in ResourceTypeCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		if in.Name == "" {
			return AckResponse{}, badRequest("a resource type needs a name")
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		if err := validateDefinitions(in.Relations, in.Permissions); err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		actor := actorFor(p)
		rt := &resourcetype.ResourceType{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Name:          in.Name,
			Description:   in.Description,
			Relations:     relationDefsFromDTO(in.Relations),
			Permissions:   permissionDefsFromDTO(in.Permissions),
			CreatedBy:     actor.ID,
			UpdatedBy:     actor.ID,
		}
		if err := deps.Engine.Store().CreateResourceType(ctx, rt); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// The plugin registry has no typed resource type hook, and the REST
		// handler emits only the audit event too. The audit event is what
		// drives the cache invalidator, and a schema change alters what the
		// graph walker can derive, so it is not optional.
		emitAudit(ctx, deps, p, "resourcetype.created", tenantID, rt.ID.String(), rt, nil)
		return AckResponse{ID: rt.ID.String()}, nil
	}
}

func resourceTypesUpdateHandler(deps Deps) func(context.Context, ResourceTypeUpdateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in ResourceTypeUpdateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		rid, err := parseResourceTypeID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()

		// Read, patch, write. UpdateResourceType persists the whole struct,
		// so building a fresh one from the request would erase every field
		// the request omitted.
		rt, err := s.GetResourceType(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		before := *rt
		if in.Description != nil {
			rt.Description = *in.Description
		}
		// A permission expression is valid only against the relations it is
		// checked with, so when either list changes the resulting pair is
		// validated together. A description-only update validates nothing:
		// it must not be blocked by a definition it does not touch.
		if in.Relations != nil || in.Permissions != nil {
			relations := relationDefsToDTO(rt.Relations)
			permissions := permissionDefsToDTO(rt.Permissions)
			if in.Relations != nil {
				relations = *in.Relations
			}
			if in.Permissions != nil {
				permissions = *in.Permissions
			}
			if err := validateDefinitions(relations, permissions); err != nil {
				return AckResponse{}, err
			}
			if in.Relations != nil {
				rt.Relations = relationDefsFromDTO(relations)
			}
			if in.Permissions != nil {
				rt.Permissions = permissionDefsFromDTO(permissions)
			}
		}
		rt.UpdatedBy = actorFor(p).ID
		rt.UpdatedAt = time.Now()
		if err := s.UpdateResourceType(ctx, rt); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		emitAudit(ctx, deps, p, "resourcetype.updated", tenantID, rt.ID.String(), rt, &before)
		return AckResponse{ID: rt.ID.String()}, nil
	}
}

func resourceTypesDeleteHandler(deps Deps) func(context.Context, ResourceTypeDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in ResourceTypeDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		rid, err := parseResourceTypeID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		rt, err := s.GetResourceType(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// A check resolves a type by name from the check's namespace up, and
		// considers tuples from the check's namespace up. So this type
		// answers for checks at its namespace and below, and every tuple in
		// scope for those checks uses it: tuples at its namespace or below
		// it, and tuples at each of its strict ancestors, because tuples
		// cascade downward. The empty prefix (the tenant root) matches
		// everything, and a root type has no strict ancestors.
		used, err := s.CountRelations(ctx, &relation.ListFilter{
			TenantID:        tenantID,
			NamespacePrefix: rt.NamespacePath,
			ObjectType:      rt.Name,
		})
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// AncestorNamespaces returns the path itself first, then each
		// ancestor up to the root, so [1:] is the strict ancestors. Each is
		// counted by exact namespace so no tuple is counted twice.
		for _, ns := range warden.AncestorNamespaces(rt.NamespacePath)[1:] {
			exact := ns
			n, err := s.CountRelations(ctx, &relation.ListFilter{
				TenantID:      tenantID,
				NamespacePath: &exact,
				ObjectType:    rt.Name,
			})
			if err != nil {
				return AckResponse{}, mapWardenError(err)
			}
			used += n
		}
		if used > 0 {
			return AckResponse{}, &dashcontract.Error{
				Code: dashcontract.CodeConflict,
				Message: fmt.Sprintf("%d relation tuples still use %s as their object type. "+
					"Delete them first: without the type the graph walker cannot resolve "+
					"a derived permission through them.", used, rt.Name),
			}
		}
		ctx = withActor(ctx, p)
		if err := s.DeleteResourceType(ctx, tenantID, rid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		emitAudit(ctx, deps, p, "resourcetype.deleted", tenantID, rid.String(), nil, rt)
		return AckResponse{}, nil
	}
}
