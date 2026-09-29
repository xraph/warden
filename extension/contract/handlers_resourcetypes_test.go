package contract

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func seedResourceType(t *testing.T, s *memory.Store, namespace, name string) *resourcetype.ResourceType {
	t.Helper()
	rt := &resourcetype.ResourceType{
		TenantID:      "t1",
		NamespacePath: namespace,
		Name:          name,
		Relations: []resourcetype.RelationDef{
			{Name: "viewer", AllowedSubjects: []string{"user"}},
		},
		Permissions: []resourcetype.PermissionDef{
			{Name: "read", Expression: "viewer"},
		},
	}
	if err := s.CreateResourceType(context.Background(), rt); err != nil {
		t.Fatalf("create resource type %q: %v", name, err)
	}
	return rt
}

// refusal asserts err is a contract error with the given code and returns it.
func refusal(t *testing.T, err error, code dashcontract.ErrorCode) *dashcontract.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want a %s refusal, got success", code)
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return ce
}

// diagnosticsOf pulls the typed diagnostics off a refusal's Details.
func diagnosticsOf(t *testing.T, ce *dashcontract.Error) []ExpressionDiagnostic {
	t.Helper()
	raw, ok := ce.Details[diagnosticsDetailKey]
	if !ok {
		t.Fatalf("the error carries no %q detail: %+v", diagnosticsDetailKey, ce.Details)
	}
	diags, ok := raw.([]ExpressionDiagnostic)
	if !ok {
		t.Fatalf("diagnostics detail is %T, want []ExpressionDiagnostic", raw)
	}
	return diags
}

func storedResourceTypes(t *testing.T, s *memory.Store) []*resourcetype.ResourceType {
	t.Helper()
	rows, err := s.ListResourceTypes(context.Background(), &resourcetype.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("list resource types: %v", err)
	}
	return rows
}

func TestResourceTypesListPagesAndCounts(t *testing.T) {
	// Five rows, pages of two: the page size, the full Total on every page,
	// the echoed limit and offset, disjoint pages, and past-the-end.
	s := memory.New()
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		seedResourceType(t, s, "", name)
	}
	h := resourceTypesListHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	seen := map[string]struct{}{}
	for _, page := range []struct{ offset, wantLen int }{{0, 2}, {2, 2}, {4, 1}} {
		got, err := h(ctx, ResourceTypesListInput{PageRequest: PageRequest{Limit: 2, Offset: page.offset}}, principalFor("t1"))
		if err != nil {
			t.Fatalf("offset %d: %v", page.offset, err)
		}
		if len(got.Items) != page.wantLen {
			t.Errorf("offset %d: %d items, want %d", page.offset, len(got.Items), page.wantLen)
		}
		if got.Total != 5 {
			t.Errorf("offset %d: total = %d, want 5 on every page", page.offset, got.Total)
		}
		if got.Limit != 2 || got.Offset != page.offset {
			t.Errorf("offset %d: echoed limit/offset = %d/%d", page.offset, got.Limit, got.Offset)
		}
		for _, rt := range got.Items {
			if _, dup := seen[rt.Name]; dup {
				t.Errorf("offset %d: %q appeared on an earlier page", page.offset, rt.Name)
			}
			seen[rt.Name] = struct{}{}
		}
	}
	if len(seen) != 5 {
		t.Errorf("pages covered %d distinct rows, want 5", len(seen))
	}

	past, err := h(ctx, ResourceTypesListInput{PageRequest: PageRequest{Limit: 2, Offset: 10}}, principalFor("t1"))
	if err != nil {
		t.Fatalf("past the end: %v", err)
	}
	if len(past.Items) != 0 || past.Total != 5 {
		t.Errorf("past the end: %d items, total %d, want 0 and 5", len(past.Items), past.Total)
	}
}

func TestResourceTypesListFiltersNarrowItemsAndTotal(t *testing.T) {
	// Each filter must narrow both the items and Total. A Total computed
	// from a different filter than the items would make every pager wrong.
	s := memory.New()
	seedResourceType(t, s, "", "document")
	seedResourceType(t, s, "", "folder")
	seedResourceType(t, s, "eng", "document")
	seedResourceType(t, s, "eng/platform", "service")
	h := resourceTypesListHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	root, eng := "", "eng"
	cases := []struct {
		name  string
		in    ResourceTypesListInput
		total int64
		match func(ResourceTypeSummary) bool
	}{
		{"no filter", ResourceTypesListInput{}, 4, func(ResourceTypeSummary) bool { return true }},
		{"tenant root", ResourceTypesListInput{NamespacePath: &root}, 2, func(r ResourceTypeSummary) bool { return r.NamespacePath == "" }},
		{"eng only, not its descendants", ResourceTypesListInput{NamespacePath: &eng}, 1, func(r ResourceTypeSummary) bool { return r.NamespacePath == "eng" }},
		{"search", ResourceTypesListInput{Search: "DOC"}, 2, func(r ResourceTypeSummary) bool { return r.Name == "document" }},
		{"search and namespace", ResourceTypesListInput{Search: "doc", NamespacePath: &eng}, 1, func(r ResourceTypeSummary) bool {
			return r.Name == "document" && r.NamespacePath == "eng"
		}},
	}
	for _, tc := range cases {
		got, err := h(ctx, tc.in, principalFor("t1"))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Total != tc.total || int64(len(got.Items)) != tc.total {
			t.Errorf("%s: total %d with %d items, want %d of each", tc.name, got.Total, len(got.Items), tc.total)
		}
		for _, r := range got.Items {
			if !tc.match(r) {
				t.Errorf("%s: filter leaked %+v", tc.name, r)
			}
		}
	}

	// A filter and a page together: Total is the filtered count, not the
	// size of the page.
	paged, err := h(ctx, ResourceTypesListInput{PageRequest: PageRequest{Limit: 1}, Search: "document"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("filter with paging: %v", err)
	}
	if len(paged.Items) != 1 || paged.Total != 2 {
		t.Errorf("filter with paging: %d items, total %d, want 1 and 2", len(paged.Items), paged.Total)
	}
}

func TestResourceTypesListCarriesCountsNotWholeDefinitions(t *testing.T) {
	// A list row showing every relation and expression of every type is a
	// wall of text. The counts are the scannable thing; the detail page
	// carries the definitions.
	s := memory.New()
	rt := &resourcetype.ResourceType{
		TenantID:      "t1",
		NamespacePath: "eng",
		Name:          "document",
		Description:   "a document",
		Relations: []resourcetype.RelationDef{
			{Name: "viewer", AllowedSubjects: []string{"user"}},
			{Name: "editor", AllowedSubjects: []string{"user"}},
			{Name: "parent", AllowedSubjects: []string{"folder"}},
		},
		Permissions: []resourcetype.PermissionDef{{Name: "read", Expression: "viewer or editor"}},
	}
	if err := s.CreateResourceType(context.Background(), rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.list: %v", err)
	}
	row := got.Items[0]
	if row.RelationCount != 3 || row.PermissionCount != 1 {
		t.Errorf("counts = %d/%d, want 3/1", row.RelationCount, row.PermissionCount)
	}
	if row.ID != rt.ID.String() || row.Name != "document" || row.NamespacePath != "eng" || row.Description != "a document" {
		t.Errorf("row = %+v", row)
	}
	if row.CreatedAt == "" || row.UpdatedAt == "" {
		t.Errorf("timestamps missing: %+v", row)
	}
}

func TestResourceTypesListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	seedResourceType(t, s, "", "mine")
	other := &resourcetype.ResourceType{TenantID: "t2", Name: "theirs"}
	if err := s.CreateResourceType(ctx, other); err != nil {
		t.Fatalf("create other tenant's type: %v", err)
	}
	h := resourceTypesListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, ResourceTypesListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.list: %v", err)
	}
	for _, rt := range got.Items {
		if rt.Name == "theirs" {
			t.Fatal("t1 can see t2's resource type: tenant scoping is not applied")
		}
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1", got.Total)
	}
}

func TestResourceTypesDetailCarriesRelationsAndExpressions(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	rt := &resourcetype.ResourceType{
		TenantID:      "t1",
		NamespacePath: "eng",
		Name:          "document",
		Description:   "a document",
		Relations: []resourcetype.RelationDef{
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
			{Name: "parent", AllowedSubjects: []string{"folder"}},
		},
		Permissions: []resourcetype.PermissionDef{
			{Name: "read", Expression: "viewer or parent->read"},
		},
		CreatedBy: "alice",
		UpdatedBy: "bob",
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, ResourceTypeDetailInput{ID: rt.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.detail: %v", err)
	}
	if got.ID != rt.ID.String() || got.Name != "document" || got.NamespacePath != "eng" || got.Description != "a document" {
		t.Errorf("summary = %+v", got.ResourceTypeSummary)
	}
	if got.RelationCount != 2 || got.PermissionCount != 1 {
		t.Errorf("counts = %d/%d, want 2/1", got.RelationCount, got.PermissionCount)
	}
	if len(got.Relations) != 2 || got.Relations[0].Name != "viewer" ||
		strings.Join(got.Relations[0].AllowedSubjects, ",") != "user,group#member" ||
		got.Relations[1].Name != "parent" || strings.Join(got.Relations[1].AllowedSubjects, ",") != "folder" {
		t.Errorf("relations = %+v", got.Relations)
	}
	if len(got.Permissions) != 1 || got.Permissions[0].Name != "read" || got.Permissions[0].Expression != "viewer or parent->read" {
		t.Errorf("permissions = %+v", got.Permissions)
	}
	if got.CreatedBy != "alice" || got.UpdatedBy != "bob" {
		t.Errorf("createdBy/updatedBy = %q/%q", got.CreatedBy, got.UpdatedBy)
	}
}

func TestResourceTypesDetailSlicesAreNeverNull(t *testing.T) {
	// A page doing data.relations.length on null throws. A stored type with
	// no definitions (nil slices) must still serialise them as [].
	s := memory.New()
	ctx := context.Background()
	bare := &resourcetype.ResourceType{TenantID: "t1", Name: "bare"}
	if err := s.CreateResourceType(ctx, bare); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesDetailHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, ResourceTypeDetailInput{ID: bare.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.detail: %v", err)
	}
	if got.Relations == nil || got.Permissions == nil {
		t.Fatal("slices must be non-nil")
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"relations":[]`) || !strings.Contains(string(raw), `"permissions":[]`) {
		t.Errorf("wire form carries null instead of []: %s", raw)
	}
}

func TestResourceTypesDetailAllowedSubjectsAreNeverNull(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	rt := &resourcetype.ResourceType{
		TenantID:  "t1",
		Name:      "doc",
		Relations: []resourcetype.RelationDef{{Name: "viewer"}},
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := resourceTypesDetailHandler(Deps{Engine: engineOver(t, s)})(ctx, ResourceTypeDetailInput{ID: rt.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.detail: %v", err)
	}
	raw, _ := json.Marshal(got.Relations)
	if !strings.Contains(string(raw), `"allowedSubjects":[]`) {
		t.Errorf("allowedSubjects serialised as null: %s", raw)
	}
}

func TestResourceTypesDetailRefusesAnotherTenantsTypeAndABadID(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	other := &resourcetype.ResourceType{TenantID: "t2", Name: "theirs"}
	if err := s.CreateResourceType(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesDetailHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, ResourceTypeDetailInput{ID: other.ID.String()}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeNotFound)
	_, err = h(ctx, ResourceTypeDetailInput{ID: "not-an-id"}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeBadRequest)
}

func TestResourceTypesCreateRefusesAnUnparseableExpression(t *testing.T) {
	// The finding. dsl.CompileExpr exists and returns diagnostics carrying
	// Pos{Line, Col}, and it is called only by the DSL exporter and the
	// evaluator's lazy compile. api/resourcetype_handler.go copies
	// Expression straight through, so an invalid expression saves fine and
	// then fails silently at check time: evaluateReBAC logs a warning and
	// treats it as no match. The permission simply never grants, with no
	// error anywhere an operator will look.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:        "document",
		Relations:   []RelationDefDTO{{Name: "viewer", AllowedSubjects: []string{"user"}}},
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "viewer or or editor"}},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !containsText(ce.Message, "read") {
		t.Errorf("message %q does not name which permission failed", ce.Message)
	}
	if n := len(storedResourceTypes(t, s)); n != 0 {
		t.Errorf("a refused create stored %d rows", n)
	}
}

func TestResourceTypesCreateReportsTheDiagnosticPosition(t *testing.T) {
	// Diagnostics carry Line and Col, which is what lets an editor mark the
	// exact column. Dropping them would waste the only precise thing the
	// parser gives us. The second `or` starts at column 11.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:        "document",
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "viewer or or editor"}},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	diags := diagnosticsOf(t, ce)
	if len(diags) == 0 {
		t.Fatal("the error carries no diagnostics: the page cannot mark the column")
	}
	d := diags[0]
	if d.Permission != "read" || d.Line != 1 || d.Col != 11 || d.Message == "" {
		t.Errorf("diagnostic = %+v, want permission read at 1:11 with a message", d)
	}

	// The position must survive the trip to the client, not just sit on the
	// Go value.
	raw, err := json.Marshal(ce)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"details"`, `"diagnostics"`, `"permission":"read"`, `"line":1`, `"col":11`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("wire form %s is missing %s", raw, want)
		}
	}
}

func TestResourceTypesCreateReportsEveryProblemAtOnce(t *testing.T) {
	// One pass should show everything wrong, in declaration order, so an
	// operator is not fixing one error per save.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:      "document",
		Relations: []RelationDefDTO{{Name: "viewer"}},
		Permissions: []PermissionDefDTO{
			{Name: "read", Expression: "viewer or ghost"},
			{Name: "write", Expression: "viewer and and viewer"},
			{Name: "admin", Expression: "phantom"},
		},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	diags := diagnosticsOf(t, ce)
	var order []string
	for _, d := range diags {
		order = append(order, d.Permission)
	}
	if strings.Join(order, ",") != "read,write,admin" {
		t.Errorf("diagnostic order = %v, want read,write,admin", order)
	}
	for _, name := range []string{"read", "write", "admin", "ghost", "phantom"} {
		if !containsText(ce.Message, name) {
			t.Errorf("message %q does not mention %s", ce.Message, name)
		}
	}
}

func TestResourceTypesCreateAcceptsAValidExpression(t *testing.T) {
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(context.Background(), ResourceTypeCreateInput{
		Name: "document",
		Relations: []RelationDefDTO{
			{Name: "viewer", AllowedSubjects: []string{"user"}},
			{Name: "editor", AllowedSubjects: []string{"user"}},
		},
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "viewer or editor"}},
	}, principalFor("t1")); err != nil {
		t.Fatalf("a valid expression must be accepted, got %v", err)
	}
}

func TestResourceTypesCreateAcceptsEveryOperatorForm(t *testing.T) {
	// The grammar has and, or, not, their symbol forms, parentheses and
	// traversal. The relation check must walk all of them and must not
	// refuse a legal expression.
	for _, expr := range []string{
		"viewer",
		"viewer or editor",
		"viewer + editor",
		"viewer and editor",
		"viewer & editor",
		"viewer and not banned",
		"viewer and !banned",
		"(viewer or editor) and not banned",
		"parent->read",
		"viewer or parent->read",
		"parent->owner->read",
		"editor and not parent->read",
	} {
		s := memory.New()
		h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})
		_, err := h(context.Background(), ResourceTypeCreateInput{
			Name: "document",
			Relations: []RelationDefDTO{
				{Name: "viewer"}, {Name: "editor"}, {Name: "banned"}, {Name: "parent"},
			},
			Permissions: []PermissionDefDTO{{Name: "read", Expression: expr}},
		}, principalFor("t1"))
		if err != nil {
			t.Errorf("%q was refused: %v", expr, err)
		}
	}
}

func TestResourceTypesCreateRefusesAnExpressionNamingAnUndeclaredRelation(t *testing.T) {
	// An expression that parses can still reference a relation the type
	// does not declare, and then it can never match. The parser cannot
	// catch this; only the type's own relation list can.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:        "document",
		Relations:   []RelationDefDTO{{Name: "viewer", AllowedSubjects: []string{"user"}}},
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "viewer or ghost"}},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !containsText(ce.Message, "ghost") {
		t.Errorf("message %q does not name the undeclared relation", ce.Message)
	}
	diags := diagnosticsOf(t, ce)
	if len(diags) != 1 || diags[0].Permission != "read" || diags[0].Line != 1 || diags[0].Col != 11 {
		t.Errorf("diagnostics = %+v, want one for read at 1:11", diags)
	}
	if n := len(storedResourceTypes(t, s)); n != 0 {
		t.Errorf("a refused create stored %d rows", n)
	}
}

func TestResourceTypesCreateChecksUndeclaredRelationsInsideEveryNode(t *testing.T) {
	// The check walks the tree. A ghost buried under not, and, parentheses
	// or as the head of a traversal must all be found.
	for _, expr := range []string{
		"viewer and not ghost",
		"(viewer or ghost) and viewer",
		"ghost->read",
		"viewer and !ghost",
		"ghost",
	} {
		s := memory.New()
		h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})
		_, err := h(context.Background(), ResourceTypeCreateInput{
			Name:        "document",
			Relations:   []RelationDefDTO{{Name: "viewer"}},
			Permissions: []PermissionDefDTO{{Name: "read", Expression: expr}},
		}, principalFor("t1"))
		ce := refusal(t, err, dashcontract.CodeBadRequest)
		if !containsText(ce.Message, "ghost") {
			t.Errorf("%q: message %q does not name ghost", expr, ce.Message)
		}
	}
}

func TestResourceTypesCreateOnlyChecksTheFirstHopOfATraversal(t *testing.T) {
	// parent->read: only `parent` lives on this type. `read` is a relation
	// or permission on whatever type the hop lands on, which this type's
	// definition cannot know, so it must not be refused as undeclared.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(context.Background(), ResourceTypeCreateInput{
		Name:        "document",
		Relations:   []RelationDefDTO{{Name: "parent", AllowedSubjects: []string{"folder"}}},
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "parent->read"}},
	}, principalFor("t1")); err != nil {
		t.Fatalf("a traversal into another type's permission was refused: %v", err)
	}
}

func TestResourceTypesCreateRefusesAnExpressionNamingAPermission(t *testing.T) {
	// The evaluator resolves a bare name as a direct relation lookup only,
	// so `read` referenced from `write` is a relation that does not exist.
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:      "document",
		Relations: []RelationDefDTO{{Name: "viewer"}},
		Permissions: []PermissionDefDTO{
			{Name: "read", Expression: "viewer"},
			{Name: "write", Expression: "read"},
		},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !containsText(ce.Message, "permission, not a relation") {
		t.Errorf("message %q does not explain that read is a permission", ce.Message)
	}
}

func TestResourceTypesCreateRefusesAnEmptyExpression(t *testing.T) {
	s := memory.New()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{
		Name:        "document",
		Relations:   []RelationDefDTO{{Name: "viewer"}},
		Permissions: []PermissionDefDTO{{Name: "read", Expression: "   "}},
	}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if len(diagnosticsOf(t, ce)) == 0 {
		t.Error("an empty expression produced no diagnostics")
	}
}

func TestResourceTypesCreateRefusesMalformedDefinitions(t *testing.T) {
	cases := []struct {
		name string
		in   ResourceTypeCreateInput
		want string
	}{
		{"no type name", ResourceTypeCreateInput{}, "name"},
		{"bad namespace", ResourceTypeCreateInput{Name: "d", NamespacePath: "/eng/"}, "namespace"},
		{"nameless relation", ResourceTypeCreateInput{Name: "d", Relations: []RelationDefDTO{{}}}, "relation needs a name"},
		{"nameless permission", ResourceTypeCreateInput{Name: "d", Permissions: []PermissionDefDTO{{Expression: "x"}}}, "permission needs a name"},
		{"duplicate relation", ResourceTypeCreateInput{Name: "d", Relations: []RelationDefDTO{{Name: "v"}, {Name: "v"}}}, "relation v is declared twice"},
		{"duplicate permission", ResourceTypeCreateInput{Name: "d",
			Relations:   []RelationDefDTO{{Name: "v"}},
			Permissions: []PermissionDefDTO{{Name: "r", Expression: "v"}, {Name: "r", Expression: "v"}}}, "permission r is declared twice"},
	}
	for _, tc := range cases {
		s := memory.New()
		_, err := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})(context.Background(), tc.in, principalFor("t1"))
		ce := refusal(t, err, dashcontract.CodeBadRequest)
		if !containsText(ce.Message, tc.want) {
			t.Errorf("%s: message %q does not contain %q", tc.name, ce.Message, tc.want)
		}
		if n := len(storedResourceTypes(t, s)); n != 0 {
			t.Errorf("%s: a refused create stored %d rows", tc.name, n)
		}
	}
}

func TestResourceTypesCreateStoresEveryFieldItWasGiven(t *testing.T) {
	// A create test asserting only a non-empty id passes when a field is
	// dropped from the handler. Read the row back and check all of it.
	s := memory.New()
	ctx := context.Background()
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	ack, err := h(ctx, ResourceTypeCreateInput{
		Name:          "document",
		NamespacePath: "eng/platform",
		Description:   "a document",
		Relations: []RelationDefDTO{
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
			{Name: "parent", AllowedSubjects: []string{"folder"}},
		},
		Permissions: []PermissionDefDTO{
			{Name: "read", Expression: "viewer or parent->read"},
			{Name: "admin", Expression: "viewer and not parent"},
		},
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.create: %v", err)
	}
	rid, err := id.ParseResourceTypeID(ack.ID)
	if err != nil {
		t.Fatalf("ack id %q: %v", ack.ID, err)
	}
	got, err := s.GetResourceType(ctx, "t1", rid)
	if err != nil {
		t.Fatalf("stored type: %v", err)
	}
	if got.TenantID != "t1" || got.NamespacePath != "eng/platform" || got.Name != "document" || got.Description != "a document" {
		t.Errorf("stored scalars = %+v", got)
	}
	if got.CreatedBy != "tester" || got.UpdatedBy != "tester" {
		t.Errorf("createdBy/updatedBy = %q/%q, want tester/tester", got.CreatedBy, got.UpdatedBy)
	}
	if len(got.Relations) != 2 ||
		got.Relations[0].Name != "viewer" || strings.Join(got.Relations[0].AllowedSubjects, ",") != "user,group#member" ||
		got.Relations[1].Name != "parent" || strings.Join(got.Relations[1].AllowedSubjects, ",") != "folder" {
		t.Errorf("stored relations = %+v", got.Relations)
	}
	if len(got.Permissions) != 2 ||
		got.Permissions[0] != (resourcetype.PermissionDef{Name: "read", Expression: "viewer or parent->read"}) ||
		got.Permissions[1] != (resourcetype.PermissionDef{Name: "admin", Expression: "viewer and not parent"}) {
		t.Errorf("stored permissions = %+v", got.Permissions)
	}
}

func TestResourceTypesCreateRefusesADuplicateName(t *testing.T) {
	s := memory.New()
	seedResourceType(t, s, "", "document")
	h := resourceTypesCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), ResourceTypeCreateInput{Name: "document"}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeConflict)
}

func TestResourceTypesUpdateLeavesOmittedFieldsAlone(t *testing.T) {
	// UpdateResourceType persists the whole struct, the same trap
	// UpdateRole carries. Update only the description and everything else
	// must survive: name, namespace, relations, permissions, metadata and
	// who created it.
	s := memory.New()
	ctx := context.Background()
	rt := &resourcetype.ResourceType{
		TenantID:      "t1",
		NamespacePath: "eng",
		Name:          "document",
		Description:   "old",
		Relations:     []resourcetype.RelationDef{{Name: "viewer", AllowedSubjects: []string{"user"}}},
		Permissions:   []resourcetype.PermissionDef{{Name: "read", Expression: "viewer"}},
		Metadata:      map[string]any{"owner": "platform"},
		CreatedBy:     "alice",
		UpdatedBy:     "alice",
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})

	desc := "a document"
	if _, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Description: &desc}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.update: %v", err)
	}
	after, err := s.GetResourceType(ctx, "t1", rt.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Description != "a document" {
		t.Errorf("description = %q, want updated", after.Description)
	}
	if after.Name != "document" || after.NamespacePath != "eng" || after.TenantID != "t1" {
		t.Errorf("identity changed: %+v", after)
	}
	if len(after.Relations) != 1 || after.Relations[0].Name != "viewer" || strings.Join(after.Relations[0].AllowedSubjects, ",") != "user" {
		t.Errorf("the update erased or changed relations: %+v", after.Relations)
	}
	if len(after.Permissions) != 1 || after.Permissions[0].Expression != "viewer" {
		t.Errorf("the update erased or changed permissions: %+v", after.Permissions)
	}
	if after.Metadata["owner"] != "platform" {
		t.Errorf("the update erased metadata: %+v", after.Metadata)
	}
	if after.CreatedBy != "alice" || after.UpdatedBy != "tester" {
		t.Errorf("createdBy/updatedBy = %q/%q, want alice/tester", after.CreatedBy, after.UpdatedBy)
	}
}

func TestResourceTypesUpdateChangesWhatItWasGivenAndNothingElse(t *testing.T) {
	// Replace each field alone, and check the other two stayed put.
	ctx := context.Background()
	newRelations := []RelationDefDTO{{Name: "viewer", AllowedSubjects: []string{"user"}}, {Name: "editor", AllowedSubjects: []string{"user"}}}
	newPermissions := []PermissionDefDTO{{Name: "read", Expression: "viewer or editor"}}
	desc := "changed"

	cases := []struct {
		name   string
		in     ResourceTypeUpdateInput
		check  func(*resourcetype.ResourceType) string
		wantOK string
	}{
		{"relations only", ResourceTypeUpdateInput{Relations: &newRelations}, func(r *resourcetype.ResourceType) string {
			if len(r.Relations) != 2 || r.Relations[1].Name != "editor" {
				return "relations not replaced"
			}
			if r.Description != "orig" || len(r.Permissions) != 1 || r.Permissions[0].Expression != "viewer" {
				return "description or permissions changed"
			}
			return ""
		}, ""},
		{"permissions only", ResourceTypeUpdateInput{Permissions: &[]PermissionDefDTO{{Name: "look", Expression: "viewer"}}}, func(r *resourcetype.ResourceType) string {
			if len(r.Permissions) != 1 || r.Permissions[0].Name != "look" {
				return "permissions not replaced"
			}
			if r.Description != "orig" || len(r.Relations) != 1 || r.Relations[0].Name != "viewer" {
				return "description or relations changed"
			}
			return ""
		}, ""},
		{"both together", ResourceTypeUpdateInput{Relations: &newRelations, Permissions: &newPermissions}, func(r *resourcetype.ResourceType) string {
			if len(r.Relations) != 2 || len(r.Permissions) != 1 || r.Permissions[0].Expression != "viewer or editor" {
				return "definitions not replaced"
			}
			if r.Description != "orig" {
				return "description changed"
			}
			return ""
		}, ""},
		{"description only", ResourceTypeUpdateInput{Description: &desc}, func(r *resourcetype.ResourceType) string {
			if r.Description != "changed" {
				return "description not replaced"
			}
			return ""
		}, ""},
	}
	for _, tc := range cases {
		s := memory.New()
		rt := &resourcetype.ResourceType{
			TenantID:    "t1",
			Name:        "document",
			Description: "orig",
			Relations:   []resourcetype.RelationDef{{Name: "viewer", AllowedSubjects: []string{"user"}}},
			Permissions: []resourcetype.PermissionDef{{Name: "read", Expression: "viewer"}},
		}
		if err := s.CreateResourceType(ctx, rt); err != nil {
			t.Fatalf("create: %v", err)
		}
		in := tc.in
		in.ID = rt.ID.String()
		if _, err := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})(ctx, in, principalFor("t1")); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		after, err := s.GetResourceType(ctx, "t1", rt.ID)
		if err != nil {
			t.Fatalf("%s: get: %v", tc.name, err)
		}
		if msg := tc.check(after); msg != "" {
			t.Errorf("%s: %s: %+v", tc.name, msg, after)
		}
	}
}

func TestResourceTypesUpdateCanClearTheDescription(t *testing.T) {
	// A pointer to "" means "set it to empty", distinct from nil.
	s := memory.New()
	ctx := context.Background()
	rt := &resourcetype.ResourceType{TenantID: "t1", Name: "document", Description: "old"}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	empty := ""
	if _, err := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Description: &empty}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.update: %v", err)
	}
	after, _ := s.GetResourceType(ctx, "t1", rt.ID)
	if after.Description != "" {
		t.Errorf("description = %q, want cleared", after.Description)
	}
}

func TestResourceTypesUpdateValidatesReplacedExpressions(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "document")
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})

	bad := []PermissionDefDTO{{Name: "read", Expression: "viewer or or editor"}}
	_, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Permissions: &bad}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if d := diagnosticsOf(t, ce); len(d) == 0 || d[0].Col != 11 {
		t.Errorf("diagnostics = %+v, want the parse error at column 11", d)
	}
	after, getErr := s.GetResourceType(ctx, "t1", rt.ID)
	if getErr != nil {
		t.Fatalf("get: %v", getErr)
	}
	if after.Permissions[0].Expression != "viewer" {
		t.Errorf("the refused update changed the stored expression to %q", after.Permissions[0].Expression)
	}
}

func TestResourceTypesUpdateChecksNewExpressionsAgainstTheStoredRelations(t *testing.T) {
	// Replacing only the permissions must still check them against the
	// relations already on the type, which the request does not carry.
	s := memory.New()
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "document") // declares viewer only
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})

	ghost := []PermissionDefDTO{{Name: "read", Expression: "viewer or ghost"}}
	_, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Permissions: &ghost}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !containsText(ce.Message, "ghost") {
		t.Errorf("message %q does not name ghost", ce.Message)
	}
	after, _ := s.GetResourceType(ctx, "t1", rt.ID)
	if after.Permissions[0].Expression != "viewer" {
		t.Errorf("the refused update changed the stored expression to %q", after.Permissions[0].Expression)
	}
}

func TestResourceTypesUpdateChecksStoredExpressionsAgainstNewRelations(t *testing.T) {
	// The other direction: dropping a relation an existing permission still
	// names would strand that permission, so it is refused.
	s := memory.New()
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "document") // read = viewer
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})

	renamed := []RelationDefDTO{{Name: "reader", AllowedSubjects: []string{"user"}}}
	_, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Relations: &renamed}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeBadRequest)
	if !containsText(ce.Message, "viewer") || !containsText(ce.Message, "read") {
		t.Errorf("message %q should name the stranded relation and permission", ce.Message)
	}
	after, _ := s.GetResourceType(ctx, "t1", rt.ID)
	if after.Relations[0].Name != "viewer" {
		t.Errorf("the refused update changed the stored relations: %+v", after.Relations)
	}

	// Replacing both lists together resolves it.
	perms := []PermissionDefDTO{{Name: "read", Expression: "reader"}}
	if _, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Relations: &renamed, Permissions: &perms}, principalFor("t1")); err != nil {
		t.Fatalf("a consistent pair was refused: %v", err)
	}
}

func TestResourceTypesUpdateOfDescriptionIsNotBlockedByAnOldBadExpression(t *testing.T) {
	// A type written before validation existed may hold an expression that
	// never parsed. Editing its description touches no definition, so it
	// must not be refused for one.
	s := memory.New()
	ctx := context.Background()
	rt := &resourcetype.ResourceType{
		TenantID:    "t1",
		Name:        "legacy",
		Permissions: []resourcetype.PermissionDef{{Name: "read", Expression: "viewer or or editor"}},
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create: %v", err)
	}
	desc := "still editable"
	if _, err := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Description: &desc}, principalFor("t1")); err != nil {
		t.Fatalf("a description-only update was refused: %v", err)
	}
	after, _ := s.GetResourceType(ctx, "t1", rt.ID)
	if after.Description != "still editable" || after.Permissions[0].Expression != "viewer or or editor" {
		t.Errorf("after = %+v", after)
	}
}

func TestResourceTypesUpdateCanEmptyTheDefinitions(t *testing.T) {
	// A pointer to an empty slice means "remove them all", distinct from
	// nil meaning "leave them alone". Without the pointer there is no way
	// to clear a definition list from the UI.
	ctx := context.Background()

	s := memory.New()
	rt := seedResourceType(t, s, "", "document")
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})
	empty := []PermissionDefDTO{}
	if _, err := h(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Permissions: &empty}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.update: %v", err)
	}
	after, err := s.GetResourceType(ctx, "t1", rt.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(after.Permissions) != 0 {
		t.Errorf("permissions = %+v, want cleared", after.Permissions)
	}
	if len(after.Relations) != 1 {
		t.Errorf("clearing permissions also touched relations: %+v", after.Relations)
	}

	// Relations can be emptied too, once no permission needs them.
	s2 := memory.New()
	rt2 := seedResourceType(t, s2, "", "document")
	h2 := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s2)})
	noRels, noPerms := []RelationDefDTO{}, []PermissionDefDTO{}
	if _, err := h2(ctx, ResourceTypeUpdateInput{ID: rt2.ID.String(), Relations: &noRels, Permissions: &noPerms}, principalFor("t1")); err != nil {
		t.Fatalf("clearing both: %v", err)
	}
	after2, _ := s2.GetResourceType(ctx, "t1", rt2.ID)
	if len(after2.Relations) != 0 || len(after2.Permissions) != 0 {
		t.Errorf("after = %+v, want both cleared", after2)
	}
}

func TestResourceTypesUpdateRefusesAnotherTenantsTypeAndABadID(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	other := &resourcetype.ResourceType{TenantID: "t2", Name: "theirs"}
	if err := s.CreateResourceType(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesUpdateHandler(Deps{Engine: engineOver(t, s)})
	desc := "hijacked"

	_, err := h(ctx, ResourceTypeUpdateInput{ID: other.ID.String(), Description: &desc}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeNotFound)
	after, _ := s.GetResourceType(ctx, "t2", other.ID)
	if after.Description != "" {
		t.Errorf("t1 changed t2's type: %+v", after)
	}
	_, err = h(ctx, ResourceTypeUpdateInput{ID: "not-an-id", Description: &desc}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeBadRequest)
}

func TestResourceTypesDeleteRefusesWhileTuplesReferenceIt(t *testing.T) {
	// Deleting a type whose tuples still exist leaves those tuples
	// referencing a schema that is gone, and the graph walker then cannot
	// resolve any derived permission through them. Refuse and say how many.
	s := memory.New()
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "document")
	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")
	seedTuple(t, s, "", "document", "spec", "viewer", "user", "bob")
	h := resourceTypesDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, ResourceTypeDeleteInput{ID: rt.ID.String()}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeConflict)
	if !containsText(ce.Message, "2 relation tuples") || !containsText(ce.Message, "document") {
		t.Errorf("message %q should name the count and the type", ce.Message)
	}
	if _, getErr := s.GetResourceType(ctx, "t1", rt.ID); getErr != nil {
		t.Errorf("the refusal did not prevent the delete: %v", getErr)
	}
}

func TestResourceTypesDeleteRemovesAnUnreferencedType(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "orphan")
	keep := seedResourceType(t, s, "", "keep")
	h := resourceTypesDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, ResourceTypeDeleteInput{ID: rt.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.delete: %v", err)
	}
	if _, err := s.GetResourceType(ctx, "t1", rt.ID); err == nil {
		t.Fatal("the type is still there")
	}
	if _, err := s.GetResourceType(ctx, "t1", keep.ID); err != nil {
		t.Errorf("the delete removed a different type: %v", err)
	}
}

func TestResourceTypesDeleteOnlyCountsTuplesThatUseThisType(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	eng := seedResourceType(t, s, "eng", "document")
	// None of these are tuples of eng's "document".
	seedTuple(t, s, "eng", "folder", "root", "viewer", "user", "alice")        // another object type
	seedTuple(t, s, "eng", "group", "ops", "member", "document", "readme")     // document only as the SUBJECT
	seedTuple(t, s, "sales", "document", "deck", "viewer", "user", "alice")    // an unrelated namespace
	seedTuple(t, s, "engineering", "document", "x", "viewer", "user", "alice") // shares a string prefix, not a namespace
	other := &relation.Tuple{
		TenantID: "t2", NamespacePath: "eng", ObjectType: "document", ObjectID: "theirs",
		Relation: "viewer", SubjectType: "user", SubjectID: "bob",
	}
	if err := s.CreateRelation(ctx, other); err != nil { // another tenant's
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, ResourceTypeDeleteInput{ID: eng.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("a type nothing uses was refused: %v", err)
	}
}

func TestResourceTypesDeleteCountsTuplesInDescendantNamespaces(t *testing.T) {
	// A type at eng answers for tuples at eng and below it, because roles,
	// permissions and types resolve up the ancestor chain.
	s := memory.New()
	ctx := context.Background()
	eng := seedResourceType(t, s, "eng", "document")
	seedTuple(t, s, "eng/platform", "document", "readme", "viewer", "user", "alice")
	h := resourceTypesDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, ResourceTypeDeleteInput{ID: eng.ID.String()}, principalFor("t1"))
	ce := refusal(t, err, dashcontract.CodeConflict)
	if !containsText(ce.Message, "1 relation tuples") {
		t.Errorf("message %q should count the descendant's tuple", ce.Message)
	}
}

func TestResourceTypesDeleteRefusesAnotherTenantsTypeAndABadID(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	other := &resourcetype.ResourceType{TenantID: "t2", Name: "theirs"}
	if err := s.CreateResourceType(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := resourceTypesDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, ResourceTypeDeleteInput{ID: other.ID.String()}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeNotFound)
	if _, getErr := s.GetResourceType(ctx, "t2", other.ID); getErr != nil {
		t.Errorf("t1 deleted t2's type: %v", getErr)
	}
	_, err = h(ctx, ResourceTypeDeleteInput{ID: "not-an-id"}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeBadRequest)
}

func TestResourceTypeCommandsEmitAudit(t *testing.T) {
	// The plugin registry has no typed resource type hook, so the audit event
	// is the only signal. It is enough: the cache invalidator flushes the
	// tenant on any audit event, and a schema change alters what the graph
	// walker derives.
	s := memory.New()
	eng, probe := probedEngine(t, s)
	deps := Deps{Engine: eng}
	ctx := context.Background()

	ack, err := resourceTypesCreateHandler(deps)(ctx, ResourceTypeCreateInput{Name: "document"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.create: %v", err)
	}
	cr := probe.event(t, "resourcetype.created")
	if cr.Actor != wantActor || cr.TenantID != "t1" || cr.EntityID != ack.ID || cr.At.IsZero() {
		t.Errorf("create event = %+v", cr)
	}
	if e, ok := cr.Entity.(*resourcetype.ResourceType); !ok || e.Name != "document" {
		t.Errorf("create Entity = %#v", cr.Entity)
	}
	if probe.ctxActor != wantActor {
		t.Errorf("the context reaching the create hooks carries actor %+v, want %+v", probe.ctxActor, wantActor)
	}

	desc := "a document"
	if _, err := resourceTypesUpdateHandler(deps)(ctx, ResourceTypeUpdateInput{ID: ack.ID, Description: &desc}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.update: %v", err)
	}
	up := probe.event(t, "resourcetype.updated")
	before, ok := up.Before.(*resourcetype.ResourceType)
	if !ok || before.Description != "" {
		t.Errorf("update Before = %#v, want the pre-update type with no description", up.Before)
	}
	if after, ok := up.Entity.(*resourcetype.ResourceType); !ok || after.Description != "a document" || after.UpdatedBy != "tester" {
		t.Errorf("update Entity = %#v, want the updated type stamped tester", up.Entity)
	}
	if up.Actor != wantActor || up.TenantID != "t1" || up.EntityID != ack.ID {
		t.Errorf("update event = %+v", up)
	}

	if _, err := resourceTypesDeleteHandler(deps)(ctx, ResourceTypeDeleteInput{ID: ack.ID}, principalFor("t1")); err != nil {
		t.Fatalf("resourceTypes.delete: %v", err)
	}
	del := probe.event(t, "resourcetype.deleted")
	if del.Actor != wantActor || del.TenantID != "t1" || del.EntityID != ack.ID || del.Before == nil {
		t.Errorf("delete event = %+v", del)
	}
	if probe.ctxActor != wantActor {
		t.Errorf("the context reaching the delete hooks carries actor %+v, want %+v", probe.ctxActor, wantActor)
	}
}

func TestResourceTypeRefusedWritesEmitNothing(t *testing.T) {
	// A refused write changed nothing, so it must not tell the audit trail
	// or the cache invalidator that something did.
	s := memory.New()
	eng, probe := probedEngine(t, s)
	deps := Deps{Engine: eng}
	ctx := context.Background()
	rt := seedResourceType(t, s, "", "document")
	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")

	bad := []PermissionDefDTO{{Name: "read", Expression: "or"}}
	_, _ = resourceTypesCreateHandler(deps)(ctx, ResourceTypeCreateInput{Name: "x", Permissions: bad}, principalFor("t1"))
	_, _ = resourceTypesUpdateHandler(deps)(ctx, ResourceTypeUpdateInput{ID: rt.ID.String(), Permissions: &bad}, principalFor("t1"))
	_, _ = resourceTypesDeleteHandler(deps)(ctx, ResourceTypeDeleteInput{ID: rt.ID.String()}, principalFor("t1"))

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.events) != 0 {
		t.Errorf("refused writes emitted %v", probe.actionsLocked())
	}
}
