package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	"github.com/xraph/warden/dsl"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// schemaReads are the five grants the schema intents need: read on
// warden:role through the manifest gate, and the other four through the
// handler.
var schemaReads = []string{
	"warden:role:read", "warden:permission:read", "warden:policy:read",
	"warden:resourcetype:read", "warden:relation:read",
}

// schemaManages are the five manage grants schema.apply needs, in the order a
// refusal names them.
var schemaManages = []string{
	"warden:role:manage", "warden:permission:manage", "warden:policy:manage",
	"warden:resourcetype:manage", "warden:relation:manage",
}

// schemaHarness runs the three handlers as a t1 user who holds every read
// and every manage.
type schemaHarness struct {
	t    *testing.T
	s    *memory.Store
	deps Deps
}

func newSchemaHarness(t *testing.T, s *memory.Store) *schemaHarness {
	t.Helper()
	// The caller's reads come from an ABAC policy, not from roles, so the
	// exported store holds no role or permission the tests below did not
	// seed themselves. The dsl carries the policy's subject list, and the
	// plan compares it. The grants test below uses the five literal role
	// grants.
	seedPolicy(t, s, "", "caller-reads-warden", func(p *policy.Policy) {
		p.Subjects = []policy.SubjectMatch{{Kind: "user", ID: "tester"}}
		p.Actions = []string{"read", "manage"}
		p.Resources = []string{"warden:*"}
	})
	return &schemaHarness{t: t, s: s, deps: Deps{Engine: engineOver(t, s)}}
}

func (h *schemaHarness) export(in SchemaExportInput) SchemaExportResponse {
	h.t.Helper()
	got, err := schemaExportHandler(h.deps)(context.Background(), in, principalFor("t1"))
	if err != nil {
		h.t.Fatalf("schema.export: %v", err)
	}
	return got
}

func (h *schemaHarness) plan(src string, prune bool) SchemaPlanResponse {
	h.t.Helper()
	got, err := schemaPlanHandler(h.deps)(context.Background(), SchemaPlanInput{Source: src, Prune: prune}, principalFor("t1"))
	if err != nil {
		h.t.Fatalf("schema.plan: %v", err)
	}
	return got
}

func (h *schemaHarness) applyRaw(src string, prune bool, digest string) (SchemaApplyResponse, error) {
	h.t.Helper()
	return schemaApplyHandler(h.deps)(context.Background(), SchemaApplyInput{Source: src, Prune: prune, Digest: digest}, principalFor("t1"))
}

// apply plans src, then applies it with that plan's digest.
func (h *schemaHarness) apply(src string, prune bool) (SchemaPlanResponse, SchemaApplyResponse) {
	h.t.Helper()
	plan := h.plan(src, prune)
	if !plan.Valid {
		h.t.Fatalf("setup: the source does not plan: %+v", plan.Diagnostics)
	}
	got, err := h.applyRaw(src, prune, plan.Digest)
	if err != nil {
		h.t.Fatalf("schema.apply: %v", err)
	}
	return plan, got
}

// seedSchemaWorld stores one of every exported kind, each with populated
// fields, in tenant t1, at the tenant root and again in the eng namespace,
// so the round trip also proves Format keeps namespaces.
func seedSchemaWorld(t *testing.T, s *memory.Store) {
	t.Helper()
	ctx := context.Background()

	viewer := &role.Role{TenantID: "t1", Name: "Viewer", Slug: "viewer", Description: "reads documents"}
	if err := s.CreateRole(ctx, viewer); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	editor := &role.Role{TenantID: "t1", Name: "Editor", Slug: "editor", ParentSlug: "viewer", MaxMembers: 5}
	if err := s.CreateRole(ctx, editor); err != nil {
		t.Fatalf("create editor: %v", err)
	}
	grantPermission(t, s, "t1", viewer, "document:read")
	grantPermission(t, s, "t1", editor, "document:write")

	seedPolicy(t, s, "", "business-hours", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Priority = 10
		p.Description = "no writes outside the office"
		p.Actions = []string{"write"}
		p.Resources = []string{"document"}
		p.Conditions = []policy.Condition{
			{Field: "context.network", Operator: policy.OpEquals, Value: "external"},
			{Field: "subject.department", Operator: policy.OpIn, Value: []any{"eng", "ops"}},
		}
	})

	rt := &resourcetype.ResourceType{
		TenantID:    "t1",
		Name:        "document",
		Description: "a shared document",
		Relations: []resourcetype.RelationDef{
			{Name: "owner", AllowedSubjects: []string{"user"}},
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
		},
		Permissions: []resourcetype.PermissionDef{
			{Name: "read", Expression: "viewer or owner"},
		},
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("create resource type: %v", err)
	}

	seedTuple(t, s, "", "document", "readme", "viewer", "user", "alice")
	seedTuple(t, s, "", "document", "readme", "viewer", "group", "eng")

	// The eng namespace: one of each kind again, with a permission the
	// dashboard's own grants use (a colon in its resource) granted to an
	// eng role.
	if err := s.CreatePermission(ctx, &permission.Permission{
		TenantID: "t1", NamespacePath: "eng", Name: "warden:role:read", Resource: "warden:role", Action: "read",
		Description: "see roles",
	}); err != nil {
		t.Fatalf("create eng permission: %v", err)
	}
	lead := &role.Role{TenantID: "t1", NamespacePath: "eng", Name: "Lead", Slug: "lead", IsDefault: true}
	if err := s.CreateRole(ctx, lead); err != nil {
		t.Fatalf("create eng role: %v", err)
	}
	if err := s.SetRolePermissions(ctx, "t1", lead.ID, []permission.Ref{
		{NamespacePath: "eng", Name: "warden:role:read"},
		{NamespacePath: "", Name: "document:read"},
	}); err != nil {
		t.Fatalf("grant eng role: %v", err)
	}
	seedPolicy(t, s, "eng", "eng-only", func(p *policy.Policy) {
		p.Subjects = []policy.SubjectMatch{{Kind: "user", Role: "lead"}, {ID: "bob"}}
		p.Actions = []string{"read"}
		p.Resources = []string{"document"}
	})
	if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{
		TenantID: "t1", NamespacePath: "eng", Name: "runbook",
		Relations:   []resourcetype.RelationDef{{Name: "owner", AllowedSubjects: []string{"user"}}},
		Permissions: []resourcetype.PermissionDef{{Name: "edit", Expression: "owner"}},
	}); err != nil {
		t.Fatalf("create eng resource type: %v", err)
	}
	seedTuple(t, s, "eng", "runbook", "deploys", "owner", "user", "bob")
}

func TestSchemaExportRoundTripsToAnEmptyPlan(t *testing.T) {
	s := memory.New()
	seedSchemaWorld(t, s)
	h := newSchemaHarness(t, s)

	exported := h.export(SchemaExportInput{})
	for _, want := range []string{"role viewer", "role editor", "document:write", "business-hours", "resource document", "viewer or owner", "relation document:readme", `namespace "eng" {`, "role lead", `resource = "warden:role"`, `{ kind = "user", role = "lead" }`} {
		if !strings.Contains(exported.Source, want) {
			t.Fatalf("the export lacks %q:\n%s", want, exported.Source)
		}
	}

	for _, prune := range []bool{false, true} {
		plan := h.plan(exported.Source, prune)
		if !plan.Valid || len(plan.Diagnostics) != 0 {
			t.Fatalf("prune=%v: the export is not valid source: %+v\n%s", prune, plan.Diagnostics, exported.Source)
		}
		if len(plan.Created) != 0 || len(plan.Updated) != 0 || len(plan.Deleted) != 0 {
			t.Errorf("prune=%v: planning an export against its own store is not empty: created %v updated %v deleted %v\n%s",
				prune, plan.Created, plan.Updated, plan.Deleted, exported.Source)
		}
	}
}

func TestSchemaExportNamespacePrefixExcludesWhatIsOutsideIt(t *testing.T) {
	s := memory.New()
	seedRoles(t, s, "", "root-only")
	seedRoles(t, s, "eng", "eng-lead")
	seedRoles(t, s, "eng/platform", "platform-lead")
	seedRoles(t, s, "engineering", "lookalike")
	h := newSchemaHarness(t, s)

	got := h.export(SchemaExportInput{NamespacePrefix: "eng"})
	for _, want := range []string{"eng-lead", "platform-lead"} {
		if !strings.Contains(got.Source, want) {
			t.Errorf("the eng export lacks %q:\n%s", want, got.Source)
		}
	}
	for _, unwanted := range []string{"root-only", "lookalike"} {
		if strings.Contains(got.Source, unwanted) {
			t.Errorf("the eng export contains %q, which is outside the namespace:\n%s", unwanted, got.Source)
		}
	}

	all := h.export(SchemaExportInput{})
	if !strings.Contains(all.Source, "root-only") {
		t.Errorf("an export with no prefix lacks the root role:\n%s", all.Source)
	}
}

// storeSnapshot captures every entity kind in tenant t1, in full, so a test
// can prove a call changed nothing rather than merely kept the counts.
func storeSnapshot(t *testing.T, s *memory.Store) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	put := func(kind string, v any, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("list %s: %v", kind, err)
		}
		raw, mErr := json.Marshal(v)
		if mErr != nil {
			t.Fatalf("marshal %s: %v", kind, mErr)
		}
		out[kind] = string(raw)
	}
	const limit = 10000
	roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: limit})
	put("roles", roles, err)
	grants := map[string][]string{}
	for _, r := range roles {
		ps, gErr := s.ListRolePermissions(ctx, "t1", r.ID)
		if gErr != nil {
			t.Fatalf("list grants: %v", gErr)
		}
		for _, p := range ps {
			grants[r.Slug] = append(grants[r.Slug], p.Name)
		}
		sort.Strings(grants[r.Slug])
	}
	raw, _ := json.Marshal(grants)
	out["grants"] = string(raw)
	perms, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", Limit: limit})
	put("permissions", perms, err)
	pols, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: "t1", Limit: limit})
	put("policies", pols, err)
	rts, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: "t1", Limit: limit})
	put("resource types", rts, err)
	tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", Limit: limit})
	put("relations", tuples, err)
	asgs, err := s.ListAssignments(ctx, &assignment.ListFilter{TenantID: "t1", Limit: limit})
	put("assignments", asgs, err)
	return out
}

func TestSchemaPlanReportsAddedAndChangedLinesAndWritesNothing(t *testing.T) {
	s := memory.New()
	seedPermission(t, s, "doc:read", "doc", "read")
	seedPermission(t, s, "doc:write", "doc", "write")
	seedRoles(t, s, "", "viewer")
	h := newSchemaHarness(t, s)

	before := storeSnapshot(t, s)

	src := `warden config 1
tenant t1

permission "doc:read" {
    resource = doc
    action = read
    description = "read a document"
}
permission "doc:write" (doc : write)

role viewer {
    name = "viewer"
}

role auditor {
    name = "Auditor"
}
`
	plan := h.plan(src, false)
	if !plan.Valid || len(plan.Diagnostics) != 0 {
		t.Fatalf("diagnostics: %+v", plan.Diagnostics)
	}
	if !reflect.DeepEqual(plan.Created, []string{"+ role//auditor"}) {
		t.Errorf("created = %v, want [+ role//auditor]", plan.Created)
	}
	if !reflect.DeepEqual(plan.Updated, []string{"~ permission//doc:read (description)"}) {
		t.Errorf("updated = %v, want [~ permission//doc:read (description)]", plan.Updated)
	}
	if len(plan.Deleted) != 0 {
		t.Errorf("deleted = %v, want none without prune", plan.Deleted)
	}
	if plan.NoOps <= 0 {
		t.Errorf("noOps = %d, want the unchanged permission and role counted", plan.NoOps)
	}
	if plan.Digest == "" {
		t.Error("a valid plan carries no digest")
	}

	if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
		for k := range before {
			if before[k] != after[k] {
				t.Errorf("a plan changed the store: %s was %s, now %s", k, before[k], after[k])
			}
		}
	}
}

func TestSchemaPlanPruneDeletesOnlyInNamespacesTheSourceCovers(t *testing.T) {
	s := memory.New()
	seedRoles(t, s, "", "kept-root", "dropped-root")
	seedRoles(t, s, "eng", "kept-eng", "dropped-eng")
	seedRoles(t, s, "ops", "untouched-ops")
	h := newSchemaHarness(t, s)

	src := `warden config 1
tenant t1

role kept-root {
    name = "KEPT-ROOT"
}

namespace "eng" {
    role kept-eng {
        name = "KEPT-ENG"
    }
}
`
	without := h.plan(src, false)
	if !without.Valid || len(without.Deleted) != 0 {
		t.Fatalf("a plan without prune deletes nothing, got %+v", without)
	}

	got := h.plan(src, true)
	if !got.Valid {
		t.Fatalf("diagnostics: %+v", got.Diagnostics)
	}
	deleted := strings.Join(got.Deleted, "\n")
	for _, want := range []string{"- role//dropped-root", "- role/eng/dropped-eng"} {
		if !strings.Contains(deleted, want) {
			t.Errorf("deleted lacks %q: %v", want, got.Deleted)
		}
	}
	if strings.Contains(deleted, "untouched-ops") {
		t.Errorf("deleted names a role in a namespace the source does not mention: %v", got.Deleted)
	}
	if strings.Contains(deleted, "kept-") {
		t.Errorf("deleted names a declared role: %v", got.Deleted)
	}
	// The caller's own grant is a policy, caller-reads-warden, at the root,
	// which the source covers and does not declare, so it is listed too.
	// Nothing in ops may be.
	for _, line := range got.Deleted {
		if strings.Contains(line, "/ops/") {
			t.Errorf("deleted names something in ops: %s", line)
		}
	}
}

func TestSchemaPlanDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		// want is the expected message; wantContains is used when the exact
		// text belongs to the dsl.
		want         string
		wantContains string
		line, col    int
	}{
		{
			name:         "a syntax error",
			src:          "warden config 1\n\nrole {\n}\n",
			wantContains: "role slug",
			line:         3, col: 6,
		},
		{
			name:         "a reference the resolver rejects",
			src:          "warden config 1\n\nrole child : ghost {\n}\n",
			wantContains: "ghost",
			line:         3, col: 1,
		},
		{
			name: "an import",
			src:  "warden config 1\n\nimport \"x.warden\"\n",
			want: "imports are not supported here: paste the imported source instead",
			line: 3, col: 1,
		},
		{
			name: "an app",
			src:  "\nwarden config 1\napp billing\n",
			want: `this source names app "billing"; the dashboard does not set an app: remove the declaration`,
			line: 2, col: 1,
		},
		{
			name: "a tenant that is not the caller's",
			src:  "\n\nwarden config 1\ntenant other\n",
			want: `this source names tenant "other"; the dashboard applies to your tenant only`,
			// Program keeps no position for the tenant line, so the header's.
			line: 3, col: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			seedRoles(t, s, "", "existing")
			h := newSchemaHarness(t, s)

			for _, prune := range []bool{false, true} {
				got := h.plan(tc.src, prune)
				if got.Valid {
					t.Fatalf("prune=%v: a source with %s is valid", prune, tc.name)
				}
				if len(got.Created) != 0 || len(got.Updated) != 0 || len(got.Deleted) != 0 || got.NoOps != 0 || got.Digest != "" {
					t.Errorf("prune=%v: an invalid plan carries a diff: %+v", prune, got)
				}
				if got.Created == nil || got.Updated == nil || got.Deleted == nil || got.Diagnostics == nil {
					t.Errorf("prune=%v: lists must marshal as [] not null: %+v", prune, got)
				}
				if len(got.Diagnostics) == 0 {
					t.Fatalf("prune=%v: no diagnostics", prune)
				}
				d := got.Diagnostics[0]
				if d.Line != tc.line || d.Col != tc.col {
					t.Errorf("prune=%v: position = %d:%d, want %d:%d (%q)", prune, d.Line, d.Col, tc.line, tc.col, d.Message)
				}
				if tc.want != "" && d.Message != tc.want {
					t.Errorf("prune=%v: message = %q, want %q", prune, d.Message, tc.want)
				}
				if tc.wantContains != "" && !strings.Contains(d.Message, tc.wantContains) {
					t.Errorf("prune=%v: message = %q, want it to contain %q", prune, d.Message, tc.wantContains)
				}
			}
		})
	}
}

func TestSchemaPlanDiagnosticsMatchTheDslPositionForPositionAndMessage(t *testing.T) {
	// The wire diagnostic is the dsl's own: same line, same column, same text.
	for _, src := range []string{
		"warden config 1\n\nrole {\n}\n",
		"warden config 1\nrole a : b {\n}\n",
		"warden config 1\n\n  permission 5\n",
	} {
		_, want := dsl.Parse("schema.warden", []byte(src))
		if len(want) == 0 {
			prog, _ := dsl.Parse("schema.warden", []byte(src))
			want = dsl.Resolve(prog)
		}
		if len(want) == 0 {
			t.Fatalf("%q: the dsl reports nothing, pick a source it rejects", src)
		}
		_, got := checkSource(src, "t1")
		if len(got) != len(want) {
			t.Fatalf("%q: %d diagnostics, dsl has %d: %+v vs %v", src, len(got), len(want), got, want)
		}
		for i := range want {
			if got[i].Line != want[i].Pos.Line || got[i].Col != want[i].Pos.Col || got[i].Message != want[i].Msg {
				t.Errorf("%q #%d: got %+v, dsl has %d:%d %q", src, i, got[i], want[i].Pos.Line, want[i].Pos.Col, want[i].Msg)
			}
		}
	}
}

func TestSchemaPlanRefusesAVariablePlaceholderAtItsPosition(t *testing.T) {
	// The lexer has no `$`: it returns ILLEGAL for it, so a `${NAME}`
	// placeholder is refused where it stands. Substitution belongs to the
	// file loader, which the dashboard never runs.
	s := memory.New()
	h := newSchemaHarness(t, s)
	got := h.plan("warden config 1\n\nrole ${NAME} {\n}\n", false)
	if got.Valid || len(got.Diagnostics) == 0 {
		t.Fatalf("a ${NAME} placeholder was accepted: %+v", got)
	}
	d := got.Diagnostics[0]
	if d.Line != 3 || d.Col != 6 {
		t.Errorf("position = %d:%d, want 3:6, where the `$` stands (%q)", d.Line, d.Col, d.Message)
	}
	var lexer bool
	for _, x := range got.Diagnostics {
		if x.Message == "lexer error: $" && x.Line == 3 && x.Col == 6 {
			lexer = true
		}
	}
	if !lexer {
		t.Errorf("no %q diagnostic at 3:6: %+v", "lexer error: $", got.Diagnostics)
	}
}

func TestSchemaPlanAcceptsTheCallersOwnTenantInTheHeader(t *testing.T) {
	s := memory.New()
	h := newSchemaHarness(t, s)
	got := h.plan("warden config 1\ntenant t1\n\nrole a {\n}\n", false)
	if !got.Valid {
		t.Fatalf("a source naming the caller's tenant was refused: %+v", got.Diagnostics)
	}
}

func TestSchemaPlanAppliesToTheCallersTenantNotTheHeaders(t *testing.T) {
	// No tenant line: the plan must still be scoped to t1, never to the
	// empty tenant that matches every row.
	s := memory.New()
	seedRoles(t, s, "", "mine")
	h := newSchemaHarness(t, s)
	got := h.plan("warden config 1\n\nrole mine {\n    name = \"mine\"\n}\n", true)
	if !got.Valid {
		t.Fatalf("diagnostics: %+v", got.Diagnostics)
	}
	if len(got.Created) != 0 || len(got.Updated) != 0 {
		t.Errorf("a source with no tenant line planned against the wrong scope: %+v", got)
	}
}

func TestSchemaPlanDigest(t *testing.T) {
	src := "warden config 1\n\nrole fresh {\n    name = \"Fresh\"\n}\n"

	t.Run("the same source and prune give the same digest", func(t *testing.T) {
		s := memory.New()
		seedRoles(t, s, "", "extra")
		h := newSchemaHarness(t, s)
		a, b := h.plan(src, true), h.plan(src, true)
		if a.Digest == "" || a.Digest != b.Digest {
			t.Errorf("digests %q and %q, want equal and non-empty", a.Digest, b.Digest)
		}
		if len(a.Digest) != 64 {
			t.Errorf("digest %q is not hex SHA-256", a.Digest)
		}
	})

	t.Run("flipping prune changes it", func(t *testing.T) {
		// Planning an export of the store gives an empty diff either way, so
		// only the flag differs between the two plans.
		s := memory.New()
		h := newSchemaHarness(t, s)
		exported := h.export(SchemaExportInput{})
		plain, pruned := h.plan(exported.Source, false), h.plan(exported.Source, true)
		if len(plain.Created)+len(plain.Updated)+len(plain.Deleted) != 0 || len(pruned.Deleted) != 0 {
			t.Fatalf("setup: the export plans a diff: %+v %+v", plain, pruned)
		}
		if plain.Digest == "" || plain.Digest == pruned.Digest {
			t.Errorf("prune=false and prune=true give digests %q and %q for an identical diff", plain.Digest, pruned.Digest)
		}
	})

	t.Run("a store change that alters the diff changes it", func(t *testing.T) {
		s := memory.New()
		h := newSchemaHarness(t, s)
		before := h.plan(src, false)
		if len(before.Created) != 1 {
			t.Fatalf("setup: want one created line, got %+v", before)
		}
		seedRoles(t, s, "", "fresh")
		after := h.plan(src, false)
		if len(after.Created) != 0 {
			t.Fatalf("setup: the role exists now, created = %v", after.Created)
		}
		if before.Digest == after.Digest {
			t.Errorf("the diff changed from %v to %v but the digest stayed %q", before.Created, after.Created, before.Digest)
		}
	})

	t.Run("a different diff gives a different digest", func(t *testing.T) {
		s := memory.New()
		h := newSchemaHarness(t, s)
		a := h.plan(src, false)
		b := h.plan("warden config 1\n\nrole other {\n}\n", false)
		if a.Digest == b.Digest {
			t.Errorf("two different diffs share digest %q", a.Digest)
		}
	})
}

func TestPlanDigestIsUnambiguousAcrossListBoundaries(t *testing.T) {
	// Length prefixes: moving a line from one list to the next must change
	// the digest.
	a := planDigest(false, &dsl.ApplyResult{Created: []string{"x"}, Updated: []string{"y"}})
	b := planDigest(false, &dsl.ApplyResult{Created: []string{"x", "y"}})
	c := planDigest(false, &dsl.ApplyResult{Created: []string{"xy"}})
	if a == b || a == c || b == c {
		t.Errorf("digests collide across list boundaries: %s %s %s", a, b, c)
	}
	// Order inside a list does not matter: the diff is a set.
	d := planDigest(true, &dsl.ApplyResult{Created: []string{"b", "a"}, NoOps: 2})
	e := planDigest(true, &dsl.ApplyResult{Created: []string{"a", "b"}, NoOps: 2})
	if d != e {
		t.Errorf("the digest depends on list order: %s vs %s", d, e)
	}
	if planDigest(true, &dsl.ApplyResult{NoOps: 1}) == planDigest(true, &dsl.ApplyResult{NoOps: 2}) {
		t.Error("noOps is not in the digest")
	}
}

func TestSchemaIntentsNeedEveryReadGrant(t *testing.T) {
	type call func(deps Deps, p dashcontract.Principal) error
	calls := map[string]call{
		"schema.export": func(deps Deps, p dashcontract.Principal) error {
			_, err := schemaExportHandler(deps)(context.Background(), SchemaExportInput{}, p)
			return err
		},
		"schema.plan": func(deps Deps, p dashcontract.Principal) error {
			_, err := schemaPlanHandler(deps)(context.Background(), SchemaPlanInput{Source: "warden config 1\n"}, p)
			return err
		},
	}
	for intent, invoke := range calls {
		for _, missing := range schemaReads {
			t.Run(intent+" without "+missing, func(t *testing.T) {
				s := memory.New()
				var held []string
				for _, g := range schemaReads {
					if g != missing {
						held = append(held, g)
					}
				}
				grantUser(t, s, "tester", held...)
				err := invoke(Deps{Engine: engineOver(t, s)}, principalFor("t1"))
				ce := refusal(t, err, dashcontract.CodePermissionDenied)
				resource := strings.TrimSuffix(missing, ":read")
				want := fmt.Sprintf("missing permission read on %s", resource)
				if ce.Message != want {
					t.Errorf("message = %q, want %q", ce.Message, want)
				}
			})
		}
		t.Run(intent+" with every grant", func(t *testing.T) {
			s := memory.New()
			grantUser(t, s, "tester", schemaReads...)
			if err := invoke(Deps{Engine: engineOver(t, s)}, principalFor("t1")); err != nil {
				t.Fatalf("a caller holding every read was refused: %v", err)
			}
		})
	}
}

func TestSchemaIntentsNeverReachAnotherTenant(t *testing.T) {
	s := memory.New()
	seedSchemaWorld(t, s)

	ctx := context.Background()
	if err := s.CreateRole(ctx, &role.Role{TenantID: "t2", Name: "T2-SECRET-ROLE", Slug: "t2-secret-role"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePermission(ctx, &permission.Permission{TenantID: "t2", Name: "secretdoc:peek", Resource: "secretdoc", Action: "peek"}); err != nil {
		t.Fatal(err)
	}
	seedPolicyFor(t, s, "t2", "", "t2-secret-policy", nil)
	if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{TenantID: "t2", Name: "t2_secret_type"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t2", ObjectType: "vault", ObjectID: "t2-secret-object", Relation: "keyholder", SubjectType: "user", SubjectID: "mallory",
	}); err != nil {
		t.Fatal(err)
	}

	h := newSchemaHarness(t, s)
	out := h.export(SchemaExportInput{})
	for _, secret := range []string{"t2-secret", "secretdoc", "t2_secret", "mallory", "vault"} {
		if strings.Contains(out.Source, secret) {
			t.Errorf("the t1 export contains %q from another tenant:\n%s", secret, out.Source)
		}
	}

	// A prune plan that declares nothing of t2 must not list t2 for deletion
	// either: it is scoped to t1.
	plan := h.plan("warden config 1\n", true)
	for _, line := range plan.Deleted {
		if strings.Contains(line, "t2") || strings.Contains(line, "secretdoc") {
			t.Errorf("a t1 prune plan lists another tenant's entity: %s", line)
		}
	}
	if t2roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t2", Limit: 10}); err != nil || len(t2roles) != 1 {
		t.Errorf("t2 changed: %v %v", t2roles, err)
	}
}

func TestSchemaIntentsRefuseWithoutATenant(t *testing.T) {
	// The table-driven guard in handlers_tenant_test.go covers the same;
	// this pins the export's prefix path too, so a prefixed export cannot
	// reach the store with an empty tenant.
	eng := engineOver(t, memory.New())
	_, err := schemaExportHandler(Deps{Engine: eng})(context.Background(), SchemaExportInput{NamespacePrefix: "eng"}, signedInNoTenant())
	refusal(t, err, dashcontract.CodePermissionDenied)
	_, err = schemaPlanHandler(Deps{Engine: eng})(context.Background(), SchemaPlanInput{Source: "warden config 1\n"}, signedInNoTenant())
	refusal(t, err, dashcontract.CodePermissionDenied)
}

func TestSchemaPlanRefusesAGrantOfAnUnknownPermissionAtTheRole(t *testing.T) {
	s := memory.New()
	h := newSchemaHarness(t, s)

	src := "warden config 1\n\npermission \"doc:read\" (doc : read)\n\nrole typo {\n    name = \"Typo\"\n    grants = [\"doc:read\", \"nope:x\"]\n}\n"
	for _, prune := range []bool{false, true} {
		got := h.plan(src, prune)
		if got.Valid || len(got.Diagnostics) != 1 {
			t.Fatalf("prune=%v: a grant of a permission that does not exist was not a single diagnostic: %+v", prune, got)
		}
		d := got.Diagnostics[0]
		if d.Line != 5 || d.Col != 1 || d.Message != `role typo grants unknown permission "nope:x"` {
			t.Errorf("prune=%v: diagnostic = %+v, want 5:1 at the role", prune, d)
		}
		if len(got.Created) != 0 || len(got.Updated) != 0 || len(got.Deleted) != 0 || got.Digest != "" {
			t.Errorf("prune=%v: an invalid plan carries a diff: %+v", prune, got)
		}
	}
}

func TestSchemaPlanLetsANamespacedRoleGrantARootPermission(t *testing.T) {
	// The real apply looks in the role's namespace, then at the root. The
	// plan must accept what the apply accepts.
	const role = "namespace \"eng\" {\n    role lead {\n        name = \"lead\"\n        grants = [\"doc:read\"]\n    }\n}\n"

	t.Run("a root permission the source declares", func(t *testing.T) {
		h := newSchemaHarness(t, memory.New())
		got := h.plan("warden config 1\n\npermission \"doc:read\" (doc : read)\n\n"+role, false)
		if !got.Valid {
			t.Fatalf("diagnostics: %+v", got.Diagnostics)
		}
		if strings.Join(got.Created, "|") != "+ permission//doc:read|+ role/eng/lead" {
			t.Errorf("created = %v", got.Created)
		}
	})

	t.Run("a root permission only the store has", func(t *testing.T) {
		s := memory.New()
		seedPermission(t, s, "doc:read", "doc", "read")
		h := newSchemaHarness(t, s)
		got := h.plan("warden config 1\n\n"+role, false)
		if !got.Valid {
			t.Fatalf("diagnostics: %+v", got.Diagnostics)
		}
		if strings.Join(got.Created, "|") != "+ role/eng/lead" {
			t.Errorf("created = %v", got.Created)
		}
	})

	t.Run("a permission in a sibling namespace does not count", func(t *testing.T) {
		h := newSchemaHarness(t, memory.New())
		got := h.plan("warden config 1\n\nnamespace \"ops\" {\n    permission \"doc:read\" (doc : read)\n}\n\n"+role, false)
		if got.Valid || len(got.Diagnostics) != 1 || !strings.Contains(got.Diagnostics[0].Message, `grants unknown permission "doc:read"`) {
			t.Errorf("the real apply would refuse this, so the plan must: %+v", got)
		}
	})
}

// applySource adds a role and a permission, changes a permission's
// description and adds a policy and a relation, against the store
// seedApplyStore builds.
const applySource = `warden config 1
tenant t1

permission "doc:read" {
    resource = doc
    action = read
    description = "read a document"
}
permission "doc:write" (doc : write)
permission "doc:share" (doc : share)

role viewer {
    name = "viewer"
}

role auditor {
    name = "Auditor"
    grants = ["doc:read"]
}

policy "freeze" {
    effect = deny
    active = true
    actions = ["write"]
    resources = ["doc"]
}

relation doc:readme viewer = user:alice
`

func seedApplyStore(t *testing.T) *memory.Store {
	t.Helper()
	s := memory.New()
	seedPermission(t, s, "doc:read", "doc", "read")
	seedPermission(t, s, "doc:write", "doc", "write")
	seedRoles(t, s, "", "viewer")
	return s
}

func TestSchemaApplyWritesExactlyWhatWasPlanned(t *testing.T) {
	s := seedApplyStore(t)
	h := newSchemaHarness(t, s)

	plan, got := h.apply(applySource, false)
	if len(plan.Created) == 0 || len(plan.Updated) == 0 {
		t.Fatalf("setup: the plan changes too little to prove anything: %+v", plan)
	}
	if !reflect.DeepEqual(got.Created, plan.Created) || !reflect.DeepEqual(got.Updated, plan.Updated) ||
		!reflect.DeepEqual(got.Deleted, plan.Deleted) || got.NoOps != plan.NoOps {
		t.Errorf("apply reported %+v, the plan said created %v updated %v deleted %v noOps %d",
			got, plan.Created, plan.Updated, plan.Deleted, plan.NoOps)
	}
	if got.Created == nil || got.Updated == nil || got.Deleted == nil {
		t.Errorf("lists must marshal as [] not null: %+v", got)
	}

	ctx := context.Background()
	if _, err := s.GetRoleBySlug(ctx, "t1", "", "auditor"); err != nil {
		t.Errorf("the planned role was not written: %v", err)
	}
	if perm, err := s.GetPermissionByName(ctx, "t1", "", "doc:share"); err != nil || perm == nil {
		t.Errorf("the planned permission was not written: %v", err)
	}
	if perm, err := s.GetPermissionByName(ctx, "t1", "", "doc:read"); err != nil || perm.Description != "read a document" {
		t.Errorf("the planned description change was not written: %v %+v", err, perm)
	}
	if _, err := s.GetPolicyByName(ctx, "t1", "", "freeze"); err != nil {
		t.Errorf("the planned policy was not written: %v", err)
	}
	tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", ObjectType: "doc", Limit: 10})
	if err != nil || len(tuples) != 1 {
		t.Errorf("the planned relation was not written: %v %v", tuples, err)
	}

	// Nothing else moved: planning the same source again is now empty.
	again := h.plan(applySource, false)
	if len(again.Created)+len(again.Updated)+len(again.Deleted) != 0 {
		t.Errorf("a second plan still has work: %+v", again)
	}
}

func TestSchemaApplyWithPruneDeletesWhatWasPlanned(t *testing.T) {
	s := seedApplyStore(t)
	seedRoles(t, s, "", "stale")
	h := newSchemaHarness(t, s)

	src := "warden config 1\n\nrole viewer {\n    name = \"viewer\"\n}\n\npermission \"doc:read\" (doc : read)\npermission \"doc:write\" (doc : write)\n\npolicy \"caller-reads-warden\" {\n    effect = allow\n    active = true\n    actions = [\"read\", \"manage\"]\n    resources = [\"warden:*\"]\n}\n"
	_, got := h.apply(src, true)
	if !strings.Contains(strings.Join(got.Deleted, "|"), "- role//stale") {
		t.Fatalf("deleted = %v, want the stale role", got.Deleted)
	}
	if _, err := s.GetRoleBySlug(context.Background(), "t1", "", "stale"); err == nil {
		t.Error("the stale role survived an applied prune")
	}
}

func TestSchemaApplyRefusesAStalePlanAndWritesNothing(t *testing.T) {
	const want = "the schema changed since you planned: plan again"

	t.Run("the store changed between plan and apply", func(t *testing.T) {
		s := seedApplyStore(t)
		h := newSchemaHarness(t, s)
		plan := h.plan(applySource, false)
		// Someone creates the role the source was about to create.
		seedRoles(t, s, "", "auditor")
		before := storeSnapshot(t, s)

		_, err := h.applyRaw(applySource, false, plan.Digest)
		ce := refusal(t, err, dashcontract.CodeConflict)
		if ce.Message != want {
			t.Errorf("message = %q, want %q", ce.Message, want)
		}
		if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
			t.Error("a refused apply changed the store")
		}
	})

	t.Run("the digest is for the other prune value", func(t *testing.T) {
		s := seedApplyStore(t)
		h := newSchemaHarness(t, s)
		plan := h.plan(applySource, false)
		before := storeSnapshot(t, s)

		_, err := h.applyRaw(applySource, true, plan.Digest)
		ce := refusal(t, err, dashcontract.CodeConflict)
		if ce.Message != want {
			t.Errorf("message = %q, want %q", ce.Message, want)
		}
		if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
			t.Error("a refused apply changed the store")
		}
	})

	for name, digest := range map[string]string{"empty": "", "made up": "deadbeef"} {
		t.Run("the digest is "+name, func(t *testing.T) {
			s := seedApplyStore(t)
			h := newSchemaHarness(t, s)
			before := storeSnapshot(t, s)

			_, err := h.applyRaw(applySource, false, digest)
			ce := refusal(t, err, dashcontract.CodeConflict)
			if ce.Message != want {
				t.Errorf("message = %q, want %q", ce.Message, want)
			}
			if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
				t.Error("a refused apply changed the store")
			}
		})
	}

	t.Run("the source is not the one planned", func(t *testing.T) {
		s := seedApplyStore(t)
		h := newSchemaHarness(t, s)
		plan := h.plan(applySource, false)
		before := storeSnapshot(t, s)

		_, err := h.applyRaw(applySource+"\nrole sneaky {\n}\n", false, plan.Digest)
		refusal(t, err, dashcontract.CodeConflict)
		if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
			t.Error("a refused apply changed the store")
		}
	})
}

func TestSchemaApplyRefusesInvalidSourceWithItsPosition(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{"a syntax error", "warden config 1\n\nrole {\n}\n", "line 3, column 6"},
		{"an import", "warden config 1\n\nimport \"x.warden\"\n", "line 3, column 1"},
		{"another tenant", "\nwarden config 1\ntenant other\n", "line 2, column 1"},
		{"an app", "\nwarden config 1\napp billing\n", "line 2, column 1"},
		{"an unknown grant", "warden config 1\n\nrole r {\n    grants = [\"nope:x\"]\n}\n", "line 3, column 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := seedApplyStore(t)
			h := newSchemaHarness(t, s)
			before := storeSnapshot(t, s)
			plan := h.plan(tc.src, false)
			if plan.Valid {
				t.Fatalf("setup: the plan accepts it: %+v", plan)
			}

			// Whatever digest it carries, the source is refused first.
			for _, digest := range []string{"", "deadbeef"} {
				_, err := h.applyRaw(tc.src, false, digest)
				ce := refusal(t, err, dashcontract.CodeBadRequest)
				if !strings.Contains(ce.Message, tc.want) || !strings.Contains(ce.Message, plan.Diagnostics[0].Message) {
					t.Errorf("message = %q, want it to name %s and %q", ce.Message, tc.want, plan.Diagnostics[0].Message)
				}
			}
			if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
				t.Error("a refused apply changed the store")
			}
		})
	}
}

func TestSchemaApplyNeedsEveryManageGrant(t *testing.T) {
	for _, missing := range schemaManages {
		t.Run("without "+missing, func(t *testing.T) {
			s := seedApplyStore(t)
			var held []string
			for _, g := range schemaManages {
				if g != missing {
					held = append(held, g)
				}
			}
			// Reads are not enough and not needed: the grant list is the
			// manage set alone.
			grantUser(t, s, "tester", held...)
			deps := Deps{Engine: engineOver(t, s)}
			before := storeSnapshot(t, s)

			_, err := schemaApplyHandler(deps)(context.Background(),
				SchemaApplyInput{Source: applySource, Digest: "deadbeef"}, principalFor("t1"))
			ce := refusal(t, err, dashcontract.CodePermissionDenied)
			want := "missing permission manage on " + strings.TrimSuffix(missing, ":manage")
			if ce.Message != want {
				t.Errorf("message = %q, want %q", ce.Message, want)
			}
			if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
				t.Error("a refused apply changed the store")
			}
		})
	}

	t.Run("read without manage", func(t *testing.T) {
		s := seedApplyStore(t)
		grantUser(t, s, "tester", schemaReads...)
		_, err := schemaApplyHandler(Deps{Engine: engineOver(t, s)})(context.Background(),
			SchemaApplyInput{Source: applySource}, principalFor("t1"))
		refusal(t, err, dashcontract.CodePermissionDenied)
	})
}

func TestSchemaApplyAuditsOnceAsTheOperator(t *testing.T) {
	s := seedApplyStore(t)
	h := newSchemaHarness(t, s)
	eng, probe := probedEngine(t, s)
	h.deps.Engine = eng

	plan, _ := h.apply(applySource, false)

	probe.mu.Lock()
	var applied []plugin.Event
	for _, e := range probe.events {
		if e.Action == "schema.applied" {
			applied = append(applied, e)
		}
	}
	probe.mu.Unlock()
	if len(applied) != 1 {
		t.Fatalf("got %d schema.applied events, want 1 (events: %v)", len(applied), probe.actions())
	}
	ev := applied[0]
	if ev.Actor != wantActor {
		t.Errorf("actor = %+v, want %+v", ev.Actor, wantActor)
	}
	if ev.TenantID != "t1" {
		t.Errorf("tenant = %q, want t1", ev.TenantID)
	}
	got, ok := ev.Entity.(schemaAppliedEvent)
	if !ok {
		t.Fatalf("entity is %T, want schemaAppliedEvent", ev.Entity)
	}
	want := schemaAppliedEvent{
		Created: len(plan.Created), Updated: len(plan.Updated), Deleted: len(plan.Deleted), NoOps: plan.NoOps,
	}
	if got != want {
		t.Errorf("entity = %+v, want %+v", got, want)
	}
	if want.Created == 0 || want.Updated == 0 || want.NoOps == 0 {
		t.Errorf("setup: the counts are too thin to tell the fields apart: %+v", want)
	}

	t.Run("none on a refusal", func(t *testing.T) {
		s := seedApplyStore(t)
		h := newSchemaHarness(t, s)
		eng, probe := probedEngine(t, s)
		h.deps.Engine = eng
		plan := h.plan(applySource, false)

		_, _ = h.applyRaw(applySource, false, "")                             // stale
		_, _ = h.applyRaw("warden config 1\nrole {\n}\n", false, plan.Digest) // invalid
		_, _ = h.applyRaw(applySource, true, plan.Digest)                     // wrong prune
		if acts := probe.actions(); strings.Contains(strings.Join(acts, ","), "schema.applied") {
			t.Errorf("a refusal was audited as an apply: %v", acts)
		}
		if acts := probe.actions(); len(acts) != 0 {
			t.Errorf("a refusal produced audit events: %v", acts)
		}
	})
}

// failingPolicyStore fails every policy write and delegates the rest.
type failingPolicyStore struct{ *memory.Store }

var errDiskFull = errors.New("disk full")

func (failingPolicyStore) CreatePolicy(context.Context, *policy.Policy) error { return errDiskFull }
func (failingPolicyStore) UpdatePolicy(context.Context, *policy.Policy) error { return errDiskFull }

func TestSchemaApplyIsNotTransactional(t *testing.T) {
	// The page tells the operator an apply can stop half way. This pins that
	// as a fact: what was written before the failure stays written.
	s := memory.New()
	h := newSchemaHarness(t, s)
	eng, err := warden.NewEngine(warden.WithStore(failingPolicyStore{s}))
	if err != nil {
		t.Fatal(err)
	}
	h.deps.Engine = eng

	src := `warden config 1
tenant t1

resource folder {
    relation owner: user
    permission edit = owner
}

permission "doc:read" (doc : read)

role reader {
    name = "Reader"
    grants = ["doc:read"]
}

policy "freeze" {
    effect = deny
    active = true
}

relation folder:root owner = user:alice
`
	plan := h.plan(src, false)
	if !plan.Valid || len(plan.Created) != 5 {
		t.Fatalf("setup: the plan should create five things, got %+v", plan)
	}
	_, err = h.applyRaw(src, false, plan.Digest)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("want the policy write failure, got %v", err)
	}

	ctx := context.Background()
	if _, gErr := s.GetResourceTypeByName(ctx, "t1", "", "folder"); gErr != nil {
		t.Errorf("the resource type written before the failure is gone: %v", gErr)
	}
	if _, gErr := s.GetPermissionByName(ctx, "t1", "", "doc:read"); gErr != nil {
		t.Errorf("the permission written before the failure is gone: %v", gErr)
	}
	reader, gErr := s.GetRoleBySlug(ctx, "t1", "", "reader")
	if gErr != nil {
		t.Fatalf("the role written before the failure is gone: %v", gErr)
	}
	if grants, _ := s.ListRolePermissions(ctx, "t1", reader.ID); len(grants) != 1 {
		t.Errorf("the role's grant was written before the policy: %v", grants)
	}
	if _, gErr := s.GetPolicyByName(ctx, "t1", "", "freeze"); gErr == nil {
		t.Error("the policy exists although its write failed")
	}
	if tuples, _ := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", ObjectType: "folder", Limit: 10}); len(tuples) != 0 {
		t.Errorf("a relation after the failed policy was written: %v", tuples)
	}
}

func TestSchemaApplyOfANamespacedExportIsANoOp(t *testing.T) {
	// The end-to-end proof the editor rests on: export a namespaced tenant,
	// plan that source, apply it with its own digest, and nothing moves.
	for _, prune := range []bool{false, true} {
		t.Run(fmt.Sprintf("prune=%v", prune), func(t *testing.T) {
			s := memory.New()
			seedSchemaWorld(t, s)
			h := newSchemaHarness(t, s)
			exported := h.export(SchemaExportInput{})
			if !strings.Contains(exported.Source, `namespace "eng"`) {
				t.Fatalf("setup: the export has no eng namespace block:\n%s", exported.Source)
			}
			before := storeSnapshot(t, s)

			plan, got := h.apply(exported.Source, prune)
			if len(plan.Created)+len(plan.Updated)+len(plan.Deleted) != 0 {
				t.Fatalf("the export plans work against its own store: %+v", plan)
			}
			if len(got.Created)+len(got.Updated)+len(got.Deleted) != 0 || got.NoOps == 0 {
				t.Errorf("applying the export is not a no-op: %+v", got)
			}
			if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
				for k := range before {
					if before[k] != after[k] {
						t.Errorf("the no-op apply changed %s:\nbefore %s\nafter  %s", k, before[k], after[k])
					}
				}
			}
		})
	}
}
