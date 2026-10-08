package dsl

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// The round trip this file pins: a tenant exported with BuildProgram and
// Format, then parsed, resolved and applied back, must change nothing, and
// the same source applied to an empty tenant must rebuild every field an
// operator can see or edit.
//
// The seed is written through the store, the way the dashboard writes it,
// so it holds the shapes the dashboard stores (numbers as float64, lists as
// []any, empty lists rather than nil) and names no DSL rule would pick.

const rtTenant = "t1"

func rtTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// seedRoundTripTenant writes every exported kind in three namespaces (the
// root, eng and eng/platform), with every field populated.
func seedRoundTripTenant(t *testing.T, s *memory.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("seed %s: %v", what, err)
		}
	}

	// Resource types.
	for _, rt := range []*resourcetype.ResourceType{
		{
			NamespacePath: "", Name: "folder", Description: "A folder",
			Relations: []resourcetype.RelationDef{
				{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
				{Name: "owner", AllowedSubjects: []string{"user"}},
			},
			Permissions: []resourcetype.PermissionDef{{Name: "view", Expression: "viewer or owner"}},
		},
		{
			NamespacePath: "eng", Name: "document", Description: "A design document",
			Relations: []resourcetype.RelationDef{
				{Name: "parent", AllowedSubjects: []string{"folder"}},
				{Name: "owner", AllowedSubjects: []string{"user"}},
				{Name: "viewer", AllowedSubjects: []string{"user", "user:*"}},
			},
			Permissions: []resourcetype.PermissionDef{
				// Stored as typed, redundant parentheses and all.
				{Name: "read", Expression: "(viewer or owner) or parent->view"},
				{Name: "edit", Expression: "owner and not viewer"},
			},
		},
		{
			// A keyword as a type name and as a relation name, a relation
			// name with a space and no allowed subjects, and a permission
			// name with a space.
			NamespacePath: "eng/platform", Name: "role",
			Relations: []resourcetype.RelationDef{
				{Name: "owner", AllowedSubjects: []string{"user"}},
				{Name: "name", AllowedSubjects: []string{"user"}},
				{Name: "on call", AllowedSubjects: []string{}},
			},
			Permissions: []resourcetype.PermissionDef{{Name: "manage it", Expression: "owner"}},
		},
	} {
		rt.TenantID = rtTenant
		must("resource type "+rt.Name, s.CreateResourceType(ctx, rt))
	}

	// Permissions. warden:role:read and warden:* are the dashboard's own
	// grants: the first has a colon in its resource, the second a glob.
	for _, p := range []*permission.Permission{
		{NamespacePath: "", Name: "doc:read", Resource: "doc", Action: "read", Description: "Read a document"},
		{NamespacePath: "", Name: "doc:write", Resource: "doc", Action: "write"},
		{NamespacePath: "", Name: "warden:role:read", Resource: "warden:role", Action: "read", Description: "See roles", IsSystem: true},
		{NamespacePath: "", Name: "warden:*", Resource: "warden", Action: "*", IsSystem: true},
		{NamespacePath: "eng", Name: "doc:read", Resource: "doc", Action: "read", Description: "Read an eng document"},
		{NamespacePath: "eng", Name: "deploy:run", Resource: "deploy", Action: "run"},
		{NamespacePath: "eng/platform", Name: "svc:restart", Resource: "svc", Action: "restart", Description: "Restart a service"},
	} {
		p.TenantID = rtTenant
		must("permission "+p.Name, s.CreatePermission(ctx, p))
	}

	// Roles, with their grants as (namespace, name) refs.
	type seededRole struct {
		r      *role.Role
		grants []permission.Ref
	}
	for _, sr := range []seededRole{
		{
			r: &role.Role{
				Slug: "admin", Name: "Administrator", Description: "Runs everything",
				IsSystem: true, MaxMembers: 3, Metadata: map[string]any{"tier": "gold"},
			},
			grants: []permission.Ref{
				{Name: "warden:role:read"}, {Name: "warden:*"}, {Name: "doc:write"},
				// A sibling namespace's permission: not reachable by name.
				{NamespacePath: "eng", Name: "deploy:run"},
			},
		},
		{r: &role.Role{Slug: "viewer", Name: "Viewer", IsDefault: true}, grants: []permission.Ref{{Name: "doc:read"}}},
		{r: &role.Role{Slug: "Auditor Team", Name: "Auditors"}},
		{
			r: &role.Role{NamespacePath: "eng", Slug: "dev", Name: "Developer"},
			grants: []permission.Ref{
				{NamespacePath: "eng", Name: "doc:read"},
				// The root doc:read, shadowed by eng's by name.
				{NamespacePath: "", Name: "doc:read"},
				{NamespacePath: "eng", Name: "deploy:run"},
			},
		},
		{
			r:      &role.Role{NamespacePath: "eng", Slug: "lead", Name: "Lead", Description: "Team lead", ParentSlug: "dev", MaxMembers: 5},
			grants: []permission.Ref{{NamespacePath: "eng", Name: "deploy:run"}},
		},
		{
			// A negative max_members is valid in the store, so it must read back.
			r: &role.Role{NamespacePath: "eng/platform", Slug: "sre", Name: "SRE", MaxMembers: -1, Metadata: map[string]any{"pager": true}},
			grants: []permission.Ref{
				{NamespacePath: "eng/platform", Name: "svc:restart"},
				// Found at the root by the fallback.
				{NamespacePath: "", Name: "doc:write"},
				// An ancestor that is not the root: not found by name.
				{NamespacePath: "eng", Name: "deploy:run"},
			},
		},
	} {
		sr.r.TenantID = rtTenant
		must("role "+sr.r.Slug, s.CreateRole(ctx, sr.r))
		if sr.grants != nil {
			must("grants of "+sr.r.Slug, s.SetRolePermissions(ctx, rtTenant, sr.r.ID, sr.grants))
		}
	}

	// Policies.
	for _, p := range []*policy.Policy{
		{
			NamespacePath: "", Name: "allow-readers", Description: "Readers read",
			Effect: policy.EffectAllow, Priority: 10, IsActive: true, Version: 1,
			Subjects:  []policy.SubjectMatch{{Kind: "user"}},
			Actions:   []string{"read"},
			Resources: []string{"document:*"},
			Conditions: []policy.Condition{
				{Field: "subject.attributes.dept", Operator: policy.OpEquals, Value: "eng"},
			},
		},
		{
			NamespacePath: "eng", Name: "Deny Contractors", Description: "No writes \"after hours\"",
			Effect: policy.EffectDeny, Priority: 100, IsActive: false, Version: 1,
			NotBefore:   rtTime("2026-01-02T03:04:05.123456789Z"),
			NotAfter:    rtTime("2027-01-01T00:00:00Z"),
			Obligations: []string{"audit-log", "notify-security"},
			Subjects: []policy.SubjectMatch{
				{ID: "alice"},
				{Role: "contractor"},
				{Kind: "user", ID: "bob", Role: "temp"},
				{},
			},
			Actions:   []string{"write", "delete"},
			Resources: []string{"document"},
			Conditions: []policy.Condition{
				{Field: "resource.owner", Operator: policy.OpNotEquals, Value: "x"},
				{Field: "subject.name", Operator: "exists"},
				{Field: "subject.gone", Operator: "not_exists"},
				{Field: "context.risk", Operator: policy.OpGreaterThan, Value: float64(0.75)},
				{Field: "context.score", Operator: "lte", Value: float64(-3)},
				{Field: "context.big", Operator: "gte", Value: float64(1000000)},
				{Field: "subject.attributes.level", Operator: policy.OpIn, Value: []any{float64(1), float64(2)}},
				{Field: "context.ip", Operator: "ip_in_cidr", Value: []any{"10.0.0.0/8"}},
				{Field: `subject.attributes["team name"]`, Operator: policy.OpEquals, Value: "core"},
				{Field: "context.time", Operator: "time_after", Value: "2026-01-01T00:00:00Z"},
				{Field: "subject.attributes.flag", Operator: policy.OpEquals, Value: true},
				{Field: "subject.email", Operator: "regex", Value: `.*@example\.com`},
				{Field: "action", Operator: policy.OpNotIn, Value: []any{"purge"}},
			},
		},
		{
			// What the dashboard stores for "no subjects, no actions": empty
			// lists, not nil.
			NamespacePath: "eng/platform", Name: "platform-open",
			Effect: policy.EffectAllow, IsActive: true, Version: 1, Priority: -5,
			Subjects: []policy.SubjectMatch{}, Actions: []string{}, Resources: []string{}, Obligations: []string{},
		},
	} {
		p.TenantID = rtTenant
		must("policy "+p.Name, s.CreatePolicy(ctx, p))
	}

	// Relation tuples, with and without a subject relation.
	for _, tp := range []*relation.Tuple{
		{NamespacePath: "", ObjectType: "folder", ObjectID: "root", Relation: "owner", SubjectType: "user", SubjectID: "alice"},
		{NamespacePath: "", ObjectType: "folder", ObjectID: "root", Relation: "viewer", SubjectType: "group", SubjectID: "eng", SubjectRelation: "member"},
		{NamespacePath: "", ObjectType: "folder", ObjectID: "root", Relation: "viewer", SubjectType: "user", SubjectID: "carol"},
		{NamespacePath: "eng", ObjectType: "document", ObjectID: "design doc.md", Relation: "parent", SubjectType: "folder", SubjectID: "root"},
		{NamespacePath: "eng", ObjectType: "document", ObjectID: "3f2a-9c", Relation: "viewer", SubjectType: "user", SubjectID: "bob@example.com"},
		{NamespacePath: "eng/platform", ObjectType: "role", ObjectID: "on-call", Relation: "name", SubjectType: "user", SubjectID: "*"},
	} {
		tp.TenantID = rtTenant
		must("tuple", s.CreateRelation(ctx, tp))
	}
}

func rtEngine(t *testing.T, s *memory.Store) *warden.Engine {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// exportParsed exports the whole tenant, formats it, and parses and
// resolves the source, failing on any diagnostic.
func exportParsed(t *testing.T, eng *warden.Engine) (*Program, string) {
	t.Helper()
	prog, err := BuildProgram(context.Background(), eng, ExportOptions{TenantID: rtTenant})
	if err != nil {
		t.Fatalf("build program: %v", err)
	}
	src := Format(prog)
	parsed, diags := Parse("export.warden", []byte(src))
	if len(diags) > 0 {
		t.Fatalf("parse the export: %v\n--- source:\n%s", diags, src)
	}
	if diags := Resolve(parsed); len(diags) > 0 {
		t.Fatalf("resolve the export: %v\n--- source:\n%s", diags, src)
	}
	return parsed, src
}

func TestRoundTrip_ExportAppliesBackUnchanged(t *testing.T) {
	ctx := context.Background()
	src := memory.New()
	seedRoundTripTenant(t, src)
	eng := rtEngine(t, src)
	before := tenantSnapshot(t, src, true)

	parsed, text := exportParsed(t, eng)

	// Plan against the source tenant: nothing to do, with prune on too.
	for _, prune := range []bool{false, true} {
		res, err := Apply(ctx, eng, parsed, ApplyOptions{TenantID: rtTenant, DryRun: true, Prune: prune})
		if err != nil {
			t.Fatalf("dry run (prune=%t): %v\n--- source:\n%s", prune, err, text)
		}
		if len(res.Created)+len(res.Updated)+len(res.Deleted) != 0 {
			t.Fatalf("dry run (prune=%t) plans changes on an unchanged export:\ncreated %v\nupdated %v\ndeleted %v\n--- source:\n%s",
				prune, res.Created, res.Updated, res.Deleted, text)
		}
	}

	// A real apply of the same source changes nothing either, including
	// what the language does not express (metadata).
	if _, err := Apply(ctx, eng, parsed, ApplyOptions{TenantID: rtTenant, Prune: true}); err != nil {
		t.Fatalf("apply back: %v", err)
	}
	if after := tenantSnapshot(t, src, true); !reflect.DeepEqual(before, after) {
		t.Fatalf("applying the export back changed the tenant:\n%s", snapshotDiff(before, after))
	}

	// The same source rebuilds an empty tenant field by field. Metadata is
	// left out of this comparison: the language has no syntax for it (see
	// the report), and the dashboard neither shows nor edits it.
	dst := memory.New()
	if _, err := Apply(ctx, rtEngine(t, dst), parsed, ApplyOptions{TenantID: rtTenant}); err != nil {
		t.Fatalf("apply to an empty tenant: %v", err)
	}
	want := tenantSnapshot(t, src, false)
	got := tenantSnapshot(t, dst, false)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("an empty tenant rebuilt from the export differs:\n%s\n--- source:\n%s", snapshotDiff(want, got), text)
	}
}

// TestRoundTrip_FormatIsStable checks the export is canonical: formatting
// the parsed export again gives the same bytes.
func TestRoundTrip_FormatIsStable(t *testing.T) {
	s := memory.New()
	seedRoundTripTenant(t, s)
	parsed, text := exportParsed(t, rtEngine(t, s))
	if again := Format(parsed); again != text {
		t.Fatalf("format of the parsed export differs:\n--- first:\n%s\n--- second:\n%s", text, again)
	}
}

// TestRoundTrip_PlanComparesEveryField edits one field of the parsed export
// at a time and checks the plan reports exactly that entity and field. A
// field Apply writes but the plan did not compare would come back as an
// empty plan here.
func TestRoundTrip_PlanComparesEveryField(t *testing.T) {
	findRole := func(p *Program, ns, slug string) *RoleDecl {
		for _, r := range p.Roles {
			if r.NamespacePath == ns && r.Slug == slug {
				return r
			}
		}
		t.Fatalf("no role %s/%s in the export", ns, slug)
		return nil
	}
	findPolicy := func(p *Program, ns, name string) *PolicyDecl {
		for _, x := range p.Policies {
			if x.NamespacePath == ns && x.Name == name {
				return x
			}
		}
		t.Fatalf("no policy %s/%s in the export", ns, name)
		return nil
	}
	findPerm := func(p *Program, ns, name string) *PermissionDecl {
		for _, x := range p.Permissions {
			if x.NamespacePath == ns && x.Name == name {
				return x
			}
		}
		t.Fatalf("no permission %s/%s in the export", ns, name)
		return nil
	}
	findRT := func(p *Program, ns, name string) *ResourceDecl {
		for _, x := range p.ResourceTypes {
			if x.NamespacePath == ns && x.Name == name {
				return x
			}
		}
		t.Fatalf("no resource type %s/%s in the export", ns, name)
		return nil
	}
	later := rtTime("2030-01-01T00:00:00Z")

	cases := []struct {
		name string
		edit func(p *Program)
		want string
	}{
		{"role name", func(p *Program) { findRole(p, "", "viewer").Name = "Readers" }, "~ role//viewer (name)"},
		{"role description", func(p *Program) { findRole(p, "eng", "lead").Description = "" }, "~ role/eng/lead (description)"},
		{"role is_system", func(p *Program) { findRole(p, "", "admin").IsSystem = false }, "~ role//admin (is_system)"},
		{"role is_default", func(p *Program) { findRole(p, "", "viewer").IsDefault = false }, "~ role//viewer (is_default)"},
		{"role max_members", func(p *Program) { findRole(p, "eng", "lead").MaxMembers = 9 }, "~ role/eng/lead (max_members)"},
		{"role parent", func(p *Program) { findRole(p, "eng", "lead").Parent = "" }, "~ role/eng/lead (parent)"},
		{"role grants", func(p *Program) {
			r := findRole(p, "", "viewer")
			r.Grants = []string{"doc:write"}
		}, "~ role//viewer (grants)"},
		{"role qualified grant", func(p *Program) {
			r := findRole(p, "eng", "dev")
			r.QualifiedGrants = nil
		}, "~ role/eng/dev (grants)"},
		{"role cleared grants", func(p *Program) {
			r := findRole(p, "eng", "lead")
			r.Grants = nil
		}, "~ role/eng/lead (grants)"},
		{"permission resource", func(p *Program) { findPerm(p, "", "doc:read").Resource = "document" }, "~ permission//doc:read (resource)"},
		{"permission action", func(p *Program) { findPerm(p, "", "doc:read").Action = "view" }, "~ permission//doc:read (action)"},
		{"permission description", func(p *Program) { findPerm(p, "", "doc:read").Description = "x" }, "~ permission//doc:read (description)"},
		{"permission is_system", func(p *Program) { findPerm(p, "", "warden:*").IsSystem = false }, "~ permission//warden:* (is_system)"},
		{"policy subjects", func(p *Program) {
			findPolicy(p, "", "allow-readers").Subjects = []*SubjectMatchDecl{{Kind: "user", ID: "zed"}}
		}, "~ policy//allow-readers (subjects)"},
		{"policy subjects removed", func(p *Program) {
			findPolicy(p, "eng", "Deny Contractors").Subjects = nil
		}, "~ policy/eng/Deny Contractors (subjects)"},
		{"policy description", func(p *Program) { findPolicy(p, "", "allow-readers").Description = "" }, "~ policy//allow-readers (description)"},
		{"policy effect", func(p *Program) { findPolicy(p, "", "allow-readers").Effect = "deny" }, "~ policy//allow-readers (effect)"},
		{"policy priority", func(p *Program) { findPolicy(p, "", "allow-readers").Priority = 11 }, "~ policy//allow-readers (priority)"},
		{"policy negative priority", func(p *Program) { findPolicy(p, "eng/platform", "platform-open").Priority = -6 }, "~ policy/eng/platform/platform-open (priority)"},
		{"role negative max_members", func(p *Program) { findRole(p, "eng/platform", "sre").MaxMembers = -2 }, "~ role/eng/platform/sre (max_members)"},
		{"policy active", func(p *Program) { findPolicy(p, "", "allow-readers").Active = false }, "~ policy//allow-readers (active)"},
		{"policy not_before", func(p *Program) { findPolicy(p, "eng", "Deny Contractors").NotBefore = nil }, "~ policy/eng/Deny Contractors (not_before)"},
		{"policy not_after", func(p *Program) { findPolicy(p, "eng", "Deny Contractors").NotAfter = later }, "~ policy/eng/Deny Contractors (not_after)"},
		{"policy obligations", func(p *Program) { findPolicy(p, "eng", "Deny Contractors").Obligations = nil }, "~ policy/eng/Deny Contractors (obligations)"},
		{"policy actions", func(p *Program) { findPolicy(p, "", "allow-readers").Actions = []string{"list"} }, "~ policy//allow-readers (actions)"},
		{"policy resources", func(p *Program) { findPolicy(p, "", "allow-readers").Resources = nil }, "~ policy//allow-readers (resources)"},
		{"policy condition value", func(p *Program) {
			findPolicy(p, "", "allow-readers").Conditions[0].Value = "ops"
		}, "~ policy//allow-readers (conditions)"},
		{"policy condition number", func(p *Program) {
			for _, c := range findPolicy(p, "eng", "Deny Contractors").Conditions {
				if c.Field == "context.risk" {
					c.Value = 0.5
				}
			}
		}, "~ policy/eng/Deny Contractors (conditions)"},
		{"resource type description", func(p *Program) { findRT(p, "", "folder").Description = "" }, "~ resource_type//folder (description)"},
		{"resource type relations", func(p *Program) {
			findRT(p, "", "folder").Relations[0].AllowedSubjects = []SubjectType{{Type: "user"}}
		}, "~ resource_type//folder (relations)"},
		{"resource type permissions", func(p *Program) {
			findRT(p, "", "folder").Permissions[0].Expr = &RefExpr{Name: "owner"}
		}, "~ resource_type//folder (permissions)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			seedRoundTripTenant(t, s)
			eng := rtEngine(t, s)
			parsed, _ := exportParsed(t, eng)
			tc.edit(parsed)
			res, err := Apply(context.Background(), eng, parsed, ApplyOptions{TenantID: rtTenant, DryRun: true})
			if err != nil {
				t.Fatalf("dry run: %v", err)
			}
			if len(res.Created) != 0 || len(res.Deleted) != 0 || !reflect.DeepEqual(res.Updated, []string{tc.want}) {
				t.Fatalf("plan: created %v, updated %v, deleted %v; want updated [%s]", res.Created, res.Updated, res.Deleted, tc.want)
			}
		})
	}
}

// TestRoundTrip_PlanComparesTheApp checks an apply that names an app plans
// the app change on every entity that stores one, and that an apply naming
// no app plans nothing (it keeps the stored app).
func TestRoundTrip_PlanComparesTheApp(t *testing.T) {
	s := memory.New()
	seedRoundTripTenant(t, s)
	eng := rtEngine(t, s)
	parsed, _ := exportParsed(t, eng)

	res, err := Apply(context.Background(), eng, parsed, ApplyOptions{TenantID: rtTenant, AppID: "app2", DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// 3 resource types, 7 permissions, 6 roles and 3 policies store an app
	// id; tuples are never updated, only created.
	if len(res.Created) != 0 || len(res.Deleted) != 0 || len(res.Updated) != 19 {
		t.Fatalf("plan: created %v, deleted %v, %d updated %v; want 19 app updates", res.Created, res.Deleted, len(res.Updated), res.Updated)
	}
	for _, line := range res.Updated {
		if !strings.HasSuffix(line, " (app)") {
			t.Errorf("an app change is reported as %q", line)
		}
	}
}

// TestRoundTrip_GrantChangeIsPlannedAndApplied is the grant ruling: a grant
// swapped from doc:read to doc:write shows in the plan, and the real apply
// writes it.
func TestRoundTrip_GrantChangeIsPlannedAndApplied(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	seedRoundTripTenant(t, s)
	eng := rtEngine(t, s)
	parsed, text := exportParsed(t, eng)

	edited := strings.Replace(text, `grants = ["doc:read"]`, `grants = ["doc:write"]`, 1)
	if edited == text {
		t.Fatalf("the export has no viewer grant line to edit:\n%s", text)
	}
	prog, diags := Parse("edited.warden", []byte(edited))
	if len(diags) > 0 {
		t.Fatalf("parse: %v", diags)
	}
	_ = parsed

	plan, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: rtTenant, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !reflect.DeepEqual(plan.Updated, []string{"~ role//viewer (grants)"}) {
		t.Fatalf("updated = %v, want [~ role//viewer (grants)]", plan.Updated)
	}
	res, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: rtTenant})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !reflect.DeepEqual(res.Updated, plan.Updated) {
		t.Fatalf("apply updated %v, the plan said %v", res.Updated, plan.Updated)
	}
	viewer, err := s.GetRoleBySlug(ctx, rtTenant, "", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	grants, err := s.ListRolePermissions(ctx, rtTenant, viewer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Name != "doc:write" || grants[0].NamespacePath != "" {
		t.Fatalf("viewer grants after apply = %v, want only the root doc:write", grantKeys(grants))
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Snapshot: every stored field, ids, timestamps and actors aside.
// ─────────────────────────────────────────────────────────────────────────

type rtRole struct {
	Name, Description, ParentSlug, AppID string
	IsSystem, IsDefault                  bool
	MaxMembers                           int
	Metadata                             string
	Grants                               []string
}

type rtPolicy struct {
	Description, Effect, AppID string
	Priority                   int
	IsActive                   bool
	NotBefore, NotAfter        string
	Obligations, Subjects      []string
	Actions, Resources         []string
	Conditions                 []string
	Metadata                   string
}

type rtSnapshot struct {
	ResourceTypes map[string]string
	Permissions   map[string]string
	Roles         map[string]rtRole
	Policies      map[string]rtPolicy
	Tuples        []string
}

func tenantSnapshot(t *testing.T, s *memory.Store, withMetadata bool) rtSnapshot {
	t.Helper()
	ctx := context.Background()
	meta := func(m map[string]any) string {
		if !withMetadata || len(m) == 0 {
			return ""
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
		}
		return strings.Join(parts, ",")
	}
	snap := rtSnapshot{
		ResourceTypes: map[string]string{},
		Permissions:   map[string]string{},
		Roles:         map[string]rtRole{},
		Policies:      map[string]rtPolicy{},
	}

	rts, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: rtTenant, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range rts {
		var b strings.Builder
		fmt.Fprintf(&b, "desc=%q app=%q meta=%q", rt.Description, rt.AppID, meta(rt.Metadata))
		for _, rel := range rt.Relations {
			fmt.Fprintf(&b, " rel %q:%q", rel.Name, rel.AllowedSubjects)
		}
		for _, p := range rt.Permissions {
			// Compared in canonical form: the store keeps the text as typed,
			// the language keeps the expression.
			fmt.Fprintf(&b, " perm %q=%q", p.Name, canonicalExpression(p.Expression))
		}
		snap.ResourceTypes[rt.NamespacePath+"/"+rt.Name] = b.String()
	}

	perms, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: rtTenant, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range perms {
		snap.Permissions[p.NamespacePath+"/"+p.Name] = fmt.Sprintf("res=%q act=%q desc=%q sys=%t app=%q meta=%q",
			p.Resource, p.Action, p.Description, p.IsSystem, p.AppID, meta(p.Metadata))
	}

	roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: rtTenant, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		grants, err := s.ListRolePermissions(ctx, rtTenant, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		snap.Roles[r.NamespacePath+"/"+r.Slug] = rtRole{
			Name: r.Name, Description: r.Description, ParentSlug: r.ParentSlug, AppID: r.AppID,
			IsSystem: r.IsSystem, IsDefault: r.IsDefault, MaxMembers: r.MaxMembers,
			Metadata: meta(r.Metadata), Grants: grantKeys(grants),
		}
	}

	pols, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: rtTenant, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	timeStr := func(tp *time.Time) string {
		if tp == nil {
			return ""
		}
		return tp.UTC().Format(time.RFC3339Nano)
	}
	list := func(in []string) []string {
		if len(in) == 0 {
			return nil
		}
		return append([]string{}, in...)
	}
	for _, p := range pols {
		rp := rtPolicy{
			Description: p.Description, Effect: string(p.Effect), AppID: p.AppID,
			Priority: p.Priority, IsActive: p.IsActive,
			NotBefore: timeStr(p.NotBefore), NotAfter: timeStr(p.NotAfter),
			Obligations: list(p.Obligations), Actions: list(p.Actions), Resources: list(p.Resources),
			Metadata: meta(p.Metadata),
		}
		for _, sm := range p.Subjects {
			rp.Subjects = append(rp.Subjects, fmt.Sprintf("kind=%q id=%q role=%q", sm.Kind, sm.ID, sm.Role))
		}
		for _, c := range p.Conditions {
			rp.Conditions = append(rp.Conditions, fmt.Sprintf("%q %s %s", c.Field, c.Operator, normalizedValue(c.Value)))
		}
		snap.Policies[p.NamespacePath+"/"+p.Name] = rp
	}

	tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: rtTenant, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range tuples {
		snap.Tuples = append(snap.Tuples, fmt.Sprintf("%s|%q:%q#%q@%q:%q#%q app=%q meta=%q",
			tp.NamespacePath, tp.ObjectType, tp.ObjectID, tp.Relation, tp.SubjectType, tp.SubjectID, tp.SubjectRelation,
			tp.AppID, meta(tp.Metadata)))
	}
	sort.Strings(snap.Tuples)
	return snap
}

func grantKeys(grants []*permission.Permission) []string {
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.NamespacePath+"/"+g.Name)
	}
	sort.Strings(out)
	return out
}

// canonicalExpression is an expression's text as the language writes it.
func canonicalExpression(src string) string {
	expr, diags := CompileExpr("<snapshot>", src)
	if len(diags) > 0 {
		return src
	}
	return FormatExpr(expr)
}

// normalizedValue renders a condition value with every number as a
// float64, so the store's JSON numbers and the parser's ints compare equal.
func normalizedValue(v any) string {
	switch x := v.(type) {
	case []string:
		items := make([]any, len(x))
		for i, s := range x {
			items[i] = s
		}
		return normalizedValue(items)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = normalizedValue(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case int:
		return fmt.Sprintf("n:%v", float64(x))
	case int64:
		return fmt.Sprintf("n:%v", float64(x))
	case float64:
		return fmt.Sprintf("n:%v", x)
	case string:
		return fmt.Sprintf("s:%q", x)
	case bool:
		return fmt.Sprintf("b:%t", x)
	case nil:
		return "nil"
	}
	return fmt.Sprintf("%T:%v", v, v)
}

func snapshotDiff(a, b rtSnapshot) string {
	var out strings.Builder
	diffMap := func(kind string, x, y map[string]string) {
		keys := map[string]struct{}{}
		for k := range x {
			keys[k] = struct{}{}
		}
		for k := range y {
			keys[k] = struct{}{}
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if x[k] != y[k] {
				fmt.Fprintf(&out, "%s %s:\n  want %s\n  got  %s\n", kind, k, x[k], y[k])
			}
		}
	}
	diffMap("resource type", a.ResourceTypes, b.ResourceTypes)
	diffMap("permission", a.Permissions, b.Permissions)
	toStr := func(m any) map[string]string {
		out := map[string]string{}
		rv := reflect.ValueOf(m)
		for _, k := range rv.MapKeys() {
			out[k.String()] = fmt.Sprintf("%+v", rv.MapIndex(k).Interface())
		}
		return out
	}
	diffMap("role", toStr(a.Roles), toStr(b.Roles))
	diffMap("policy", toStr(a.Policies), toStr(b.Policies))
	if !reflect.DeepEqual(a.Tuples, b.Tuples) {
		fmt.Fprintf(&out, "tuples:\n  want %q\n  got  %q\n", a.Tuples, b.Tuples)
	}
	return out.String()
}
