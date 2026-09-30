package dsl

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Program {
	t.Helper()
	prog, errs := Parse("test.warden", []byte(src))
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("parse error: %s", e)
		}
		t.FailNow()
	}
	return prog
}

func TestParser_Header(t *testing.T) {
	prog := mustParse(t, "warden config 1\ntenant t1\napp app1\n")
	if prog.Version != 1 {
		t.Errorf("version = %d, want 1", prog.Version)
	}
	if prog.Tenant != "t1" {
		t.Errorf("tenant = %q, want t1", prog.Tenant)
	}
	if prog.App != "app1" {
		t.Errorf("app = %q, want app1", prog.App)
	}
}

func TestParser_ResourceWithPermissions(t *testing.T) {
	src := `
warden config 1

resource document {
    relation owner: user
    relation editor: user | group#member
    relation viewer: user | group#member

    permission read = viewer or editor or owner
    permission edit = editor or owner
    permission delete = owner
}
`
	prog := mustParse(t, src)
	if len(prog.ResourceTypes) != 1 {
		t.Fatalf("expected 1 resource type, got %d", len(prog.ResourceTypes))
	}
	doc := prog.ResourceTypes[0]
	if doc.Name != "document" {
		t.Errorf("name = %q", doc.Name)
	}
	if len(doc.Relations) != 3 {
		t.Errorf("expected 3 relations, got %d", len(doc.Relations))
	}
	if len(doc.Permissions) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(doc.Permissions))
	}

	// Spot-check the editor relation has user + group#member.
	editor := doc.Relations[1]
	if editor.Name != "editor" {
		t.Errorf("relation[1].Name = %q", editor.Name)
	}
	if len(editor.AllowedSubjects) != 2 {
		t.Fatalf("expected 2 allowed subjects, got %d", len(editor.AllowedSubjects))
	}
	if editor.AllowedSubjects[1].Type != "group" || editor.AllowedSubjects[1].Relation != "member" {
		t.Errorf("got %+v", editor.AllowedSubjects[1])
	}

	// `read = viewer or editor or owner` should be a left-associative OrExpr.
	read := doc.Permissions[0]
	if read.Name != "read" {
		t.Errorf("permission[0].Name = %q", read.Name)
	}
	if _, ok := read.Expr.(*OrExpr); !ok {
		t.Errorf("expected OrExpr at top of `read`, got %T", read.Expr)
	}
}

func TestParser_ExpressionTraversal(t *testing.T) {
	src := `
warden config 1

resource folder {
    relation parent: folder
    relation owner: user

    permission read = owner or parent->read
}
`
	prog := mustParse(t, src)
	rt := prog.ResourceTypes[0]
	read := rt.Permissions[0]
	or, ok := read.Expr.(*OrExpr)
	if !ok {
		t.Fatalf("expected OrExpr, got %T", read.Expr)
	}
	tr, ok := or.Right.(*TraverseExpr)
	if !ok {
		t.Fatalf("expected TraverseExpr on right, got %T", or.Right)
	}
	if got := strings.Join(tr.Steps, "->"); got != "parent->read" {
		t.Errorf("traversal steps = %q", got)
	}
}

func TestParser_RoleWithInheritance(t *testing.T) {
	src := `
warden config 1

role viewer {
    name = "Viewer"
    grants = ["doc:read", "wiki:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["doc:write"]
}

role admin : editor {
    name = "Administrator"
    grants += ["doc:*"]
}
`
	prog := mustParse(t, src)
	if len(prog.Roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(prog.Roles))
	}
	editor := prog.Roles[1]
	if editor.Slug != "editor" {
		t.Errorf("editor.Slug = %q", editor.Slug)
	}
	if editor.Parent != "viewer" {
		t.Errorf("editor.Parent = %q", editor.Parent)
	}
	if !editor.GrantsAppend {
		t.Errorf("editor should have GrantsAppend=true")
	}
	admin := prog.Roles[2]
	if admin.Parent != "editor" {
		t.Errorf("admin.Parent = %q", admin.Parent)
	}
}

func TestParser_PermissionShorthand(t *testing.T) {
	src := `
warden config 1

permission "document:read"   (document : read)
permission "document:write"  (document : write)
`
	prog := mustParse(t, src)
	if len(prog.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(prog.Permissions))
	}
	if prog.Permissions[0].Resource != "document" || prog.Permissions[0].Action != "read" {
		t.Errorf("expected document:read, got %+v", prog.Permissions[0])
	}
}

func TestParser_PolicyWithConditions(t *testing.T) {
	src := `
warden config 1

policy "business-hours" {
    effect = allow
    priority = 100
    active = true
    actions = ["read", "write"]
    resources = ["document"]
    when {
        context.time time_after "09:00:00Z"
        context.time time_before "17:00:00Z"
        subject.attributes.department == "engineering"
    }
}
`
	prog := mustParse(t, src)
	if len(prog.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(prog.Policies))
	}
	pol := prog.Policies[0]
	if pol.Effect != "allow" {
		t.Errorf("effect = %q", pol.Effect)
	}
	if pol.Priority != 100 {
		t.Errorf("priority = %d", pol.Priority)
	}
	if !pol.Active {
		t.Errorf("active should be true")
	}
	if len(pol.Conditions) != 3 {
		t.Fatalf("expected 3 conditions, got %d", len(pol.Conditions))
	}
	if pol.Conditions[0].Operator != "time_after" {
		t.Errorf("condition[0].Operator = %q", pol.Conditions[0].Operator)
	}
	if pol.Conditions[2].Operator != "eq" {
		t.Errorf("condition[2].Operator = %q", pol.Conditions[2].Operator)
	}
}

func TestParser_NestedNamespaces(t *testing.T) {
	src := `
warden config 1
tenant acme

namespace "engineering" {
    role eng-viewer {
        name = "Engineering Viewer"
        grants = ["doc:read"]
    }

    namespace "platform" {
        role platform-admin : eng-viewer {
            name = "Platform Admin"
            grants += ["infra:*"]
        }
    }
}

namespace "billing" {
    role billing-admin {
        name = "Billing Admin"
        grants = ["invoice:*"]
    }
}
`
	prog := mustParse(t, src)
	// Flattened roles.
	if len(prog.Roles) != 3 {
		t.Fatalf("expected 3 roles after flattening, got %d", len(prog.Roles))
	}

	want := map[string]string{
		"eng-viewer":     "engineering",
		"platform-admin": "engineering/platform",
		"billing-admin":  "billing",
	}
	for _, r := range prog.Roles {
		if got := want[r.Slug]; got != r.NamespacePath {
			t.Errorf("role %s: namespace = %q, want %q", r.Slug, r.NamespacePath, got)
		}
	}
}

func TestParser_TopLevelRelations(t *testing.T) {
	src := `
warden config 1

relation document:welcome owner = user:alice
relation document:welcome viewer = group:eng#member
`
	prog := mustParse(t, src)
	if len(prog.Relations) != 2 {
		t.Fatalf("expected 2 relations, got %d", len(prog.Relations))
	}
	r := prog.Relations[1]
	if r.SubjectType != "group" || r.SubjectID != "eng" || r.SubjectRelation != "member" {
		t.Errorf("got %+v", r)
	}
}

func TestParser_Errors(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"missing header", "role viewer {}"},
		{"unclosed role block", "warden config 1\nrole viewer {"},
		{"bad expression", "warden config 1\nresource doc { permission read = }"},
		{"bad effect", `warden config 1
policy "x" { effect = maybe }`},
		{"unknown char in expression", "warden config 1\nresource doc { permission read = @ }"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := Parse("test.warden", []byte(tt.src))
			if len(errs) == 0 {
				t.Fatalf("expected at least one parse error, got none")
			}
		})
	}
}

func TestParser_PolicySubjects(t *testing.T) {
	prog := mustParse(t, `
warden config 1

policy "p" {
    effect = allow
    subjects = [
        { kind = "user" },
        { id = "alice" },
        { role = "admin" },
        { kind = "user", id = "bob", role = "temp" },
        { kind = "service" id = "ci" },
        {},
    ]
}

policy "none" {
    effect = allow
}
`)
	want := []SubjectMatchDecl{
		{Kind: "user"},
		{ID: "alice"},
		{Role: "admin"},
		{Kind: "user", ID: "bob", Role: "temp"},
		{Kind: "service", ID: "ci"},
		{},
	}
	got := prog.Policies[0].Subjects
	if len(got) != len(want) {
		t.Fatalf("subjects = %d matchers, want %d", len(got), len(want))
	}
	for i, m := range got {
		if m.Kind != want[i].Kind || m.ID != want[i].ID || m.Role != want[i].Role {
			t.Errorf("matcher %d = %+v, want %+v", i, *m, want[i])
		}
		if m.Pos.Line == 0 {
			t.Errorf("matcher %d has no position", i)
		}
	}
	if prog.Policies[1].Subjects != nil {
		t.Errorf("a policy without a subjects clause has subjects %v", prog.Policies[1].Subjects)
	}
}

func TestParser_SubjectsErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"unknown field", `subjects = [{ name = "x" }]`, `unknown subject matcher field "name"`},
		{"not a string", `subjects = [{ kind = user }]`, "expected a string after kind ="},
		{"not a matcher", `subjects = ["user:alice"]`, "expected a subject matcher"},
		{"a field twice", `subjects = [{ id = "a", id = "b" }]`, `field "id" is given twice`},
		{"no list", `subjects = { kind = "user" }`, "expected `[` to open the subjects list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "warden config 1\npolicy \"p\" {\n    effect = allow\n    " + tc.body + "\n}\n"
			_, errs := Parse("t.warden", []byte(src))
			found := false
			for _, e := range errs {
				if strings.Contains(e.Msg, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("want a diagnostic containing %q, got %v", tc.want, errs)
			}
		})
	}
}

func TestParser_QuotedNames(t *testing.T) {
	prog := mustParse(t, `
warden config 1
tenant "0f3a-tenant"
app "my app"

resource "role" {
    relation "name": "user:*" | group#"member of"
    relation "on call":
    relation watcher: user
    permission "manage it" = watcher
}

permission "warden:role:read" {
    resource = "warden:role"
    action = read
}
permission "warden:*" ("warden" : "*")

role "Auditor Team" : "Base Role" {
    name = "Auditors"
}
role "Base Role" {
    name = "Base"
}

relation "role":"3f2a" "name" = user:"bob@example.com"#"member of"
`)
	if prog.Tenant != "0f3a-tenant" || prog.App != "my app" {
		t.Errorf("header = %q / %q", prog.Tenant, prog.App)
	}
	rt := prog.ResourceTypes[0]
	if rt.Name != "role" || rt.Relations[0].Name != "name" {
		t.Errorf("resource = %q, first relation %q", rt.Name, rt.Relations[0].Name)
	}
	subj := rt.Relations[0].AllowedSubjects
	if len(subj) != 2 || subj[0].Type != "user:*" || subj[1].Type != "group" || subj[1].Relation != "member of" {
		t.Errorf("allowed subjects = %+v", subj)
	}
	if rt.Relations[1].Name != "on call" || len(rt.Relations[1].AllowedSubjects) != 0 {
		t.Errorf("a relation with no subject types parsed as %+v", rt.Relations[1])
	}
	if rt.Permissions[0].Name != "manage it" {
		t.Errorf("resource permission name = %q", rt.Permissions[0].Name)
	}
	p := prog.Permissions[0]
	if p.Resource != "warden:role" || p.Action != "read" {
		t.Errorf("warden:role:read parsed as resource %q action %q", p.Resource, p.Action)
	}
	if g := prog.Permissions[1]; g.Resource != "warden" || g.Action != "*" {
		t.Errorf("warden:* parsed as resource %q action %q", g.Resource, g.Action)
	}
	if r := prog.Roles[0]; r.Slug != "Auditor Team" || r.Parent != "Base Role" {
		t.Errorf("role = %q parent %q", r.Slug, r.Parent)
	}
	rel := prog.Relations[0]
	if rel.ObjectType != "role" || rel.ObjectID != "3f2a" || rel.Relation != "name" ||
		rel.SubjectType != "user" || rel.SubjectID != "bob@example.com" || rel.SubjectRelation != "member of" {
		t.Errorf("tuple = %+v", *rel)
	}
}

func TestParser_Grants(t *testing.T) {
	prog := mustParse(t, `
warden config 1
role a {
    grants = ["doc:read", { namespace = "eng", name = "deploy:run" }, { namespace = "", name = "doc:write" }]
}
role b {
    grants = []
}
role c {
    name = "C"
}
`)
	a := prog.Roles[0]
	if len(a.Grants) != 1 || a.Grants[0] != "doc:read" {
		t.Errorf("plain grants = %v", a.Grants)
	}
	if len(a.QualifiedGrants) != 2 ||
		a.QualifiedGrants[0].NamespacePath != "eng" || a.QualifiedGrants[0].Name != "deploy:run" ||
		a.QualifiedGrants[1].NamespacePath != "" || a.QualifiedGrants[1].Name != "doc:write" {
		t.Errorf("qualified grants = %+v %+v", a.QualifiedGrants[0], a.QualifiedGrants[1])
	}
	if !a.GrantsSet || !prog.Roles[1].GrantsSet {
		t.Error("a grants clause, even an empty one, sets GrantsSet")
	}
	if prog.Roles[2].GrantsSet {
		t.Error("a role without a grants clause has GrantsSet")
	}

	_, errs := Parse("t.warden", []byte("warden config 1\nrole a {\n    grants = [{ namespace = \"eng\" }]\n}\n"))
	if len(errs) == 0 || !strings.Contains(errs[0].Msg, "needs a name") {
		t.Errorf("a qualified grant without a name: %v", errs)
	}
}

func TestParser_ConditionValues(t *testing.T) {
	prog := mustParse(t, `
warden config 1
policy "p" {
    effect = deny
    when {
        context.risk > 0.75
        context.score <= -3
        context.drift >= -0.5
        subject.attributes.level in [1, 2]
        subject.attributes.mixed in ["a", 1, true]
        context.ip ip_in_cidr ["10.0.0.0/8"]
        subject.name exists
        "subject.attributes[\"team name\"]" == "core"
        resource.owner exists true
        subject.role not exists
        resource.description != "x"
    }
}
`)
	conds := prog.Policies[0].Conditions
	want := []struct {
		field, op string
		value     any
	}{
		{"context.risk", "gt", 0.75},
		{"context.score", "lte", -3},
		{"context.drift", "gte", -0.5},
		{"subject.attributes.level", "in", []any{1, 2}},
		{"subject.attributes.mixed", "in", []any{"a", 1, true}},
		{"context.ip", "ip_in_cidr", []string{"10.0.0.0/8"}},
		// No value: the next condition starts on its own line, even though
		// it starts with a string.
		{"subject.name", "exists", nil},
		{`subject.attributes["team name"]`, "eq", "core"},
		// A value on the operator's own line is read.
		{"resource.owner", "exists", true},
		{"subject.role", "not_exists", nil},
		{"resource.description", "neq", "x"},
	}
	if len(conds) != len(want) {
		t.Fatalf("conditions = %d, want %d", len(conds), len(want))
	}
	for i, w := range want {
		c := conds[i]
		if c.Field != w.field || c.Operator != w.op || !reflect.DeepEqual(c.Value, w.value) {
			t.Errorf("condition %d = %q %s %#v, want %q %s %#v", i, c.Field, c.Operator, c.Value, w.field, w.op, w.value)
		}
	}
}
