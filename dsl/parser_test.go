package dsl

import (
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
