package dsl

import (
	"context"
	"strings"
	"testing"

	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

func resolveSrc(t *testing.T, src string) []*Diagnostic {
	t.Helper()
	prog, parseErrs := Parse("test.warden", []byte(src))
	if len(parseErrs) > 0 {
		for _, e := range parseErrs {
			t.Logf("parse error: %s", e)
		}
		// Continue anyway; Resolve should still run on best-effort AST.
	}
	return Resolve(prog)
}

func wantDiagContaining(t *testing.T, errs []*Diagnostic, sub string) {
	t.Helper()
	for _, e := range errs {
		if strings.Contains(e.Msg, sub) {
			return
		}
	}
	t.Fatalf("expected diagnostic containing %q, got: %v", sub, errs)
}

func TestResolve_HappyPath(t *testing.T) {
	src := `
warden config 1
tenant t1

resource document {
    relation owner: user
    relation editor: user
    relation viewer: user
    permission read = viewer or editor or owner
}

permission "document:read"  (document : read)
permission "document:write" (document : write)

role viewer {
    name = "Viewer"
    grants = ["document:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["document:write"]
}
`
	errs := resolveSrc(t, src)
	if len(errs) > 0 {
		t.Fatalf("expected no diagnostics, got %v", errs)
	}
}

func TestResolve_DuplicateRole(t *testing.T) {
	src := `
warden config 1
role viewer { name = "A" }
role viewer { name = "B" }
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "already declared")
}

func TestResolve_UnknownParent(t *testing.T) {
	src := `
warden config 1
role editor : ghost {
    name = "Editor"
}
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "unknown parent")
}

// The engine looks a parent up only in the role's own namespace (the store
// keeps the slug alone), so a parent the source finds in an ancestor or
// through an absolute path to another namespace is refused.
func TestResolve_AParentOutsideTheRolesNamespaceIsRefused(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"ancestor", `
warden config 1
role super-admin {
    name = "Super"
}
namespace "engineering" {
    role admin : super-admin {
        name = "Eng Admin"
    }
}
`, `role "admin" names parent "super-admin", which is in namespace "", not the role's own namespace "engineering"; a role inherits only from a parent in its own namespace, so declare the parent there`},
		{"absolute path", `
warden config 1
namespace "engineering" {
    role admin {
        name = "Eng Admin"
    }
}
namespace "billing" {
    role steward : /engineering/admin {
        name = "Billing Steward"
    }
}
`, `role "steward" names parent "/engineering/admin", which is in namespace "engineering", not the role's own namespace "billing"; a role inherits only from a parent in its own namespace, so declare the parent there`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := resolveSrc(t, tc.src)
			if len(errs) != 1 || !strings.HasSuffix(errs[0].String(), tc.want) {
				t.Fatalf("errs = %v\nwant one ending %s", errs, tc.want)
			}
		})
	}
}

// The loop the reviewer found: x names /b/y and y names x. Resolve saw no
// cycle through the cross-namespace edge, and the store would have held
// x <-> y as a loop in namespace a. Now the cross-namespace parent is
// refused and nothing is written.
func TestApply_ACrossNamespaceParentCannotStoreALoop(t *testing.T) {
	src := `
warden config 1
namespace "a" {
    role x : /b/y { name = "X" }
    role y : x { name = "Y" }
}
namespace "b" {
    role y { name = "Other Y" }
}
`
	prog, perrs := Parse("test.warden", []byte(src))
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	errs := Resolve(prog)
	if len(errs) != 1 || !strings.Contains(errs[0].String(), `role "x" names parent "/b/y", which is in namespace "b"`) {
		t.Fatalf("errs = %v", errs)
	}
	s := memory.New()
	if _, err := Apply(context.Background(), engineOverStore(t, s), prog, ApplyOptions{TenantID: "t1"}); err == nil {
		t.Fatal("apply succeeded")
	}
	roles, err := s.ListRoles(context.Background(), &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 0 {
		t.Errorf("stored %d roles, want 0", len(roles))
	}
}

// An absolute path into the role's own namespace names the same role a
// bare slug would, so it is accepted.
func TestResolve_AnAbsoluteParentInTheRolesOwnNamespaceResolves(t *testing.T) {
	src := `
warden config 1
namespace "engineering" {
    role admin {
        name = "Eng Admin"
    }
    role lead : /engineering/admin {
        name = "Lead"
    }
}
`
	if errs := resolveSrc(t, src); len(errs) > 0 {
		t.Fatalf("expected absolute path to resolve, got: %v", errs)
	}
}

func TestResolve_RoleParentCycle(t *testing.T) {
	src := `
warden config 1
role a : b { name = "A" }
role b : a { name = "B" }
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "cycle")
}

func TestResolve_UndeclaredRelationInExpression(t *testing.T) {
	src := `
warden config 1
resource document {
    relation owner: user
    permission read = viewer or owner
}
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "undeclared relation")
}

func TestResolve_TraversalIntoUndeclaredType(t *testing.T) {
	src := `
warden config 1
resource document {
    relation parent: folder
    permission read = parent->view
}
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "undeclared resource type")
}

func TestResolve_TraversalChain(t *testing.T) {
	src := `
warden config 1
resource folder {
    relation owner: user
    relation viewer: user
    permission view = owner or viewer
}
resource document {
    relation parent: folder
    relation owner: user
    permission read = owner or parent->view
}
`
	errs := resolveSrc(t, src)
	if len(errs) > 0 {
		t.Fatalf("expected valid traversal, got %v", errs)
	}
}

// TestResolve_NamesFollowTheStore pins the relaxed name rules: a name is
// valid when the store and the dashboard would accept it, so a tenant's
// names always export to source that resolves.
func TestResolve_NamesFollowTheStore(t *testing.T) {
	accepted := `
warden config 1
role Viewer {
    name = "Upper case slug"
}
role "Auditor Team" {
    name = "A slug with a space"
}
permission "warden:role:read" {
    resource = "warden:role"
    action = read
}
permission "warden:*" {
    resource = "warden"
    action = "*"
}
resource "role" {
    relation "name": user
}
policy "Deny Contractors" {
    effect = deny
}
`
	if errs := resolveSrc(t, accepted); len(errs) > 0 {
		t.Fatalf("names the store accepts were refused: %v", errs)
	}

	for _, tc := range []struct {
		name, src, want string
	}{
		{"empty role slug", "warden config 1\nrole \"\" {\n}\n", "role slug"},
		{"empty resource type name", "warden config 1\nresource \"\" {\n}\n", "resource type name"},
		{"blank policy name", "warden config 1\npolicy \"  \" {\n    effect = allow\n}\n", "policy name"},
		{"permission without an action", "warden config 1\npermission \"doc\"\n", "`<resource>:<action>`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantDiagContaining(t, resolveSrc(t, tc.src), tc.want)
		})
	}
}

func TestResolve_BadNamespacePath(t *testing.T) {
	src := `
warden config 1
namespace "Eng" {
    role admin {
        name = "X"
    }
}
`
	errs := resolveSrc(t, src)
	if len(errs) == 0 {
		t.Fatal("expected diagnostic on uppercase namespace segment")
	}
}

// TestResolve_RefusesConditionsTheStoreCannotHold pins checkConditions: a
// stored policy's conditions are a flat list that must all hold, with no
// negation and no OR, so each shape that would be stored as something else
// is a diagnostic at that condition. So is a condition that stores as
// written but that the evaluator cannot read.
func TestResolve_RefusesConditionsTheStoreCannotHold(t *testing.T) {
	for _, tc := range []struct {
		name, when string
		line       int
		want       string
	}{
		{"negate", `subject.a == "x" negate`, 5, "`negate` cannot be stored"},
		{"negate inside all_of", "all_of {\n            subject.a == \"x\" negate\n        }", 6, "`negate` cannot be stored"},
		{"any_of with two conditions", "any_of {\n            subject.a == \"x\"\n            subject.b == \"y\"\n        }", 5, "any_of with 2 conditions cannot be stored"},
		{"any_of nested in all_of", "all_of {\n            subject.c == \"z\"\n            any_of {\n                subject.a == \"x\"\n                subject.b == \"y\"\n            }\n        }", 7, "any_of with 2 conditions cannot be stored"},
		{"empty any_of", "any_of {}", 5, "an empty any_of can never hold"},
		// policy.ValidateCondition: shapes that store fine but that the
		// evaluator cannot read.
		{"not in given a string", `context.ip not in "10.0.0.1"`, 5, "not_in needs a list of values"},
		{"in given a string", `subject.dept in "eng"`, 5, "in needs a list of values"},
		{"in given a string inside all_of", "all_of {\n            subject.dept in \"eng\"\n        }", 6, "in needs a list of values"},
		{"a time of day", `context.time time_after "09:00:00Z"`, 5, "invalid RFC3339 time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "warden config 1\npolicy \"p\" {\n    effect = deny\n    when {\n        " + tc.when + "\n    }\n}\n"
			errs := resolveSrc(t, src)
			if len(errs) != 1 || !strings.Contains(errs[0].Msg, tc.want) || errs[0].Pos.Line != tc.line {
				t.Fatalf("want one diagnostic at line %d containing %q, got %v\n%s", tc.line, tc.want, errs, src)
			}
		})
	}
}

func TestResolve_AcceptsListsForInAndNotIn(t *testing.T) {
	src := "warden config 1\npolicy \"p\" {\n    effect = deny\n    when {\n        context.ip not in [\"10.0.0.1\", \"10.0.0.2\"]\n        subject.level in [1, 2]\n    }\n}\n"
	if errs := resolveSrc(t, src); len(errs) != 0 {
		t.Fatalf("want no diagnostics, got %v\n%s", errs, src)
	}
}

// The LSP offers a parent by its absolute path into the role's own
// namespace, `/viewer` at the root as well as `/eng/viewer`. Both resolve.
func TestResolve_AbsoluteParentInOwnNamespaceResolves(t *testing.T) {
	src := `
warden config 1
role viewer { name = "Viewer" }
role admin : /viewer { name = "Admin" }
namespace "eng" {
    role viewer { name = "Eng Viewer" }
    role lead : /eng/viewer { name = "Eng Lead" }
}
`
	if errs := resolveSrc(t, src); len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
}
