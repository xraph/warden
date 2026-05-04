package dsl

import (
	"strings"
	"testing"
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

func TestResolve_AncestorParentInDifferentNamespace(t *testing.T) {
	src := `
warden config 1
role super-admin {
    name = "Super"
}
namespace "engineering" {
    role admin : super-admin {
        name = "Eng Admin"
    }
}
`
	errs := resolveSrc(t, src)
	if len(errs) > 0 {
		t.Fatalf("expected ancestor parent to resolve, got: %v", errs)
	}
}

func TestResolve_AbsoluteParentPath(t *testing.T) {
	src := `
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
`
	errs := resolveSrc(t, src)
	if len(errs) > 0 {
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

func TestResolve_BadSlugRegex(t *testing.T) {
	src := `
warden config 1
role Viewer {
    name = "Bad"
}
`
	errs := resolveSrc(t, src)
	wantDiagContaining(t, errs, "must match")
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
