package dsl

import (
	"context"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/store/memory"
)

func newTestEngine(t *testing.T) (*warden.Engine, *memory.Store) {
	t.Helper()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, s
}

func TestApply_FullProgram(t *testing.T) {
	src := `
warden config 1
tenant t1

resource document {
    relation owner: user
    relation editor: user
    relation viewer: user
    permission read = viewer or editor or owner
    permission edit = editor or owner
    permission delete = owner
}

permission "document:read"   (document : read)
permission "document:write"  (document : edit)
permission "document:delete" (document : delete)

role viewer {
    name = "Viewer"
    grants = ["document:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["document:write"]
}

role admin : editor {
    name = "Administrator"
    grants += ["document:delete"]
}

policy "business-hours" {
    effect = allow
    priority = 100
    active = true
    actions = ["edit", "delete"]
    resources = ["document"]
    when {
        context.time time_after "09:00:00Z"
    }
}
`
	prog, errs := Parse("test.warden", []byte(src))
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("parse error: %s", e)
		}
		t.FailNow()
	}
	eng, _ := newTestEngine(t)
	ctx := context.Background()
	result, err := Apply(ctx, eng, prog, ApplyOptions{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Expect: 1 resource type + 3 perm catalog entries + 3 roles + 1 policy = 8 creates.
	if len(result.Created) != 8 {
		t.Errorf("expected 8 created entries, got %d: %v", len(result.Created), result.Created)
	}
	if result.NoOps != 0 {
		t.Errorf("first apply should have no no-ops, got %d", result.NoOps)
	}

	// Apply again — should be entirely no-ops.
	prog2, _ := Parse("test.warden", []byte(src))
	result2, err := Apply(ctx, eng, prog2, ApplyOptions{})
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(result2.Created) != 0 || len(result2.Updated) != 0 {
		t.Errorf("idempotency failure: created=%v updated=%v", result2.Created, result2.Updated)
	}
}

func TestApply_RBACFlow(t *testing.T) {
	src := `
warden config 1
tenant t1

permission "document:read"   (document : read)
permission "document:write"  (document : write)

role viewer {
    name = "Viewer"
    grants = ["document:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["document:write"]
}
`
	prog, _ := Parse("test.warden", []byte(src))
	eng, s := newTestEngine(t)
	ctx := context.Background()
	if _, err := Apply(ctx, eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Verify the engine sees the role hierarchy by running a Check.
	// We need an assignment first.
	editor, err := s.GetRoleBySlug(ctx, "t1", "editor")
	if err != nil || editor == nil {
		t.Fatalf("editor role not created: %v", err)
	}

	// Manual assignment — DSL doesn't model assignments yet; that's runtime.
	tenantCtx := warden.WithTenant(context.Background(), "", "t1")
	if err := s.CreateAssignment(tenantCtx, &assignment.Assignment{
		ID:          id.NewAssignmentID(),
		TenantID:    "t1",
		RoleID:      editor.ID,
		SubjectKind: "user",
		SubjectID:   "u1",
	}); err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}

	// Editor inherits viewer → user can read.
	result, err := eng.Check(tenantCtx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "u1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("expected allow via inheritance, got %s: %s", result.Decision, result.Reason)
	}
}

func TestApply_RolesToposorted(t *testing.T) {
	// admin appears before its parent editor in source — applier must order them.
	src := `
warden config 1
tenant t1

permission "doc:read"  (doc : read)
permission "doc:write" (doc : write)
permission "doc:del"   (doc : del)

role admin : editor {
    name = "Admin"
    grants = ["doc:del"]
}

role editor : viewer {
    name = "Editor"
    grants = ["doc:write"]
}

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}
`
	prog, _ := Parse("test.warden", []byte(src))
	eng, _ := newTestEngine(t)
	ctx := context.Background()
	if _, err := Apply(ctx, eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

func TestApply_DryRunNoWrites(t *testing.T) {
	src := `
warden config 1
tenant t1

permission "doc:read" (doc : read)
role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}
`
	prog, _ := Parse("test.warden", []byte(src))
	eng, s := newTestEngine(t)
	ctx := context.Background()
	result, err := Apply(ctx, eng, prog, ApplyOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run apply: %v", err)
	}
	if len(result.Created) == 0 {
		t.Errorf("expected planned creates in dry-run output")
	}
	// Verify nothing was actually created.
	if _, err := s.GetRoleBySlug(ctx, "t1", "viewer"); err == nil {
		t.Errorf("dry-run should not have written role")
	}
}

func TestApply_Prune(t *testing.T) {
	// First apply creates "legacy" role.
	prog1, _ := Parse("test.warden", []byte(`
warden config 1
tenant t1
permission "x:y" (x : y)
role legacy {
    name = "Legacy"
    grants = ["x:y"]
}
`))
	eng, s := newTestEngine(t)
	ctx := context.Background()
	if _, err := Apply(ctx, eng, prog1, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}

	// Second apply omits "legacy". With Prune=true it should be deleted.
	prog2, _ := Parse("test.warden", []byte(`
warden config 1
tenant t1
permission "x:y" (x : y)
role current {
    name = "Current"
    grants = ["x:y"]
}
`))
	if _, err := Apply(ctx, eng, prog2, ApplyOptions{Prune: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRoleBySlug(ctx, "t1", "legacy"); err == nil {
		t.Fatalf("prune should have deleted legacy role")
	}
}

func TestApply_MissingTenantErrors(t *testing.T) {
	prog, _ := Parse("test.warden", []byte("warden config 1\n"))
	eng, _ := newTestEngine(t)
	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{}); err == nil {
		t.Fatal("expected missing-tenant error")
	} else if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("expected tenant error, got %v", err)
	}
}

func TestApply_ResolveErrorsBubbleUp(t *testing.T) {
	prog, _ := Parse("test.warden", []byte(`
warden config 1
tenant t1
role editor : ghost {
    name = "Editor"
}
`))
	eng, _ := newTestEngine(t)
	_, err := Apply(context.Background(), eng, prog, ApplyOptions{})
	if err == nil {
		t.Fatal("expected resolve error to bubble up")
	}
	if !strings.Contains(err.Error(), "unknown parent") {
		t.Errorf("got %v", err)
	}
}

