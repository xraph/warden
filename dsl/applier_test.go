package dsl

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
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
	editor, err := s.GetRoleBySlug(ctx, "t1", "", "editor")
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
	if _, err := s.GetRoleBySlug(ctx, "t1", "", "viewer"); err == nil {
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
	if _, err := s.GetRoleBySlug(ctx, "t1", "", "legacy"); err == nil {
		t.Fatalf("prune should have deleted legacy role")
	}
}

// TestApply_PruneRefusesEmptyTenant guards against a Prune=true apply with
// no tenant set (neither opts.TenantID nor `tenant` in source) deleting
// every entity in the shared global (tenant-less) scope: a single-tenant
// app's whole dataset, since Apply without a tenant writes there by
// design (see TestApply_NoTenantAppliesToGlobalScope).
func TestApply_PruneRefusesEmptyTenant(t *testing.T) {
	prog, _ := Parse("test.warden", []byte(`
warden config 1
permission "x:y" (x : y)
role current {
    name = "Current"
    grants = ["x:y"]
}
`))
	eng, _ := newTestEngine(t)
	ctx := context.Background()

	_, err := Apply(ctx, eng, prog, ApplyOptions{Prune: true})
	if err == nil {
		t.Fatal("expected Apply to refuse Prune with no tenant set")
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("expected error to mention tenant, got: %v", err)
	}
}

// TestApply_NoTenantAppliesToGlobalScope pins the optional-tenant
// behavior: source without a `tenant` declaration and no
// opts.TenantID applies cleanly to the empty-string tenant (global
// scope). Single-tenant apps that never call warden.WithTenant rely
// on this — every Check the engine runs uses an empty tenant_id too,
// so it all matches.
func TestApply_NoTenantAppliesToGlobalScope(t *testing.T) {
	prog, _ := Parse("test.warden", []byte(`
warden config 1

permission "doc:read" (document : read)

role viewer {
  name   = "Viewer"
  grants = ["doc:read"]
}
`))
	ctx := context.Background()
	eng, s := newTestEngine(t)

	res, err := Apply(ctx, eng, prog, ApplyOptions{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(res.Created) == 0 {
		t.Fatal("expected entries created")
	}

	// The role landed under tenant "" (global). Confirm by reading via
	// the same scope.
	r, err := s.GetRoleBySlug(ctx, "", "", "viewer")
	if err != nil {
		t.Fatalf("GetRoleBySlug(\"\"): %v", err)
	}
	if r.TenantID != "" {
		t.Errorf("role.TenantID = %q, want empty (global scope)", r.TenantID)
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

// recordingAuditPlugin implements plugin.Plugin and plugin.Audit,
// recording every event it's handed.
type recordingAuditPlugin struct {
	events []plugin.Event
}

func (p *recordingAuditPlugin) Name() string { return "recording-audit" }

func (p *recordingAuditPlugin) OnAudit(_ context.Context, ev plugin.Event) error {
	p.events = append(p.events, ev)
	return nil
}

func TestApply_SetsDeclarativeActorAndEmitsAudit(t *testing.T) {
	src := `
warden config 1
tenant t1

permission "doc:read" (document : read)
role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}
`
	prog, errs := Parse("test.warden", []byte(src))
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	s := memory.New()
	rec := &recordingAuditPlugin{}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(rec))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	if _, err := Apply(ctx, eng, prog, ApplyOptions{}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	r, err := s.GetRoleBySlug(ctx, "t1", "", "viewer")
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if r.CreatedBy != warden.SystemActor.ID {
		t.Errorf("role.CreatedBy = %q, want %q", r.CreatedBy, warden.SystemActor.ID)
	}
	if r.UpdatedBy != warden.SystemActor.ID {
		t.Errorf("role.UpdatedBy = %q, want %q", r.UpdatedBy, warden.SystemActor.ID)
	}

	p, err := s.GetPermissionByName(ctx, "t1", "", "doc:read")
	if err != nil {
		t.Fatalf("GetPermissionByName: %v", err)
	}
	if p.CreatedBy != warden.SystemActor.ID {
		t.Errorf("permission.CreatedBy = %q, want %q", p.CreatedBy, warden.SystemActor.ID)
	}

	if len(rec.events) != 2 {
		t.Fatalf("expected 2 audit events (permission.created, role.created), got %d: %+v", len(rec.events), rec.events)
	}
	seenActions := map[string]bool{}
	for _, ev := range rec.events {
		seenActions[ev.Action] = true
		actor, ok := ev.Actor.(warden.Actor)
		if !ok {
			t.Fatalf("event Actor is not a warden.Actor: %+v", ev.Actor)
		}
		if actor.Via != "declarative" {
			t.Errorf("event %s: Actor.Via = %q, want %q", ev.Action, actor.Via, "declarative")
		}
		if actor.Kind != warden.SystemActor.Kind || actor.ID != warden.SystemActor.ID {
			t.Errorf("event %s: Actor = %+v, want Kind/ID matching warden.SystemActor", ev.Action, actor)
		}
		if ev.TenantID != "t1" {
			t.Errorf("event %s: TenantID = %q, want %q", ev.Action, ev.TenantID, "t1")
		}
	}
	if !seenActions["role.created"] || !seenActions["permission.created"] {
		t.Errorf("missing expected actions, got %+v", seenActions)
	}
}

func TestApply_DryRunEmitsNoAudit(t *testing.T) {
	prog, errs := Parse("test.warden", []byte(`
warden config 1
tenant t1

permission "doc:read" (document : read)
role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}
`))
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}

	s := memory.New()
	rec := &recordingAuditPlugin{}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(rec))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if _, err := Apply(context.Background(), eng, prog, ApplyOptions{DryRun: true}); err != nil {
		t.Fatalf("dry-run apply: %v", err)
	}
	if len(rec.events) != 0 {
		t.Errorf("dry run must not emit audit events, got %d: %+v", len(rec.events), rec.events)
	}
}

// TestApply_PruneIsScopedToCoveredNamespaces: a namespace is covered when
// the program declares something in it (an entity or a block, even an empty
// one). Prune never reaches an entity in a namespace the program does not
// mention, and coverage is exact rather than a prefix.
func TestApply_PruneIsScopedToCoveredNamespaces(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)

	seed, errs := Parse("seed.warden", []byte(`
warden config 1
tenant t1
role root-keep { name = "root-keep" }
role root-drop { name = "root-drop" }
namespace "eng" {
    role eng-keep { name = "eng-keep" }
    role eng-drop { name = "eng-drop" }
    namespace "platform" {
        role platform-drop { name = "platform-drop" }
    }
}
namespace "ops" {
    role ops-drop { name = "ops-drop" }
}
namespace "legal" {
    role legal-drop { name = "legal-drop" }
}
`))
	if len(errs) > 0 {
		t.Fatalf("parse seed: %v", errs)
	}
	if _, err := Apply(ctx, eng, seed, ApplyOptions{}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Covers the root (root-keep), eng (eng-keep) and ops (an empty block).
	// It says nothing about eng/platform or legal.
	src, errs := Parse("edit.warden", []byte(`
warden config 1
tenant t1
role root-keep { name = "root-keep" }
namespace "eng" {
    role eng-keep { name = "eng-keep" }
}
namespace "ops" {
}
`))
	if len(errs) > 0 {
		t.Fatalf("parse edit: %v", errs)
	}

	res, err := Apply(ctx, eng, src, ApplyOptions{Prune: true, DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	want := []string{"- role//root-drop", "- role/eng/eng-drop", "- role/ops/ops-drop"}
	sort.Strings(res.Deleted)
	sort.Strings(want)
	if strings.Join(res.Deleted, "|") != strings.Join(want, "|") {
		t.Errorf("deleted = %v, want %v", res.Deleted, want)
	}

	if _, err := Apply(ctx, eng, src, ApplyOptions{Prune: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, gone := range []struct{ ns, slug string }{{"", "root-drop"}, {"eng", "eng-drop"}, {"ops", "ops-drop"}} {
		if _, err := s.GetRoleBySlug(ctx, "t1", gone.ns, gone.slug); err == nil {
			t.Errorf("role %s/%s survived the prune", gone.ns, gone.slug)
		}
	}
	for _, kept := range []struct{ ns, slug string }{{"eng/platform", "platform-drop"}, {"legal", "legal-drop"}, {"", "root-keep"}, {"eng", "eng-keep"}} {
		if _, err := s.GetRoleBySlug(ctx, "t1", kept.ns, kept.slug); err != nil {
			t.Errorf("role %s/%s was pruned or lost: %v", kept.ns, kept.slug, err)
		}
	}
}
