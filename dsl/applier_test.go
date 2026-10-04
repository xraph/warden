package dsl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
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
        context.time time_after "2026-01-01T09:00:00Z"
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

// TestApply_DryRunGrantsResolveLikeTheRealApply: a dry run must accept and
// refuse the same grants the real apply does, and report an unknown grant as
// a diagnostic at the role.
func TestApply_DryRunGrantsResolveLikeTheRealApply(t *testing.T) {
	ctx := context.Background()
	const eng = `namespace "eng" {
    role lead {
        name = "lead"
        grants = ["doc:read"]
    }
}
`
	parse := func(t *testing.T, src string) *Program {
		t.Helper()
		prog, errs := Parse("g.warden", []byte(src))
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return prog
	}

	for _, tc := range []struct {
		name string
		src  string
		ok   bool
	}{
		{"a typo", "warden config 1\ntenant t1\npermission \"doc:read\" (doc : read)\nrole r {\n    grants = [\"nope:x\"]\n}\n", false},
		{"a child role granting a root permission", "warden config 1\ntenant t1\npermission \"doc:read\" (doc : read)\n" + eng, true},
		{"a permission in a sibling namespace", "warden config 1\ntenant t1\nnamespace \"ops\" {\n    permission \"doc:read\" (doc : read)\n}\n" + eng, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog := parse(t, tc.src)

			e1, _ := newTestEngine(t)
			_, dryErr := Apply(ctx, e1, prog, ApplyOptions{DryRun: true})
			e2, _ := newTestEngine(t)
			_, realErr := Apply(ctx, e2, prog, ApplyOptions{})

			if (dryErr == nil) != tc.ok || (realErr == nil) != tc.ok {
				t.Fatalf("dry run err = %v, real apply err = %v, want success = %v", dryErr, realErr, tc.ok)
			}
			if tc.ok {
				return
			}
			for name, err := range map[string]error{"dry run": dryErr, "real apply": realErr} {
				var derr *DiagnosticError
				if !errors.As(err, &derr) || len(derr.Diags) != 1 || !strings.Contains(derr.Diags[0].Msg, "grants unknown permission") {
					t.Errorf("%s: want one unknown-grant diagnostic, got %v", name, err)
					continue
				}
				if derr.Diags[0].Pos.Line == 0 {
					t.Errorf("%s: the diagnostic has no position", name)
				}
			}
		})
	}
}

// TestApply_GrantsClauseOwnsTheGrantSet pins what a grants clause means: a
// role with one (even `grants = []`) gets exactly that set, and a role
// without one keeps whatever it had.
func TestApply_GrantsClauseOwnsTheGrantSet(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)
	apply := func(src string) *ApplyResult {
		t.Helper()
		prog := mustParse(t, src)
		res, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1"})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		return res
	}
	grantsOf := func(slug string) []string {
		t.Helper()
		r, err := s.GetRoleBySlug(ctx, "t1", "", slug)
		if err != nil {
			t.Fatal(err)
		}
		ps, err := s.ListRolePermissions(ctx, "t1", r.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(ps))
		for _, p := range ps {
			out = append(out, p.Name)
		}
		sort.Strings(out)
		return out
	}
	const perms = "warden config 1\npermission \"doc:read\" (doc : read)\npermission \"doc:write\" (doc : write)\n"

	apply(perms + "role a {\n    grants = [\"doc:read\", \"doc:write\"]\n}\nrole b {\n    grants = [\"doc:read\"]\n}\n")

	res := apply(perms + "role a {\n    grants = []\n}\nrole b {\n    name = \"b\"\n}\n")
	if got := grantsOf("a"); len(got) != 0 {
		t.Errorf("grants = [] left %v", got)
	}
	if got := grantsOf("b"); len(got) != 1 || got[0] != "doc:read" {
		t.Errorf("a role without a grants clause lost its grants: %v", got)
	}
	if !contains(res.Updated, "~ role//a (grants)") {
		t.Errorf("clearing the grants is not reported: %v", res.Updated)
	}
	for _, line := range res.Updated {
		if strings.HasPrefix(line, "~ role//b") {
			t.Errorf("a role without a grants clause is reported as changed: %s", line)
		}
	}
}

func contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestApply_QualifiedGrantsReachWhatANameCannot checks a qualified grant
// reaches a sibling namespace's permission and a shadowed root one, and
// that one naming nothing is a diagnostic at the grant.
func TestApply_QualifiedGrantsReachWhatANameCannot(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)
	prog := mustParse(t, `warden config 1
permission "doc:read" (doc : read)
namespace "eng" {
    permission "doc:read" (doc : read)
    role dev {
        grants = ["doc:read", { namespace = "", name = "doc:read" }, { namespace = "ops", name = "page:send" }]
    }
}
namespace "ops" {
    permission "page:send" (page : send)
}
`)
	if _, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	dev, err := s.GetRoleBySlug(ctx, "t1", "eng", "dev")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := s.ListRolePermissions(ctx, "t1", dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(ps))
	for _, p := range ps {
		got = append(got, p.NamespacePath+"/"+p.Name)
	}
	sort.Strings(got)
	want := []string{"/doc:read", "eng/doc:read", "ops/page:send"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("grants = %v, want %v", got, want)
	}

	bad := mustParse(t, "warden config 1\nrole r {\n    grants = [{ namespace = \"eng\", name = \"nope:x\" }]\n}\n")
	for _, dry := range []bool{true, false} {
		e2, _ := newTestEngine(t)
		_, err := Apply(ctx, e2, bad, ApplyOptions{TenantID: "t1", DryRun: dry})
		var derr *DiagnosticError
		if !errors.As(err, &derr) || len(derr.Diags) != 1 ||
			!strings.Contains(derr.Diags[0].Msg, `grants unknown permission "nope:x" in namespace "eng"`) || derr.Diags[0].Pos.Line != 3 {
			t.Errorf("dry=%t: want one positioned diagnostic at the grant, got %v", dry, err)
		}
	}
}

// TestApply_UnknownGrantStopsBeforeAnyWrite checks a real apply refuses an
// unknown grant before it writes anything, as the dry run does.
func TestApply_UnknownGrantStopsBeforeAnyWrite(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)
	prog := mustParse(t, "warden config 1\npermission \"doc:read\" (doc : read)\nrole r {\n    grants = [\"typo:x\"]\n}\n")
	if _, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1"}); err == nil {
		t.Fatal("an unknown grant applied")
	}
	ps, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Errorf("the refused apply wrote %d permissions", len(ps))
	}
}

// TestApply_UpdateKeepsWhatTheLanguageDoesNotExpress checks an update
// leaves metadata and the app id alone when the source cannot mean to
// change them.
func TestApply_UpdateKeepsWhatTheLanguageDoesNotExpress(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)
	src := "warden config 1\npermission \"doc:read\" (doc : read)\nrole r {\n    name = \"R\"\n}\npolicy \"p\" {\n    effect = allow\n}\n"
	if _, err := Apply(ctx, eng, mustParse(t, src), ApplyOptions{TenantID: "t1", AppID: "app1"}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetRoleBySlug(ctx, "t1", "", "r")
	r.Metadata = map[string]any{"team": "core"}
	if err := s.UpdateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetPolicyByName(ctx, "t1", "", "p")
	p.Metadata = map[string]any{"ticket": "SEC-1"}
	if err := s.UpdatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	edited := strings.Replace(strings.Replace(src, `"R"`, `"Renamed"`, 1), "effect = allow", "effect = deny", 1)
	res, err := Apply(ctx, eng, mustParse(t, edited), ApplyOptions{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Updated, "~ role//r (name)") || !contains(res.Updated, "~ policy//p (effect)") {
		t.Fatalf("updated = %v", res.Updated)
	}
	r, _ = s.GetRoleBySlug(ctx, "t1", "", "r")
	if r.Name != "Renamed" || r.Metadata["team"] != "core" || r.AppID != "app1" {
		t.Errorf("role after update: name %q metadata %v app %q", r.Name, r.Metadata, r.AppID)
	}
	p, _ = s.GetPolicyByName(ctx, "t1", "", "p")
	if p.Effect != "deny" || p.Metadata["ticket"] != "SEC-1" || p.AppID != "app1" {
		t.Errorf("policy after update: effect %q metadata %v app %q", p.Effect, p.Metadata, p.AppID)
	}
}

// TestApply_StorableConditionGroupsRoundTrip checks the grouping shapes
// Resolve accepts are stored exactly: all_of at any depth (an AND) and a
// one-condition any_of (just that condition). Before, a group nested in
// all_of was dropped entirely.
func TestApply_StorableConditionGroupsRoundTrip(t *testing.T) {
	ctx := context.Background()
	eng, s := newTestEngine(t)
	prog := mustParse(t, `warden config 1
policy "p" {
    effect = deny
    when {
        subject.a == "1"
        all_of {
            subject.b == "2"
            all_of {
                subject.c == "3"
            }
            any_of {
                subject.d == "4"
            }
        }
        any_of {
            all_of {
                subject.e == "5"
                subject.f == "6"
            }
        }
        all_of {}
    }
}
`)
	if _, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	p, err := s.GetPolicyByName(ctx, "t1", "", "p")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(p.Conditions))
	for _, c := range p.Conditions {
		got = append(got, fmt.Sprintf("%s %s %v", c.Field, c.Operator, c.Value))
	}
	want := []string{"subject.a eq 1", "subject.b eq 2", "subject.c eq 3", "subject.d eq 4", "subject.e eq 5", "subject.f eq 6"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Fatalf("stored conditions = %v, want %v", got, want)
	}

	// Planning the same source again is a no-op, so the flattened store
	// and the grouped source agree.
	res, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updated) != 0 {
		t.Fatalf("re-planning the grouped source reports %v", res.Updated)
	}
}

// TestApply_RefusedConditionsWriteNothing checks a refused shape stops the
// apply before any write.
func TestApply_RefusedConditionsWriteNothing(t *testing.T) {
	ctx := context.Background()
	for _, when := range []string{`subject.a == "x" negate`, "any_of {\n subject.a == \"x\"\n subject.b == \"y\"\n}"} {
		eng, s := newTestEngine(t)
		prog := mustParse(t, "warden config 1\npolicy \"p\" {\n    effect = deny\n    when {\n"+when+"\n    }\n}\n")
		_, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1"})
		var derr *DiagnosticError
		if !errors.As(err, &derr) {
			t.Fatalf("%q: want a diagnostic, got %v", when, err)
		}
		if _, err := s.GetPolicyByName(ctx, "t1", "", "p"); err == nil {
			t.Errorf("%q: the refused policy was stored", when)
		}
	}
}

// failPolicyStore fails every policy create and delegates the rest.
type failPolicyStore struct{ *memory.Store }

func (failPolicyStore) CreatePolicy(context.Context, *policy.Policy) error {
	return errors.New("disk full")
}

// TestApply_FailureReturnsWhatWasWritten: the store has no transaction, so a
// failure part way leaves earlier writes in place. Apply returns the partial
// result with the error, and it lists only what was written: the entity whose
// write failed, and everything after it, are not in it.
func TestApply_FailureReturnsWhatWasWritten(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(failPolicyStore{s}))
	if err != nil {
		t.Fatal(err)
	}
	prog, errs := Parse("p.warden", []byte(`warden config 1
tenant t1
permission "doc:read" (doc : read)
role reader {
    name = "Reader"
    grants = ["doc:read"]
}
policy "freeze" {
    effect = deny
    active = true
}
relation doc:readme viewer = user:alice
`))
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	res, err := Apply(ctx, eng, prog, ApplyOptions{})
	if err == nil {
		t.Fatal("want the policy write to fail")
	}
	if res == nil {
		t.Fatal("a failed write returned no partial result")
	}
	if strings.Join(res.Created, "|") != "+ permission//doc:read|+ role//reader" {
		t.Errorf("created = %v, want the permission and the role only", res.Created)
	}
	if _, err := s.GetRoleBySlug(ctx, "t1", "", "reader"); err != nil {
		t.Errorf("the role written before the failure is gone: %v", err)
	}

	// An error raised before any write carries no result.
	bad, _ := Parse("b.warden", []byte("warden config 1\nrole r : ghost {\n}\n"))
	if res, err := Apply(ctx, eng, bad, ApplyOptions{TenantID: "t1"}); err == nil || res != nil {
		t.Errorf("a diagnostic should return (nil, err), got %v, %v", res, err)
	}
}
