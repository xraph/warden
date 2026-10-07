package extension

import (
	"context"
	"sync"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/store/memory"
)

// newBootstrappedExtension builds an Extension with a real engine (via
// Register, the same path production code takes) backed by a fresh
// memory store, ready for BootstrapAdmin calls.
func newBootstrappedExtension(t *testing.T, name string) *Extension {
	t.Helper()
	ext := New(WithStore(memory.New()))
	if err := ext.Register(newTestApp(name)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return ext
}

const bootstrapTenant = "t1"

func TestBootstrapAdmin_CreatesRoleAndPermissions(t *testing.T) {
	ext := newBootstrappedExtension(t, "bootstrap-create")
	ctx := context.Background()
	subject := warden.Subject{Kind: warden.SubjectUser, ID: "alice"}

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	st := ext.Engine().Store()

	r, err := st.GetRoleBySlug(ctx, bootstrapTenant, "", bootstrapAdminSlug)
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if !r.IsSystem {
		t.Error("bootstrap role is not IsSystem")
	}
	if r.CreatedBy != warden.SystemActor.ID {
		t.Errorf("role.CreatedBy = %q, want %q", r.CreatedBy, warden.SystemActor.ID)
	}

	// bootstrapPermissions lists 17 entries: 6 manage + read_audit + check
	// (8, matching the REST API's named list), the 6 "read" companions, and
	// the three the dashboard contract's gate adds: warden:maintenance:manage,
	// warden:config:read and warden:overview:read.
	if len(bootstrapPermissions) != 17 {
		t.Fatalf("bootstrapPermissions has %d entries, want 17 (8 manage/check/read_audit + 6 read companions + 3 dashboard); test assertions below assume this", len(bootstrapPermissions))
	}

	perms, err := st.ListRolePermissions(ctx, bootstrapTenant, r.ID)
	if err != nil {
		t.Fatalf("ListRolePermissions: %v", err)
	}
	if len(perms) != len(bootstrapPermissions) {
		t.Fatalf("role has %d granted permissions, want %d: %+v", len(perms), len(bootstrapPermissions), perms)
	}
	wantNames := make(map[string]struct{}, len(bootstrapPermissions))
	for _, bp := range bootstrapPermissions {
		wantNames[bp.name()] = struct{}{}
	}
	for _, p := range perms {
		if _, ok := wantNames[p.Name]; !ok {
			t.Errorf("unexpected granted permission %q", p.Name)
		}
		if p.CreatedBy != warden.SystemActor.ID {
			t.Errorf("permission %q CreatedBy = %q, want %q", p.Name, p.CreatedBy, warden.SystemActor.ID)
		}
	}

	assignments, err := st.ListAssignments(ctx, &assignment.ListFilter{TenantID: bootstrapTenant, RoleID: &r.ID})
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d: %+v", len(assignments), assignments)
	}
	if assignments[0].SubjectID != "alice" || assignments[0].GrantedBy != warden.SystemActor.ID {
		t.Errorf("assignment = %+v, want SubjectID=alice GrantedBy=%s", assignments[0], warden.SystemActor.ID)
	}
}

func TestBootstrapAdmin_SecondCallIsNoOp(t *testing.T) {
	ext := newBootstrappedExtension(t, "bootstrap-idempotent")
	ctx := context.Background()
	subject := warden.Subject{Kind: warden.SubjectUser, ID: "alice"}

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("first BootstrapAdmin: %v", err)
	}
	st := ext.Engine().Store()
	first, err := st.GetRoleBySlug(ctx, bootstrapTenant, "", bootstrapAdminSlug)
	if err != nil {
		t.Fatalf("GetRoleBySlug after first call: %v", err)
	}

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("second BootstrapAdmin: %v", err)
	}
	second, err := st.GetRoleBySlug(ctx, bootstrapTenant, "", bootstrapAdminSlug)
	if err != nil {
		t.Fatalf("GetRoleBySlug after second call: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("role ID changed across calls: %s -> %s", first.ID, second.ID)
	}

	perms, err := st.ListRolePermissions(ctx, bootstrapTenant, second.ID)
	if err != nil {
		t.Fatalf("ListRolePermissions: %v", err)
	}
	if len(perms) != len(bootstrapPermissions) {
		t.Fatalf("after second call: %d granted permissions, want %d (no duplicates)", len(perms), len(bootstrapPermissions))
	}

	assignments, err := st.ListAssignments(ctx, &assignment.ListFilter{TenantID: bootstrapTenant, RoleID: &second.ID})
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("after second call: %d assignments, want 1 (no duplicate assignment)", len(assignments))
	}
}

func TestBootstrapAdmin_SecondSubjectAddsAssignmentOnly(t *testing.T) {
	ext := newBootstrappedExtension(t, "bootstrap-second-subject")
	ctx := context.Background()
	st := ext.Engine().Store()

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, warden.Subject{Kind: warden.SubjectUser, ID: "alice"}); err != nil {
		t.Fatalf("bootstrap for alice: %v", err)
	}
	first, err := st.GetRoleBySlug(ctx, bootstrapTenant, "", bootstrapAdminSlug)
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, warden.Subject{Kind: warden.SubjectUser, ID: "bob"}); err != nil {
		t.Fatalf("bootstrap for bob: %v", err)
	}
	second, err := st.GetRoleBySlug(ctx, bootstrapTenant, "", bootstrapAdminSlug)
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("a second subject caused a new role to be created: %s -> %s", first.ID, second.ID)
	}

	assignments, err := st.ListAssignments(ctx, &assignment.ListFilter{TenantID: bootstrapTenant, RoleID: &second.ID})
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(assignments) != 2 {
		t.Fatalf("expected 2 assignments (alice, bob), got %d: %+v", len(assignments), assignments)
	}
	subjects := map[string]bool{}
	for _, a := range assignments {
		subjects[a.SubjectID] = true
	}
	if !subjects["alice"] || !subjects["bob"] {
		t.Fatalf("expected assignments for alice and bob, got %+v", assignments)
	}
}

func TestBootstrapAdmin_EnablesEnforceAfterBootstrap(t *testing.T) {
	ext := newBootstrappedExtension(t, "bootstrap-enforce")
	ctx := context.Background()
	subject := warden.Subject{Kind: warden.SubjectUser, ID: "alice"}

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	req := &warden.CheckRequest{
		Subject:  subject,
		Action:   warden.Action{Name: "manage"},
		Resource: warden.Resource{Type: "warden:role"},
		TenantID: bootstrapTenant,
	}
	if err := ext.Engine().Enforce(ctx, req); err != nil {
		t.Fatalf("Enforce(alice, manage, warden:role) failed after bootstrap: %v", err)
	}
}

func TestBootstrapAdmin_GrantsTheDashboardContractPermissions(t *testing.T) {
	ext := newBootstrappedExtension(t, "bootstrap-dashboard")
	ctx := context.Background()
	subject := warden.Subject{Kind: warden.SubjectUser, ID: "alice"}
	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	// Every (action, resource) pair the contract's intent table requires.
	for _, c := range []struct{ action, resource string }{
		{"manage", "warden:maintenance"},
		{"read", "warden:config"},
		{"read", "warden:overview"},
		{"read_audit", "warden:check_log"},
		{"read", "warden:role"},
		{"read", "warden:permission"},
		{"manage", "warden:permission"},
	} {
		req := &warden.CheckRequest{
			Subject:  subject,
			Action:   warden.Action{Name: c.action},
			Resource: warden.Resource{Type: c.resource},
			TenantID: bootstrapTenant,
		}
		if err := ext.Engine().Enforce(ctx, req); err != nil {
			t.Errorf("bootstrap admin lacks %s on %s: %v", c.action, c.resource, err)
		}
	}
}

// auditRecorder collects audit events from the engine's plugin registry.
type auditRecorder struct {
	mu     sync.Mutex
	events []plugin.Event
}

func (a *auditRecorder) Name() string { return "audit-recorder" }

func (a *auditRecorder) OnAudit(_ context.Context, ev plugin.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *auditRecorder) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = nil
}

func (a *auditRecorder) counts() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]int{}
	for _, e := range a.events {
		out[e.Action]++
	}
	return out
}

func newAuditedExtension(t *testing.T, name string) (*Extension, *auditRecorder) {
	t.Helper()
	rec := &auditRecorder{}
	ext := New(WithStore(memory.New()), WithPlugin(rec))
	if err := ext.Register(newTestApp(name)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return ext, rec
}

func TestBootstrapAdmin_EmitsAuditForEverythingItCreates(t *testing.T) {
	ext, rec := newAuditedExtension(t, "bootstrap-audit")
	ctx := context.Background()

	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, warden.Subject{Kind: warden.SubjectUser, ID: "alice"}); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	n := len(bootstrapPermissions)
	want := map[string]int{
		"role.created":        1,
		"permission.created":  n,
		"permission.attached": n,
		"assignment.created":  1,
	}
	got := rec.counts()
	for action, c := range want {
		if got[action] != c {
			t.Errorf("%s events = %d, want %d (all: %v)", action, got[action], c, got)
		}
	}

	wantActor := warden.Actor{Kind: warden.SystemActor.Kind, ID: warden.SystemActor.ID, Via: "bootstrap"}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, e := range rec.events {
		if e.Actor != wantActor {
			t.Errorf("%s actor = %+v, want %+v", e.Action, e.Actor, wantActor)
		}
		if e.TenantID != bootstrapTenant {
			t.Errorf("%s tenant = %q, want %q", e.Action, e.TenantID, bootstrapTenant)
		}
		if e.At.IsZero() {
			t.Errorf("%s has no timestamp", e.Action)
		}
		if e.Action == "assignment.created" {
			a, ok := e.Entity.(*assignment.Assignment)
			if !ok || a.SubjectID != "alice" || a.SubjectKind != "user" {
				t.Errorf("assignment.created Entity = %#v, want the alice assignment", e.Entity)
			}
		}
	}
}

func TestBootstrapAdmin_SecondCallEmitsNothing(t *testing.T) {
	ext, rec := newAuditedExtension(t, "bootstrap-audit-idempotent")
	ctx := context.Background()
	subject := warden.Subject{Kind: warden.SubjectUser, ID: "alice"}
	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("first: %v", err)
	}

	rec.reset()
	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, subject); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := rec.counts(); len(got) != 0 {
		t.Fatalf("an idempotent second call emitted %v, want nothing", got)
	}

	rec.reset()
	if err := ext.BootstrapAdmin(ctx, bootstrapTenant, warden.Subject{Kind: warden.SubjectUser, ID: "bob"}); err != nil {
		t.Fatalf("second subject: %v", err)
	}
	if got := rec.counts(); len(got) != 1 || got["assignment.created"] != 1 {
		t.Fatalf("a second subject emitted %v, want one assignment.created", got)
	}
}

// BootstrapAdmin writes its permissions straight to the store, so it holds
// the rule the other write paths check: no action contains ':'. Resources
// keep theirs (warden:role).
func TestBootstrapPermissionsHaveNoColonInTheirActions(t *testing.T) {
	for _, bp := range bootstrapPermissions {
		if err := permission.CheckAction(bp.action); err != nil {
			t.Errorf("bootstrap permission %s: %v", bp.name(), err)
		}
	}
}
