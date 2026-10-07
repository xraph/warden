package keysmithbridge_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/keysmithbridge"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// wardenBridge is the interface Keysmith's warden_hook extension calls,
// copied here so this module does not import Keysmith. The source of truth is
// github.com/xraph/keysmith/warden_hook.WardenBridge. If the two drift, the
// hook stops compiling against Bridge, so update this copy with it.
type wardenBridge interface {
	AssignRoleToAPIKey(ctx context.Context, tenantID, keyID, roleSlug string) error
	UnassignRoleFromAPIKey(ctx context.Context, tenantID, keyID string) error
	SyncScopesToPermissions(ctx context.Context, tenantID string, scopes []string) error
}

var _ wardenBridge = (*keysmithbridge.Bridge)(nil)

const tenant = "t1"

// recorder notes the plugin events the bridge emits.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) Name() string { return "recorder" }
func (r *recorder) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, s)
}
func (r *recorder) OnRoleAssigned(context.Context, *assignment.Assignment) error {
	r.note("role.assigned")
	return nil
}
func (r *recorder) OnRoleUnassigned(context.Context, *assignment.Assignment) error {
	r.note("role.unassigned")
	return nil
}
func (r *recorder) OnPermissionCreated(context.Context, *permission.Permission) error {
	r.note("permission.created")
	return nil
}
func (r *recorder) OnAudit(_ context.Context, ev plugin.Event) error {
	r.note("audit:" + ev.Action)
	return nil
}
func (r *recorder) count(s string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e == s {
			n++
		}
	}
	return n
}

type rig struct {
	eng *warden.Engine
	st  *memory.Store
	rec *recorder
	b   *keysmithbridge.Bridge
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st := memory.New()
	rec := &recorder{}
	eng, err := warden.NewEngine(
		warden.WithStore(st),
		warden.WithCache(warden.NewMemoryCache()),
		warden.WithPlugin(rec),
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return &rig{eng: eng, st: st, rec: rec, b: keysmithbridge.New(eng)}
}

// seedRole creates a role in the tenant root that grants invoices:read.
func (r *rig) seedRole(t *testing.T, tenantID, slug string, maxMembers int) *role.Role {
	t.Helper()
	ctx := context.Background()
	ro := &role.Role{ID: id.NewRoleID(), TenantID: tenantID, Name: slug, Slug: slug, MaxMembers: maxMembers}
	if err := r.st.CreateRole(ctx, ro); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	p := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: tenantID,
		Name: "invoices:read", Resource: "invoices", Action: "read",
	}
	if err := r.st.CreatePermission(ctx, p); err != nil && !errors.Is(err, warden.ErrDuplicatePermission) {
		t.Fatalf("CreatePermission: %v", err)
	}
	if err := r.st.AttachPermission(ctx, tenantID, ro.ID, permission.Ref{Name: p.Name}); err != nil {
		t.Fatalf("AttachPermission: %v", err)
	}
	return ro
}

func (r *rig) can(t *testing.T, tenantID string) bool {
	t.Helper()
	res, err := r.eng.Check(context.Background(), &warden.CheckRequest{
		TenantID: tenantID,
		Subject:  warden.Subject{Kind: warden.SubjectAPIKey, ID: "k1"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "invoices", ID: "i1"},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return res.Allowed
}

func (r *rig) assignments(t *testing.T, tenantID, keyID string) []*assignment.Assignment {
	t.Helper()
	rows, err := r.st.ListAssignments(context.Background(), &assignment.ListFilter{
		TenantID: tenantID, SubjectKind: "api_key", SubjectID: keyID,
	})
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	return rows
}

func TestEmptyTenantIsRefused(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.seedRole(t, tenant, "api-key", 0)

	for name, err := range map[string]error{
		"assign":   r.b.AssignRoleToAPIKey(ctx, "", "k1", "api-key"),
		"unassign": r.b.UnassignRoleFromAPIKey(ctx, "", "k1"),
		"sync":     r.b.SyncScopesToPermissions(ctx, "", []string{"a:b"}),
	} {
		if !errors.Is(err, warden.ErrTenantRequired) {
			t.Errorf("%s: got %v, want ErrTenantRequired", name, err)
		}
	}
	if n := len(r.assignments(t, "", "")); n != 0 {
		t.Errorf("an empty tenant wrote %d assignments", n)
	}
}

func TestNilEngineIsAnError(t *testing.T) {
	b := keysmithbridge.New(nil)
	if err := b.AssignRoleToAPIKey(context.Background(), tenant, "k1", "api-key"); err == nil {
		t.Fatal("want an error from a bridge with no engine")
	}
}

func TestAssignGrantsAndUnassignRevokes(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.seedRole(t, tenant, "api-key", 0)

	// Warm the cache with a denial so the test proves invalidation too.
	if r.can(t, tenant) {
		t.Fatal("key allowed before assignment")
	}
	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if !r.can(t, tenant) {
		t.Fatal("key denied after assignment (stale cache or missing grant)")
	}

	rows := r.assignments(t, tenant, "k1")
	if len(rows) != 1 {
		t.Fatalf("got %d assignments, want 1", len(rows))
	}
	a := rows[0]
	if a.SubjectKind != "api_key" || a.SubjectID != "k1" || a.NamespacePath != "" || a.ResourceType != "" {
		t.Errorf("unexpected assignment: %+v", a)
	}
	if a.GrantedBy != "keysmith" {
		t.Errorf("GrantedBy = %q, want keysmith", a.GrantedBy)
	}

	if err := r.b.UnassignRoleFromAPIKey(ctx, tenant, "k1"); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if r.can(t, tenant) {
		t.Fatal("key still allowed after unassignment (stale cache or leftover row)")
	}
	if n := len(r.assignments(t, tenant, "k1")); n != 0 {
		t.Errorf("%d assignments left", n)
	}
}

func TestAssignIsIdempotent(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.seedRole(t, tenant, "api-key", 0)

	for i := 0; i < 3; i++ {
		if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
			t.Fatalf("assign #%d: %v", i, err)
		}
	}
	if n := len(r.assignments(t, tenant, "k1")); n != 1 {
		t.Errorf("got %d assignments, want 1", n)
	}
	if n := r.rec.count("role.assigned"); n != 1 {
		t.Errorf("role.assigned emitted %d times, want 1", n)
	}
}

func TestAssignMissingRoleNamesTheSlug(t *testing.T) {
	r := newRig(t)
	err := r.b.AssignRoleToAPIKey(context.Background(), tenant, "k1", "ghost-role")
	if err == nil {
		t.Fatal("want an error for a missing role")
	}
	if !strings.Contains(err.Error(), `"ghost-role"`) {
		t.Errorf("error %q does not name the slug", err)
	}
	if !errors.Is(err, warden.ErrNotFound) {
		t.Errorf("error %v does not wrap ErrNotFound", err)
	}
	if n := len(r.assignments(t, tenant, "k1")); n != 0 {
		t.Errorf("a failed assign left %d rows", n)
	}
}

func TestAssignRejectsEmptyKeyAndSlug(t *testing.T) {
	r := newRig(t)
	r.seedRole(t, tenant, "api-key", 0)
	if err := r.b.AssignRoleToAPIKey(context.Background(), tenant, "", "api-key"); err == nil {
		t.Error("want an error for an empty key ID")
	}
	if err := r.b.AssignRoleToAPIKey(context.Background(), tenant, "k1", ""); err == nil {
		t.Error("want an error for an empty role slug")
	}
	if err := r.b.UnassignRoleFromAPIKey(context.Background(), tenant, ""); err == nil {
		t.Error("want an error for an empty key ID on unassign")
	}
}

func TestAssignUsesTheTenantsRole(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.seedRole(t, "other", "api-key", 0) // only the other tenant has the role

	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err == nil {
		t.Fatal("a role from another tenant must not be found")
	}
	r.seedRole(t, tenant, "api-key", 0)
	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if r.can(t, "other") {
		t.Error("assignment leaked into the other tenant")
	}
}

func TestAssignHonoursTheMemberCap(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.seedRole(t, tenant, "api-key", 1)

	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
		t.Fatalf("first key: %v", err)
	}
	err := r.b.AssignRoleToAPIKey(ctx, tenant, "k2", "api-key")
	var full *assignment.RoleFullError
	if !errors.As(err, &full) {
		t.Fatalf("second key: got %v, want a RoleFullError", err)
	}
	// A key that already holds the role is never refused by the cap.
	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
		t.Fatalf("repeat for the member: %v", err)
	}
}

func TestAssignReplacesAnExpiredGrant(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	ro := r.seedRole(t, tenant, "api-key", 0)
	past := time.Now().Add(-time.Hour)
	// A hand-made, expired row for this key must not count as "already held".
	other := &assignment.Assignment{
		TenantID: tenant, RoleID: ro.ID, SubjectKind: "api_key", SubjectID: "k1",
		NamespacePath: "", ResourceType: "doc", ResourceID: "d1", ExpiresAt: &past,
	}
	if err := r.st.CreateAssignment(ctx, other); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "api-key"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if !r.can(t, tenant) {
		t.Fatal("key denied: the expired resource-scoped row was mistaken for the grant")
	}
}

func TestUnassignRemovesEveryAssignmentOfTheKeyOnly(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	ro := r.seedRole(t, tenant, "api-key", 0)
	r.seedRole(t, tenant, "second", 0)
	r.seedRole(t, "other", "api-key", 0)

	for _, key := range []string{"k1", "k2"} {
		if err := r.b.AssignRoleToAPIKey(ctx, tenant, key, "api-key"); err != nil {
			t.Fatalf("assign %s: %v", key, err)
		}
	}
	if err := r.b.AssignRoleToAPIKey(ctx, tenant, "k1", "second"); err != nil {
		t.Fatalf("assign second: %v", err)
	}
	// A resource-scoped row and a namespaced row for k1, written directly.
	for _, a := range []*assignment.Assignment{
		{TenantID: tenant, RoleID: ro.ID, SubjectKind: "api_key", SubjectID: "k1", ResourceType: "invoices", ResourceID: "i9"},
		{TenantID: tenant, RoleID: ro.ID, SubjectKind: "api_key", SubjectID: "k1", NamespacePath: "eng"},
	} {
		if err := r.st.CreateAssignment(ctx, a); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Same key ID in another tenant, a user with the same ID, and another key.
	otherRole, err := r.st.GetRoleBySlug(ctx, "other", "", "api-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []*assignment.Assignment{
		{TenantID: "other", RoleID: otherRole.ID, SubjectKind: "api_key", SubjectID: "k1"},
		{TenantID: tenant, RoleID: ro.ID, SubjectKind: "user", SubjectID: "k1"},
	} {
		if err := r.st.CreateAssignment(ctx, a); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if got := len(r.assignments(t, tenant, "k1")); got != 4 {
		t.Fatalf("setup: k1 has %d assignments, want 4", got)
	}
	if err := r.b.UnassignRoleFromAPIKey(ctx, tenant, "k1"); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if got := len(r.assignments(t, tenant, "k1")); got != 0 {
		t.Errorf("k1 still has %d assignments", got)
	}
	if got := len(r.assignments(t, tenant, "k2")); got != 1 {
		t.Errorf("k2 has %d assignments, want 1", got)
	}
	if got := len(r.assignments(t, "other", "k1")); got != 1 {
		t.Errorf("the other tenant's k1 has %d assignments, want 1", got)
	}
	users, _ := r.st.ListAssignments(ctx, &assignment.ListFilter{TenantID: tenant, SubjectKind: "user", SubjectID: "k1"})
	if len(users) != 1 {
		t.Errorf("the user subject has %d assignments, want 1", len(users))
	}
	if n := r.rec.count("role.unassigned"); n != 4 {
		t.Errorf("role.unassigned emitted %d times, want 4", n)
	}
}

func TestUnassignWithNothingToRemoveIsANoOp(t *testing.T) {
	r := newRig(t)
	if err := r.b.UnassignRoleFromAPIKey(context.Background(), tenant, "never-seen"); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if n := r.rec.count("role.unassigned"); n != 0 {
		t.Errorf("emitted %d unassign events for nothing", n)
	}
}

func TestUnassignWalksMoreThanOnePage(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const roles = 620 // a page is 500
	for i := 0; i < roles; i++ {
		slug := "r" + strings.Repeat("x", i/26) + string(rune('a'+i%26))
		ro := &role.Role{ID: id.NewRoleID(), TenantID: tenant, Name: slug, Slug: slug}
		if err := r.st.CreateRole(ctx, ro); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if err := r.st.CreateAssignment(ctx, &assignment.Assignment{
			TenantID: tenant, RoleID: ro.ID, SubjectKind: "api_key", SubjectID: "k1",
		}); err != nil {
			t.Fatalf("CreateAssignment: %v", err)
		}
	}
	if err := r.b.UnassignRoleFromAPIKey(ctx, tenant, "k1"); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if n := len(r.assignments(t, tenant, "k1")); n != 0 {
		t.Errorf("%d assignments left after unassign", n)
	}
}

func permissions(t *testing.T, r *rig, tenantID string) map[string]*permission.Permission {
	t.Helper()
	rows, err := r.st.ListPermissions(context.Background(), &permission.ListFilter{TenantID: tenantID})
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	out := make(map[string]*permission.Permission, len(rows))
	for _, p := range rows {
		out[p.Name] = p
	}
	return out
}

func TestSyncMapsScopesOntoResourceAndAction(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	err := r.b.SyncScopesToPermissions(ctx, tenant, []string{
		"billing:read",          // plain resource:action
		"billing:invoices:read", // split at the last colon
		"admin",                 // no separator
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	got := permissions(t, r, tenant)
	want := []struct{ name, resource, action string }{
		{"billing:read", "billing", "read"},
		{"billing:invoices:read", "billing:invoices", "read"},
		{"admin:access", "admin", "access"},
	}
	if len(got) != len(want) {
		t.Errorf("got %d permissions, want %d: %v", len(got), len(want), got)
	}
	for _, w := range want {
		p, ok := got[w.name]
		if !ok {
			t.Errorf("permission %q missing", w.name)
			continue
		}
		if p.Resource != w.resource || p.Action != w.action {
			t.Errorf("%q: resource=%q action=%q, want %q/%q", w.name, p.Resource, p.Action, w.resource, w.action)
		}
		if p.NamespacePath != "" {
			t.Errorf("%q is in namespace %q, want the root", w.name, p.NamespacePath)
		}
		if p.Resource+":"+p.Action != p.Name {
			t.Errorf("%q breaks the Name == Resource:Action rule", p.Name)
		}
		if p.IsSystem {
			t.Errorf("%q must not be a system permission", p.Name)
		}
	}
	if n := r.rec.count("permission.created"); n != 3 {
		t.Errorf("permission.created emitted %d times, want 3", n)
	}
}

func TestSyncLeavesExistingPermissionsAlone(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	existing := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: tenant, Name: "billing:read",
		Resource: "billing", Action: "read", Description: "hand written", IsSystem: true,
	}
	if err := r.st.CreatePermission(ctx, existing); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := r.b.SyncScopesToPermissions(ctx, tenant, []string{"billing:read", "billing:read"}); err != nil {
			t.Fatalf("sync #%d: %v", i, err)
		}
	}
	got := permissions(t, r, tenant)
	if len(got) != 1 {
		t.Fatalf("got %d permissions, want 1", len(got))
	}
	p := got["billing:read"]
	if p.ID != existing.ID || p.Description != "hand written" || !p.IsSystem {
		t.Errorf("existing permission was changed: %+v", p)
	}
	if n := r.rec.count("permission.created"); n != 0 {
		t.Errorf("emitted %d creation events for existing permissions", n)
	}
}

func TestSyncStaysInsideTheTenant(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.b.SyncScopesToPermissions(ctx, tenant, []string{"billing:read"}); err != nil {
		t.Fatal(err)
	}
	if n := len(permissions(t, r, "other")); n != 0 {
		t.Errorf("the other tenant got %d permissions", n)
	}
	if err := r.b.SyncScopesToPermissions(ctx, "other", []string{"billing:read"}); err != nil {
		t.Fatal(err)
	}
	if n := len(permissions(t, r, "other")); n != 1 {
		t.Errorf("the other tenant has %d permissions, want its own 1", n)
	}
}

func TestSyncRefusesWildcardsAndMalformedScopes(t *testing.T) {
	bad := []string{"*", "billing:*", "*:read", "bill*", "", "   ", ":read", "billing:", ":"}
	for _, scope := range bad {
		t.Run(scope, func(t *testing.T) {
			r := newRig(t)
			err := r.b.SyncScopesToPermissions(context.Background(), tenant, []string{scope})
			if err == nil {
				t.Fatalf("scope %q: want an error", scope)
			}
			if n := len(permissions(t, r, tenant)); n != 0 {
				t.Errorf("scope %q created %d permissions", scope, n)
			}
		})
	}
}

func TestSyncKeepsGoingPastABadScope(t *testing.T) {
	r := newRig(t)
	err := r.b.SyncScopesToPermissions(context.Background(), tenant, []string{"billing:*", "billing:read", "", "reports:run"})
	if err == nil {
		t.Fatal("want the bad scopes reported")
	}
	if !strings.Contains(err.Error(), `"billing:*"`) {
		t.Errorf("error %q does not name the wildcard scope", err)
	}
	got := permissions(t, r, tenant)
	if _, ok := got["billing:read"]; !ok {
		t.Error("billing:read was skipped because of an earlier bad scope")
	}
	if _, ok := got["reports:run"]; !ok {
		t.Error("reports:run was skipped because of an earlier bad scope")
	}
}

func TestSyncNoScopesIsANoOp(t *testing.T) {
	r := newRig(t)
	if err := r.b.SyncScopesToPermissions(context.Background(), tenant, nil); err != nil {
		t.Fatal(err)
	}
}

// racyStore reports a duplicate for every create, as a store does when a
// concurrent caller got there first, while still hiding the row from the
// by-name read that comes before it.
type racyStore struct {
	*memory.Store
}

func (s racyStore) GetPermissionByName(_ context.Context, _, _, _ string) (*permission.Permission, error) {
	return nil, warden.ErrPermissionNotFound
}

func (s racyStore) CreatePermission(context.Context, *permission.Permission) error {
	return warden.ErrDuplicatePermission
}

func TestSyncTreatsADuplicateFromARaceAsSuccess(t *testing.T) {
	eng, err := warden.NewEngine(warden.WithStore(racyStore{memory.New()}))
	if err != nil {
		t.Fatal(err)
	}
	b := keysmithbridge.New(eng)
	if err := b.SyncScopesToPermissions(context.Background(), tenant, []string{"billing:read"}); err != nil {
		t.Fatalf("a duplicate from a concurrent create must count as success, got %v", err)
	}
}

func TestWithActorSetsGrantedBy(t *testing.T) {
	st := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(st))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{eng: eng, st: st}
	r.seedRole(t, tenant, "api-key", 0)
	b := keysmithbridge.New(eng, keysmithbridge.WithActor(warden.Actor{Kind: "service", ID: "ci"}))

	if err := b.AssignRoleToAPIKey(context.Background(), tenant, "k1", "api-key"); err != nil {
		t.Fatal(err)
	}
	if got := r.assignments(t, tenant, "k1")[0].GrantedBy; got != "ci" {
		t.Errorf("GrantedBy = %q, want ci", got)
	}

	// An actor on the context wins over the bridge's own.
	ctx := warden.WithActor(context.Background(), warden.Actor{Kind: "user", ID: "u7"})
	if err := b.AssignRoleToAPIKey(ctx, tenant, "k2", "api-key"); err != nil {
		t.Fatal(err)
	}
	if got := r.assignments(t, tenant, "k2")[0].GrantedBy; got != "u7" {
		t.Errorf("GrantedBy = %q, want u7", got)
	}
}
