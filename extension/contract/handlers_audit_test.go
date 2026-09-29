package contract

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// auditProbe records every audit event and the typed role and permission
// hooks the dashboard handlers are expected to fire.
type auditProbe struct {
	mu       sync.Mutex
	events   []plugin.Event
	typed    []string
	lastCtx  context.Context
	ctxActor warden.Actor
}

func (a *auditProbe) Name() string { return "audit-probe" }

func (a *auditProbe) OnAudit(ctx context.Context, ev plugin.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	a.lastCtx = ctx
	a.ctxActor, _ = warden.ActorFromContext(ctx)
	return nil
}

func (a *auditProbe) note(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.typed = append(a.typed, s)
}

func (a *auditProbe) OnRoleCreated(context.Context, *role.Role) error {
	a.note("role.created")
	return nil
}
func (a *auditProbe) OnRoleUpdated(context.Context, *role.Role) error {
	a.note("role.updated")
	return nil
}
func (a *auditProbe) OnRoleDeleted(context.Context, id.RoleID) error {
	a.note("role.deleted")
	return nil
}
func (a *auditProbe) OnPermissionCreated(context.Context, *permission.Permission) error {
	a.note("permission.created")
	return nil
}
func (a *auditProbe) OnPermissionDeleted(context.Context, id.PermissionID) error {
	a.note("permission.deleted")
	return nil
}
func (a *auditProbe) OnPermissionAttached(context.Context, id.RoleID, id.PermissionID) error {
	a.note("permission.attached")
	return nil
}
func (a *auditProbe) OnPermissionDetached(context.Context, id.RoleID, id.PermissionID) error {
	a.note("permission.detached")
	return nil
}

func (a *auditProbe) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.events))
	for _, e := range a.events {
		out = append(out, e.Action)
	}
	return out
}

func (a *auditProbe) event(t *testing.T, action string) plugin.Event {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("no %q audit event; got %v", action, a.actionsLocked())
	return plugin.Event{}
}

func (a *auditProbe) actionsLocked() []string {
	out := make([]string, 0, len(a.events))
	for _, e := range a.events {
		out = append(out, e.Action)
	}
	return out
}

func (a *auditProbe) hasTyped(s string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.typed {
		if x == s {
			return true
		}
	}
	return false
}

func probedEngine(t *testing.T, s *memory.Store, cfg warden.Config) (*warden.Engine, *auditProbe) {
	t.Helper()
	probe := &auditProbe{}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithConfig(cfg), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng, probe
}

// wantActor is what a dashboard write by principalFor's user must record.
var wantActor = warden.Actor{Kind: "user", ID: "tester", Via: "dashboard"}

func TestRolesCreateEmitsAuditAndTheTypedHook(t *testing.T) {
	s := memory.New()
	eng, probe := probedEngine(t, s, warden.Config{})
	h := rolesCreateHandler(Deps{Engine: eng})

	ack, err := h(context.Background(), RoleCreateInput{Name: "Ops", Slug: "ops"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.create: %v", err)
	}

	ev := probe.event(t, "role.created")
	if ev.Actor != wantActor {
		t.Errorf("actor = %+v, want %+v", ev.Actor, wantActor)
	}
	if ev.TenantID != "t1" || ev.EntityID != ack.ID {
		t.Errorf("tenant/entity = %q/%q, want t1/%s", ev.TenantID, ev.EntityID, ack.ID)
	}
	if ev.At.IsZero() {
		t.Error("event has no timestamp")
	}
	if !probe.hasTyped("role.created") {
		t.Error("the typed OnRoleCreated hook did not fire")
	}
	rid, _ := id.ParseRoleID(ack.ID)
	stored, err := s.GetRole(context.Background(), "t1", rid)
	if err != nil {
		t.Fatalf("stored role: %v", err)
	}
	if stored.CreatedBy != "tester" || stored.UpdatedBy != "tester" {
		t.Errorf("created_by/updated_by = %q/%q, want tester/tester", stored.CreatedBy, stored.UpdatedBy)
	}
}

func TestRolesUpdateAndDeleteEmitAuditWithBefore(t *testing.T) {
	s := memory.New()
	seeded := seedRoles(t, s, "", "ops")
	eng, probe := probedEngine(t, s, warden.Config{})
	deps := Deps{Engine: eng}
	newName := "Operations"

	if _, err := rolesUpdateHandler(deps)(context.Background(), RoleUpdateInput{ID: seeded[0].ID.String(), Name: &newName}, principalFor("t1")); err != nil {
		t.Fatalf("roles.update: %v", err)
	}
	upd := probe.event(t, "role.updated")
	before, ok := upd.Before.(*role.Role)
	if !ok || before.Name != "ops" {
		t.Errorf("update Before = %#v, want the pre-update role named ops", upd.Before)
	}
	if after, ok := upd.Entity.(*role.Role); !ok || after.Name != newName || after.UpdatedBy != "tester" {
		t.Errorf("update Entity = %#v, want the updated role stamped tester", upd.Entity)
	}
	if upd.Actor != wantActor || !probe.hasTyped("role.updated") {
		t.Errorf("update actor/typed = %+v/%v", upd.Actor, probe.hasTyped("role.updated"))
	}

	if _, err := rolesDeleteHandler(deps)(context.Background(), RoleDeleteInput{ID: seeded[0].ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("roles.delete: %v", err)
	}
	del := probe.event(t, "role.deleted")
	if del.EntityID != seeded[0].ID.String() || del.Before == nil || del.Actor != wantActor {
		t.Errorf("delete event = %+v", del)
	}
	if !probe.hasTyped("role.deleted") {
		t.Error("the typed OnRoleDeleted hook did not fire")
	}
}

func TestRolePermissionCommandsEmitAudit(t *testing.T) {
	s := memory.New()
	seeded := seedRoles(t, s, "", "ops")
	seedPermission(t, s, "document:read", "document", "read")
	seedPermission(t, s, "document:write", "document", "write")
	eng, probe := probedEngine(t, s, warden.Config{})
	deps := Deps{Engine: eng}
	rid := seeded[0].ID.String()

	if _, err := rolesAttachPermissionHandler(deps)(context.Background(), RolePermissionInput{RoleID: rid, PermissionName: "document:read"}, principalFor("t1")); err != nil {
		t.Fatalf("attach: %v", err)
	}
	att := probe.event(t, "permission.attached")
	if att.Actor != wantActor || att.EntityID != rid || att.TenantID != "t1" {
		t.Errorf("attach event = %+v", att)
	}
	if !probe.hasTyped("permission.attached") {
		t.Error("the typed OnPermissionAttached hook did not fire")
	}

	if _, err := rolesDetachPermissionHandler(deps)(context.Background(), RolePermissionInput{RoleID: rid, PermissionName: "document:read"}, principalFor("t1")); err != nil {
		t.Fatalf("detach: %v", err)
	}
	det := probe.event(t, "permission.detached")
	if det.Actor != wantActor || det.EntityID != rid {
		t.Errorf("detach event = %+v", det)
	}
	if !probe.hasTyped("permission.detached") {
		t.Error("the typed OnPermissionDetached hook did not fire")
	}

	if _, err := rolesSetPermissionsHandler(deps)(context.Background(), RoleSetPermissionsInput{
		RoleID:      rid,
		Permissions: []PermissionRef{{Name: "document:write"}},
	}, principalFor("t1")); err != nil {
		t.Fatalf("set: %v", err)
	}
	set := probe.event(t, "role.permissions_set")
	if set.Actor != wantActor || set.EntityID != rid {
		t.Errorf("set event = %+v", set)
	}
	if set.Before == nil || set.Entity == nil {
		t.Errorf("set event should carry the before and after grant sets: %+v", set)
	}
}

func TestPermissionCommandsEmitAudit(t *testing.T) {
	s := memory.New()
	eng, probe := probedEngine(t, s, warden.Config{})
	deps := Deps{Engine: eng}

	ack, err := permissionsCreateHandler(deps)(context.Background(), PermissionCreateInput{Resource: "document", Action: "read"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.create: %v", err)
	}
	cr := probe.event(t, "permission.created")
	if cr.Actor != wantActor || cr.EntityID != ack.ID || !probe.hasTyped("permission.created") {
		t.Errorf("create event = %+v typed=%v", cr, probe.hasTyped("permission.created"))
	}
	pid, _ := id.ParsePermissionID(ack.ID)
	stored, err := s.GetPermission(context.Background(), "t1", pid)
	if err != nil {
		t.Fatalf("stored permission: %v", err)
	}
	if stored.CreatedBy != "tester" || stored.UpdatedBy != "tester" {
		t.Errorf("created_by/updated_by = %q/%q", stored.CreatedBy, stored.UpdatedBy)
	}

	desc := "read documents"
	if _, err := permissionsUpdateHandler(deps)(context.Background(), PermissionUpdateInput{ID: ack.ID, Description: &desc}, principalFor("t1")); err != nil {
		t.Fatalf("permissions.update: %v", err)
	}
	up := probe.event(t, "permission.updated")
	if up.Actor != wantActor || up.Before == nil {
		t.Errorf("update event = %+v", up)
	}

	if _, err := permissionsDeleteHandler(deps)(context.Background(), PermissionDeleteInput{ID: ack.ID}, principalFor("t1")); err != nil {
		t.Fatalf("permissions.delete: %v", err)
	}
	del := probe.event(t, "permission.deleted")
	if del.Actor != wantActor || del.EntityID != ack.ID || del.Before == nil || !probe.hasTyped("permission.deleted") {
		t.Errorf("delete event = %+v", del)
	}
}

// warmAllow seeds user alice as a reader in t1 and warms the engine cache
// with an ALLOW for document:read.
func warmAllow(t *testing.T, s *memory.Store) (*warden.Engine, *role.Role) {
	t.Helper()
	seedAllow(t, s)
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithConfig(warden.Config{CacheTTL: time.Hour}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	r, err := s.GetRoleBySlug(context.Background(), "t1", "", "reader")
	if err != nil {
		t.Fatalf("reader role: %v", err)
	}
	if !aliceMayRead(t, eng) {
		t.Fatal("setup: alice should be allowed before the mutation")
	}
	return eng, r
}

func aliceMayRead(t *testing.T, eng *warden.Engine) bool {
	t.Helper()
	res, err := eng.Check(context.Background(), &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "d1"},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	return res.Allowed
}

func TestADashboardDetachInvalidatesACachedAllow(t *testing.T) {
	s := memory.New()
	eng, r := warmAllow(t, s)

	_, err := rolesDetachPermissionHandler(Deps{Engine: eng})(context.Background(),
		RolePermissionInput{RoleID: r.ID.String(), PermissionName: "document:read"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("roles.detachPermission: %v", err)
	}
	if aliceMayRead(t, eng) {
		t.Fatal("alice was still allowed after the grant was detached: the cache served a stale ALLOW")
	}
}

func TestADashboardRoleDeleteInvalidatesACachedAllow(t *testing.T) {
	s := memory.New()
	eng, r := warmAllow(t, s)

	if _, err := rolesDeleteHandler(Deps{Engine: eng})(context.Background(), RoleDeleteInput{ID: r.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("roles.delete: %v", err)
	}
	if aliceMayRead(t, eng) {
		t.Fatal("alice was still allowed after her role was deleted: the cache served a stale ALLOW")
	}
}

func TestADashboardSetPermissionsInvalidatesACachedAllow(t *testing.T) {
	s := memory.New()
	eng, r := warmAllow(t, s)

	if _, err := rolesSetPermissionsHandler(Deps{Engine: eng})(context.Background(),
		RoleSetPermissionsInput{RoleID: r.ID.String(), Permissions: []PermissionRef{}}, principalFor("t1")); err != nil {
		t.Fatalf("roles.setPermissions: %v", err)
	}
	if aliceMayRead(t, eng) {
		t.Fatal("alice was still allowed after her role's grants were cleared")
	}
}

func TestMaintenanceRunIsAudited(t *testing.T) {
	s := memory.New()
	eng, probe := probedEngine(t, s, warden.Config{})

	if _, err := maintenanceRunHandler(Deps{Engine: eng})(context.Background(), struct{}{}, principalFor("t1")); err != nil {
		t.Fatalf("maintenance.run: %v", err)
	}
	ev := probe.event(t, "maintenance.run")
	if ev.Actor != wantActor || ev.TenantID != "t1" {
		t.Errorf("event actor/tenant = %+v/%q", ev.Actor, ev.TenantID)
	}
	if _, ok := ev.Entity.(warden.MaintenanceReport); !ok {
		t.Errorf("Entity = %#v, want the warden.MaintenanceReport", ev.Entity)
	}
}

func TestCacheInvalidateIsAudited(t *testing.T) {
	s := memory.New()
	eng, probe := probedEngine(t, s, warden.Config{})
	h := cacheInvalidateHandler(Deps{Engine: eng})

	if _, err := h(context.Background(), CacheInvalidateInput{}, principalFor("t1")); err != nil {
		t.Fatalf("tenant flush: %v", err)
	}
	if _, err := h(context.Background(), CacheInvalidateInput{SubjectKind: "user", SubjectID: "alice"}, principalFor("t1")); err != nil {
		t.Fatalf("subject flush: %v", err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	var got []map[string]string
	for _, e := range probe.events {
		if e.Action != "maintenance.cache_invalidated" {
			continue
		}
		if e.Actor != wantActor || e.TenantID != "t1" {
			t.Errorf("event actor/tenant = %+v/%q", e.Actor, e.TenantID)
		}
		m, ok := e.Entity.(map[string]string)
		if !ok {
			t.Fatalf("Entity = %#v, want a map[string]string", e.Entity)
		}
		got = append(got, m)
	}
	if len(got) != 2 {
		t.Fatalf("got %d cache_invalidated events, want 2", len(got))
	}
	if got[0]["scope"] != "tenant" || got[1]["scope"] != "subject" || got[1]["subject_id"] != "alice" {
		t.Errorf("events = %v", got)
	}
}
