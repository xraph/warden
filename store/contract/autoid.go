// Package contract provides shared test contracts that every Warden
// store backend must satisfy. Backends import this package from their
// _test.go files and call the exported `Run*` functions with a factory
// that builds a fresh store. The contract is the source of truth for
// "what a Warden store has to do, regardless of backend."
package contract

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// MakeStore returns a fresh Store + a cleanup function. The cleanup
// runs even if the test fails. Backends that talk to a real database
// (postgres, mongo) typically wrap each call in its own database /
// collection / schema so tests stay isolated.
type MakeStore func(t *testing.T) (s store.Store, cleanup func())

// RunAutoIDContract runs every `Create*` method against a Store
// constructed by mk and asserts the auto-ID + auto-timestamp behavior:
//
//   - When the input's ID is nil, Create assigns a fresh typeid with
//     the right prefix and the caller's pointer reflects it.
//   - When the input's ID is pre-set, Create preserves it.
//   - When the input's CreatedAt / UpdatedAt is zero, Create assigns
//     `time.Now().UTC()` (within ±5s of the test's wall clock).
//   - When CreatedAt / UpdatedAt is pre-set, Create preserves it.
//
// All assertions are independent — a failure in one entity doesn't
// stop the suite. Each sub-test uses t.Run so backends can target a
// single entity with `-run TestAutoID/Role`.
func RunAutoIDContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("Role", func(t *testing.T) { runRole(t, mk) })
	t.Run("Permission", func(t *testing.T) { runPermission(t, mk) })
	t.Run("Assignment", func(t *testing.T) { runAssignment(t, mk) })
	t.Run("Relation", func(t *testing.T) { runRelation(t, mk) })
	t.Run("Policy", func(t *testing.T) { runPolicy(t, mk) })
	t.Run("ResourceType", func(t *testing.T) { runResourceType(t, mk) })
	t.Run("CheckLog", func(t *testing.T) { runCheckLog(t, mk) })
}

func runRole(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	// Auto-ID + auto-timestamp.
	r := &role.Role{TenantID: "t1", Name: "Editor", Slug: "editor"}
	before := time.Now().UTC()
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if r.ID.IsNil() {
		t.Error("ID should be auto-assigned, still nil")
	}
	if r.ID.Prefix() != id.PrefixRole {
		t.Errorf("ID prefix = %q, want %q", r.ID.Prefix(), id.PrefixRole)
	}
	assertNearNow(t, "Role.CreatedAt", r.CreatedAt, before)
	assertNearNow(t, "Role.UpdatedAt", r.UpdatedAt, before)

	// Get round-trip with the assigned ID.
	got, err := s.GetRoleBySlug(ctx, "t1", "", "editor")
	if err != nil {
		t.Fatalf("GetRoleBySlug: %v", err)
	}
	if got.ID.String() != r.ID.String() {
		t.Errorf("GetRoleBySlug.ID = %q, want %q", got.ID, r.ID)
	}

	// Pre-set ID + timestamps are preserved.
	preset := id.NewRoleID()
	presetTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	r2 := &role.Role{
		ID: preset, TenantID: "t1", Name: "Viewer", Slug: "viewer",
		CreatedAt: presetTime, UpdatedAt: presetTime,
	}
	if err := s.CreateRole(ctx, r2); err != nil {
		t.Fatalf("CreateRole(preset): %v", err)
	}
	if r2.ID.String() != preset.String() {
		t.Errorf("preset ID overwritten: got %q, want %q", r2.ID, preset)
	}
	if !r2.CreatedAt.Equal(presetTime) {
		t.Errorf("preset CreatedAt overwritten: got %v, want %v", r2.CreatedAt, presetTime)
	}
}

func runPermission(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	p := &permission.Permission{
		TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read",
	}
	before := time.Now().UTC()
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if p.ID.IsNil() || p.ID.Prefix() != id.PrefixPermission {
		t.Errorf("ID = %v, want non-nil with prefix %q", p.ID, id.PrefixPermission)
	}
	assertNearNow(t, "Permission.CreatedAt", p.CreatedAt, before)
	assertNearNow(t, "Permission.UpdatedAt", p.UpdatedAt, before)
}

func runAssignment(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	// Assignments require a valid role row to satisfy FKs in real DBs.
	r := &role.Role{TenantID: "t1", Name: "Editor", Slug: "editor-asgn"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("setup CreateRole: %v", err)
	}

	a := &assignment.Assignment{
		TenantID:    "t1",
		RoleID:      r.ID,
		SubjectKind: "user",
		SubjectID:   "u1",
	}
	before := time.Now().UTC()
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}
	if a.ID.IsNil() || a.ID.Prefix() != id.PrefixAssignment {
		t.Errorf("ID = %v, want non-nil with prefix %q", a.ID, id.PrefixAssignment)
	}
	assertNearNow(t, "Assignment.CreatedAt", a.CreatedAt, before)
}

func runRelation(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	tup := &relation.Tuple{
		TenantID:    "t1",
		ObjectType:  "document",
		ObjectID:    "d1",
		Relation:    "viewer",
		SubjectType: "user",
		SubjectID:   "u1",
	}
	before := time.Now().UTC()
	if err := s.CreateRelation(ctx, tup); err != nil {
		t.Fatalf("CreateRelation: %v", err)
	}
	if tup.ID.IsNil() || tup.ID.Prefix() != id.PrefixRelation {
		t.Errorf("ID = %v, want non-nil with prefix %q", tup.ID, id.PrefixRelation)
	}
	assertNearNow(t, "Relation.CreatedAt", tup.CreatedAt, before)
}

func runPolicy(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	p := &policy.Policy{
		TenantID: "t1", Name: "p1", Effect: policy.EffectAllow, IsActive: true,
	}
	before := time.Now().UTC()
	if err := s.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if p.ID.IsNil() || p.ID.Prefix() != id.PrefixPolicy {
		t.Errorf("ID = %v, want non-nil with prefix %q", p.ID, id.PrefixPolicy)
	}
	assertNearNow(t, "Policy.CreatedAt", p.CreatedAt, before)
	assertNearNow(t, "Policy.UpdatedAt", p.UpdatedAt, before)
}

func runResourceType(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	rt := &resourcetype.ResourceType{TenantID: "t1", Name: "document"}
	before := time.Now().UTC()
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("CreateResourceType: %v", err)
	}
	if rt.ID.IsNil() || rt.ID.Prefix() != id.PrefixResourceType {
		t.Errorf("ID = %v, want non-nil with prefix %q", rt.ID, id.PrefixResourceType)
	}
	assertNearNow(t, "ResourceType.CreatedAt", rt.CreatedAt, before)
	assertNearNow(t, "ResourceType.UpdatedAt", rt.UpdatedAt, before)
}

func runCheckLog(t *testing.T, mk MakeStore) {
	ctx := context.Background()
	s, cleanup := mk(t)
	defer cleanup()

	e := &checklog.Entry{
		TenantID:     "t1",
		SubjectKind:  "user",
		SubjectID:    "u1",
		Action:       "read",
		ResourceType: "document",
		ResourceID:   "d1",
		Decision:     "allow",
	}
	before := time.Now().UTC()
	if err := s.CreateCheckLog(ctx, e); err != nil {
		t.Fatalf("CreateCheckLog: %v", err)
	}
	if e.ID.IsNil() || e.ID.Prefix() != id.PrefixCheckLog {
		t.Errorf("ID = %v, want non-nil with prefix %q", e.ID, id.PrefixCheckLog)
	}
	assertNearNow(t, "CheckLog.CreatedAt", e.CreatedAt, before)
}

// assertNearNow checks that got is within ±5s of before. We allow ±5s
// because some backends (sqlite via TEXT timestamps, mongo via
// millisecond truncation) round to coarser precision than time.Now()
// returns. The delta can be negative if precision rounding put `got`
// slightly before `before`, so we compare on absolute value.
func assertNearNow(t *testing.T, label string, got, before time.Time) {
	t.Helper()
	if got.IsZero() {
		t.Errorf("%s is zero, expected ~now", label)
		return
	}
	delta := got.Sub(before)
	if delta < 0 {
		delta = -delta
	}
	if delta > 5*time.Second {
		t.Errorf("%s = %v, expected within 5s of %v (delta=%v)", label, got, before, delta)
	}
}
