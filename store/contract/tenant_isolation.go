package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// NewStore builds a fresh Store for one sub-test. Backends register their
// own teardown with t.Cleanup, so the contract never has to unwind anything
// itself.
type NewStore func(t *testing.T) store.Store

// Tenants used by every case in this contract. Rows are always written for
// tiOwner; every by-ID call is then repeated as tiOther, which must behave
// exactly as if the row did not exist.
const (
	tiOwner = "t1"
	tiOther = "t2"
)

// RunTenantIsolationContract asserts that a store treats the tenant as part
// of the key on every by-ID operation.
//
// The bug this guards: each by-ID method used to filter on the primary key
// alone, so any caller holding an ID from tenant A could read, overwrite or
// delete that row while acting as tenant B. Primary keys are typeids, which
// leak through logs, URLs and exports, so "you need the ID" was never a
// boundary.
//
// The rule every backend has to satisfy: a by-ID call carrying the wrong
// tenant behaves exactly as if the row did not exist. It returns the same
// not-found sentinel a genuinely missing row returns, never a distinct
// "forbidden" error, because a distinct error would itself confirm that the
// ID exists somewhere. Writes leave the real row untouched.
func RunTenantIsolationContract(t *testing.T, newStore NewStore) {
	t.Helper()

	t.Run("Role", func(t *testing.T) { runRoleIsolation(t, newStore) })
	t.Run("Permission", func(t *testing.T) { runPermissionIsolation(t, newStore) })
	t.Run("Assignment", func(t *testing.T) { runAssignmentIsolation(t, newStore) })
	t.Run("Policy", func(t *testing.T) { runPolicyIsolation(t, newStore) })
	t.Run("ResourceType", func(t *testing.T) { runResourceTypeIsolation(t, newStore) })
	t.Run("Relation", func(t *testing.T) { runRelationIsolation(t, newStore) })
	t.Run("CheckLog", func(t *testing.T) { runCheckLogIsolation(t, newStore) })
	t.Run("RolePermissions", func(t *testing.T) { runRolePermissionIsolation(t, newStore) })
	t.Run("BatchReads", func(t *testing.T) { runBatchReadIsolation(t, newStore) })
	t.Run("RelationFanoutLimit", func(t *testing.T) { runRelationFanoutLimit(t, newStore) })
}

// ───── Role ─────

func runRoleIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r := tiRole(t, s, tiOwner, "viewer")

	if _, err := s.GetRole(ctx, tiOther, r.ID); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("GetRole as other tenant: want ErrRoleNotFound, got %v", err)
	}
	if got, err := s.GetRole(ctx, tiOwner, r.ID); err != nil || got == nil {
		t.Fatalf("GetRole as owner: %v", err)
	}

	// An update that claims the row for another tenant must not match.
	hijack := *r
	hijack.TenantID = tiOther
	hijack.Name = "Hijacked"
	if err := s.UpdateRole(ctx, &hijack); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("UpdateRole as other tenant: want ErrRoleNotFound, got %v", err)
	}
	after, err := s.GetRole(ctx, tiOwner, r.ID)
	if err != nil {
		t.Fatalf("GetRole after rejected update: %v", err)
	}
	if after.Name != r.Name || after.TenantID != tiOwner {
		t.Errorf("row changed by rejected update: name=%q tenant=%q", after.Name, after.TenantID)
	}

	// A legitimate update still lands, and never rewrites the tenant.
	after.Name = "Viewer v2"
	if err := s.UpdateRole(ctx, after); err != nil {
		t.Fatalf("UpdateRole as owner: %v", err)
	}
	reread, err := s.GetRole(ctx, tiOwner, r.ID)
	if err != nil {
		t.Fatalf("GetRole after owner update: %v", err)
	}
	if reread.Name != "Viewer v2" {
		t.Errorf("owner update did not land: name=%q", reread.Name)
	}
	if reread.TenantID != tiOwner {
		t.Errorf("owner update rewrote tenant: %q", reread.TenantID)
	}

	if err := s.DeleteRole(ctx, tiOther, r.ID); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("DeleteRole as other tenant: want ErrRoleNotFound, got %v", err)
	}
	if _, err := s.GetRole(ctx, tiOwner, r.ID); err != nil {
		t.Errorf("row deleted by other tenant: %v", err)
	}
	if err := s.DeleteRole(ctx, tiOwner, r.ID); err != nil {
		t.Fatalf("DeleteRole as owner: %v", err)
	}
	if _, err := s.GetRole(ctx, tiOwner, r.ID); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("GetRole after owner delete: want ErrRoleNotFound, got %v", err)
	}
}

// ───── Permission ─────

func runPermissionIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	p := tiPermission(t, s, tiOwner, "doc:read")

	if _, err := s.GetPermission(ctx, tiOther, p.ID); !errors.Is(err, warden.ErrPermissionNotFound) {
		t.Errorf("GetPermission as other tenant: want ErrPermissionNotFound, got %v", err)
	}

	hijack := *p
	hijack.TenantID = tiOther
	hijack.Description = "hijacked"
	if err := s.UpdatePermission(ctx, &hijack); !errors.Is(err, warden.ErrPermissionNotFound) {
		t.Errorf("UpdatePermission as other tenant: want ErrPermissionNotFound, got %v", err)
	}
	after, err := s.GetPermission(ctx, tiOwner, p.ID)
	if err != nil {
		t.Fatalf("GetPermission after rejected update: %v", err)
	}
	if after.Description != "" || after.TenantID != tiOwner {
		t.Errorf("row changed by rejected update: desc=%q tenant=%q", after.Description, after.TenantID)
	}

	if err := s.DeletePermission(ctx, tiOther, p.ID); !errors.Is(err, warden.ErrPermissionNotFound) {
		t.Errorf("DeletePermission as other tenant: want ErrPermissionNotFound, got %v", err)
	}
	if _, err := s.GetPermission(ctx, tiOwner, p.ID); err != nil {
		t.Errorf("row deleted by other tenant: %v", err)
	}
	if err := s.DeletePermission(ctx, tiOwner, p.ID); err != nil {
		t.Fatalf("DeletePermission as owner: %v", err)
	}
}

// ───── Assignment ─────

func runAssignmentIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r := tiRole(t, s, tiOwner, "viewer")
	a := tiAssignment(t, s, tiOwner, r.ID, nil)

	if _, err := s.GetAssignment(ctx, tiOther, a.ID); !errors.Is(err, warden.ErrAssignmentNotFound) {
		t.Errorf("GetAssignment as other tenant: want ErrAssignmentNotFound, got %v", err)
	}
	if err := s.DeleteAssignment(ctx, tiOther, a.ID); !errors.Is(err, warden.ErrAssignmentNotFound) {
		t.Errorf("DeleteAssignment as other tenant: want ErrAssignmentNotFound, got %v", err)
	}
	if _, err := s.GetAssignment(ctx, tiOwner, a.ID); err != nil {
		t.Errorf("row deleted by other tenant: %v", err)
	}

	if subs, err := s.ListSubjectsForRole(ctx, tiOther, r.ID); err != nil || len(subs) != 0 {
		t.Errorf("ListSubjectsForRole as other tenant: want 0 rows, got %d (err %v)", len(subs), err)
	}
	if subs, err := s.ListSubjectsForRole(ctx, tiOwner, r.ID); err != nil || len(subs) != 1 {
		t.Errorf("ListSubjectsForRole as owner: want 1 row, got %d (err %v)", len(subs), err)
	}

	// Expiring assignments are scoped too: a row expiring inside the window
	// is invisible to another tenant's access review.
	soon := time.Now().UTC().Add(1 * time.Hour)
	expiring := tiAssignment(t, s, tiOwner, r.ID, &soon)
	cutoff := time.Now().UTC().Add(24 * time.Hour)
	if rows, err := s.ListExpiringAssignments(ctx, tiOther, cutoff, 0); err != nil || len(rows) != 0 {
		t.Errorf("ListExpiringAssignments as other tenant: want 0 rows, got %d (err %v)", len(rows), err)
	}
	rows, err := s.ListExpiringAssignments(ctx, tiOwner, cutoff, 0)
	if err != nil {
		t.Fatalf("ListExpiringAssignments as owner: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != expiring.ID {
		t.Errorf("ListExpiringAssignments as owner: want the expiring row, got %d rows", len(rows))
	}

	// A bulk delete by role must not reach across the tenant boundary.
	if err := s.DeleteAssignmentsByRole(ctx, tiOther, r.ID); err != nil {
		t.Fatalf("DeleteAssignmentsByRole as other tenant: %v", err)
	}
	if subs, err := s.ListSubjectsForRole(ctx, tiOwner, r.ID); err != nil || len(subs) != 2 {
		t.Errorf("assignments deleted by other tenant: want 2 rows, got %d (err %v)", len(subs), err)
	}
	if err := s.DeleteAssignmentsByRole(ctx, tiOwner, r.ID); err != nil {
		t.Fatalf("DeleteAssignmentsByRole as owner: %v", err)
	}
	if subs, err := s.ListSubjectsForRole(ctx, tiOwner, r.ID); err != nil || len(subs) != 0 {
		t.Errorf("DeleteAssignmentsByRole as owner: want 0 rows left, got %d (err %v)", len(subs), err)
	}
}

// ───── Policy ─────

func runPolicyIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	polID := createPolicy(t, s, tiOwner, "", "readonly")

	if _, err := s.GetPolicy(ctx, tiOther, polID); !errors.Is(err, warden.ErrPolicyNotFound) {
		t.Errorf("GetPolicy as other tenant: want ErrPolicyNotFound, got %v", err)
	}
	p, err := s.GetPolicy(ctx, tiOwner, polID)
	if err != nil {
		t.Fatalf("GetPolicy as owner: %v", err)
	}

	hijack := *p
	hijack.TenantID = tiOther
	hijack.Description = "hijacked"
	if err := s.UpdatePolicy(ctx, &hijack); !errors.Is(err, warden.ErrPolicyNotFound) {
		t.Errorf("UpdatePolicy as other tenant: want ErrPolicyNotFound, got %v", err)
	}
	after, err := s.GetPolicy(ctx, tiOwner, polID)
	if err != nil {
		t.Fatalf("GetPolicy after rejected update: %v", err)
	}
	if after.Description != "" || after.TenantID != tiOwner {
		t.Errorf("row changed by rejected update: desc=%q tenant=%q", after.Description, after.TenantID)
	}

	if err := s.SetPolicyVersion(ctx, tiOther, polID, 99); !errors.Is(err, warden.ErrPolicyNotFound) {
		t.Errorf("SetPolicyVersion as other tenant: want ErrPolicyNotFound, got %v", err)
	}
	if after, err = s.GetPolicy(ctx, tiOwner, polID); err != nil || after.Version == 99 {
		t.Errorf("version changed by other tenant: version=%d (err %v)", after.Version, err)
	}
	if err := s.SetPolicyVersion(ctx, tiOwner, polID, 7); err != nil {
		t.Fatalf("SetPolicyVersion as owner: %v", err)
	}
	if after, err = s.GetPolicy(ctx, tiOwner, polID); err != nil || after.Version != 7 {
		t.Errorf("SetPolicyVersion as owner did not land: version=%d (err %v)", after.Version, err)
	}

	if err := s.DeletePolicy(ctx, tiOther, polID); !errors.Is(err, warden.ErrPolicyNotFound) {
		t.Errorf("DeletePolicy as other tenant: want ErrPolicyNotFound, got %v", err)
	}
	if _, err := s.GetPolicy(ctx, tiOwner, polID); err != nil {
		t.Errorf("row deleted by other tenant: %v", err)
	}
	if err := s.DeletePolicy(ctx, tiOwner, polID); err != nil {
		t.Fatalf("DeletePolicy as owner: %v", err)
	}
}

// ───── Resource type ─────

func runResourceTypeIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	rt := tiResourceType(t, s, tiOwner, "document")

	if _, err := s.GetResourceType(ctx, tiOther, rt.ID); !errors.Is(err, warden.ErrResourceTypeNotFound) {
		t.Errorf("GetResourceType as other tenant: want ErrResourceTypeNotFound, got %v", err)
	}

	hijack := *rt
	hijack.TenantID = tiOther
	hijack.Description = "hijacked"
	if err := s.UpdateResourceType(ctx, &hijack); !errors.Is(err, warden.ErrResourceTypeNotFound) {
		t.Errorf("UpdateResourceType as other tenant: want ErrResourceTypeNotFound, got %v", err)
	}
	after, err := s.GetResourceType(ctx, tiOwner, rt.ID)
	if err != nil {
		t.Fatalf("GetResourceType after rejected update: %v", err)
	}
	if after.Description != "" || after.TenantID != tiOwner {
		t.Errorf("row changed by rejected update: desc=%q tenant=%q", after.Description, after.TenantID)
	}

	if err := s.DeleteResourceType(ctx, tiOther, rt.ID); !errors.Is(err, warden.ErrResourceTypeNotFound) {
		t.Errorf("DeleteResourceType as other tenant: want ErrResourceTypeNotFound, got %v", err)
	}
	if _, err := s.GetResourceType(ctx, tiOwner, rt.ID); err != nil {
		t.Errorf("row deleted by other tenant: %v", err)
	}
	if err := s.DeleteResourceType(ctx, tiOwner, rt.ID); err != nil {
		t.Fatalf("DeleteResourceType as owner: %v", err)
	}
}

// ───── Relation ─────

func runRelationIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	tup := tiTuple(tiOwner, "doc", "d1", "viewer", "user", "u1")
	createRelation(t, s, tup)

	if err := s.DeleteRelation(ctx, tiOther, tup.ID); !errors.Is(err, warden.ErrRelationNotFound) {
		t.Errorf("DeleteRelation as other tenant: want ErrRelationNotFound, got %v", err)
	}
	still, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: tiOwner})
	if err != nil || len(still) != 1 {
		t.Errorf("tuple deleted by other tenant: want 1 row, got %d (err %v)", len(still), err)
	}
	if err := s.DeleteRelation(ctx, tiOwner, tup.ID); err != nil {
		t.Fatalf("DeleteRelation as owner: %v", err)
	}
	if err := s.DeleteRelation(ctx, tiOwner, tup.ID); !errors.Is(err, warden.ErrRelationNotFound) {
		t.Errorf("DeleteRelation of a gone tuple: want ErrRelationNotFound, got %v", err)
	}
}

// ───── Check log ─────

func runCheckLogIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	e := tiCheckLog(t, s, tiOwner, "user", "u1")

	if _, err := s.GetCheckLog(ctx, tiOther, e.ID); !errors.Is(err, warden.ErrCheckLogNotFound) {
		t.Errorf("GetCheckLog as other tenant: want ErrCheckLogNotFound, got %v", err)
	}
	got, err := s.GetCheckLog(ctx, tiOwner, e.ID)
	if err != nil {
		t.Fatalf("GetCheckLog as owner: %v", err)
	}
	// The check_logs_v2 columns have to survive a round trip, or an auditor
	// cannot reconstruct why a decision went the way it did.
	if len(got.MatchedBy) != 1 || got.MatchedBy[0] != e.MatchedBy[0] {
		t.Errorf("MatchedBy did not round-trip: got %+v", got.MatchedBy)
	}
	if len(got.Obligations) != 1 || got.Obligations[0] != e.Obligations[0] {
		t.Errorf("Obligations did not round-trip: got %v", got.Obligations)
	}
	if got.RequestID != e.RequestID || got.TraceID != e.TraceID {
		t.Errorf("correlation IDs did not round-trip: request=%q trace=%q", got.RequestID, got.TraceID)
	}
	if !got.Cached || got.Error != e.Error {
		t.Errorf("cached/error did not round-trip: cached=%v error=%q", got.Cached, got.Error)
	}

	n, err := s.DeleteCheckLogsBySubject(ctx, tiOther, "user", "u1")
	if err != nil {
		t.Fatalf("DeleteCheckLogsBySubject as other tenant: %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteCheckLogsBySubject as other tenant deleted %d rows, want 0", n)
	}
	if _, err := s.GetCheckLog(ctx, tiOwner, e.ID); err != nil {
		t.Errorf("entry deleted by other tenant: %v", err)
	}

	n, err = s.DeleteCheckLogsBySubject(ctx, tiOwner, "user", "u1")
	if err != nil {
		t.Fatalf("DeleteCheckLogsBySubject as owner: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteCheckLogsBySubject as owner deleted %d rows, want 1", n)
	}
	if _, err := s.GetCheckLog(ctx, tiOwner, e.ID); !errors.Is(err, warden.ErrCheckLogNotFound) {
		t.Errorf("GetCheckLog after owner delete: want ErrCheckLogNotFound, got %v", err)
	}
}

// ───── Role/permission junction ─────

func runRolePermissionIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r := tiRole(t, s, tiOwner, "viewer")
	p := tiPermission(t, s, tiOwner, "doc:read")
	ref := permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name}

	if err := s.AttachPermission(ctx, tiOther, r.ID, ref); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("AttachPermission as other tenant: want ErrRoleNotFound, got %v", err)
	}
	if err := s.AttachPermission(ctx, tiOwner, r.ID, ref); err != nil {
		t.Fatalf("AttachPermission as owner: %v", err)
	}

	if perms, err := s.ListRolePermissions(ctx, tiOther, r.ID); err != nil || len(perms) != 0 {
		t.Errorf("ListRolePermissions as other tenant: want 0 rows, got %d (err %v)", len(perms), err)
	}
	if perms, err := s.ListPermissionsByRole(ctx, tiOther, r.ID); err != nil || len(perms) != 0 {
		t.Errorf("ListPermissionsByRole as other tenant: want 0 rows, got %d (err %v)", len(perms), err)
	}
	perms, err := s.ListRolePermissions(ctx, tiOwner, r.ID)
	if err != nil || len(perms) != 1 {
		t.Fatalf("ListRolePermissions as owner: want 1 row, got %d (err %v)", len(perms), err)
	}

	if err := s.DetachPermission(ctx, tiOther, r.ID, ref); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("DetachPermission as other tenant: want ErrRoleNotFound, got %v", err)
	}
	if err := s.SetRolePermissions(ctx, tiOther, r.ID, nil); !errors.Is(err, warden.ErrRoleNotFound) {
		t.Errorf("SetRolePermissions as other tenant: want ErrRoleNotFound, got %v", err)
	}
	if perms, err = s.ListRolePermissions(ctx, tiOwner, r.ID); err != nil || len(perms) != 1 {
		t.Errorf("grant removed by other tenant: want 1 row, got %d (err %v)", len(perms), err)
	}

	if err := s.SetRolePermissions(ctx, tiOwner, r.ID, nil); err != nil {
		t.Fatalf("SetRolePermissions as owner: %v", err)
	}
	if perms, err = s.ListRolePermissions(ctx, tiOwner, r.ID); err != nil || len(perms) != 0 {
		t.Errorf("SetRolePermissions as owner: want 0 rows left, got %d (err %v)", len(perms), err)
	}
}

// ───── Batch reads ─────

func runBatchReadIsolation(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r1 := tiRole(t, s, tiOwner, "viewer")
	r2 := tiRole(t, s, tiOwner, "editor")
	p := tiPermission(t, s, tiOwner, "doc:read")
	ref := permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name}
	if err := s.AttachPermission(ctx, tiOwner, r1.ID, ref); err != nil {
		t.Fatalf("AttachPermission: %v", err)
	}
	unknown := id.NewRoleID()

	got, err := s.GetRoles(ctx, tiOwner, []id.RoleID{r1.ID, r2.ID, unknown})
	if err != nil {
		t.Fatalf("GetRoles as owner: %v", err)
	}
	seen := make(map[id.RoleID]bool, len(got))
	for _, r := range got {
		seen[r.ID] = true
	}
	if len(got) != 2 || !seen[r1.ID] || !seen[r2.ID] {
		t.Errorf("GetRoles as owner: want exactly r1 and r2, got %d rows", len(got))
	}

	if got, err = s.GetRoles(ctx, tiOther, []id.RoleID{r1.ID, r2.ID}); err != nil || len(got) != 0 {
		t.Errorf("GetRoles as other tenant: want 0 rows, got %d (err %v)", len(got), err)
	}
	if got, err = s.GetRoles(ctx, tiOwner, nil); err != nil || len(got) != 0 {
		t.Errorf("GetRoles with no IDs: want 0 rows, got %d (err %v)", len(got), err)
	}

	byRole, err := s.ListRolePermissionsForRoles(ctx, tiOwner, []id.RoleID{r1.ID, r2.ID})
	if err != nil {
		t.Fatalf("ListRolePermissionsForRoles as owner: %v", err)
	}
	if len(byRole[r1.ID]) != 1 || byRole[r1.ID][0].Name != p.Name {
		t.Errorf("ListRolePermissionsForRoles: want r1 to grant %q, got %v", p.Name, byRole[r1.ID])
	}
	if len(byRole[r2.ID]) != 0 {
		t.Errorf("ListRolePermissionsForRoles: want r2 to grant nothing, got %d", len(byRole[r2.ID]))
	}

	other, err := s.ListRolePermissionsForRoles(ctx, tiOther, []id.RoleID{r1.ID, r2.ID})
	if err != nil {
		t.Fatalf("ListRolePermissionsForRoles as other tenant: %v", err)
	}
	if len(other[r1.ID]) != 0 {
		t.Errorf("ListRolePermissionsForRoles as other tenant: want 0 grants, got %d", len(other[r1.ID]))
	}
}

// ───── Relation fan-out limit ─────

func runRelationFanoutLimit(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	for i := range 5 {
		createRelation(t, s, tiTuple(tiOwner, "doc", "d1", "viewer", "user", slugFor("u", i)))
	}

	subs, err := s.ListRelationSubjects(ctx, tiOwner, nil, "doc", "d1", "viewer", 2)
	if err != nil {
		t.Fatalf("ListRelationSubjects with limit: %v", err)
	}
	if len(subs) != 2 {
		t.Errorf("ListRelationSubjects limit 2: got %d rows", len(subs))
	}
	if subs, err = s.ListRelationSubjects(ctx, tiOwner, nil, "doc", "d1", "viewer", 0); err != nil || len(subs) != 5 {
		t.Errorf("ListRelationSubjects limit 0: want 5 rows, got %d (err %v)", len(subs), err)
	}

	objs, err := s.ListRelationObjects(ctx, tiOwner, "", "user", "u-0", "viewer", 0)
	if err != nil || len(objs) != 1 {
		t.Errorf("ListRelationObjects as owner: want 1 row, got %d (err %v)", len(objs), err)
	}
}

// ───── Seed helpers ─────

func tiRole(t *testing.T, s store.Store, tenantID, slug string) *role.Role { //nolint:unparam // shared seed helper; tenantID kept as a parameter so each case reads as "seed for this tenant"
	t.Helper()
	r := &role.Role{
		ID: id.NewRoleID(), TenantID: tenantID, NamespacePath: "",
		Name: slug, Slug: slug,
	}
	if err := s.CreateRole(context.Background(), r); err != nil {
		t.Fatalf("seed role %q: %v", slug, err)
	}
	return r
}

func tiPermission(t *testing.T, s store.Store, tenantID, name string) *permission.Permission {
	t.Helper()
	p := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: tenantID, NamespacePath: "",
		Name: name, Resource: "doc", Action: "read",
	}
	if err := s.CreatePermission(context.Background(), p); err != nil {
		t.Fatalf("seed permission %q: %v", name, err)
	}
	return p
}

func tiAssignment(t *testing.T, s store.Store, tenantID string, roleID id.RoleID, expiresAt *time.Time) *assignment.Assignment {
	t.Helper()
	a := &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: tenantID, NamespacePath: "",
		RoleID: roleID, SubjectKind: "user", SubjectID: id.NewAssignmentID().String(),
		ExpiresAt: expiresAt,
	}
	createAssignment(t, s, a)
	return a
}

func tiResourceType(t *testing.T, s store.Store, tenantID, name string) *resourcetype.ResourceType {
	t.Helper()
	rt := &resourcetype.ResourceType{
		ID: id.NewResourceTypeID(), TenantID: tenantID, NamespacePath: "",
		Name:        name,
		Relations:   []resourcetype.RelationDef{},
		Permissions: []resourcetype.PermissionDef{},
	}
	if err := s.CreateResourceType(context.Background(), rt); err != nil {
		t.Fatalf("seed resource type %q: %v", name, err)
	}
	return rt
}

func tiTuple(tenantID, objectType, objectID, rel, subjectType, subjectID string) *relation.Tuple {
	return &relation.Tuple{
		ID: id.NewRelationID(), TenantID: tenantID, NamespacePath: "",
		ObjectType: objectType, ObjectID: objectID, Relation: rel,
		SubjectType: subjectType, SubjectID: subjectID,
	}
}

func tiCheckLog(t *testing.T, s store.Store, tenantID, subjectKind, subjectID string) *checklog.Entry {
	t.Helper()
	e := &checklog.Entry{
		ID: id.NewCheckLogID(), TenantID: tenantID, NamespacePath: "",
		SubjectKind: subjectKind, SubjectID: subjectID,
		Action: "read", ResourceType: "doc", ResourceID: "d1",
		Decision:    "allow",
		MatchedBy:   []checklog.MatchRef{{Source: "rbac", RuleID: "role-1", Detail: "role grants doc:read"}},
		Obligations: []string{"mask:ssn"},
		RequestID:   "req-1",
		TraceID:     "trace-1",
		Cached:      true,
		Error:       "",
	}
	if err := s.CreateCheckLog(context.Background(), e); err != nil {
		t.Fatalf("seed check log: %v", err)
	}
	return e
}
