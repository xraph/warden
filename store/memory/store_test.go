package memory

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

// Compile-time check that *Store implements store.Store.
var _ store.Store = (*Store)(nil)

func TestRoleCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	r := &role.Role{
		ID:       id.NewRoleID(),
		TenantID: "t1",
		AppID:    "app1",
		Name:     "admin",
		Slug:     "admin",
	}

	// Create
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}

	// Get
	got, err := s.GetRole(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "admin" {
		t.Fatalf("expected admin, got %s", got.Name)
	}

	// GetBySlug
	got, err = s.GetRoleBySlug(ctx, "t1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != r.ID {
		t.Fatal("slug lookup mismatch")
	}

	// Update
	r.Name = "super-admin"
	err = s.UpdateRole(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRole(ctx, r.ID)
	if got.Name != "super-admin" {
		t.Fatal("update failed")
	}

	// List
	list, _ := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if len(list) != 1 {
		t.Fatalf("expected 1 role, got %d", len(list))
	}

	// Count
	count, _ := s.CountRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	// Delete
	err = s.DeleteRole(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.GetRole(ctx, r.ID)
	if err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestPermissionCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	p := &permission.Permission{
		ID:       id.NewPermissionID(),
		TenantID: "t1",
		AppID:    "app1",
		Name:     "document:read",
		Resource: "document",
		Action:   "read",
	}

	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetPermission(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "document:read" {
		t.Fatal("mismatch")
	}

	got, err = s.GetPermissionByName(ctx, "t1", "document:read")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != p.ID {
		t.Fatal("name lookup mismatch")
	}

	err = s.DeletePermission(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.GetPermission(ctx, p.ID)
	if err == nil {
		t.Fatal("expected not found")
	}
}

func TestRolePermissionAttach(t *testing.T) {
	ctx := context.Background()
	s := New()

	roleID := id.NewRoleID()
	perm1 := id.NewPermissionID()
	perm2 := id.NewPermissionID()

	// Create role and permissions.
	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "editor", Slug: "editor"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: perm1, TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: perm2, TenantID: "t1", Name: "doc:write", Resource: "doc", Action: "write"})

	// Attach
	_ = s.AttachPermission(ctx, roleID, perm1)
	_ = s.AttachPermission(ctx, roleID, perm2)

	perms, _ := s.ListRolePermissions(ctx, roleID)
	if len(perms) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(perms))
	}

	// ListPermissionsByRole
	permObjs, _ := s.ListPermissionsByRole(ctx, roleID)
	if len(permObjs) != 2 {
		t.Fatalf("expected 2 permission objects, got %d", len(permObjs))
	}

	// Detach
	_ = s.DetachPermission(ctx, roleID, perm1)
	perms, _ = s.ListRolePermissions(ctx, roleID)
	if len(perms) != 1 {
		t.Fatalf("expected 1 permission after detach, got %d", len(perms))
	}

	// SetRolePermissions (replace all)
	_ = s.SetRolePermissions(ctx, roleID, []id.PermissionID{perm1})
	perms, _ = s.ListRolePermissions(ctx, roleID)
	if len(perms) != 1 {
		t.Fatalf("expected 1 permission after set, got %d", len(perms))
	}
}

func TestAssignmentCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	roleID := id.NewRoleID()
	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "admin", Slug: "admin"})

	a := &assignment.Assignment{
		ID:          id.NewAssignmentID(),
		TenantID:    "t1",
		RoleID:      roleID,
		SubjectKind: "user",
		SubjectID:   "u1",
	}

	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetAssignment(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SubjectID != "u1" {
		t.Fatal("mismatch")
	}

	roles, _ := s.ListRolesForSubject(ctx, "t1", "user", "u1")
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	subjects, _ := s.ListSubjectsForRole(ctx, roleID)
	if len(subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(subjects))
	}

	if err := s.DeleteAssignment(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRelationCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	tup := &relation.Tuple{
		ID:          id.NewRelationID(),
		TenantID:    "t1",
		ObjectType:  "document",
		ObjectID:    "doc1",
		Relation:    "viewer",
		SubjectType: "user",
		SubjectID:   "u1",
	}

	if err := s.CreateRelation(ctx, tup); err != nil {
		t.Fatal(err)
	}

	// CheckDirectRelation
	ok, _ := s.CheckDirectRelation(ctx, "t1", "document", "doc1", "viewer", "user", "u1")
	if !ok {
		t.Fatal("expected direct relation")
	}

	ok, _ = s.CheckDirectRelation(ctx, "t1", "document", "doc1", "editor", "user", "u1")
	if ok {
		t.Fatal("expected no relation for editor")
	}

	// ListRelationSubjects
	subs, _ := s.ListRelationSubjects(ctx, "t1", "document", "doc1", "viewer")
	if len(subs) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(subs))
	}

	// DeleteRelationTuple
	_ = s.DeleteRelationTuple(ctx, "t1", "document", "doc1", "viewer", "user", "u1")
	ok, _ = s.CheckDirectRelation(ctx, "t1", "document", "doc1", "viewer", "user", "u1")
	if ok {
		t.Fatal("expected relation deleted")
	}
}

func TestPolicyCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	p := &policy.Policy{
		ID:       id.NewPolicyID(),
		TenantID: "t1",
		Name:     "ip-restrict",
		Effect:   policy.EffectDeny,
		IsActive: true,
		Actions:  []string{"*"},
		Conditions: []policy.Condition{
			{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: "10.0.0.0/8"},
		},
	}

	if err := s.CreatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ip-restrict" {
		t.Fatal("mismatch")
	}

	// ListActivePolicies
	active, _ := s.ListActivePolicies(ctx, "t1")
	if len(active) != 1 {
		t.Fatalf("expected 1 active policy, got %d", len(active))
	}

	// SetPolicyVersion
	_ = s.SetPolicyVersion(ctx, p.ID, 2)
	got, _ = s.GetPolicy(ctx, p.ID)
	if got.Version != 2 {
		t.Fatal("version not updated")
	}

	// Delete
	_ = s.DeletePolicy(ctx, p.ID)
	_, err = s.GetPolicy(ctx, p.ID)
	if err == nil {
		t.Fatal("expected not found")
	}
}

func TestResourceTypeCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	rt := &resourcetype.ResourceType{
		ID:       id.NewResourceTypeID(),
		TenantID: "t1",
		Name:     "document",
		Relations: []resourcetype.RelationDef{
			{Name: "owner", AllowedSubjects: []string{"user"}},
		},
		Permissions: []resourcetype.PermissionDef{
			{Name: "read", Expression: "owner"},
		},
	}

	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetResourceType(ctx, rt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "document" {
		t.Fatal("mismatch")
	}

	got, err = s.GetResourceTypeByName(ctx, "t1", "document")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Relations) != 1 {
		t.Fatal("relations not preserved")
	}

	_ = s.DeleteResourceType(ctx, rt.ID)
	_, err = s.GetResourceType(ctx, rt.ID)
	if err == nil {
		t.Fatal("expected not found")
	}
}

func TestCheckLogCRUD(t *testing.T) {
	ctx := context.Background()
	s := New()

	e := &checklog.Entry{
		ID:           id.NewCheckLogID(),
		TenantID:     "t1",
		SubjectKind:  "user",
		SubjectID:    "u1",
		Action:       "read",
		ResourceType: "document",
		ResourceID:   "doc1",
		Decision:     "allow",
		CreatedAt:    time.Now(),
	}

	if err := s.CreateCheckLog(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCheckLog(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != "allow" {
		t.Fatal("mismatch")
	}

	logs, _ := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1"})
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	// Purge
	purged, _ := s.PurgeCheckLogs(ctx, time.Now().Add(time.Hour))
	if purged != 1 {
		t.Fatalf("expected 1 purged, got %d", purged)
	}
}

func TestDeleteByTenant(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Create entities for tenant t1.
	_ = s.CreateRole(ctx, &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: "r1", Slug: "r1"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "p1"})
	_ = s.CreatePolicy(ctx, &policy.Policy{ID: id.NewPolicyID(), TenantID: "t1", Name: "pol1"})
	_ = s.CreateResourceType(ctx, &resourcetype.ResourceType{ID: id.NewResourceTypeID(), TenantID: "t1", Name: "rt1"})

	// Create entities for tenant t2.
	_ = s.CreateRole(ctx, &role.Role{ID: id.NewRoleID(), TenantID: "t2", Name: "r2", Slug: "r2"})

	// Delete t1.
	_ = s.DeleteRolesByTenant(ctx, "t1")
	_ = s.DeletePermissionsByTenant(ctx, "t1")
	_ = s.DeletePoliciesByTenant(ctx, "t1")
	_ = s.DeleteResourceTypesByTenant(ctx, "t1")

	roles, _ := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if len(roles) != 0 {
		t.Fatal("t1 roles not deleted")
	}
	roles, _ = s.ListRoles(ctx, &role.ListFilter{TenantID: "t2"})
	if len(roles) != 1 {
		t.Fatal("t2 roles should remain")
	}
}

func TestMigratePingClose(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
