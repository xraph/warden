package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// Tenant used by every case in this contract.
const afTenant = "af-t1"

// RunActorFieldsContract asserts that every backend persists CreatedBy and
// UpdatedBy (GrantedBy for assignments) across a real round trip: create
// with an actor, update with a different actor where the entity supports
// updates, read back, and check both fields.
//
// The bug this guards: the postgres and sqlite update column lists were
// missing updated_by, so an update silently dropped it, and the mongo
// models never mapped the actor columns at all, so they round-tripped as
// empty strings on every backend. created_by must never move: an update
// carries a different actor for created_by too (to catch a store that
// blindly writes whatever the caller passed), and the read-back must still
// show the original creator.
func RunActorFieldsContract(t *testing.T, newStore NewStore) {
	t.Helper()

	t.Run("Role", func(t *testing.T) { runRoleActorFields(t, newStore) })
	t.Run("Permission", func(t *testing.T) { runPermissionActorFields(t, newStore) })
	t.Run("Policy", func(t *testing.T) { runPolicyActorFields(t, newStore) })
	t.Run("ResourceType", func(t *testing.T) { runResourceTypeActorFields(t, newStore) })
	t.Run("Relation", func(t *testing.T) { runRelationActorFields(t, newStore) })
	t.Run("Assignment", func(t *testing.T) { runAssignmentActorFields(t, newStore) })
}

const (
	afCreator = "user:alice"
	afUpdater = "user:bob"
)

func runRoleActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r := &role.Role{
		ID: id.NewRoleID(), TenantID: afTenant, NamespacePath: "",
		Name: "actor-fields", Slug: "actor-fields", CreatedBy: afCreator,
	}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	r.UpdatedBy = afUpdater
	r.CreatedBy = afUpdater // an update must not move created_by even if the caller tries.
	if err := s.UpdateRole(ctx, r); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}

	got, err := s.GetRole(ctx, afTenant, r.ID)
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.CreatedBy != afCreator {
		t.Errorf("CreatedBy moved: want %q, got %q", afCreator, got.CreatedBy)
	}
	if got.UpdatedBy != afUpdater {
		t.Errorf("UpdatedBy did not persist: want %q, got %q", afUpdater, got.UpdatedBy)
	}
}

func runPermissionActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	p := &permission.Permission{
		ID: id.NewPermissionID(), TenantID: afTenant, NamespacePath: "",
		Name: "actor-fields", Resource: "doc", Action: "read", CreatedBy: afCreator,
	}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}

	p.UpdatedBy = afUpdater
	p.CreatedBy = afUpdater
	if err := s.UpdatePermission(ctx, p); err != nil {
		t.Fatalf("UpdatePermission: %v", err)
	}

	got, err := s.GetPermission(ctx, afTenant, p.ID)
	if err != nil {
		t.Fatalf("GetPermission: %v", err)
	}
	if got.CreatedBy != afCreator {
		t.Errorf("CreatedBy moved: want %q, got %q", afCreator, got.CreatedBy)
	}
	if got.UpdatedBy != afUpdater {
		t.Errorf("UpdatedBy did not persist: want %q, got %q", afUpdater, got.UpdatedBy)
	}
}

func runPolicyActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ID: id.NewPolicyID(), TenantID: afTenant, NamespacePath: "",
		Name: "actor-fields", Effect: policy.EffectAllow, Version: 1,
		Subjects: []policy.SubjectMatch{}, Actions: []string{}, Resources: []string{},
		Conditions: []policy.Condition{}, Obligations: []string{},
		CreatedBy: afCreator,
	}
	if err := s.CreatePolicy(ctx, pol); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	pol.UpdatedBy = afUpdater
	pol.CreatedBy = afUpdater
	if err := s.UpdatePolicy(ctx, pol); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}

	got, err := s.GetPolicy(ctx, afTenant, pol.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.CreatedBy != afCreator {
		t.Errorf("CreatedBy moved: want %q, got %q", afCreator, got.CreatedBy)
	}
	if got.UpdatedBy != afUpdater {
		t.Errorf("UpdatedBy did not persist: want %q, got %q", afUpdater, got.UpdatedBy)
	}
}

func runResourceTypeActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	rt := &resourcetype.ResourceType{
		ID: id.NewResourceTypeID(), TenantID: afTenant, NamespacePath: "",
		Name:        "actor-fields",
		Relations:   []resourcetype.RelationDef{},
		Permissions: []resourcetype.PermissionDef{},
		CreatedBy:   afCreator,
	}
	if err := s.CreateResourceType(ctx, rt); err != nil {
		t.Fatalf("CreateResourceType: %v", err)
	}

	rt.UpdatedBy = afUpdater
	rt.CreatedBy = afUpdater
	if err := s.UpdateResourceType(ctx, rt); err != nil {
		t.Fatalf("UpdateResourceType: %v", err)
	}

	got, err := s.GetResourceType(ctx, afTenant, rt.ID)
	if err != nil {
		t.Fatalf("GetResourceType: %v", err)
	}
	if got.CreatedBy != afCreator {
		t.Errorf("CreatedBy moved: want %q, got %q", afCreator, got.CreatedBy)
	}
	if got.UpdatedBy != afUpdater {
		t.Errorf("UpdatedBy did not persist: want %q, got %q", afUpdater, got.UpdatedBy)
	}
}

// runRelationActorFields checks CreatedBy only: relation tuples have no
// Update method and no UpdatedBy field, so there is nothing to move.
func runRelationActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	tuple := &relation.Tuple{
		ID: id.NewRelationID(), TenantID: afTenant, NamespacePath: "",
		ObjectType: "doc", ObjectID: "d1", Relation: "viewer",
		SubjectType: "user", SubjectID: "u1", CreatedBy: afCreator,
	}
	if err := s.CreateRelation(ctx, tuple); err != nil {
		t.Fatalf("CreateRelation: %v", err)
	}

	rows, err := s.ListRelations(ctx, &relation.ListFilter{
		TenantID: afTenant, ObjectType: "doc", ObjectID: "d1", Relation: "viewer",
		SubjectType: "user", SubjectID: "u1",
	})
	if err != nil {
		t.Fatalf("ListRelations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListRelations: want 1 row, got %d", len(rows))
	}
	if rows[0].CreatedBy != afCreator {
		t.Errorf("CreatedBy did not persist: want %q, got %q", afCreator, rows[0].CreatedBy)
	}
}

// runAssignmentActorFields checks GrantedBy: assignments have no Update
// method either, so this is a create-then-read round trip.
func runAssignmentActorFields(t *testing.T, newStore NewStore) {
	s := newStore(t)
	ctx := context.Background()

	r := &role.Role{
		ID: id.NewRoleID(), TenantID: afTenant, NamespacePath: "",
		Name: "actor-fields-role", Slug: "actor-fields-role",
	}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	a := &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: afTenant, NamespacePath: "",
		RoleID: r.ID, SubjectKind: "user", SubjectID: "u1", GrantedBy: afCreator,
	}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}

	got, err := s.GetAssignment(ctx, afTenant, a.ID)
	if err != nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if got.GrantedBy != afCreator {
		t.Errorf("GrantedBy did not persist: want %q, got %q", afCreator, got.GrantedBy)
	}
}
