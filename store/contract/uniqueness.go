package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// RunUniquenessContract asserts the documented uniqueness invariant
// across every entity type a Warden store persists:
//
//   - Two entities sharing (tenant_id, namespace_path, slug|name) are
//     rejected with the matching ErrDuplicate* sentinel.
//   - Same slug|name across different namespaces is allowed.
//   - Same slug|name across different tenants is allowed.
//
// Backends call this from their own test files with a MakeStore factory
// (see autoid.go for the same pattern). Each subtest gets its own
// fresh store via the factory so tests don't interfere.
func RunUniquenessContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("Role", func(t *testing.T) { runRoleUniqueness(t, mk) })
	t.Run("Permission", func(t *testing.T) { runPermissionUniqueness(t, mk) })
	t.Run("Policy", func(t *testing.T) { runPolicyUniqueness(t, mk) })
	t.Run("ResourceType", func(t *testing.T) { runResourceTypeUniqueness(t, mk) })
	t.Run("Assignment", func(t *testing.T) { runAssignmentUniqueness(t, mk) })
}

// ───── Role ─────

func runRoleUniqueness(t *testing.T, mk MakeStore) {
	t.Run("DuplicateInSameScope_Rejected", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		mkRole := func() *role.Role {
			return &role.Role{
				ID: id.NewRoleID(), TenantID: "t1", NamespacePath: "/app",
				Name: "Viewer", Slug: "viewer",
			}
		}
		if err := s.CreateRole(ctx, mkRole()); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := s.CreateRole(ctx, mkRole())
		if !errors.Is(err, warden.ErrDuplicateRole) {
			t.Fatalf("expected ErrDuplicateRole, got %v", err)
		}
		if !errors.Is(err, warden.ErrAlreadyExists) {
			t.Fatalf("expected error to wrap ErrAlreadyExists, got %v", err)
		}
	})

	t.Run("DuplicateSlugInDifferentNamespace_Allowed", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		for _, ns := range []string{"/app/v1", "/app/v2"} {
			err := s.CreateRole(ctx, &role.Role{
				ID: id.NewRoleID(), TenantID: "t1", NamespacePath: ns,
				Name: "Viewer", Slug: "viewer",
			})
			if err != nil {
				t.Fatalf("create in ns %q: %v", ns, err)
			}
		}
	})

	t.Run("DuplicateSlugInDifferentTenant_Allowed", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		for _, tenant := range []string{"t1", "t2"} {
			err := s.CreateRole(ctx, &role.Role{
				ID: id.NewRoleID(), TenantID: tenant, NamespacePath: "/app",
				Name: "Viewer", Slug: "viewer",
			})
			if err != nil {
				t.Fatalf("create in tenant %q: %v", tenant, err)
			}
		}
	})
}

// ───── Permission ─────

func runPermissionUniqueness(t *testing.T, mk MakeStore) {
	t.Run("DuplicateInSameScope_Rejected", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		mkPerm := func() *permission.Permission {
			return &permission.Permission{
				ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: "/app",
				Name: "doc:read", Resource: "doc", Action: "read",
			}
		}
		if err := s.CreatePermission(ctx, mkPerm()); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := s.CreatePermission(ctx, mkPerm())
		if !errors.Is(err, warden.ErrDuplicatePermission) {
			t.Fatalf("expected ErrDuplicatePermission, got %v", err)
		}
	})

	t.Run("DuplicateNameInDifferentNamespace_Allowed", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		for _, ns := range []string{"/app/v1", "/app/v2"} {
			err := s.CreatePermission(ctx, &permission.Permission{
				ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: ns,
				Name: "doc:read", Resource: "doc", Action: "read",
			})
			if err != nil {
				t.Fatalf("create in ns %q: %v", ns, err)
			}
		}
	})
}

// ───── Policy ─────

func runPolicyUniqueness(t *testing.T, mk MakeStore) {
	t.Run("DuplicateInSameScope_Rejected", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		mkPol := func() *policy.Policy {
			return &policy.Policy{
				ID: id.NewPolicyID(), TenantID: "t1", NamespacePath: "/app",
				Name: "no-after-hours", Effect: policy.EffectDeny,
				// Postgres has NOT NULL JSONB columns for these slices; supply
				// empty rather than nil so the marshaler emits "[]" not NULL.
				Subjects:    []policy.SubjectMatch{},
				Actions:     []string{},
				Resources:   []string{},
				Conditions:  []policy.Condition{},
				Obligations: []string{},
			}
		}
		if err := s.CreatePolicy(ctx, mkPol()); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := s.CreatePolicy(ctx, mkPol())
		if !errors.Is(err, warden.ErrDuplicatePolicy) {
			t.Fatalf("expected ErrDuplicatePolicy, got %v", err)
		}
	})
}

// ───── ResourceType ─────

func runResourceTypeUniqueness(t *testing.T, mk MakeStore) {
	t.Run("DuplicateInSameScope_Rejected", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		mkRT := func() *resourcetype.ResourceType {
			return &resourcetype.ResourceType{
				ID: id.NewResourceTypeID(), TenantID: "t1", NamespacePath: "/app",
				Name: "doc",
				// Postgres has NOT NULL JSONB columns; supply empty
				// slices so the marshaler emits "[]" not NULL.
				Relations:   []resourcetype.RelationDef{},
				Permissions: []resourcetype.PermissionDef{},
			}
		}
		if err := s.CreateResourceType(ctx, mkRT()); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := s.CreateResourceType(ctx, mkRT())
		if !errors.Is(err, warden.ErrDuplicateResourceType) {
			t.Fatalf("expected ErrDuplicateResourceType, got %v", err)
		}
	})
}

// ───── Assignment ─────

func runAssignmentUniqueness(t *testing.T, mk MakeStore) {
	t.Run("DuplicateInSameScope_Rejected", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		// Assignments require an existing role to satisfy the FK on
		// postgres. Memory and sqlite don't enforce FK so any role_id
		// works there; postgres needs a real role.
		roleID := seedRole(t, s, "t1", "/app", "viewer")

		mkAsg := func() *assignment.Assignment {
			return &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: "/app",
				RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
			}
		}
		if err := s.CreateAssignment(ctx, mkAsg()); err != nil {
			t.Fatalf("first create: %v", err)
		}
		err := s.CreateAssignment(ctx, mkAsg())
		if !errors.Is(err, warden.ErrDuplicateAssignment) {
			t.Fatalf("expected ErrDuplicateAssignment, got %v", err)
		}
	})

	t.Run("SameRoleSubjectInDifferentScopedResource_Allowed", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		roleID := seedRole(t, s, "t1", "/app", "viewer")

		for _, rid := range []string{"doc1", "doc2"} {
			err := s.CreateAssignment(ctx, &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: "/app",
				RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
				ResourceType: "doc", ResourceID: rid,
			})
			if err != nil {
				t.Fatalf("create scoped to %q: %v", rid, err)
			}
		}
	})
}

// seedRole creates a role and returns its ID. Used by tests that
// need a foreign-key target.
func seedRole(t *testing.T, s store.Store, tenantID, namespacePath, slug string) id.RoleID {
	t.Helper()
	r := &role.Role{
		ID: id.NewRoleID(), TenantID: tenantID, NamespacePath: namespacePath,
		Name: slug, Slug: slug,
	}
	if err := s.CreateRole(context.Background(), r); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	return r.ID
}
