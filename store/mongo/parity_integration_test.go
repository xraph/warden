//go:build integration

// Focused integration tests for the mongo-parity fixes: duplicate-key
// mapping on CreateRelation (the one entity RunUniquenessContract doesn't
// cover), DeleteRole's cascade, SetRolePermissions' replace semantics, the
// expiry predicate on the two role-lookup methods the Check() hot path
// calls, namespace_path filtering on List*/Count*, search-string escaping,
// and the opt-in check-log TTL index.
package mongo

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
)

// setupMongoStore is like setupMongo but returns the concrete *Store (not
// the store.Store interface) so tests can pass construction Options and
// reach into unexported collections/fields to assert on index state.
func setupMongoStore(t *testing.T, opts ...Option) (*Store, func()) {
	t.Helper()
	uri := connURI(t)
	dbName := freshDBName(t)
	ctx := context.Background()

	drv := mongodriver.New()
	if err := drv.Open(ctx, uri, mongodriver.WithDatabase(dbName)); err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		_ = drv.Close()
		t.Fatalf("grove open: %v", err)
	}
	s := New(db, opts...)
	if err := s.Migrate(ctx); err != nil {
		_ = drv.Close()
		t.Fatalf("migrate: %v", err)
	}
	cleanup := func() {
		_ = drv.Database().Drop(context.Background())
		_ = drv.Close()
	}
	return s, cleanup
}

// ───── duplicate-key mapping ─────

// TestMongo_CreateRelation_DuplicateRejected covers the one entity
// RunUniquenessContract doesn't: relation tuples aren't slug/name scoped,
// so they get their own focused test for the mongod.IsDuplicateKeyError ->
// wardenerr.ErrDuplicateRelation mapping.
func TestMongo_CreateRelation_DuplicateRejected(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mkTuple := func() *relation.Tuple {
		return &relation.Tuple{
			ID: id.NewRelationID(), TenantID: "t1", NamespacePath: "/app",
			ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
			SubjectType: "user", SubjectID: "alice",
		}
	}
	if err := s.CreateRelation(ctx, mkTuple()); err != nil {
		t.Fatalf("first create: %v", err)
	}
	err := s.CreateRelation(ctx, mkTuple())
	if !errors.Is(err, warden.ErrDuplicateRelation) {
		t.Fatalf("expected ErrDuplicateRelation, got %v", err)
	}
	if !errors.Is(err, warden.ErrAlreadyExists) {
		t.Fatalf("expected error to wrap ErrAlreadyExists, got %v", err)
	}
}

// ───── DeleteRole cascade ─────

func TestMongo_DeleteRole_CascadesAssignmentsAndGrants(t *testing.T) {
	s, cleanup := setupMongoStore(t)
	defer cleanup()
	ctx := context.Background()

	r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: "Editor", Slug: "editor"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	p := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: p.Name}); err != nil {
		t.Fatalf("attach permission: %v", err)
	}
	a := &assignment.Assignment{ID: id.NewAssignmentID(), TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "alice"}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("create assignment: %v", err)
	}

	if err := s.DeleteRole(ctx, "t1", r.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	if _, err := s.GetAssignment(ctx, "t1", a.ID); !errors.Is(err, warden.ErrAssignmentNotFound) {
		t.Fatalf("expected assignment to be gone after role delete, got %v", err)
	}

	count, err := s.mdb.NewFind((*rolePermissionModel)(nil)).
		Filter(bson.M{"role_id": r.ID.String()}).
		Count(ctx)
	if err != nil {
		t.Fatalf("count role-permission grants: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 role-permission grants after role delete, got %d", count)
	}
}

// ───── SetRolePermissions replace semantics ─────

func TestMongo_SetRolePermissions_ReplacesExisting(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: "Editor", Slug: "editor"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	p1 := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"}
	p2 := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:write", Resource: "doc", Action: "write"}
	for _, p := range []*permission.Permission{p1, p2} {
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("create permission %q: %v", p.Name, err)
		}
	}

	if err := s.SetRolePermissions(ctx, "t1", r.ID, []permission.Ref{{Name: p1.Name}}); err != nil {
		t.Fatalf("set [p1]: %v", err)
	}
	perms, err := s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list after set [p1]: %v", err)
	}
	if len(perms) != 1 || perms[0].Name != p1.Name {
		t.Fatalf("expected [%s], got %v", p1.Name, permNames(perms))
	}

	if err := s.SetRolePermissions(ctx, "t1", r.ID, []permission.Ref{{Name: p2.Name}}); err != nil {
		t.Fatalf("set [p2]: %v", err)
	}
	perms, err = s.ListRolePermissions(ctx, "t1", r.ID)
	if err != nil {
		t.Fatalf("list after set [p2]: %v", err)
	}
	if len(perms) != 1 || perms[0].Name != p2.Name {
		t.Fatalf("expected replace to leave exactly [%s], got %v", p2.Name, permNames(perms))
	}
}

func permNames(perms []*permission.Permission) []string {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = p.Name
	}
	return out
}

// ───── expiry predicate ─────

func TestMongo_ListRolesForSubject_ExcludesExpiredAssignments(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mkRole := func(slug string) id.RoleID {
		r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: slug, Slug: slug}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role %q: %v", slug, err)
		}
		return r.ID
	}
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)

	expiredRole := mkRole("expired")
	activeRole := mkRole("active")
	neverExpiresRole := mkRole("never-expires")

	seed := func(roleID id.RoleID, exp *time.Time) {
		a := &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleID,
			SubjectKind: "user", SubjectID: "alice", ExpiresAt: exp,
		}
		if err := s.CreateAssignment(ctx, a); err != nil {
			t.Fatalf("create assignment for role %s: %v", roleID, err)
		}
	}
	seed(expiredRole, &past)
	seed(activeRole, &future)
	seed(neverExpiresRole, nil)

	got, err := s.ListRolesForSubject(ctx, "t1", nil, "user", "alice")
	if err != nil {
		t.Fatalf("ListRolesForSubject: %v", err)
	}
	gotSet := make(map[string]bool, len(got))
	for _, rid := range got {
		gotSet[rid.String()] = true
	}
	if gotSet[expiredRole.String()] {
		t.Errorf("expired assignment's role leaked into ListRolesForSubject")
	}
	if !gotSet[activeRole.String()] {
		t.Errorf("future-expiring assignment's role missing from ListRolesForSubject")
	}
	if !gotSet[neverExpiresRole.String()] {
		t.Errorf("never-expiring assignment's role missing from ListRolesForSubject")
	}
}

func TestMongo_ListRolesForSubjectOnResource_ExcludesExpiredAssignments(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mkRole := func(slug string) id.RoleID {
		r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: slug, Slug: slug}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role %q: %v", slug, err)
		}
		return r.ID
	}
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)

	expiredRole := mkRole("expired-res")
	activeRole := mkRole("active-res")

	seed := func(roleID id.RoleID, exp *time.Time) {
		a := &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleID,
			SubjectKind: "user", SubjectID: "bob",
			ResourceType: "doc", ResourceID: "doc1", ExpiresAt: exp,
		}
		if err := s.CreateAssignment(ctx, a); err != nil {
			t.Fatalf("create assignment for role %s: %v", roleID, err)
		}
	}
	seed(expiredRole, &past)
	seed(activeRole, &future)

	got, err := s.ListRolesForSubjectOnResource(ctx, "t1", nil, "user", "bob", "doc", "doc1")
	if err != nil {
		t.Fatalf("ListRolesForSubjectOnResource: %v", err)
	}
	gotSet := make(map[string]bool, len(got))
	for _, rid := range got {
		gotSet[rid.String()] = true
	}
	if gotSet[expiredRole.String()] {
		t.Errorf("expired assignment's role leaked into ListRolesForSubjectOnResource")
	}
	if !gotSet[activeRole.String()] {
		t.Errorf("future-expiring assignment's role missing from ListRolesForSubjectOnResource")
	}
}

// ───── namespace_path / namespace_prefix filters ─────

func TestMongo_ListRoles_NamespaceFilter(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mk := func(ns, slug string) {
		r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", NamespacePath: ns, Name: slug, Slug: slug}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role in %q: %v", ns, err)
		}
	}
	mk("eng", "r-eng")
	mk("eng/platform", "r-eng-platform")
	mk("sales", "r-sales")
	mk("engineering", "r-engineering") // shares the "eng" string prefix, not the namespace

	t.Run("ExactMatch", func(t *testing.T) {
		exact := "eng"
		got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePath: &exact})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].Slug != "r-eng" {
			t.Fatalf("exact match on %q: expected [r-eng], got %v", exact, roleSlugs(got))
		}
		n, err := s.CountRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePath: &exact})
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatalf("CountRoles exact = %d, want 1", n)
		}
	})

	t.Run("PrefixMatchesSelfAndDescendants", func(t *testing.T) {
		got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		slugs := roleSlugs(got)
		want := map[string]bool{"r-eng": true, "r-eng-platform": true}
		if len(got) != len(want) {
			t.Fatalf("prefix %q: expected %d roles, got %d (%v)", "eng", len(want), len(got), slugs)
		}
		for _, s := range slugs {
			if !want[s] {
				t.Fatalf("prefix %q leaked unrelated role %q (got %v)", "eng", s, slugs)
			}
		}
	})
}

func TestMongo_ListPermissions_NamespaceFilter(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mk := func(ns, name string) {
		p := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: ns, Name: name, Resource: "doc", Action: "read"}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("create permission in %q: %v", ns, err)
		}
	}
	mk("eng", "p-eng")
	mk("eng/platform", "p-eng-platform")
	mk("sales", "p-sales")

	got, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		names := make([]string, len(got))
		for i, p := range got {
			names[i] = p.Name
		}
		t.Fatalf("prefix %q: expected 2 permissions, got %d (%v)", "eng", len(got), names)
	}
}

func roleSlugs(roles []*role.Role) []string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = r.Slug
	}
	return out
}

// ───── search escaping and length cap ─────

func TestMongo_ListPermissions_SearchIsLiteralNotRegex(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	mk := func(name string) {
		p := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: name, Resource: "doc", Action: "read"}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("create permission %q: %v", name, err)
		}
	}
	// "doc.read" contains a regex metacharacter ('.'); if the search string
	// were compiled as a pattern instead of escaped, "docXread" would also
	// match "doc.read" because '.' matches any character.
	mk("doc.read")
	mk("docXread")
	mk("unrelated")

	got, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", Search: "doc.read"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "doc.read" {
		names := make([]string, len(got))
		for i, p := range got {
			names[i] = p.Name
		}
		t.Fatalf("search %q: expected only the literal match [doc.read], got %v", "doc.read", names)
	}
}

func TestMongo_ListPermissions_SearchTruncatesOversizedInput(t *testing.T) {
	s, cleanup := setupMongo(t)
	defer cleanup()
	ctx := context.Background()

	p := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("create permission: %v", err)
	}

	huge := strings.Repeat("a", 10_000)
	if _, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", Search: huge}); err != nil {
		t.Fatalf("oversized search should be truncated, not error: %v", err)
	}
	if _, err := s.CountPermissions(ctx, &permission.ListFilter{TenantID: "t1", Search: huge}); err != nil {
		t.Fatalf("oversized search should be truncated, not error: %v", err)
	}
}

// ───── check-log TTL index, opt-in only ─────

func TestMongo_CheckLogTTLIndex_OnlyWhenConfigured(t *testing.T) {
	t.Run("Default_NoTTLIndex", func(t *testing.T) {
		s, cleanup := setupMongoStore(t)
		defer cleanup()
		if hasIndex(t, s, colCheckLogs, checkLogTTLIndexName) {
			t.Fatalf("TTL index must not exist without WithCheckLogTTL")
		}
	})

	t.Run("WithCheckLogTTL_CreatesIndex", func(t *testing.T) {
		s, cleanup := setupMongoStore(t, WithCheckLogTTL(24*time.Hour))
		defer cleanup()
		if !hasIndex(t, s, colCheckLogs, checkLogTTLIndexName) {
			t.Fatalf("expected TTL index to exist when constructed with WithCheckLogTTL")
		}
	})
}

func hasIndex(t *testing.T, s *Store, collection, name string) bool {
	t.Helper()
	ctx := context.Background()
	cur, err := s.mdb.Collection(collection).Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes on %s: %v", collection, err)
	}
	defer func() { _ = cur.Close(ctx) }()
	var docs []bson.M
	if err := cur.All(ctx, &docs); err != nil {
		t.Fatalf("decode indexes on %s: %v", collection, err)
	}
	for _, d := range docs {
		if n, _ := d["name"].(string); n == name {
			return true
		}
	}
	return false
}
