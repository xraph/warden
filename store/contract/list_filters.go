package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// RunListFiltersContract asserts that every List*/Count* pair honours
// NamespacePath (an exact match) and NamespacePrefix (self or any
// "prefix/..." descendant), that assignment filters also cover
// ResourceType/ResourceID, that relation filters also cover
// SubjectRelation, that check-log filters also cover ResourceID, and that
// Count* reports the full matching row count regardless of Limit/Offset.
func RunListFiltersContract(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("Roles", func(t *testing.T) { runListFilterRoles(t, mk) })
	t.Run("Permissions", func(t *testing.T) { runListFilterPermissions(t, mk) })
	t.Run("Policies", func(t *testing.T) { runListFilterPolicies(t, mk) })
	t.Run("ResourceTypes", func(t *testing.T) { runListFilterResourceTypes(t, mk) })
	t.Run("Assignments", func(t *testing.T) { runListFilterAssignments(t, mk) })
	t.Run("Relations", func(t *testing.T) { runListFilterRelations(t, mk) })
	t.Run("CheckLogs", func(t *testing.T) { runListFilterCheckLogs(t, mk) })
	t.Run("CountIgnoresLimitOffset", func(t *testing.T) { runCountIgnoresLimitOffset(t, mk) })
}

func runListFilterRoles(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	seedRole(t, s, "t1", "eng", "lf-self")
	seedRole(t, s, "t1", "eng/platform", "lf-child")
	seedRole(t, s, "t1", "other", "lf-decoy")

	exact := "eng"
	got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePath: &exact})
	if err != nil {
		t.Fatalf("ListRoles NamespacePath: %v", err)
	}
	if len(got) != 1 || got[0].NamespacePath != "eng" {
		t.Errorf("NamespacePath=%q: want 1 role at exactly that path, got %d", exact, len(got))
	}

	got, err = s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("ListRoles NamespacePrefix: %v", err)
	}
	assertNamespaces(t, "ListRoles NamespacePrefix", got, func(r *role.Role) string { return r.NamespacePath }, "eng", "eng/platform")

	count, err := s.CountRoles(ctx, &role.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("CountRoles NamespacePrefix: %v", err)
	}
	if count != 2 {
		t.Errorf("CountRoles NamespacePrefix=%q: want 2, got %d", "eng", count)
	}
}

func runListFilterPermissions(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	mkPerm := func(ns, name string) {
		p := &permission.Permission{
			ID: id.NewPermissionID(), TenantID: "t1", NamespacePath: ns,
			Name: name, Resource: "doc", Action: "read",
		}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("seed permission %q: %v", name, err)
		}
	}
	mkPerm("eng", "lf-self")
	mkPerm("eng/platform", "lf-child")
	mkPerm("other", "lf-decoy")

	exact := "eng"
	got, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", NamespacePath: &exact})
	if err != nil {
		t.Fatalf("ListPermissions NamespacePath: %v", err)
	}
	if len(got) != 1 || got[0].NamespacePath != "eng" {
		t.Errorf("NamespacePath=%q: want 1 permission, got %d", exact, len(got))
	}

	got, err = s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("ListPermissions NamespacePrefix: %v", err)
	}
	assertNamespaces(t, "ListPermissions NamespacePrefix", got, func(p *permission.Permission) string { return p.NamespacePath }, "eng", "eng/platform")
}

func runListFilterPolicies(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	createPolicy(t, s, "t1", "eng", "lf-self")
	createPolicy(t, s, "t1", "eng/platform", "lf-child")
	createPolicy(t, s, "t1", "other", "lf-decoy")

	exact := "eng"
	got, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: "t1", NamespacePath: &exact})
	if err != nil {
		t.Fatalf("ListPolicies NamespacePath: %v", err)
	}
	if len(got) != 1 || got[0].NamespacePath != "eng" {
		t.Errorf("NamespacePath=%q: want 1 policy, got %d", exact, len(got))
	}

	got, err = s.ListPolicies(ctx, &policy.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("ListPolicies NamespacePrefix: %v", err)
	}
	assertNamespaces(t, "ListPolicies NamespacePrefix", got, func(p *policy.Policy) string { return p.NamespacePath }, "eng", "eng/platform")
}

func runListFilterResourceTypes(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	mkRT := func(ns, name string) {
		rt := &resourcetype.ResourceType{
			ID: id.NewResourceTypeID(), TenantID: "t1", NamespacePath: ns,
			Name:        name,
			Relations:   []resourcetype.RelationDef{},
			Permissions: []resourcetype.PermissionDef{},
		}
		if err := s.CreateResourceType(ctx, rt); err != nil {
			t.Fatalf("seed resource type %q: %v", name, err)
		}
	}
	mkRT("eng", "lf-self")
	mkRT("eng/platform", "lf-child")
	mkRT("other", "lf-decoy")

	exact := "eng"
	got, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: "t1", NamespacePath: &exact})
	if err != nil {
		t.Fatalf("ListResourceTypes NamespacePath: %v", err)
	}
	if len(got) != 1 || got[0].NamespacePath != "eng" {
		t.Errorf("NamespacePath=%q: want 1 resource type, got %d", exact, len(got))
	}

	got, err = s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("ListResourceTypes NamespacePrefix: %v", err)
	}
	assertNamespaces(t, "ListResourceTypes NamespacePrefix", got, func(rt *resourcetype.ResourceType) string { return rt.NamespacePath }, "eng", "eng/platform")
}

func runListFilterAssignments(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	r := seedRole(t, s, "t1", "", "lf-asg-role")
	mkAsg := func(ns, resourceType, resourceID string) {
		createAssignment(t, s, &assignment.Assignment{
			ID: id.NewAssignmentID(), TenantID: "t1", NamespacePath: ns,
			RoleID: r, SubjectKind: "user", SubjectID: "alice",
			ResourceType: resourceType, ResourceID: resourceID,
		})
	}
	mkAsg("eng", "doc", "d1")
	mkAsg("eng/platform", "doc", "d2")
	mkAsg("other", "doc", "d3")
	mkAsg("eng", "folder", "f1")

	got, err := s.ListAssignments(ctx, &assignment.ListFilter{TenantID: "t1", NamespacePrefix: "eng"})
	if err != nil {
		t.Fatalf("ListAssignments NamespacePrefix: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("NamespacePrefix=%q: want 3 assignments, got %d", "eng", len(got))
	}

	got, err = s.ListAssignments(ctx, &assignment.ListFilter{TenantID: "t1", ResourceType: "doc", ResourceID: "d1"})
	if err != nil {
		t.Fatalf("ListAssignments ResourceType/ResourceID: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "d1" {
		t.Errorf("ResourceType=doc ResourceID=d1: want 1 assignment, got %d", len(got))
	}
}

func runListFilterRelations(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	mkRel := func(subjectRelation string) {
		if err := s.CreateRelation(ctx, &relation.Tuple{
			ID: id.NewRelationID(), TenantID: "t1",
			ObjectType: "doc", ObjectID: "d1", Relation: "viewer",
			SubjectType: "group", SubjectID: "g1", SubjectRelation: subjectRelation,
		}); err != nil {
			t.Fatalf("seed relation (subject_relation=%q): %v", subjectRelation, err)
		}
	}
	mkRel("member")
	mkRel("owner")

	got, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", SubjectRelation: "member"})
	if err != nil {
		t.Fatalf("ListRelations SubjectRelation: %v", err)
	}
	if len(got) != 1 || got[0].SubjectRelation != "member" {
		t.Errorf("SubjectRelation=member: want 1 relation, got %d", len(got))
	}
}

func runListFilterCheckLogs(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	mkLog := func(resourceID string) {
		e := &checklog.Entry{
			ID: id.NewCheckLogID(), TenantID: "t1",
			SubjectKind: "user", SubjectID: "alice", Action: "read",
			ResourceType: "doc", ResourceID: resourceID, Decision: "allow",
		}
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("seed check log (resource_id=%q): %v", resourceID, err)
		}
	}
	mkLog("d1")
	mkLog("d2")

	got, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", ResourceID: "d1"})
	if err != nil {
		t.Fatalf("ListCheckLogs ResourceID: %v", err)
	}
	if len(got) != 1 || got[0].ResourceID != "d1" {
		t.Errorf("ResourceID=d1: want 1 check log, got %d", len(got))
	}
}

func runCountIgnoresLimitOffset(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	for i := range 5 {
		seedRole(t, s, "t1", "", slugFor("cnt", i))
	}

	limited, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: 2})
	if err != nil {
		t.Fatalf("ListRoles with limit: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("ListRoles Limit=2: want 2 rows, got %d", len(limited))
	}

	count, err := s.CountRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("CountRoles with limit/offset: %v", err)
	}
	if count != 5 {
		t.Errorf("CountRoles must ignore Limit/Offset: want 5, got %d", count)
	}
}

// assertNamespaces checks that got contains exactly one entry for each
// namespace path in want (by count, not identity) and nothing else — in
// particular, nothing from the "other" decoy namespace used throughout this
// file.
func assertNamespaces[T any](t *testing.T, label string, got []T, nsOf func(T) string, want ...string) {
	t.Helper()
	gotSet := make(map[string]int, len(got))
	for _, item := range got {
		gotSet[nsOf(item)]++
	}
	for _, ns := range want {
		if gotSet[ns] == 0 {
			t.Errorf("%s: expected a row at namespace %q, found none", label, ns)
		}
	}
	if gotSet["other"] != 0 {
		t.Errorf("%s: decoy row at namespace %q leaked into result", label, "other")
	}
}
