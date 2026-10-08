package contract

import (
	"context"
	"sort"
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
	t.Run("DefaultLimitCap", func(t *testing.T) { runListDefaultLimitCap(t, mk) })
	t.Run("PagingWalk", func(t *testing.T) { runListPagingWalk(t, mk) })
	t.Run("Ordering", func(t *testing.T) { runListOrdering(t, mk) })
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

	mkLog := func(resourceID, decision string, cached bool) {
		e := &checklog.Entry{
			ID: id.NewCheckLogID(), TenantID: "t1",
			SubjectKind: "user", SubjectID: "alice", Action: "read",
			ResourceType: "doc", ResourceID: resourceID, Decision: decision,
			Cached: cached,
		}
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("seed check log (resource_id=%q): %v", resourceID, err)
		}
	}
	mkLog("d1", "allow", false)
	mkLog("d2", "allow", true)
	mkLog("d3", "deny_default", true)
	mkLog("d4", "deny_default", false)

	resources := func(label string, f *checklog.QueryFilter, want ...string) {
		t.Helper()
		got, err := s.ListCheckLogs(ctx, f)
		if err != nil {
			t.Fatalf("%s: ListCheckLogs: %v", label, err)
		}
		gotIDs := make([]string, 0, len(got))
		for _, e := range got {
			gotIDs = append(gotIDs, e.ResourceID)
		}
		sort.Strings(gotIDs)
		if !equalStrings(gotIDs, want) {
			t.Errorf("%s: list want %v, got %v", label, want, gotIDs)
		}
		n, err := s.CountCheckLogs(ctx, f)
		if err != nil {
			t.Fatalf("%s: CountCheckLogs: %v", label, err)
		}
		if n != int64(len(want)) {
			t.Errorf("%s: count want %d, got %d", label, len(want), n)
		}
	}

	yes, no := true, false
	resources("ResourceID=d1", &checklog.QueryFilter{TenantID: "t1", ResourceID: "d1"}, "d1")
	resources("Cached=nil", &checklog.QueryFilter{TenantID: "t1"}, "d1", "d2", "d3", "d4")
	resources("Cached=true", &checklog.QueryFilter{TenantID: "t1", Cached: &yes}, "d2", "d3")
	resources("Cached=false", &checklog.QueryFilter{TenantID: "t1", Cached: &no}, "d1", "d4")
	resources("Cached=true+Decision", &checklog.QueryFilter{TenantID: "t1", Cached: &yes, Decision: "deny_default"}, "d3")
	resources("Cached=false+Decision", &checklog.QueryFilter{TenantID: "t1", Cached: &no, Decision: "allow"}, "d1")
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

// runListDefaultLimitCap asserts the L6 default: a List* call with no
// explicit Limit still caps at 1000 rows, on every backend, while Count*
// keeps reporting the true total. Roles is enough to exercise the shared
// pagination path: postgres and sqlite apply the same fanoutLimit/listLimit
// helper across every entity, and memory's applyPagination is generic over
// all of them too.
func runListDefaultLimitCap(t *testing.T, mk MakeStore) {
	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	const seeded = 1001
	for i := range seeded {
		seedRole(t, s, "t1", "", slugFor("cap", i))
	}

	got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("ListRoles with no Limit: %v", err)
	}
	if len(got) != 1000 {
		t.Errorf("ListRoles with no Limit set: want the default cap of 1000 rows, got %d", len(got))
	}

	count, err := s.CountRoles(ctx, &role.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("CountRoles with no Limit: %v", err)
	}
	if count != seeded {
		t.Errorf("CountRoles must report every matching row regardless of List's default cap: want %d, got %d", seeded, count)
	}
}

// assertNamespaces checks that got contains exactly one entry for each
// namespace path in want (by count, not identity) and nothing else: in
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

// ──────────────────────────────────────────────────
// Paging contract
// ──────────────────────────────────────────────────

const (
	// pagingSeeded is well past the default cap, so an unlimited call has
	// something to truncate.
	//
	// It is 5000 rather than a hair over the cap for a second reason:
	// Postgres only reorders tied rows once the table is big enough that
	// the planner picks a different sort for a shallow page than for a deep
	// one (a parallel Gather Merge near the start, a plain serial Sort once
	// LIMIT+OFFSET grows). Below roughly 3000 rows every page shares one
	// plan and the missing tiebreaker stays invisible; at 5000 a walk
	// reproducibly loses rows. Lower this and the test stops being able to
	// fail.
	pagingSeeded = 5000
	// pagingPage is the explicit Limit the offset walk pages with.
	pagingPage = 500
	// pagingCap mirrors the L6 default every backend applies when a caller
	// leaves Limit unset.
	pagingCap = 1000
)

// pagingCreatedAt is the single timestamp every row in the paging contract
// shares. created_at is the leading sort key on all four backends, so
// pinning it puts the whole burden of ordering on the tiebreaker: with no
// tiebreaker, a page boundary lands in the middle of one tied run and rows
// shuffle between calls. Real data ties like this too, whenever a bulk seed
// or a migration writes a batch of rows inside one timestamp tick.
var pagingCreatedAt = time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

// runListPagingWalk asserts both halves of the L6 pagination contract for
// every general List*: an unlimited call truncates at the default cap, and
// paging with an explicit Limit visits every seeded row exactly once. The
// second half is what catches a non-total ORDER BY, where offset paging
// silently repeats some rows and skips others.
func runListPagingWalk(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("Roles", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			r := &role.Role{
				ID: id.NewRoleID(), TenantID: "t1",
				Name: slugFor("pg", i), Slug: slugFor("pg", i),
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreateRole(ctx, r); err != nil {
				t.Fatalf("seed role %d: %v", i, err)
			}
			seeded = append(seeded, r.ID.String())
		}
		assertPagingWalk(t, "ListRoles", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(r *role.Role) string { return r.ID.String() }), err
		})
	})

	t.Run("Permissions", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			p := &permission.Permission{
				ID: id.NewPermissionID(), TenantID: "t1",
				Name: slugFor("pg", i), Resource: "doc", Action: "read",
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreatePermission(ctx, p); err != nil {
				t.Fatalf("seed permission %d: %v", i, err)
			}
			seeded = append(seeded, p.ID.String())
		}
		assertPagingWalk(t, "ListPermissions", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(p *permission.Permission) string { return p.ID.String() }), err
		})
	})

	t.Run("Policies", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			p := &policy.Policy{
				ID: id.NewPolicyID(), TenantID: "t1",
				Name: slugFor("pg", i), Effect: policy.EffectAllow, IsActive: true,
				Subjects: []policy.SubjectMatch{}, Actions: []string{},
				Resources: []string{}, Conditions: []policy.Condition{},
				Obligations: []string{},
				CreatedAt:   pagingCreatedAt,
			}
			if err := s.CreatePolicy(ctx, p); err != nil {
				t.Fatalf("seed policy %d: %v", i, err)
			}
			seeded = append(seeded, p.ID.String())
		}
		assertPagingWalk(t, "ListPolicies", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(p *policy.Policy) string { return p.ID.String() }), err
		})
	})

	t.Run("ResourceTypes", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			rt := &resourcetype.ResourceType{
				ID: id.NewResourceTypeID(), TenantID: "t1",
				Name:      slugFor("pg", i),
				Relations: []resourcetype.RelationDef{}, Permissions: []resourcetype.PermissionDef{},
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreateResourceType(ctx, rt); err != nil {
				t.Fatalf("seed resource type %d: %v", i, err)
			}
			seeded = append(seeded, rt.ID.String())
		}
		assertPagingWalk(t, "ListResourceTypes", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(rt *resourcetype.ResourceType) string { return rt.ID.String() }), err
		})
	})

	t.Run("Assignments", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		roleID := seedRole(t, s, "t1", "", "pg-asg-role")
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			a := &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1",
				RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
				ResourceType: "doc", ResourceID: slugFor("pg", i),
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreateAssignment(ctx, a); err != nil {
				t.Fatalf("seed assignment %d: %v", i, err)
			}
			seeded = append(seeded, a.ID.String())
		}
		assertPagingWalk(t, "ListAssignments", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListAssignments(ctx, &assignment.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(a *assignment.Assignment) string { return a.ID.String() }), err
		})
	})

	t.Run("Relations", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			tuple := &relation.Tuple{
				ID: id.NewRelationID(), TenantID: "t1",
				ObjectType: "doc", ObjectID: slugFor("pg", i), Relation: "viewer",
				SubjectType: "user", SubjectID: "alice",
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreateRelation(ctx, tuple); err != nil {
				t.Fatalf("seed relation %d: %v", i, err)
			}
			seeded = append(seeded, tuple.ID.String())
		}
		assertPagingWalk(t, "ListRelations", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(tu *relation.Tuple) string { return tu.ID.String() }), err
		})
	})

	t.Run("CheckLogs", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		seeded := make([]string, 0, pagingSeeded)
		for i := range pagingSeeded {
			e := &checklog.Entry{
				ID: id.NewCheckLogID(), TenantID: "t1",
				SubjectKind: "user", SubjectID: "alice", Action: "read",
				ResourceType: "doc", ResourceID: slugFor("pg", i), Decision: "allow",
				CreatedAt: pagingCreatedAt,
			}
			if err := s.CreateCheckLog(ctx, e); err != nil {
				t.Fatalf("seed check log %d: %v", i, err)
			}
			seeded = append(seeded, e.ID.String())
		}
		assertPagingWalk(t, "ListCheckLogs", seeded, func(limit, offset int) ([]string, error) {
			got, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", Limit: limit, Offset: offset})
			return idStrings(got, func(e *checklog.Entry) string { return e.ID.String() }), err
		})
	})
}

// assertPagingWalk checks that listIDs caps an unlimited call at pagingCap
// and that paging it with pagingPage visits every seeded id exactly once.
func assertPagingWalk(t *testing.T, label string, seeded []string, listIDs func(limit, offset int) ([]string, error)) {
	t.Helper()

	unlimited, err := listIDs(0, 0)
	if err != nil {
		t.Fatalf("%s with no Limit: %v", label, err)
	}
	if len(unlimited) != pagingCap {
		t.Errorf("%s with no Limit set: want the default cap of %d rows, got %d", label, pagingCap, len(unlimited))
	}

	// The walk is bounded rather than "until an empty page" so a backend
	// that keeps handing back full pages fails the assertion below instead
	// of hanging the suite.
	seen := make(map[string]int, len(seeded))
	for offset := 0; offset <= len(seeded)+pagingPage; offset += pagingPage {
		page, err := listIDs(pagingPage, offset)
		if err != nil {
			t.Fatalf("%s Limit=%d Offset=%d: %v", label, pagingPage, offset, err)
		}
		for _, rowID := range page {
			seen[rowID]++
		}
		if len(page) < pagingPage {
			break
		}
	}

	var missing, repeated int
	for _, rowID := range seeded {
		switch n := seen[rowID]; {
		case n == 0:
			missing++
		case n > 1:
			repeated++
		}
	}
	if missing != 0 || repeated != 0 {
		t.Errorf("%s paged with Limit=%d: want each of the %d seeded rows exactly once, got %d never visited and %d visited more than once",
			label, pagingPage, len(seeded), missing, repeated)
	}
	if unseeded := len(seen) - (len(seeded) - missing); unseeded > 0 {
		t.Errorf("%s paged with Limit=%d: %d rows came back that were never seeded", label, pagingPage, unseeded)
	}
}

// idStrings projects a list result down to the ids the paging walk tracks.
func idStrings[T any](items []T, idOf func(T) string) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = idOf(item)
	}
	return out
}

// ──────────────────────────────────────────────────
// Ordering contract
// ──────────────────────────────────────────────────

// runListOrdering pins the row order two List* calls promise, which the
// paging walk cannot: it only checks that every row is visited once, so a
// backend that pages a stable but different order still passes it. A caller
// asking for Limit: 10 gets a different slice depending on that order.
//
//   - ListCheckLogs is newest first: an audit reader wants the latest
//     decisions, so created_at descending, then id descending.
//   - ListPolicies is evaluation order: priority ascending, then created_at
//     ascending, then id ascending.
func runListOrdering(t *testing.T, mk MakeStore) {
	t.Helper()

	t.Run("CheckLogsNewestFirst", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		base := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
		// Seed out of order so insertion order cannot pass by accident.
		offsets := []int{3, 0, 4, 1, 2}
		for _, off := range offsets {
			e := &checklog.Entry{
				ID: id.NewCheckLogID(), TenantID: "t1",
				SubjectKind: "user", SubjectID: "alice", Action: "read",
				ResourceType: "doc", ResourceID: slugFor("ord", off), Decision: "allow",
				CreatedAt: base.Add(time.Duration(off) * time.Minute),
			}
			if err := s.CreateCheckLog(ctx, e); err != nil {
				t.Fatalf("seed check log %d: %v", off, err)
			}
		}

		got, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1"})
		if err != nil {
			t.Fatalf("ListCheckLogs: %v", err)
		}
		want := []string{slugFor("ord", 4), slugFor("ord", 3), slugFor("ord", 2), slugFor("ord", 1), slugFor("ord", 0)}
		gotOrder := make([]string, len(got))
		for i, e := range got {
			gotOrder[i] = e.ResourceID
		}
		if !equalStrings(gotOrder, want) {
			t.Errorf("ListCheckLogs order: want newest first %v, got %v", want, gotOrder)
		}

		top, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", Limit: 2})
		if err != nil {
			t.Fatalf("ListCheckLogs Limit 2: %v", err)
		}
		if len(top) != 2 || top[0].ResourceID != want[0] || top[1].ResourceID != want[1] {
			t.Errorf("ListCheckLogs Limit 2: want the two newest %v, got %d rows", want[:2], len(top))
		}
	})

	t.Run("PoliciesPriorityFirst", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		base := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
		type seed struct {
			name     string
			priority int
			offset   int
		}
		// Later-created rows carry the lower priority number, so a created_at
		// only sort visibly disagrees with the contract.
		seeds := []seed{
			{"p10-early", 10, 0},
			{"p10-late", 10, 2},
			{"p1-late", 1, 3},
			{"p5-mid", 5, 1},
			{"p1-early", 1, 1},
		}
		for _, sd := range seeds {
			p := &policy.Policy{
				ID: id.NewPolicyID(), TenantID: "t1",
				Name: sd.name, Effect: policy.EffectAllow, IsActive: true, Priority: sd.priority,
				Subjects: []policy.SubjectMatch{}, Actions: []string{},
				Resources: []string{}, Conditions: []policy.Condition{},
				Obligations: []string{},
				CreatedAt:   base.Add(time.Duration(sd.offset) * time.Minute),
			}
			if err := s.CreatePolicy(ctx, p); err != nil {
				t.Fatalf("seed policy %s: %v", sd.name, err)
			}
		}
		// Two rows tied on both priority and created_at: id breaks the tie.
		tieIDs := make([]string, 0, 2)
		for _, name := range []string{"tie-a", "tie-b"} {
			p := &policy.Policy{
				ID: id.NewPolicyID(), TenantID: "t1",
				Name: name, Effect: policy.EffectAllow, IsActive: true, Priority: 20,
				Subjects: []policy.SubjectMatch{}, Actions: []string{},
				Resources: []string{}, Conditions: []policy.Condition{},
				Obligations: []string{},
				CreatedAt:   base,
			}
			if err := s.CreatePolicy(ctx, p); err != nil {
				t.Fatalf("seed policy %s: %v", name, err)
			}
			tieIDs = append(tieIDs, p.ID.String())
		}
		sort.Strings(tieIDs)

		got, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: "t1"})
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		wantNames := []string{"p1-early", "p1-late", "p5-mid", "p10-early", "p10-late"}
		if len(got) != len(wantNames)+2 {
			t.Fatalf("ListPolicies: want %d rows, got %d", len(wantNames)+2, len(got))
		}
		for i, name := range wantNames {
			if got[i].Name != name {
				gotNames := make([]string, len(got))
				for j, p := range got {
					gotNames[j] = p.Name
				}
				t.Fatalf("ListPolicies order: want priority, then created_at first %v, got %v", wantNames, gotNames)
			}
		}
		gotTie := []string{got[5].ID.String(), got[6].ID.String()}
		if !equalStrings(gotTie, tieIDs) {
			t.Errorf("ListPolicies tie on priority and created_at: want id ascending %v, got %v", tieIDs, gotTie)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
