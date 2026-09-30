package warden

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// subjectSeed builds roles and assignments for alice in tenant t1.
type subjectSeed struct {
	t *testing.T
	s *memory.Store
}

func (sd subjectSeed) role(ns, slug, parent string) *role.Role {
	sd.t.Helper()
	r := &role.Role{TenantID: "t1", NamespacePath: ns, Name: slug, Slug: slug, ParentSlug: parent}
	if err := sd.s.CreateRole(context.Background(), r); err != nil {
		sd.t.Fatalf("create role %s/%s: %v", ns, slug, err)
	}
	return r
}

func (sd subjectSeed) assign(ns string, r *role.Role, tweak func(*assignment.Assignment)) {
	sd.t.Helper()
	a := &assignment.Assignment{TenantID: "t1", NamespacePath: ns, RoleID: r.ID, SubjectKind: "user", SubjectID: "alice"}
	if tweak != nil {
		tweak(a)
	}
	if err := sd.s.CreateAssignment(context.Background(), a); err != nil {
		sd.t.Fatalf("create assignment for %s: %v", r.Slug, err)
	}
}

func newSubjectEngine(t *testing.T) (*Engine, subjectSeed) {
	t.Helper()
	s := memory.New()
	eng := newExplainEngine(t, WithStore(s))
	return eng, subjectSeed{t: t, s: s}
}

// sortedSlugs returns the slugs of roles, sorted. The memory store lists
// assignments from a map, so the order across two calls is not stable.
func sortedSlugs(roles []*role.Role) []string {
	out := rolesToSlugs(roles)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

func subjectRolesAt(t *testing.T, eng *Engine, ns string) (direct, all []string) {
	t.Helper()
	d, a, err := eng.SubjectRoles(context.Background(), SubjectUser, "alice",
		WithCallTenantID("t1"), WithCallNamespacePath(ns))
	if err != nil {
		t.Fatalf("SubjectRoles at %q: %v", ns, err)
	}
	return sortedSlugs(d), sortedSlugs(a)
}

// assertMatchesCheck is the equivalence test: SubjectRoles' all slugs equal
// the roles Check's RBAC resolution reaches for a check at ns on a resource
// that has no resource-scoped assignment.
func assertMatchesCheck(t *testing.T, eng *Engine, ns string) {
	t.Helper()
	_, all := subjectRolesAt(t, eng, ns)
	req := &CheckRequest{
		Subject:  Subject{Kind: SubjectUser, ID: "alice"},
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "document", ID: "unassigned-doc"},
	}
	ctx := context.Background()
	scope, _, err := eng.prepareCheck(ctx, req, []CallOption{WithCallTenantID("t1"), WithCallNamespacePath(ns)})
	if err != nil {
		t.Fatalf("prepareCheck: %v", err)
	}
	checkRoles, err := eng.resolveAssignedRoles(ctx, scope, req)
	if err != nil {
		t.Fatalf("resolveAssignedRoles: %v", err)
	}
	if want := sortedSlugs(checkRoles); !slices.Equal(all, want) {
		t.Fatalf("at %q: SubjectRoles all = %v, Check resolves %v", ns, all, want)
	}
}

func TestSubjectRoles_NamespaceAncestry(t *testing.T) {
	eng, sd := newSubjectEngine(t)
	sd.assign("", sd.role("", "admin", ""), nil)
	sd.assign("eng", sd.role("eng", "eng-lead", ""), nil)
	sd.assign("eng/platform", sd.role("eng/platform", "plat-op", ""), nil)

	direct, all := subjectRolesAt(t, eng, "")
	if want := []string{"admin"}; !slices.Equal(direct, want) || !slices.Equal(all, want) {
		t.Fatalf("at root: direct %v all %v, want %v for both", direct, all, want)
	}

	direct, all = subjectRolesAt(t, eng, "eng/platform")
	if want := []string{"admin", "eng-lead", "plat-op"}; !slices.Equal(direct, want) || !slices.Equal(all, want) {
		t.Fatalf("at eng/platform: direct %v all %v, want %v for both", direct, all, want)
	}

	for _, ns := range []string{"", "eng", "eng/platform"} {
		assertMatchesCheck(t, eng, ns)
	}
}

func TestSubjectRoles_InheritanceLooksUpTheParentInTheChildsNamespace(t *testing.T) {
	eng, sd := newSubjectEngine(t)
	sd.role("eng", "viewer", "")
	sd.assign("eng", sd.role("eng", "editor", "viewer"), nil)
	// auditor exists only at the root; ops at eng names it as its parent,
	// and the engine looks a parent up in the child's own namespace.
	sd.role("", "auditor", "")
	sd.assign("eng", sd.role("eng", "ops", "auditor"), nil)

	direct, all := subjectRolesAt(t, eng, "eng")
	if want := []string{"editor", "ops"}; !slices.Equal(direct, want) {
		t.Fatalf("direct = %v, want %v", direct, want)
	}
	if want := []string{"editor", "ops", "viewer"}; !slices.Equal(all, want) {
		t.Fatalf("all = %v, want %v", all, want)
	}
	assertMatchesCheck(t, eng, "eng")
}

func TestSubjectRoles_ExcludesAnExpiredAssignment(t *testing.T) {
	eng, sd := newSubjectEngine(t)
	sd.assign("", sd.role("", "live", ""), nil)
	past := time.Now().Add(-time.Hour)
	sd.assign("", sd.role("", "lapsed", ""), func(a *assignment.Assignment) { a.ExpiresAt = &past })

	direct, all := subjectRolesAt(t, eng, "")
	if want := []string{"live"}; !slices.Equal(direct, want) || !slices.Equal(all, want) {
		t.Fatalf("direct %v all %v, want %v for both", direct, all, want)
	}
	assertMatchesCheck(t, eng, "")
}

func TestSubjectRoles_ExcludesAResourceScopedAssignment(t *testing.T) {
	eng, sd := newSubjectEngine(t)
	sd.assign("", sd.role("", "member", ""), nil)
	sd.assign("", sd.role("", "doc-owner", ""), func(a *assignment.Assignment) {
		a.ResourceType, a.ResourceID = "document", "doc1"
	})

	direct, all := subjectRolesAt(t, eng, "")
	if want := []string{"member"}; !slices.Equal(direct, want) || !slices.Equal(all, want) {
		t.Fatalf("direct %v all %v, want %v for both", direct, all, want)
	}
	assertMatchesCheck(t, eng, "")
}

func TestSubjectRoles_NoAssignmentsIsEmptyNotAnError(t *testing.T) {
	eng, _ := newSubjectEngine(t)
	d, a, err := eng.SubjectRoles(context.Background(), SubjectUser, "nobody", WithCallTenantID("t1"))
	if err != nil {
		t.Fatalf("SubjectRoles: %v", err)
	}
	if len(d) != 0 || len(a) != 0 {
		t.Fatalf("direct %v all %v, want both empty", d, a)
	}
}

func TestSubjectRoles_ScopeFollowsCheck(t *testing.T) {
	eng, sd := newSubjectEngine(t)
	sd.assign("", sd.role("", "admin", ""), nil)

	// No tenant anywhere: refused as Check refuses it.
	if _, _, err := eng.SubjectRoles(context.Background(), SubjectUser, "alice"); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("err = %v, want ErrTenantRequired", err)
	}

	// Tenant from the context.
	ctx := WithTenant(context.Background(), "app1", "t1")
	_, all, err := eng.SubjectRoles(ctx, SubjectUser, "alice")
	if err != nil {
		t.Fatalf("SubjectRoles: %v", err)
	}
	if got := sortedSlugs(all); !slices.Equal(got, []string{"admin"}) {
		t.Fatalf("all = %v, want [admin]", got)
	}

	// A call option overrides the context's tenant.
	_, all, err = eng.SubjectRoles(ctx, SubjectUser, "alice", WithCallTenantID("t2"))
	if err != nil {
		t.Fatalf("SubjectRoles: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("all under t2 = %v, want empty", sortedSlugs(all))
	}
}

func TestPolicySelectsSubject(t *testing.T) {
	sm := func(ms ...policy.SubjectMatch) *policy.Policy { return &policy.Policy{Subjects: ms} }
	cases := []struct {
		name  string
		pol   *policy.Policy
		kind  SubjectKind
		id    string
		roles []string
		want  bool
	}{
		{"no subjects selects anyone", sm(), SubjectService, "svc", nil, true},
		{"kind selects any user", sm(policy.SubjectMatch{Kind: "user"}), SubjectUser, "bob", nil, true},
		{"kind selects no service", sm(policy.SubjectMatch{Kind: "user"}), SubjectService, "bob", nil, false},
		{"id selects alice as a user", sm(policy.SubjectMatch{ID: "alice"}), SubjectUser, "alice", nil, true},
		{"id selects alice as a service", sm(policy.SubjectMatch{ID: "alice"}), SubjectService, "alice", nil, true},
		{"id rejects bob", sm(policy.SubjectMatch{ID: "alice"}), SubjectUser, "bob", nil, false},
		{"role held", sm(policy.SubjectMatch{Role: "editor"}), SubjectUser, "bob", []string{"viewer", "editor"}, true},
		{"role not held", sm(policy.SubjectMatch{Role: "editor"}), SubjectUser, "bob", []string{"viewer"}, false},
		{"role with no roles", sm(policy.SubjectMatch{Role: "editor"}), SubjectUser, "bob", nil, false},
		{"kind and role both agree", sm(policy.SubjectMatch{Kind: "user", Role: "editor"}), SubjectUser, "bob", []string{"editor"}, true},
		{"kind and role, wrong kind", sm(policy.SubjectMatch{Kind: "user", Role: "editor"}), SubjectService, "bob", []string{"editor"}, false},
		{"kind and role, role missing", sm(policy.SubjectMatch{Kind: "user", Role: "editor"}), SubjectUser, "bob", nil, false},
		{"one of several matchers agrees", sm(policy.SubjectMatch{ID: "carol"}, policy.SubjectMatch{Kind: "service"}, policy.SubjectMatch{Role: "editor"}), SubjectUser, "bob", []string{"editor"}, true},
		{"none of several matchers agrees", sm(policy.SubjectMatch{ID: "carol"}, policy.SubjectMatch{Kind: "service"}), SubjectUser, "bob", []string{"editor"}, false},
		{"empty matcher selects everyone", sm(policy.SubjectMatch{}), SubjectService, "svc", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PolicySelectsSubject(tc.pol, tc.kind, tc.id, tc.roles); got != tc.want {
				t.Fatalf("PolicySelectsSubject = %v, want %v", got, tc.want)
			}
		})
	}
}
