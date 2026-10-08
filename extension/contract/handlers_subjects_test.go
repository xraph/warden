package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// sectionReads are the grants the subject view checks beyond its intent's.
var sectionReads = []string{"warden:role:read", "warden:relation:read", "warden:policy:read"}

// grantSectionReads lets principalFor's user ("tester") read every section,
// so a test about what a section holds is not a test about withholding. A
// store that already grants them is left alone, so tests can ask twice.
func grantSectionReads(t *testing.T, s *memory.Store) {
	t.Helper()
	if _, err := s.GetRoleBySlug(context.Background(), "t1", "", "r-tester"); err == nil {
		return
	}
	grantUser(t, s, "tester", sectionReads...)
}

// subjectDetail runs the handler as a t1 user who may read every section.
func subjectDetail(t *testing.T, s *memory.Store, in SubjectDetailInput) SubjectDetailResponse {
	t.Helper()
	grantSectionReads(t, s)
	h := subjectsDetailHandler(Deps{Engine: engineOver(t, s)})
	got, err := h(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("subjects.detail: %v", err)
	}
	return got
}

// seedRoleIn stores a role with an optional parent and returns it.
func seedRoleIn(t *testing.T, s *memory.Store, tenant, namespace, slug, parent string) *role.Role {
	t.Helper()
	r := &role.Role{TenantID: tenant, NamespacePath: namespace, Name: strings.ToUpper(slug), Slug: slug, ParentSlug: parent}
	if err := s.CreateRole(context.Background(), r); err != nil {
		t.Fatalf("create role %q: %v", slug, err)
	}
	return r
}

// grantPermission stores a permission (resource:action) and attaches it.
func grantPermission(t *testing.T, s *memory.Store, tenant string, r *role.Role, name string) {
	t.Helper()
	ctx := context.Background()
	res, act := splitPerm(t, name)
	if _, err := s.GetPermissionByName(ctx, tenant, "", name); err != nil {
		if err := s.CreatePermission(ctx, &permission.Permission{TenantID: tenant, Name: name, Resource: res, Action: act}); err != nil {
			t.Fatalf("create permission %s: %v", name, err)
		}
	}
	if err := s.AttachPermission(ctx, tenant, r.ID, permission.Ref{Name: name}); err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
}

func assignTo(t *testing.T, s *memory.Store, a *assignment.Assignment) *assignment.Assignment {
	t.Helper()
	if a.TenantID == "" {
		a.TenantID = "t1"
	}
	if a.SubjectKind == "" {
		a.SubjectKind = "user"
	}
	if a.SubjectID == "" {
		a.SubjectID = "alice"
	}
	if err := s.CreateAssignment(context.Background(), a); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	return a
}

func roleBySlug(t *testing.T, got SubjectDetailResponse, slug string) SubjectRole {
	t.Helper()
	for _, r := range got.Roles {
		if r.Slug == slug {
			return r
		}
	}
	t.Fatalf("role %q is not in the response: %+v", slug, got.Roles)
	return SubjectRole{}
}

func TestSubjectsDetailRefusesWhatItCannotAnswer(t *testing.T) {
	s := memory.New()
	h := subjectsDetailHandler(Deps{Engine: engineOver(t, s)})
	for name, tc := range map[string]struct {
		in   SubjectDetailInput
		want string
	}{
		"no subject id":    {SubjectDetailInput{SubjectKind: "user"}, "subjectId"},
		"bad namespace":    {SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "/eng/"}, "namespacePath"},
		"reserved segment": {SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng//x"}, "namespacePath"},
	} {
		_, err := h(context.Background(), tc.in, principalFor("t1"))
		var ce *dashcontract.Error
		if !errors.As(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s: want BAD_REQUEST, got %v", name, err)
			continue
		}
		if !strings.Contains(ce.Message, tc.want) {
			t.Errorf("%s: message %q does not name %s", name, ce.Message, tc.want)
		}
	}
}

func TestSubjectsDetailAcceptsAnySubjectKind(t *testing.T) {
	s := memory.New()
	h := subjectsDetailHandler(Deps{Engine: engineOver(t, s)})
	for _, kind := range []string{"", "user", "api_key", "made_up"} {
		if _, err := h(context.Background(), SubjectDetailInput{SubjectKind: kind, SubjectID: "x"}, principalFor("t1")); err != nil {
			t.Errorf("kind %q refused: %v", kind, err)
		}
	}
}

func TestSubjectsDetailAnEmptySubjectGetsEmptyListsNotNulls(t *testing.T) {
	// The page maps over every list, and a nil slice is JSON null.
	got := subjectDetail(t, memory.New(), SubjectDetailInput{SubjectKind: "user", SubjectID: "nobody"})
	if got.Roles == nil || got.Assignments == nil || got.Relations == nil || got.Policies == nil || got.Withheld == nil {
		t.Errorf("a list is nil: %+v", got)
	}
	if got.AssignmentsTruncated || got.RelationsTruncated {
		t.Error("nothing to truncate")
	}
}

func TestSubjectsDetailRolesAreTheResolvedSetWithHowEachArrived(t *testing.T) {
	s := memory.New()
	base := seedRoleIn(t, s, "t1", "", "base", "")
	admin := seedRoleIn(t, s, "t1", "", "admin", "base")
	dev := seedRoleIn(t, s, "t1", "eng", "dev", "")
	ops := seedRoleIn(t, s, "t1", "eng/platform", "ops", "")
	seedRoleIn(t, s, "t1", "", "unrelated", "")
	grantPermission(t, s, "t1", base, "doc:read")
	grantPermission(t, s, "t1", admin, "doc:*")
	grantPermission(t, s, "t1", admin, "user:delete")
	grantPermission(t, s, "t1", ops, "deploy:run")
	assignTo(t, s, &assignment.Assignment{RoleID: admin.ID})
	assignTo(t, s, &assignment.Assignment{RoleID: dev.ID, NamespacePath: "eng"})
	assignTo(t, s, &assignment.Assignment{RoleID: ops.ID, NamespacePath: "eng/platform"})

	t.Run("root sees only the root assignment", func(t *testing.T) {
		got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
		if len(got.Roles) != 2 {
			t.Fatalf("roles = %+v, want admin and base", got.Roles)
		}
		a := roleBySlug(t, got, "admin")
		if a.Via != "assigned" || len(a.InheritedBy) != 0 {
			t.Errorf("admin = via %q inheritedBy %v, want assigned and none", a.Via, a.InheritedBy)
		}
		if a.ID != admin.ID.String() || a.Name != "ADMIN" || a.NamespacePath != "" {
			t.Errorf("admin identity fields wrong: %+v", a)
		}
		b := roleBySlug(t, got, "base")
		if b.Via != "inherited" {
			t.Errorf("base via = %q, want inherited", b.Via)
		}
		if len(b.InheritedBy) != 1 || b.InheritedBy[0] != "admin" {
			t.Errorf("base inheritedBy = %v, want [admin]", b.InheritedBy)
		}
		names := map[string]SubjectPermission{}
		for _, p := range a.Permissions {
			names[p.Name] = p
		}
		if len(a.Permissions) != 2 || names["doc:*"].Resource != "doc" || names["doc:*"].Action != "*" || names["user:delete"].Action != "delete" {
			t.Errorf("admin permissions = %+v", a.Permissions)
		}
		if len(b.Permissions) != 1 || b.Permissions[0].Name != "doc:read" {
			t.Errorf("base permissions = %+v", b.Permissions)
		}
	})

	t.Run("a deeper namespace adds the roles assigned on the way down", func(t *testing.T) {
		got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng/platform"})
		want := map[string]string{"admin": "assigned", "base": "inherited", "dev": "assigned", "ops": "assigned"}
		if len(got.Roles) != len(want) {
			t.Fatalf("roles = %+v, want %v", got.Roles, want)
		}
		for slug, via := range want {
			if r := roleBySlug(t, got, slug); r.Via != via {
				t.Errorf("%s via = %q, want %q", slug, r.Via, via)
			}
		}
		if ops := roleBySlug(t, got, "ops"); len(ops.Permissions) != 1 || ops.Permissions[0].Name != "deploy:run" {
			t.Errorf("ops permissions = %+v", ops.Permissions)
		}
		if dev := roleBySlug(t, got, "dev"); dev.Permissions == nil {
			t.Error("a role with no grants must carry [], not null")
		}
	})

	t.Run("a sibling namespace does not see them", func(t *testing.T) {
		got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "sandbox"})
		for _, r := range got.Roles {
			if r.Slug == "dev" || r.Slug == "ops" {
				t.Errorf("%s leaked into sandbox", r.Slug)
			}
		}
	})
}

func TestSubjectsDetailInheritedByNeedsTheChildInTheParentsNamespace(t *testing.T) {
	// The engine looks a parent up in the CHILD's namespace, so a child
	// elsewhere that shares the slug does not inherit from this role.
	s := memory.New()
	seedRoleIn(t, s, "t1", "", "base", "")
	seedRoleIn(t, s, "t1", "eng", "base", "")
	child := seedRoleIn(t, s, "t1", "eng", "lead", "base")
	assignTo(t, s, &assignment.Assignment{RoleID: child.ID, NamespacePath: "eng"})

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng"})
	var engBase, rootBase *SubjectRole
	for i := range got.Roles {
		r := &got.Roles[i]
		if r.Slug == "base" && r.NamespacePath == "eng" {
			engBase = r
		}
		if r.Slug == "base" && r.NamespacePath == "" {
			rootBase = r
		}
	}
	if engBase == nil {
		t.Fatalf("eng/base is not resolved: %+v", got.Roles)
	}
	if len(engBase.InheritedBy) != 1 || engBase.InheritedBy[0] != "lead" {
		t.Errorf("eng base inheritedBy = %v, want [lead]", engBase.InheritedBy)
	}
	if rootBase != nil && len(rootBase.InheritedBy) != 0 {
		t.Errorf("root base inheritedBy = %v, want none", rootBase.InheritedBy)
	}
}

func TestSubjectsDetailInheritedBySortsItsSlugs(t *testing.T) {
	s := memory.New()
	seedRoleIn(t, s, "t1", "", "base", "")
	for _, slug := range []string{"zeta", "alpha", "mid"} {
		r := seedRoleIn(t, s, "t1", "", slug, "base")
		assignTo(t, s, &assignment.Assignment{RoleID: r.ID})
	}
	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	b := roleBySlug(t, got, "base")
	if fmt.Sprint(b.InheritedBy) != "[alpha mid zeta]" {
		t.Errorf("inheritedBy = %v, want sorted", b.InheritedBy)
	}
}

func TestSubjectsDetailListsARoleAssignedAtTwoAncestorsOnce(t *testing.T) {
	s := memory.New()
	r := seedRoleIn(t, s, "t1", "", "reader", "")
	assignTo(t, s, &assignment.Assignment{RoleID: r.ID})
	assignTo(t, s, &assignment.Assignment{RoleID: r.ID, NamespacePath: "eng"})

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng"})
	n := 0
	for _, x := range got.Roles {
		if x.Slug == "reader" {
			n++
			if x.Via != "assigned" {
				t.Errorf("via = %q, want assigned", x.Via)
			}
		}
	}
	if n != 1 {
		t.Errorf("reader appears %d times, want once", n)
	}
	if len(got.Assignments) != 2 {
		t.Errorf("assignments = %d, want both rows", len(got.Assignments))
	}
}

func TestSubjectsDetailAssignmentsCoverEveryNamespaceForThisSubjectOnly(t *testing.T) {
	s := memory.New()
	r := seedRoleIn(t, s, "t1", "", "reader", "")
	now := time.Now()
	past, soon, later := now.Add(-time.Hour), now.Add(24*time.Hour), now.Add(30*24*time.Hour)
	gone := assignTo(t, s, &assignment.Assignment{RoleID: r.ID, ExpiresAt: &past})
	near := assignTo(t, s, &assignment.Assignment{RoleID: r.ID, NamespacePath: "eng", ExpiresAt: &soon})
	far := assignTo(t, s, &assignment.Assignment{RoleID: r.ID, NamespacePath: "eng/platform", ExpiresAt: &later})
	scoped := assignTo(t, s, &assignment.Assignment{RoleID: r.ID, NamespacePath: "sandbox", ResourceType: "doc", ResourceID: "d1"})
	// Same id, another kind, and another id, same kind.
	assignTo(t, s, &assignment.Assignment{RoleID: r.ID, SubjectKind: "api_key"})
	assignTo(t, s, &assignment.Assignment{RoleID: r.ID, SubjectID: "bob"})

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Assignments) != 4 {
		t.Fatalf("assignments = %+v, want alice's four (every namespace, kind and id both matched)", got.Assignments)
	}
	by := map[string]SubjectAssignment{}
	for _, a := range got.Assignments {
		by[a.ID] = a
	}
	if a := by[gone.ID.String()]; !a.Expired || a.ExpiringSoon {
		t.Errorf("lapsed row = expired %v soon %v, want expired and not soon", a.Expired, a.ExpiringSoon)
	}
	if a := by[near.ID.String()]; a.Expired || !a.ExpiringSoon || a.ExpiresAt == "" {
		t.Errorf("row inside the horizon = %+v, want live and expiringSoon with a date", a)
	}
	if a := by[far.ID.String()]; a.Expired || a.ExpiringSoon {
		t.Errorf("row outside the horizon = %+v, want live and not soon", a)
	}
	a := by[scoped.ID.String()]
	if a.ResourceType != "doc" || a.ResourceID != "d1" || a.ExpiresAt != "" || a.Expired || a.ExpiringSoon {
		t.Errorf("resource-scoped row = %+v", a)
	}
	if a.RoleID != r.ID.String() || a.RoleSlug != "reader" || a.NamespacePath != "sandbox" {
		t.Errorf("row identity fields = %+v", a)
	}
}

func seedManyAssignments(t *testing.T, s *memory.Store, n int) {
	t.Helper()
	r := seedRoleIn(t, s, "t1", "", "reader", "")
	for i := 0; i < n; i++ {
		assignTo(t, s, &assignment.Assignment{RoleID: r.ID, ResourceType: "doc", ResourceID: fmt.Sprintf("d%03d", i)})
	}
}

func TestSubjectsDetailCapsAssignmentsAtTwoHundredAndSaysSo(t *testing.T) {
	s := memory.New()
	seedManyAssignments(t, s, 201)
	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Assignments) != 200 || !got.AssignmentsTruncated {
		t.Errorf("got %d rows truncated=%v, want 200 and true", len(got.Assignments), got.AssignmentsTruncated)
	}

	exact := memory.New()
	seedManyAssignments(t, exact, 200)
	got = subjectDetail(t, exact, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Assignments) != 200 || got.AssignmentsTruncated {
		t.Errorf("exactly 200: got %d rows truncated=%v, want 200 and false", len(got.Assignments), got.AssignmentsTruncated)
	}
}

func seedSubjectTuple(t *testing.T, s *memory.Store, tenant, ns, objID, subjType, subjID string) *relation.Tuple {
	t.Helper()
	tp := &relation.Tuple{
		TenantID: tenant, NamespacePath: ns, ObjectType: "doc", ObjectID: objID,
		Relation: "viewer", SubjectType: subjType, SubjectID: subjID,
	}
	if err := s.CreateRelation(context.Background(), tp); err != nil {
		t.Fatalf("create tuple: %v", err)
	}
	return tp
}

func TestSubjectsDetailRelationsAreTheTuplesNamingThisSubject(t *testing.T) {
	s := memory.New()
	root := seedSubjectTuple(t, s, "t1", "", "readme", "user", "alice")
	eng := seedSubjectTuple(t, s, "t1", "eng", "spec", "user", "alice")
	seedSubjectTuple(t, s, "t1", "", "readme", "user", "bob")
	seedSubjectTuple(t, s, "t1", "", "readme", "api_key", "alice")
	// alice as the OBJECT of a tuple is not her relation.
	obj := &relation.Tuple{TenantID: "t1", ObjectType: "user", ObjectID: "alice", Relation: "owner", SubjectType: "user", SubjectID: "bob"}
	if err := s.CreateRelation(context.Background(), obj); err != nil {
		t.Fatalf("create tuple: %v", err)
	}

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Relations) != 2 {
		t.Fatalf("relations = %+v, want alice's two across namespaces", got.Relations)
	}
	by := map[string]SubjectRelation{}
	for _, r := range got.Relations {
		by[r.ID] = r
	}
	if r := by[eng.ID.String()]; r.NamespacePath != "eng" || r.ObjectType != "doc" || r.ObjectID != "spec" || r.Relation != "viewer" {
		t.Errorf("eng tuple = %+v", r)
	}
	if _, ok := by[root.ID.String()]; !ok {
		t.Error("root tuple missing")
	}
}

func TestSubjectsDetailCapsRelationsAtTwoHundredAndSaysSo(t *testing.T) {
	seed := func(n int) *memory.Store {
		s := memory.New()
		for i := 0; i < n; i++ {
			seedSubjectTuple(t, s, "t1", "", fmt.Sprintf("o%03d", i), "user", "alice")
		}
		return s
	}
	got := subjectDetail(t, seed(201), SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Relations) != 200 || !got.RelationsTruncated {
		t.Errorf("got %d rows truncated=%v, want 200 and true", len(got.Relations), got.RelationsTruncated)
	}
	got = subjectDetail(t, seed(200), SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Relations) != 200 || got.RelationsTruncated {
		t.Errorf("exactly 200: got %d rows truncated=%v, want 200 and false", len(got.Relations), got.RelationsTruncated)
	}
}

func TestSubjectsDetailPoliciesAreThoseInEffectAndSelectingThisSubject(t *testing.T) {
	s := memory.New()
	viewer := seedRoleIn(t, s, "t1", "", "viewer", "")
	assignTo(t, s, &assignment.Assignment{RoleID: viewer.ID})
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	subj := func(m ...policy.SubjectMatch) func(*policy.Policy) {
		return func(p *policy.Policy) { p.Subjects = m }
	}
	seedPolicyFor(t, s, "t1", "", "everyone-none", subj())
	seedPolicyFor(t, s, "t1", "", "everyone-empty", subj(policy.SubjectMatch{}))
	seedPolicyFor(t, s, "t1", "", "by-kind", subj(policy.SubjectMatch{Kind: "user"}))
	seedPolicyFor(t, s, "t1", "", "by-id", subj(policy.SubjectMatch{Kind: "user", ID: "alice"}))
	seedPolicyFor(t, s, "t1", "", "by-role", subj(policy.SubjectMatch{Role: "viewer"}))
	seedPolicyFor(t, s, "t1", "", "role-beats-id", subj(policy.SubjectMatch{Kind: "user", ID: "alice", Role: "viewer"}))
	seedPolicyFor(t, s, "t1", "", "first-agreeing", subj(
		policy.SubjectMatch{Kind: "api_key"}, policy.SubjectMatch{ID: "alice"}, policy.SubjectMatch{Kind: "user"}))
	seedPolicyFor(t, s, "t1", "", "role-not-held", subj(policy.SubjectMatch{Role: "admin"}))
	seedPolicyFor(t, s, "t1", "", "other-kind", subj(policy.SubjectMatch{Kind: "api_key"}))
	seedPolicyFor(t, s, "t1", "", "other-id", subj(policy.SubjectMatch{ID: "bob"}))
	seedPolicyFor(t, s, "t1", "", "inactive", func(p *policy.Policy) { p.IsActive = false })
	seedPolicyFor(t, s, "t1", "", "lapsed", func(p *policy.Policy) { p.NotAfter = &past })
	seedPolicyFor(t, s, "t1", "", "not-yet", func(p *policy.Policy) { p.NotBefore = &future })
	// Denies only on doc, so it cannot deny the viewer's own section reads.
	seedPolicyFor(t, s, "t1", "", "deny-first", func(p *policy.Policy) {
		p.Effect, p.Priority, p.Resources = policy.EffectDeny, 7, []string{"doc"}
	})
	seedPolicyFor(t, s, "t1", "sandbox", "elsewhere", nil)
	seedPolicyFor(t, s, "t1", "eng", "eng-only", nil)
	seedPolicyFor(t, s, "t2", "", "theirs", nil)

	want := map[string]string{
		"everyone-none":  "everyone",
		"everyone-empty": "everyone",
		"by-kind":        "kind",
		"by-id":          "id",
		"by-role":        "role:viewer",
		"role-beats-id":  "role:viewer",
		"first-agreeing": "id",
		"deny-first":     "everyone",
	}
	check := func(t *testing.T, got SubjectDetailResponse, want map[string]string) {
		t.Helper()
		by := map[string]SubjectPolicy{}
		for _, p := range got.Policies {
			by[p.Name] = p
		}
		for name, sel := range want {
			p, ok := by[name]
			if !ok {
				t.Errorf("policy %q missing: %+v", name, got.Policies)
				continue
			}
			if p.SelectedBy != sel {
				t.Errorf("%s selectedBy = %q, want %q", name, p.SelectedBy, sel)
			}
		}
		for name := range by {
			if _, ok := want[name]; !ok {
				t.Errorf("policy %q must not be listed", name)
			}
		}
	}

	root := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	check(t, root, want)
	for _, p := range root.Policies {
		if p.Name == "deny-first" && (p.Effect != string(policy.EffectDeny) || p.Priority != 7 || p.ID == "" || p.NamespacePath != "") {
			t.Errorf("deny-first fields = %+v", p)
		}
	}

	// A policy at an ancestor applies below it; one at a sibling never does.
	// The viewer role is assigned at the root, so it still resolves at eng.
	withEng := map[string]string{"eng-only": "everyone"}
	for k, v := range want {
		withEng[k] = v
	}
	check(t, subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng/platform"}), withEng)
}

func TestSubjectsDetailPolicyRolesComeFromTheResolvedSetIncludingInherited(t *testing.T) {
	// A policy selecting "base" applies to a subject who only inherits it.
	s := memory.New()
	seedRoleIn(t, s, "t1", "", "base", "")
	admin := seedRoleIn(t, s, "t1", "", "admin", "base")
	assignTo(t, s, &assignment.Assignment{RoleID: admin.ID})
	seedPolicyFor(t, s, "t1", "", "for-base", func(p *policy.Policy) { p.Subjects = []policy.SubjectMatch{{Role: "base"}} })

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"})
	if len(got.Policies) != 1 || got.Policies[0].SelectedBy != "role:base" {
		t.Errorf("policies = %+v, want for-base selected by role:base", got.Policies)
	}
}

func TestSubjectsDetailHasNoRecentChecks(t *testing.T) {
	// The check log needs read_audit, which the intent's grant does not
	// cover, so the page reads it through checkLogs.list instead.
	s := memory.New()
	eng := engineOver(t, s)
	seedCheckLog(t, eng, &checklog.Entry{TenantID: "t1", SubjectKind: "user", SubjectID: "alice", Action: "read", Decision: "allow", CreatedAt: time.Now()})
	grantSectionReads(t, s)

	got, err := subjectsDetailHandler(Deps{Engine: eng})(context.Background(), SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("subjects.detail: %v", err)
	}
	raw := marshalDetail(t, got)
	if strings.Contains(raw, "recentChecks") {
		t.Errorf("response still carries recentChecks: %s", raw)
	}
	if !strings.Contains(raw, `"withheld":[]`) {
		t.Errorf("a viewer holding every grant must get \"withheld\":[], got %s", raw)
	}
}

func TestSubjectsDetailNeverShowsAnotherTenantsRows(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	eng := engineOver(t, s)
	mine := seedRoleIn(t, s, "t1", "", "mine", "")
	theirs := seedRoleIn(t, s, "t2", "", "theirs", "")
	grantPermission(t, s, "t2", theirs, "secret:read")
	assignTo(t, s, &assignment.Assignment{RoleID: mine.ID})
	other := assignTo(t, s, &assignment.Assignment{TenantID: "t2", RoleID: theirs.ID})
	otherTuple := seedSubjectTuple(t, s, "t2", "", "vault", "user", "alice")
	otherPolicy := seedPolicyFor(t, s, "t2", "", "theirs-policy", nil)
	grantSectionReads(t, s)

	h := subjectsDetailHandler(Deps{Engine: eng})
	got, err := h(ctx, SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("subjects.detail: %v", err)
	}
	// Asserted on identity: a count passes when the wrong rows arrive in the
	// right quantity.
	for _, r := range got.Roles {
		if r.Slug == "theirs" || len(r.Permissions) != 0 {
			t.Errorf("t2's role or grant leaked: %+v", r)
		}
	}
	for _, a := range got.Assignments {
		if a.ID == other.ID.String() {
			t.Error("t2's assignment leaked")
		}
	}
	for _, r := range got.Relations {
		if r.ID == otherTuple.ID.String() {
			t.Error("t2's relation leaked")
		}
	}
	for _, p := range got.Policies {
		if p.ID == otherPolicy.ID.String() {
			t.Error("t2's policy leaked")
		}
	}
	if len(got.Roles) != 1 || got.Roles[0].Slug != "mine" || len(got.Assignments) != 1 {
		t.Errorf("t1's own rows are wrong: roles %+v assignments %+v", got.Roles, got.Assignments)
	}
}

// A store treats an empty SubjectKind/SubjectType filter as "any kind", but
// the engine matches "" exactly. With subjectKind "" the lists must hold only
// rows whose kind is exactly "".

func createBareAssignment(t *testing.T, s *memory.Store, r *role.Role, kind, resourceID string, at time.Time) *assignment.Assignment {
	t.Helper()
	a := &assignment.Assignment{
		TenantID: "t1", RoleID: r.ID, SubjectKind: kind, SubjectID: "alice",
		ResourceType: "doc", ResourceID: resourceID, CreatedAt: at,
	}
	if err := s.CreateAssignment(context.Background(), a); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
	return a
}

func createBareTuple(t *testing.T, s *memory.Store, subjType, objID string, at time.Time) *relation.Tuple {
	t.Helper()
	tp := &relation.Tuple{
		TenantID: "t1", ObjectType: "doc", ObjectID: objID, Relation: "viewer",
		SubjectType: subjType, SubjectID: "alice", CreatedAt: at,
	}
	if err := s.CreateRelation(context.Background(), tp); err != nil {
		t.Fatalf("create tuple: %v", err)
	}
	return tp
}

func TestSubjectsDetailEmptyKindKeepsOnlyRowsOfKindEmpty(t *testing.T) {
	s := memory.New()
	eng := engineOver(t, s)
	r := seedRoleIn(t, s, "t1", "", "reader", "")
	now := time.Now()
	var wantA, wantT string
	for i, kind := range []string{"", "user", "api_key"} {
		at := now.Add(time.Duration(i) * time.Minute)
		a := createBareAssignment(t, s, r, kind, "d1", at)
		tp := createBareTuple(t, s, kind, "o1", at)
		if kind == "" {
			wantA, wantT = a.ID.String(), tp.ID.String()
		}
	}
	grantSectionReads(t, s)

	got, err := subjectsDetailHandler(Deps{Engine: eng})(context.Background(), SubjectDetailInput{SubjectID: "alice"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("subjects.detail: %v", err)
	}
	if len(got.Assignments) != 1 || got.Assignments[0].ID != wantA {
		t.Errorf("assignments = %+v, want only the empty-kind row %s", got.Assignments, wantA)
	}
	if len(got.Relations) != 1 || got.Relations[0].ID != wantT {
		t.Errorf("relations = %+v, want only the empty-type row %s", got.Relations, wantT)
	}
	if got.AssignmentsTruncated || got.RelationsTruncated {
		t.Error("nothing was cut off")
	}
}

func TestSubjectsDetailEmptyKindPagesPastManyNonMatchingRows(t *testing.T) {
	// More than a page of other-kind rows come first in the store's order, so
	// a single fetch of 201 would hold no empty-kind row at all.
	const noise = 450
	seed := func(t *testing.T, matching int) (*memory.Store, []string, []string) {
		t.Helper()
		s := memory.New()
		r := seedRoleIn(t, s, "t1", "", "reader", "")
		base := time.Now().Add(-24 * time.Hour)
		var as, ts []string
		// Assignments and tuples list oldest first, so the noise is oldest.
		for i := 0; i < noise; i++ {
			kind := []string{"user", "api_key"}[i%2]
			createBareAssignment(t, s, r, kind, fmt.Sprintf("n%03d", i), base.Add(time.Duration(i)*time.Second))
			createBareTuple(t, s, kind, fmt.Sprintf("n%03d", i), base.Add(time.Duration(i)*time.Second))
		}
		for i := 0; i < matching; i++ {
			at := base.Add(time.Hour + time.Duration(i)*time.Second)
			a := createBareAssignment(t, s, r, "", fmt.Sprintf("m%03d", i), at)
			tp := createBareTuple(t, s, "", fmt.Sprintf("m%03d", i), at)
			as, ts = append(as, a.ID.String()), append(ts, tp.ID.String())
		}
		return s, as, ts
	}
	run := func(t *testing.T, s *memory.Store) SubjectDetailResponse {
		t.Helper()
		grantSectionReads(t, s)
		got, err := subjectsDetailHandler(Deps{Engine: engineOver(t, s)})(context.Background(), SubjectDetailInput{SubjectID: "alice"}, principalFor("t1"))
		if err != nil {
			t.Fatalf("subjects.detail: %v", err)
		}
		return got
	}

	t.Run("a few matching rows are found behind the noise", func(t *testing.T) {
		s, as, ts := seed(t, 3)
		got := run(t, s)
		if len(got.Assignments) != 3 || len(got.Relations) != 3 {
			t.Fatalf("got %d assignments, %d relations, want 3 of each",
				len(got.Assignments), len(got.Relations))
		}
		if got.AssignmentsTruncated || got.RelationsTruncated {
			t.Error("three rows are not truncated")
		}
		for i, a := range got.Assignments {
			if a.ID != as[i] {
				t.Errorf("assignment %d = %s, want %s", i, a.ID, as[i])
			}
		}
		for i, r := range got.Relations {
			if r.ID != ts[i] {
				t.Errorf("relation %d = %s, want %s", i, r.ID, ts[i])
			}
		}
	})

	t.Run("truncation reflects the matching rows, not the noise", func(t *testing.T) {
		s, _, _ := seed(t, 201)
		got := run(t, s)
		if len(got.Assignments) != 200 || !got.AssignmentsTruncated {
			t.Errorf("201 matching assignments: got %d truncated=%v, want 200 and true", len(got.Assignments), got.AssignmentsTruncated)
		}
		if len(got.Relations) != 200 || !got.RelationsTruncated {
			t.Errorf("201 matching relations: got %d truncated=%v, want 200 and true", len(got.Relations), got.RelationsTruncated)
		}
		s, _, _ = seed(t, 200)
		got = run(t, s)
		if len(got.Assignments) != 200 || got.AssignmentsTruncated || len(got.Relations) != 200 || got.RelationsTruncated {
			t.Errorf("exactly 200 matching: assignments %d/%v relations %d/%v, want 200 and not truncated",
				len(got.Assignments), got.AssignmentsTruncated, len(got.Relations), got.RelationsTruncated)
		}
	})
}

func marshalDetail(t *testing.T, got SubjectDetailResponse) string {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// seedWholePicture gives alice one of everything the view can show: an
// assigned role that inherits another, each with a grant, 201 relations (so
// a withheld section is visibly not truncated), and a policy selecting her.
func seedWholePicture(t *testing.T, s *memory.Store) {
	t.Helper()
	base := seedRoleIn(t, s, "t1", "", "hidden-base", "")
	editor := seedRoleIn(t, s, "t1", "", "editor", "hidden-base")
	grantPermission(t, s, "t1", base, "secretdoc:peek")
	grantPermission(t, s, "t1", editor, "secretdoc:edit")
	assignTo(t, s, &assignment.Assignment{RoleID: editor.ID})
	for i := 0; i < subjectListCap+1; i++ {
		tp := &relation.Tuple{
			TenantID: "t1", ObjectType: "vault", ObjectID: fmt.Sprintf("hidden-object-%03d", i),
			Relation: "keyholder", SubjectType: "user", SubjectID: "alice",
		}
		if err := s.CreateRelation(context.Background(), tp); err != nil {
			t.Fatalf("create tuple: %v", err)
		}
	}
	seedPolicyFor(t, s, "t1", "", "hidden-policy", func(p *policy.Policy) {
		p.Subjects = []policy.SubjectMatch{{Kind: "user", ID: "alice"}}
		p.Resources = []string{"vault"}
	})
}

func detailAs(t *testing.T, s *memory.Store) SubjectDetailResponse {
	t.Helper()
	got, err := subjectsDetailHandler(Deps{Engine: engineOver(t, s)})(context.Background(),
		SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("subjects.detail: %v", err)
	}
	return got
}

func TestSubjectsDetailWithOnlyTheAssignmentGrantWithholdsEveryOtherSection(t *testing.T) {
	// The manifest gate checks read on warden:assignment and nothing else,
	// so that grant alone must not reveal roles, relations or policies.
	s := memory.New()
	seedWholePicture(t, s)
	grantUser(t, s, "tester", "warden:assignment:read")

	got := detailAs(t, s)
	if len(got.Assignments) != 1 || got.Assignments[0].RoleSlug != "editor" {
		t.Errorf("assignments = %+v, want alice's editor assignment", got.Assignments)
	}
	if fmt.Sprint(got.Withheld) != "[roles relations policies]" {
		t.Errorf("withheld = %v, want [roles relations policies]", got.Withheld)
	}
	if len(got.Roles) != 0 || len(got.Relations) != 0 || len(got.Policies) != 0 || got.RelationsTruncated {
		t.Errorf("a withheld section carried data: roles %+v relations %d (truncated %v) policies %+v",
			got.Roles, len(got.Relations), got.RelationsTruncated, got.Policies)
	}
	raw := marshalDetail(t, got)
	for _, secret := range []string{"hidden-base", "EDITOR", "secretdoc", "hidden-object", "keyholder", "hidden-policy"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the JSON reveals %q: %s", secret, raw)
		}
	}
	for _, empty := range []string{`"roles":[]`, `"relations":[]`, `"policies":[]`, `"relationsTruncated":false`} {
		if !strings.Contains(raw, empty) {
			t.Errorf("the JSON lacks %s: %s", empty, raw)
		}
	}
}

func TestSubjectsDetailEachGrantRevealsExactlyItsSection(t *testing.T) {
	for _, tc := range []struct {
		grant    string
		section  string
		withheld string
	}{
		{"warden:role:read", "roles", "[relations policies]"},
		{"warden:relation:read", "relations", "[roles policies]"},
		{"warden:policy:read", "policies", "[roles relations]"},
	} {
		t.Run(tc.section, func(t *testing.T) {
			s := memory.New()
			seedWholePicture(t, s)
			grantUser(t, s, "tester", "warden:assignment:read", tc.grant)

			got := detailAs(t, s)
			if fmt.Sprint(got.Withheld) != tc.withheld {
				t.Errorf("withheld = %v, want %s", got.Withheld, tc.withheld)
			}
			sizes := map[string]int{"roles": len(got.Roles), "relations": len(got.Relations), "policies": len(got.Policies)}
			for name, n := range sizes {
				if name == tc.section && n == 0 {
					t.Errorf("%s is empty though %s is held", name, tc.grant)
				}
				if name != tc.section && n != 0 {
					t.Errorf("%s has %d rows though only %s is held", name, n, tc.grant)
				}
			}
			if got.RelationsTruncated != (tc.section == "relations") {
				t.Errorf("relationsTruncated = %v, want it only when relations are shown", got.RelationsTruncated)
			}
			if tc.section == "roles" {
				if e := roleBySlug(t, got, "editor"); len(e.Permissions) != 1 || e.Permissions[0].Name != "secretdoc:edit" {
					t.Errorf("editor permissions = %+v", e.Permissions)
				}
				roleBySlug(t, got, "hidden-base")
			}
			if tc.section == "policies" && (len(got.Policies) != 1 || got.Policies[0].Name != "hidden-policy") {
				t.Errorf("policies = %+v, want hidden-policy", got.Policies)
			}
			if len(got.Assignments) != 1 {
				t.Errorf("assignments = %+v, want the one row under the intent's own grant", got.Assignments)
			}
		})
	}
}

// failingGrantStore fails the resource-role lookup Check makes for the
// viewer ("tester"), so a grant check errors while every read the handler
// makes about alice still works.
type failingGrantStore struct{ *memory.Store }

func (f failingGrantStore) ListRolesForSubjectOnResource(ctx context.Context, tenantID string, namespaces []string, kind, subjectID, resourceType, resourceID string) ([]id.RoleID, error) {
	if subjectID == "tester" {
		return nil, errors.New("role table unavailable")
	}
	return f.Store.ListRolesForSubjectOnResource(ctx, tenantID, namespaces, kind, subjectID, resourceType, resourceID)
}

func TestSubjectsDetailFailsWhenAGrantCheckCannotBeAnswered(t *testing.T) {
	mem := memory.New()
	seedWholePicture(t, mem)
	grantUser(t, mem, "tester", sectionReads...)
	eng, err := warden.NewEngine(warden.WithStore(failingGrantStore{mem}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := subjectsDetailHandler(Deps{Engine: eng})(context.Background(),
		SubjectDetailInput{SubjectKind: "user", SubjectID: "alice"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodeInternal {
		t.Fatalf("want INTERNAL, got %v with %+v", err, got)
	}
	if !strings.Contains(ce.Message, "role table unavailable") {
		t.Errorf("message %q does not carry the engine's cause", ce.Message)
	}
}

func TestSubjectsDetailRelationsCarryTheSubjectRelationOfAUserset(t *testing.T) {
	// group:eng#member on doc:spec grants every member of eng, which is not
	// the same as a grant to the group itself.
	s := memory.New()
	ctx := context.Background()
	userset := &relation.Tuple{TenantID: "t1", ObjectType: "doc", ObjectID: "spec", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member"}
	direct := &relation.Tuple{TenantID: "t1", ObjectType: "doc", ObjectID: "readme", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng"}
	for _, tp := range []*relation.Tuple{userset, direct} {
		if err := s.CreateRelation(ctx, tp); err != nil {
			t.Fatalf("create tuple: %v", err)
		}
	}

	got := subjectDetail(t, s, SubjectDetailInput{SubjectKind: "group", SubjectID: "eng"})
	by := map[string]SubjectRelation{}
	for _, r := range got.Relations {
		by[r.ID] = r
	}
	if r := by[userset.ID.String()]; r.SubjectRelation != "member" {
		t.Errorf("userset tuple = %+v, want subjectRelation member", r)
	}
	if r := by[direct.ID.String()]; r.SubjectRelation != "" {
		t.Errorf("direct tuple = %+v, want no subjectRelation", r)
	}
	raw := marshalDetail(t, got)
	if strings.Count(raw, `"subjectRelation":"member"`) != 1 || strings.Count(raw, `"subjectRelation"`) != 1 {
		t.Errorf("want subjectRelation on the userset row only (omitted when empty): %s", raw)
	}
}
