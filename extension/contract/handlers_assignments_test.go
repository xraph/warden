package contract

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedAssignment binds a subject to a role, optionally with an expiry.
func seedAssignment(t *testing.T, s *memory.Store, roleID, subjectID string, expires *time.Time) *assignment.Assignment {
	t.Helper()
	rid, err := parseRoleIDForTest(roleID)
	if err != nil {
		t.Fatalf("parse role id %q: %v", roleID, err)
	}
	a := &assignment.Assignment{
		TenantID:    "t1",
		RoleID:      rid,
		SubjectKind: "user",
		SubjectID:   subjectID,
		ExpiresAt:   expires,
	}
	if err := s.CreateAssignment(context.Background(), a); err != nil {
		t.Fatalf("create assignment for %q: %v", subjectID, err)
	}
	return a
}

func TestAssignmentsListPagesAndReportsTheTotal(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	for _, who := range []string{"a", "b", "c", "d", "e"} {
		seedAssignment(t, s, r.ID.String(), who, nil)
	}
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), AssignmentsListInput{PageRequest: PageRequest{Limit: 2}}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.list: %v", err)
	}
	if len(got.Items) != 2 {
		t.Errorf("returned %d items, want 2", len(got.Items))
	}
	if got.Total != 5 {
		t.Errorf("total = %d, want 5", got.Total)
	}
}

func TestAssignmentsListMarksExpiredRowsExpired(t *testing.T) {
	// The finding this page exists to fix. ListRolesForSubject filters
	// expired assignments (store/memory/store.go:685) so the engine ignores
	// them, but filterAssignments behind ListAssignments does not. So an
	// expired row is IN the list and grants nothing, and the list must say
	// so or it is lying to the operator.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	seedAssignment(t, s, r.ID.String(), "gone", &past)
	seedAssignment(t, s, r.ID.String(), "soon", &future)
	seedAssignment(t, s, r.ID.String(), "forever", nil)
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), AssignmentsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.list: %v", err)
	}
	if len(got.Items) != 3 {
		t.Fatalf("returned %d items, want all 3 including the expired one", len(got.Items))
	}
	bySubject := map[string]AssignmentSummary{}
	for _, a := range got.Items {
		bySubject[a.SubjectID] = a
	}
	if !bySubject["gone"].Expired {
		t.Error("the past-dated assignment is not marked expired: the page would show it as live")
	}
	if bySubject["soon"].Expired {
		t.Error("a future expiry must not be marked expired")
	}
	if bySubject["forever"].Expired {
		t.Error("an assignment with no expiry must not be marked expired")
	}
	if bySubject["forever"].ExpiresAt != "" {
		t.Errorf("no expiry should serialise as empty, got %q", bySubject["forever"].ExpiresAt)
	}
}

func TestAssignmentsListCarriesTheRoleItBinds(t *testing.T) {
	// A row reading only a role id is unreadable. The page needs the slug.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	seedAssignment(t, s, r.ID.String(), "alice", nil)
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), AssignmentsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.list: %v", err)
	}
	if got.Items[0].RoleSlug != "reader" {
		t.Errorf("roleSlug = %q, want reader", got.Items[0].RoleSlug)
	}
}

func TestAssignmentsListIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	mine := seedRoles(t, s, "", "mine")[0]
	seedAssignment(t, s, mine.ID.String(), "alice", nil)
	theirs := &role.Role{TenantID: "t2", Name: "T", Slug: "theirs"}
	if err := s.CreateRole(ctx, theirs); err != nil {
		t.Fatalf("create other tenant's role: %v", err)
	}
	other := &assignment.Assignment{
		TenantID: "t2", RoleID: theirs.ID, SubjectKind: "user", SubjectID: "bob",
	}
	if err := s.CreateAssignment(ctx, other); err != nil {
		t.Fatalf("create other tenant's assignment: %v", err)
	}
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(ctx, AssignmentsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.list: %v", err)
	}
	// Asserted on identity, not count: a count assertion passes when the
	// wrong rows arrive in the right quantity.
	for _, a := range got.Items {
		if a.SubjectID == "bob" {
			t.Fatal("t1 can see t2's assignment: tenant scoping is not applied")
		}
	}
	if got.Total != 1 {
		t.Errorf("total = %d, want 1", got.Total)
	}
}

func TestAssignmentsCreateBinds(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.create: %v", err)
	}
	if got.ID == "" {
		t.Fatal("create returned no id")
	}
}

func TestAssignmentsCreateAcceptsASystemRole(t *testing.T) {
	// Deliberate, and the opposite of every role WRITE in plan 2a.
	// extension/bootstrap.go:100 creates a system role and :168 assigns a
	// subject to it, so guarding assignment writes with guardSystemRole
	// would break first-run bootstrap from the dashboard. Assigning is a
	// membership change, not a role edit.
	s := memory.New()
	ctx := context.Background()
	sys := &role.Role{TenantID: "t1", Name: "System", Slug: "warden-admin", IsSystem: true}
	if err := s.CreateRole(ctx, sys); err != nil {
		t.Fatalf("create system role: %v", err)
	}
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, AssignmentCreateInput{
		RoleID: sys.ID.String(), SubjectKind: "user", SubjectID: "root",
	}, principalFor("t1")); err != nil {
		t.Fatalf("assigning to a system role must be allowed, got %v", err)
	}
}

func TestAssignmentsCreateRefusesPastTheMemberCap(t *testing.T) {
	// No store enforces Role.MaxMembers: none counts members before an
	// insert, and ErrMaxMembersExceeded is returned by nothing. So a role
	// capped at 2 accepts unlimited assignments unless this guard (and its
	// REST twin, both on assignment.CheckMemberCap) refuses.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 2}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	for _, who := range []string{"a", "b"} {
		if _, err := h(ctx, AssignmentCreateInput{
			RoleID: r.ID.String(), SubjectKind: "user", SubjectID: who,
		}, principalFor("t1")); err != nil {
			t.Fatalf("assigning %q within the cap: %v", who, err)
		}
	}

	_, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "c",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal past the member cap")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict, got %v", err)
	}
	if !containsText(ce.Message, "2") {
		t.Errorf("message %q does not name the cap", ce.Message)
	}
}

func TestAssignmentsCreateIgnoresACapOfZero(t *testing.T) {
	// MaxMembers 0 means unlimited. No field comment says so; the evidence
	// is the omitempty tag and the templ dashboard rendering the cap only
	// `if r.MaxMembers > 0`. A guard treating 0 as "no members allowed"
	// would block every assignment on every role that never set a cap.
	s := memory.New()
	r := seedRoles(t, s, "", "uncapped")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	for _, who := range []string{"a", "b", "c"} {
		if _, err := h(context.Background(), AssignmentCreateInput{
			RoleID: r.ID.String(), SubjectKind: "user", SubjectID: who,
		}, principalFor("t1")); err != nil {
			t.Fatalf("assigning %q to an uncapped role: %v", who, err)
		}
	}
}

func TestAssignmentsCreateCountsOnlyLiveMembersAgainstTheCap(t *testing.T) {
	// An expired assignment grants nothing, so it must not occupy a seat.
	// Counting it would lock a role out permanently as old grants pile up.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 1}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	seedAssignment(t, s, r.ID.String(), "gone", &past)
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "live",
	}, principalFor("t1")); err != nil {
		t.Fatalf("an expired assignment must not occupy a seat, got %v", err)
	}
}

func TestAssignmentsCreateRejectsAnUnknownSubjectKind(t *testing.T) {
	// warden.SubjectKind is a closed set: user, api_key, service,
	// service_acct. A typo stores an assignment no check will ever match,
	// because the engine compares the kind verbatim.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(context.Background(), AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "usr", SubjectID: "alice",
	}, principalFor("t1"))
	if err == nil {
		t.Fatal("want a refusal for an unknown subject kind")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}

func TestAssignmentsDeleteRemovesIt(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	a := seedAssignment(t, s, r.ID.String(), "alice", nil)
	h := assignmentsDeleteHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, AssignmentDeleteInput{ID: a.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("assignments.delete: %v", err)
	}
	if _, err := s.GetAssignment(ctx, "t1", a.ID); err == nil {
		t.Fatal("the assignment is still there")
	}
}

func TestAssignmentsExpiringListsWhatIsAboutToLapse(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	soon := time.Now().Add(2 * time.Hour)
	far := time.Now().Add(100 * 24 * time.Hour)
	seedAssignment(t, s, r.ID.String(), "soon", &soon)
	seedAssignment(t, s, r.ID.String(), "far", &far)
	seedAssignment(t, s, r.ID.String(), "never", nil)
	h := assignmentsExpiringHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ExpiringInput{WithinHours: 24}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.expiring: %v", err)
	}
	subjects := make([]string, 0, len(got.Items))
	for _, a := range got.Items {
		subjects = append(subjects, a.SubjectID)
	}
	if len(subjects) != 1 || subjects[0] != "soon" {
		t.Errorf("expiring = %v, want only soon", subjects)
	}
}

func TestAssignmentsExpiringDefaultsItsWindow(t *testing.T) {
	// A window of zero must not mean "nothing expires", which would make an
	// empty page look healthy.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	soon := time.Now().Add(2 * time.Hour)
	seedAssignment(t, s, r.ID.String(), "soon", &soon)
	h := assignmentsExpiringHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ExpiringInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.expiring: %v", err)
	}
	if len(got.Items) != 1 {
		t.Errorf("an unset window returned %d items, want the default window to catch the one expiring in 2h", len(got.Items))
	}
}

func TestAssignmentsExpiringIncludesWhatAlreadyLapsed(t *testing.T) {
	// ListExpiringAssignments takes a "before" instant and returns
	// everything with an expiry earlier than it, which includes expiries
	// already in the PAST (store/memory/store.go:736). That is the right
	// behaviour for a feed of what needs attention, since a grant that
	// lapsed last week still needs somebody to renew or remove it. But the
	// feed must distinguish the two, or "expiring soon" and "already dead"
	// read identically.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	past := time.Now().Add(-time.Hour)
	soon := time.Now().Add(2 * time.Hour)
	seedAssignment(t, s, r.ID.String(), "gone", &past)
	seedAssignment(t, s, r.ID.String(), "soon", &soon)
	h := assignmentsExpiringHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ExpiringInput{WithinHours: 24}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.expiring: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("returned %d items, want both the lapsed and the lapsing", len(got.Items))
	}
	bySubject := map[string]AssignmentSummary{}
	for _, a := range got.Items {
		bySubject[a.SubjectID] = a
	}
	if !bySubject["gone"].Expired {
		t.Error("the already-lapsed row is not marked expired: the feed cannot distinguish it from one expiring soon")
	}
	if bySubject["soon"].Expired {
		t.Error("a row expiring in 2h must not be marked expired yet")
	}
}

// assignProbe adds the two assignment hooks to auditProbe.
type assignProbe struct{ *auditProbe }

func (a assignProbe) OnRoleAssigned(context.Context, *assignment.Assignment) error {
	a.note("role.assigned")
	return nil
}

func (a assignProbe) OnRoleUnassigned(context.Context, *assignment.Assignment) error {
	a.note("role.unassigned")
	return nil
}

func TestAssignmentsWritesEmitAuditAndTheTypedHooks(t *testing.T) {
	// The audit event is what flushes the decision cache. A revoke that
	// emitted nothing would leave the revoked subject holding a cached ALLOW.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	probe := assignProbe{&auditProbe{}}
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithPlugin(probe))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	deps := Deps{Engine: eng}
	ctx := context.Background()

	ack, err := assignmentsCreateHandler(deps)(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.create: %v", err)
	}
	created := probe.event(t, "assignment.created")
	if created.Actor != wantActor || created.TenantID != "t1" || created.EntityID != ack.ID {
		t.Errorf("create event = %+v", created)
	}
	if !probe.hasTyped("role.assigned") {
		t.Error("the typed OnRoleAssigned hook did not fire")
	}
	aid, _ := id.ParseAssignmentID(ack.ID)
	stored, err := s.GetAssignment(ctx, "t1", aid)
	if err != nil {
		t.Fatalf("stored assignment: %v", err)
	}
	if stored.GrantedBy != "tester" {
		t.Errorf("grantedBy = %q, want tester", stored.GrantedBy)
	}

	if _, err := assignmentsDeleteHandler(deps)(ctx, AssignmentDeleteInput(ack), principalFor("t1")); err != nil {
		t.Fatalf("assignments.delete: %v", err)
	}
	del := probe.event(t, "assignment.deleted")
	if del.EntityID != ack.ID || del.Before == nil || del.Actor != wantActor {
		t.Errorf("delete event = %+v", del)
	}
	if !probe.hasTyped("role.unassigned") {
		t.Error("the typed OnRoleUnassigned hook did not fire")
	}
}

func TestAssignmentsCreateRefusesAnotherTenantsRole(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	theirs := &role.Role{TenantID: "t2", Name: "T", Slug: "theirs"}
	if err := s.CreateRole(ctx, theirs); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, AssignmentCreateInput{
		RoleID: theirs.ID.String(), SubjectKind: "user", SubjectID: "alice",
	}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Fatalf("want CodeNotFound for a role in another tenant, got %v", err)
	}
}

func TestAssignmentsDeleteRefusesAnotherTenantsAssignment(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	theirs := &role.Role{TenantID: "t2", Name: "T", Slug: "theirs"}
	if err := s.CreateRole(ctx, theirs); err != nil {
		t.Fatalf("create: %v", err)
	}
	other := &assignment.Assignment{TenantID: "t2", RoleID: theirs.ID, SubjectKind: "user", SubjectID: "bob"}
	if err := s.CreateAssignment(ctx, other); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := assignmentsDeleteHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, AssignmentDeleteInput{ID: other.ID.String()}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Fatalf("want CodeNotFound, got %v", err)
	}
	if _, err := s.GetAssignment(ctx, "t2", other.ID); err != nil {
		t.Fatalf("t2's assignment was deleted by t1: %v", err)
	}
}

func TestAssignmentsCreateRefusesADuplicateBinding(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})
	in := AssignmentCreateInput{RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice"}

	if _, err := h(context.Background(), in, principalFor("t1")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := h(context.Background(), in, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("want CodeConflict for a duplicate binding, got %v", err)
	}
}

func TestAssignmentsCreateRejectsAPastOrMalformedExpiry(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	for name, raw := range map[string]string{
		"past":      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"malformed": "tomorrow",
	} {
		_, err := h(context.Background(), AssignmentCreateInput{
			RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", ExpiresAt: raw,
		}, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s expiry: want CodeBadRequest, got %v", name, err)
		}
	}
}

// seedBinding binds a subject to a role at a namespace and resource.
func seedBinding(t *testing.T, s *memory.Store, r *role.Role, subjectID, ns, resType, resID string) {
	t.Helper()
	a := &assignment.Assignment{
		TenantID: "t1", NamespacePath: ns, RoleID: r.ID, SubjectKind: "user", SubjectID: subjectID,
		ResourceType: resType, ResourceID: resID,
	}
	if err := s.CreateAssignment(context.Background(), a); err != nil {
		t.Fatalf("seed binding %q at %q %s:%s: %v", subjectID, ns, resType, resID, err)
	}
}

func subjectsOf(items []AssignmentSummary) map[string]bool {
	out := map[string]bool{}
	for _, a := range items {
		out[a.SubjectID] = true
	}
	return out
}

func TestAssignmentsCapCountsDistinctSubjectsNotRows(t *testing.T) {
	// Assignment uniqueness includes namespace, resource type and resource id,
	// so one subject can hold several rows for one role. Alice on two
	// documents is ONE member. Counting rows would fill a cap of 2 with her
	// alone and refuse bob.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 2}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})
	bind := func(who, resID string) error {
		_, err := h(ctx, AssignmentCreateInput{
			RoleID: r.ID.String(), SubjectKind: "user", SubjectID: who,
			ResourceType: "doc", ResourceID: resID,
		}, principalFor("t1"))
		return err
	}

	if err := bind("alice", "1"); err != nil {
		t.Fatalf("alice on doc 1: %v", err)
	}
	if err := bind("alice", "2"); err != nil {
		t.Fatalf("alice on doc 2 is the same member and must be allowed: %v", err)
	}
	if err := bind("bob", "1"); err != nil {
		t.Fatalf("bob is the second member of a cap of 2, but was refused: %v", err)
	}
	// The role is now full. A further binding for an EXISTING member adds
	// nobody, so it must still succeed.
	if err := bind("alice", "3"); err != nil {
		t.Fatalf("a third binding for a subject who is already a member adds no member, got %v", err)
	}
	// A genuinely new subject is the one that must be refused.
	err := bind("carol", "1")
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("a third distinct member must be refused with CodeConflict, got %v", err)
	}
}

func TestAssignmentsCapDoesNotConfuseSubjectKinds(t *testing.T) {
	// user:alice and service:alice are different members.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 1}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})
	if _, err := h(ctx, AssignmentCreateInput{RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice"}, principalFor("t1")); err != nil {
		t.Fatalf("user alice: %v", err)
	}
	_, err := h(ctx, AssignmentCreateInput{RoleID: r.ID.String(), SubjectKind: "service", SubjectID: "alice"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("service:alice is a different member and must hit the cap, got %v", err)
	}
}

func TestAssignmentsCreateReportsTheRealErrorBeforeTheCap(t *testing.T) {
	// The cap is checked last. A malformed request against a full role must
	// say what is wrong with the request, and a duplicate binding by an
	// existing member must say it is a duplicate, not that the role is full.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 1}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	seedBinding(t, s, r, "alice", "", "", "")
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "bob", ExpiresAt: "tomorrow",
	}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("malformed expiry on a full role: want CodeBadRequest, got %v", err)
	}

	_, err = h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice",
	}, principalFor("t1"))
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeConflict {
		t.Fatalf("duplicate on a full role: want CodeConflict, got %v", err)
	}
	if containsText(ce.Message, "capped") {
		t.Errorf("a duplicate binding reported the cap instead of the duplicate: %q", ce.Message)
	}
}

func TestAssignmentsCreateStoresWhatItWasGiven(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})
	when := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

	ack, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "service", SubjectID: "svc-1",
		NamespacePath: "eng/platform", ResourceType: "doc", ResourceID: "42",
		ExpiresAt: when.Format(time.RFC3339),
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.create: %v", err)
	}
	aid, _ := id.ParseAssignmentID(ack.ID)
	got, err := s.GetAssignment(ctx, "t1", aid)
	if err != nil {
		t.Fatalf("stored assignment: %v", err)
	}
	if got.RoleID != r.ID {
		t.Errorf("roleId = %s, want %s", got.RoleID, r.ID)
	}
	if got.TenantID != "t1" {
		t.Errorf("tenant = %q, want t1", got.TenantID)
	}
	if got.SubjectKind != "service" || got.SubjectID != "svc-1" {
		t.Errorf("subject = %s:%s, want service:svc-1", got.SubjectKind, got.SubjectID)
	}
	if got.NamespacePath != "eng/platform" {
		t.Errorf("namespace = %q, want eng/platform", got.NamespacePath)
	}
	if got.ResourceType != "doc" || got.ResourceID != "42" {
		t.Errorf("resource = %s:%s, want doc:42", got.ResourceType, got.ResourceID)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(when) {
		t.Errorf("expiresAt = %v, want %v", got.ExpiresAt, when)
	}
}

func TestAssignmentsCreateRejectsAnEmptySubjectIDAndABadNamespace(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	cases := map[string]AssignmentCreateInput{
		"empty subject id":  {RoleID: r.ID.String(), SubjectKind: "user"},
		"leading slash":     {RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", NamespacePath: "/eng"},
		"reserved segment":  {RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", NamespacePath: "system"},
		"empty segment":     {RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", NamespacePath: "eng//x"},
		"malformed role id": {RoleID: "nope", SubjectKind: "user", SubjectID: "alice"},
	}
	for name, in := range cases {
		_, err := h(context.Background(), in, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s: want CodeBadRequest, got %v", name, err)
		}
	}
	if n, _ := s.CountAssignments(context.Background(), &assignment.ListFilter{TenantID: "t1"}); n != 0 {
		t.Errorf("a refused create still stored %d rows", n)
	}
}

func TestAssignmentsListFiltersByNamespaceWithPointerSemantics(t *testing.T) {
	// nil means every namespace, a pointer to "" means the tenant root only,
	// and a pointer to a path means exactly that namespace.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	seedBinding(t, s, r, "root", "", "", "")
	seedBinding(t, s, r, "eng", "eng", "", "")
	seedBinding(t, s, r, "ops", "ops", "", "")
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()
	str := func(v string) *string { return &v }

	all, err := h(ctx, AssignmentsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("nil namespace: %v", err)
	}
	if len(all.Items) != 3 || all.Total != 3 {
		t.Errorf("nil namespace: %d items, total %d, want every namespace (3, 3)", len(all.Items), all.Total)
	}

	root, err := h(ctx, AssignmentsListInput{NamespacePath: str("")}, principalFor("t1"))
	if err != nil {
		t.Fatalf("root namespace: %v", err)
	}
	if got := subjectsOf(root.Items); len(got) != 1 || !got["root"] || root.Total != 1 {
		t.Errorf("\"\" namespace: got %v total %d, want only the tenant root row", got, root.Total)
	}

	eng, err := h(ctx, AssignmentsListInput{NamespacePath: str("eng")}, principalFor("t1"))
	if err != nil {
		t.Fatalf("eng namespace: %v", err)
	}
	if got := subjectsOf(eng.Items); len(got) != 1 || !got["eng"] || eng.Total != 1 {
		t.Errorf("eng namespace: got %v total %d, want only the eng row", got, eng.Total)
	}
}

func TestAssignmentsListFiltersByRoleSubjectAndResourceAndCountsTheSame(t *testing.T) {
	s := memory.New()
	rs := seedRoles(t, s, "", "reader", "writer")
	reader, writer := rs[0], rs[1]
	seedBinding(t, s, reader, "alice", "", "", "")
	seedBinding(t, s, reader, "bob", "", "", "")
	seedBinding(t, s, writer, "alice", "", "", "")
	seedBinding(t, s, writer, "alice", "", "doc", "7")
	h := assignmentsListHandler(Deps{Engine: engineOver(t, s)})
	ctx := context.Background()

	byRole, err := h(ctx, AssignmentsListInput{RoleID: reader.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("by role: %v", err)
	}
	if len(byRole.Items) != 2 || byRole.Total != 2 {
		t.Errorf("roleId filter: %d items, total %d, want 2, 2", len(byRole.Items), byRole.Total)
	}
	for _, a := range byRole.Items {
		if a.RoleID != reader.ID.String() {
			t.Errorf("roleId filter leaked a row for role %s", a.RoleID)
		}
	}

	bySubject, err := h(ctx, AssignmentsListInput{SubjectID: "alice"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("by subject: %v", err)
	}
	if len(bySubject.Items) != 3 || bySubject.Total != 3 {
		t.Errorf("subjectId filter: %d items, total %d, want 3, 3", len(bySubject.Items), bySubject.Total)
	}
	if got := subjectsOf(bySubject.Items); len(got) != 1 || !got["alice"] {
		t.Errorf("subjectId filter returned %v, want only alice", got)
	}

	byKind, err := h(ctx, AssignmentsListInput{SubjectKind: "service"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("by kind: %v", err)
	}
	if len(byKind.Items) != 0 || byKind.Total != 0 {
		t.Errorf("subjectKind filter: %d items, total %d, want 0, 0", len(byKind.Items), byKind.Total)
	}

	byRes, err := h(ctx, AssignmentsListInput{ResourceType: "doc", ResourceID: "7"}, principalFor("t1"))
	if err != nil {
		t.Fatalf("by resource: %v", err)
	}
	if len(byRes.Items) != 1 || byRes.Total != 1 || byRes.Items[0].ResourceID != "7" {
		t.Errorf("resource filter: %+v total %d, want the one doc:7 row", byRes.Items, byRes.Total)
	}

	combined, err := h(ctx, AssignmentsListInput{
		RoleID: writer.ID.String(), SubjectID: "alice", PageRequest: PageRequest{Limit: 1},
	}, principalFor("t1"))
	if err != nil {
		t.Fatalf("combined: %v", err)
	}
	if len(combined.Items) != 1 || combined.Total != 2 {
		t.Errorf("combined filter with limit 1: %d items, total %d, want 1 item of a total of 2", len(combined.Items), combined.Total)
	}
}

func TestAssignmentsListRejectsAMalformedRoleID(t *testing.T) {
	h := assignmentsListHandler(Deps{Engine: engineOver(t, memory.New())})
	_, err := h(context.Background(), AssignmentsListInput{RoleID: "nope"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Fatalf("want CodeBadRequest, got %v", err)
	}
}

func TestAssignmentsExpiringClampsAnOversizedLimitToTheMaximum(t *testing.T) {
	// The store sorts ascending by expiry and returns rows that lapsed long
	// ago. Enough of them fill a default-sized page and push every upcoming
	// expiry off it. An oversized limit must clamp to the maximum, not fall
	// back to the default, or asking for more would get less.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	for i := 0; i < defaultPageLimit+5; i++ {
		lapsed := time.Now().Add(-time.Duration(i+2) * time.Hour)
		seedAssignment(t, s, r.ID.String(), fmt.Sprintf("old-%d", i), &lapsed)
	}
	soon := time.Now().Add(2 * time.Hour)
	seedAssignment(t, s, r.ID.String(), "upcoming", &soon)
	h := assignmentsExpiringHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ExpiringInput{WithinHours: 24, Limit: maxPageLimit * 10}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.expiring: %v", err)
	}
	if !subjectsOf(got.Items)["upcoming"] {
		t.Errorf("an oversized limit returned %d rows and lost the upcoming expiry: it fell back to the default page instead of clamping to the max", len(got.Items))
	}
	if len(got.Items) != defaultPageLimit+6 {
		t.Errorf("returned %d items, want all %d", len(got.Items), defaultPageLimit+6)
	}
}

func TestAssignmentsExpiringHonoursASmallLimit(t *testing.T) {
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	for i := 0; i < 4; i++ {
		when := time.Now().Add(time.Duration(i+1) * time.Hour)
		seedAssignment(t, s, r.ID.String(), fmt.Sprintf("s-%d", i), &when)
	}
	h := assignmentsExpiringHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ExpiringInput{WithinHours: 24, Limit: 2}, principalFor("t1"))
	if err != nil {
		t.Fatalf("assignments.expiring: %v", err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("returned %d items, want 2", len(got.Items))
	}
	if got.Items[0].SubjectID != "s-0" || got.Items[1].SubjectID != "s-1" {
		t.Errorf("want the soonest two in ascending order, got %s then %s", got.Items[0].SubjectID, got.Items[1].SubjectID)
	}
}

func parseRoleIDForTest(raw string) (id.RoleID, error) { return id.ParseRoleID(raw) }

func TestAssignmentsCreateRefusesAHalfScopedResource(t *testing.T) {
	// An id without a type is a GLOBAL grant (ListRolesForSubject keeps any
	// row whose ResourceType is empty, whatever its ResourceID), and a type
	// without an id matches only checks on a resource whose id is "". Both
	// look scoped and are not, so both are refused and nothing is stored.
	s := memory.New()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	cases := map[string]struct {
		in   AssignmentCreateInput
		want string
	}{
		"id without type": {
			in:   AssignmentCreateInput{RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", ResourceID: "d-42"},
			want: "resourceId needs a resourceType",
		},
		"type without id": {
			in:   AssignmentCreateInput{RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice", ResourceType: "document"},
			want: "resourceType needs a resourceId",
		},
	}
	for name, tc := range cases {
		_, err := h(context.Background(), tc.in, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%s: want CodeBadRequest, got %v", name, err)
			continue
		}
		if !containsText(ce.Message, tc.want) {
			t.Errorf("%s: message %q does not name the rule %q", name, ce.Message, tc.want)
		}
	}
	if n, _ := s.CountAssignments(context.Background(), &assignment.ListFilter{TenantID: "t1"}); n != 0 {
		t.Errorf("a refused half-scoped create still stored %d rows", n)
	}
}

func TestAssignmentsCreateAcceptsBothOrNeitherResourceField(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := seedRoles(t, s, "", "reader")[0]
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	if _, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "alice",
		ResourceType: "document", ResourceID: "d-42",
	}, principalFor("t1")); err != nil {
		t.Fatalf("both resource fields: %v", err)
	}
	if _, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "bob",
	}, principalFor("t1")); err != nil {
		t.Fatalf("neither resource field: %v", err)
	}
	if n, _ := s.CountAssignments(ctx, &assignment.ListFilter{TenantID: "t1"}); n != 2 {
		t.Errorf("stored %d rows, want 2", n)
	}
}

func TestAssignmentsCreateReportsAHalfScopeBeforeTheCap(t *testing.T) {
	// Input first, cap last: a half-scoped request against a full role must
	// name the scope rule, not the cap.
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Small", Slug: "small", MaxMembers: 1}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	seedBinding(t, s, r, "alice", "", "", "")
	h := assignmentsCreateHandler(Deps{Engine: engineOver(t, s)})

	_, err := h(ctx, AssignmentCreateInput{
		RoleID: r.ID.String(), SubjectKind: "user", SubjectID: "bob", ResourceID: "d-42",
	}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Fatalf("half scope on a full role: want CodeBadRequest, got %v", err)
	}
}
