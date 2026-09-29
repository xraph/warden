package contract

import (
	"context"
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
	// Role.MaxMembers is enforced by NOTHING below this layer.
	// ErrMaxMembersExceeded is handled in api/helpers.go:34 and returned by
	// zero places, and no store counts members before an insert. So a role
	// capped at 2 accepts unlimited assignments unless this guard refuses.
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
	var subjects []string
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

	if _, err := assignmentsDeleteHandler(deps)(ctx, AssignmentDeleteInput{ID: ack.ID}, principalFor("t1")); err != nil {
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

func parseRoleIDForTest(raw string) (id.RoleID, error) { return id.ParseRoleID(raw) }
