package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// cappedRoleOver stores a role named "Small" with the given cap and binds
// one live user per name in live and one expired user per name in expired.
func cappedRoleOver(t *testing.T, s *memory.Store, maxMembers int, live, expired []string) *role.Role {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: testTenant, Name: "Small", Slug: "small", MaxMembers: maxMembers}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	bind := func(who string, expires *time.Time) {
		if err := s.CreateAssignment(ctx, &assignment.Assignment{
			TenantID: testTenant, RoleID: r.ID, SubjectKind: "user", SubjectID: who, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("assign %q: %v", who, err)
		}
	}
	for _, who := range live {
		bind(who, nil)
	}
	for _, who := range expired {
		bind(who, &past)
	}
	return r
}

func storedRoleIn(t *testing.T, s *memory.Store, r *role.Role) *role.Role {
	t.Helper()
	got, err := s.GetRole(context.Background(), testTenant, r.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	return got
}

func putRole(h http.Handler, r *role.Role, body map[string]any) int {
	return do(h, request(http.MethodPut, "/v1/roles/"+r.ID.String(), "alice", testTenant, body)).Code
}

func TestRoles_UpdateCapBelowLiveMembersIs409(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	r := cappedRoleOver(t, s.Store, 5, []string{"a", "b", "c"}, nil)

	rec := do(h, request(http.MethodPut, "/v1/roles/"+r.ID.String(), "alice", testTenant, map[string]any{
		"max_members": 2, "name": "Renamed",
	}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	decodeJSON(t, rec, &body)
	want := `"Small" has 3 members, so its cap cannot be lowered to 2`
	if body.Message != want && body.Error != want {
		t.Errorf("body = %s, want the message %q", rec.Body.String(), want)
	}
	if after := storedRoleIn(t, s.Store, r); after.MaxMembers != 5 || after.Name != "Small" {
		t.Errorf("the refusal wrote something: cap %d, name %q", after.MaxMembers, after.Name)
	}
}

func TestRoles_UpdateCapOnAnUncappedRoleBelowItsMembersIs409(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	r := cappedRoleOver(t, s.Store, 0, []string{"a", "b"}, nil)

	if code := putRole(h, r, map[string]any{"max_members": 1}); code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", code)
	}
	if after := storedRoleIn(t, s.Store, r); after.MaxMembers != 0 {
		t.Errorf("cap = %d, want 0 (unchanged)", after.MaxMembers)
	}
}

func TestRoles_UpdateCapAtOrAboveLiveMembersOrClearedSaves(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newCap int
	}{
		{"exactly the live count", 3},
		{"raised", 10},
		{"cleared to unlimited", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &racingPolicyStore{Store: memory.New()}
			h := newTestAPIOver(t, s)
			r := cappedRoleOver(t, s.Store, 5, []string{"a", "b", "c"}, nil)

			if code := putRole(h, r, map[string]any{"max_members": tc.newCap}); code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			if after := storedRoleIn(t, s.Store, r); after.MaxMembers != tc.newCap {
				t.Errorf("cap = %d, want %d", after.MaxMembers, tc.newCap)
			}
		})
	}
}

func TestRoles_UpdateCapDoesNotCountExpiredAssignments(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	r := cappedRoleOver(t, s.Store, 5, []string{"a", "b"}, []string{"old1", "old2"})

	rec := do(h, request(http.MethodPut, "/v1/roles/"+r.ID.String(), "alice", testTenant, map[string]any{"max_members": 1}))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `has 2 members`) {
		t.Fatalf("lowering to 1: status = %d body=%s, want 409 counting 2 live members", rec.Code, rec.Body.String())
	}
	if code := putRole(h, r, map[string]any{"max_members": 2}); code != http.StatusOK {
		t.Fatalf("lowering to the live count: status = %d, want 200", code)
	}
	if after := storedRoleIn(t, s.Store, r); after.MaxMembers != 2 {
		t.Errorf("cap = %d, want 2", after.MaxMembers)
	}
}

func TestRoles_UpdateOverFullRoleWithTheCapUnchangedSaves(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	r := cappedRoleOver(t, s.Store, 1, []string{"a", "b", "c"}, nil)

	if code := putRole(h, r, map[string]any{"name": "First"}); code != http.StatusOK {
		t.Fatalf("rename with the cap omitted: status = %d, want 200", code)
	}
	if code := putRole(h, r, map[string]any{"name": "Second", "max_members": 1}); code != http.StatusOK {
		t.Fatalf("rename with the cap resent unchanged: status = %d, want 200", code)
	}
	if after := storedRoleIn(t, s.Store, r); after.Name != "Second" || after.MaxMembers != 1 {
		t.Errorf("stored name %q cap %d, want Second and 1", after.Name, after.MaxMembers)
	}
}

func assignREST(h http.Handler, r *role.Role, body map[string]any) *httptest.ResponseRecorder {
	b := map[string]any{"role_id": r.ID.String(), "subject_kind": "user"}
	for k, v := range body {
		b[k] = v
	}
	return do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, b))
}

func liveRowsFor(t *testing.T, s *memory.Store, r *role.Role) int {
	t.Helper()
	held, err := s.ListSubjectsForRole(context.Background(), testTenant, r.ID)
	if err != nil {
		t.Fatalf("list subjects: %v", err)
	}
	return len(held)
}

func TestAssignments_CreatePastTheMemberCapIs409(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	r := cappedRoleOver(t, s.Store, 2, []string{"a", "b"}, nil)

	rec := assignREST(h, r, map[string]any{"subject_id": "c"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	decodeJSON(t, rec, &body)
	want := `"Small" is capped at 2 members and already has 2`
	if body.Message != want && body.Error != want {
		t.Errorf("body = %s, want the message %q", rec.Body.String(), want)
	}
	if n := liveRowsFor(t, s.Store, r); n != 2 {
		t.Errorf("the refusal wrote an assignment: %d rows, want 2", n)
	}
}

func TestAssignments_CreateWithinTheMemberCapSaves(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cap     int
		live    []string
		expired []string
		body    map[string]any
	}{
		{"a seat is free", 3, []string{"a", "b"}, nil, map[string]any{"subject_id": "c"}},
		{"expired assignments hold no seat", 2, []string{"a"}, []string{"old1", "old2"}, map[string]any{"subject_id": "c"}},
		{"a cap of 0 is unlimited", 0, []string{"a", "b", "c"}, nil, map[string]any{"subject_id": "d"}},
		{"a member's second binding adds nobody", 2, []string{"a", "b"}, nil,
			map[string]any{"subject_id": "a", "resource_type": "doc", "resource_id": "1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &racingPolicyStore{Store: memory.New()}
			h := newTestAPIOver(t, s)
			r := cappedRoleOver(t, s.Store, tc.cap, tc.live, tc.expired)

			if rec := assignREST(h, r, tc.body); rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAssignments_CreateForAnUnknownRoleIs404(t *testing.T) {
	s := &racingPolicyStore{Store: memory.New()}
	h := newTestAPIOver(t, s)
	ghost := &role.Role{ID: id.NewRoleID()}

	if rec := assignREST(h, ghost, map[string]any{"subject_id": "a"}); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}
