package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/resourcetype"
)

// duplicateCase posts the same create twice and expects the second to be a
// 409 that carries the store's own message.
type duplicateCase struct {
	name string
	path string
	body func(t *testing.T, h http.Handler) map[string]any
	want error
}

func TestDuplicates_AnswerConflict409(t *testing.T) {
	cases := []duplicateCase{
		{
			name: "role", path: "/v1/roles", want: warden.ErrDuplicateRole,
			body: func(*testing.T, http.Handler) map[string]any {
				return map[string]any{"name": "Editor", "slug": "editor"}
			},
		},
		{
			name: "permission", path: "/v1/permissions", want: warden.ErrDuplicatePermission,
			body: func(*testing.T, http.Handler) map[string]any {
				return map[string]any{"name": "document:read", "resource": "document", "action": "read"}
			},
		},
		{
			name: "policy", path: "/v1/policies", want: warden.ErrDuplicatePolicy,
			body: func(*testing.T, http.Handler) map[string]any {
				return map[string]any{"name": "allow-read", "effect": "allow", "is_active": true}
			},
		},
		{
			name: "resource type", path: "/v1/resource-types", want: warden.ErrDuplicateResourceType,
			body: func(*testing.T, http.Handler) map[string]any {
				return map[string]any{"name": "document"}
			},
		},
		{
			name: "assignment", path: "/v1/assignments", want: warden.ErrDuplicateAssignment,
			body: func(t *testing.T, h http.Handler) map[string]any {
				t.Helper()
				rc := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
					"name": "Viewer", "slug": "viewer",
				}))
				if rc.Code != http.StatusCreated {
					t.Fatalf("seed role: status = %d; body=%s", rc.Code, rc.Body.String())
				}
				var r struct {
					ID string `json:"id"`
				}
				decodeJSON(t, rc, &r)
				return map[string]any{"role_id": r.ID, "subject_kind": "user", "subject_id": "bob"}
			},
		},
		{
			name: "relation", path: "/v1/relations", want: warden.ErrDuplicateRelation,
			body: func(*testing.T, http.Handler) map[string]any {
				return map[string]any{
					"object_type": "document", "object_id": "doc1", "relation": "viewer",
					"subject_type": "user", "subject_id": "bob",
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestAPI(t)
			body := tc.body(t, h)

			first := do(h, request(http.MethodPost, tc.path, "alice", testTenant, body))
			if first.Code != http.StatusCreated {
				t.Fatalf("first create: status = %d, want 201; body=%s", first.Code, first.Body.String())
			}
			second := do(h, request(http.MethodPost, tc.path, "alice", testTenant, body))
			if second.Code != http.StatusConflict {
				t.Fatalf("duplicate create: status = %d, want 409; body=%s", second.Code, second.Body.String())
			}
			if !strings.Contains(second.Body.String(), tc.want.Error()) {
				t.Errorf("body = %s, want the store's message %q", second.Body.String(), tc.want.Error())
			}
		})
	}
}

// TestMapError_DuplicateWrappedIsConflict covers a duplicate that reaches
// mapError wrapped by a caller's own context, the way a store or handler
// adds the entity name.
func TestMapError_DuplicateWrappedIsConflict(t *testing.T) {
	for _, base := range []error{
		warden.ErrAlreadyExists,
		warden.ErrDuplicateRole,
		warden.ErrDuplicatePermission,
		warden.ErrDuplicatePolicy,
		warden.ErrDuplicateResourceType,
		warden.ErrDuplicateAssignment,
		warden.ErrDuplicateRelation,
	} {
		err := mapError(fmt.Errorf("creating %q: %w", "x", base))
		if got := statusOf(t, err); got != http.StatusConflict {
			t.Errorf("%v: status = %d, want 409", base, got)
		}
	}
}

// TestMapError_OtherRefusalsKeepTheirStatus pins the statuses that sit
// next to the duplicate case, so folding duplicates into 409 does not
// move them. None of these is a duplicate, and none wraps
// warden.ErrAlreadyExists.
func TestMapError_OtherRefusalsKeepTheirStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"system role", warden.ErrSystemRoleImmutable, http.StatusBadRequest},
		{"system permission", warden.ErrSystemPermissionImmutable, http.StatusBadRequest},
		{"cyclic inheritance", fmt.Errorf("role a: %w", warden.ErrCyclicRoleInheritance), http.StatusBadRequest},
		{"members exceeded", warden.ErrMaxMembersExceeded, http.StatusBadRequest},
		{"invalid condition", fmt.Errorf("%w: unknown operator %q", warden.ErrInvalidCondition, "nope"), http.StatusBadRequest},
		{"undeclared tuple", &resourcetype.UndeclaredTupleError{}, http.StatusBadRequest},
		{"role cap below members", &assignment.CapBelowMembersError{}, http.StatusConflict},
		{"role full", &assignment.RoleFullError{}, http.StatusConflict},
		{"stale write", warden.ErrStaleWrite, http.StatusConflict},
		{"access denied", warden.ErrAccessDenied, http.StatusForbidden},
		{"role not found", warden.ErrRoleNotFound, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if errors.Is(tc.err, warden.ErrAlreadyExists) {
				t.Fatalf("fixture wraps ErrAlreadyExists, so it is a duplicate")
			}
			if got := statusOf(t, mapError(tc.err)); got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMapError_UnknownErrorPassesThrough(t *testing.T) {
	boom := errors.New("store down")
	if got := mapError(boom); !errors.Is(got, boom) {
		t.Fatalf("mapError(%v) = %v, want the error unchanged", boom, got)
	}
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he interface{ StatusCode() int }
	if !errors.As(err, &he) {
		t.Fatalf("error %v carries no HTTP status", err)
	}
	return he.StatusCode()
}

// TestPolicies_RenameOntoTakenName409 covers the update path: a rename onto
// a name another policy holds in the same tenant and namespace is a
// duplicate, and a policy keeping its own name is not.
func TestPolicies_RenameOntoTakenName409(t *testing.T) {
	h := newTestAPI(t)
	mk := func(name string) string {
		t.Helper()
		rec := do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
			"name": name, "effect": "allow", "is_active": true,
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %q: status = %d; body=%s", name, rec.Code, rec.Body.String())
		}
		var p struct {
			ID string `json:"id"`
		}
		decodeJSON(t, rec, &p)
		return p.ID
	}
	mk("alpha")
	beta := mk("beta")

	rec := do(h, request(http.MethodPut, "/v1/policies/"+beta, "alice", testTenant, map[string]any{"name": "alpha"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("rename onto a taken name: status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), warden.ErrDuplicatePolicy.Error()) {
		t.Errorf("body = %s, want the store's message", rec.Body.String())
	}
	get := do(h, request(http.MethodGet, "/v1/policies/"+beta, "alice", testTenant, nil))
	if !strings.Contains(get.Body.String(), `"name":"beta"`) {
		t.Errorf("the refused rename wrote something: %s", get.Body.String())
	}

	own := do(h, request(http.MethodPut, "/v1/policies/"+beta, "alice", testTenant, map[string]any{
		"name": "beta", "description": "same name",
	}))
	if own.Code != http.StatusOK {
		t.Fatalf("keeping its own name: status = %d, want 200; body=%s", own.Code, own.Body.String())
	}
	free := do(h, request(http.MethodPut, "/v1/policies/"+beta, "alice", testTenant, map[string]any{"name": "gamma"}))
	if free.Code != http.StatusOK {
		t.Fatalf("rename to a free name: status = %d, want 200; body=%s", free.Code, free.Body.String())
	}
}
