package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// TestFetchRoles_BoundedForDropdown pins the dropdown fetches to an explicit
// cap. They feed <select> elements, so the bound has to be the dashboard's
// own decision rather than whatever limit the backend happens to default to:
// the memory backend applies none and the SQL backends apply 1000.
func TestFetchRoles_BoundedForDropdown(t *testing.T) {
	const n = dropdownOptionLimit + 137

	s := memory.New()
	ctx := context.Background()
	base := time.Now().UTC()
	for i := range n {
		r := &role.Role{
			ID:        id.NewRoleID(),
			TenantID:  "t1",
			Name:      fmt.Sprintf("Role %04d", i),
			Slug:      fmt.Sprintf("role-%04d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base,
		}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("seed role %d: %v", i, err)
		}
	}

	got, err := fetchRoles(ctx, s, "t1")
	if err != nil {
		t.Fatalf("fetch roles: %v", err)
	}
	if len(got) != dropdownOptionLimit {
		t.Errorf("roles for dropdown: got %d, want %d", len(got), dropdownOptionLimit)
	}
}

func TestFetchPermissions_BoundedForDropdown(t *testing.T) {
	const n = dropdownOptionLimit + 137

	s := memory.New()
	ctx := context.Background()
	base := time.Now().UTC()
	for i := range n {
		p := &permission.Permission{
			ID:        id.NewPermissionID(),
			TenantID:  "t1",
			Name:      fmt.Sprintf("doc:act%04d", i),
			Resource:  "doc",
			Action:    fmt.Sprintf("act%04d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Millisecond),
			UpdatedAt: base,
		}
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatalf("seed permission %d: %v", i, err)
		}
	}

	got, err := fetchPermissions(ctx, s, "t1")
	if err != nil {
		t.Fatalf("fetch permissions: %v", err)
	}
	if len(got) != dropdownOptionLimit {
		t.Errorf("permissions for dropdown: got %d, want %d", len(got), dropdownOptionLimit)
	}
}

// TestParseLimitParam_ClampsHugeRequests pins an upper bound on the page size
// a caller can ask for. Without one, ?limit=1000000 is passed straight to the
// store, which honours any positive limit it is given.
func TestParseLimitParam_ClampsHugeRequests(t *testing.T) {
	tests := []struct {
		name  string
		param string
		def   int
		want  int
	}{
		{"absent falls back to the default", "", 20, 20},
		{"ordinary value is kept", "50", 20, 50},
		{"zero falls back to the default", "0", 20, 20},
		{"negative falls back to the default", "-1", 20, 20},
		{"oversized value is clamped", "1000000", 20, maxPageLimit},
		{"exactly the maximum is kept", fmt.Sprint(maxPageLimit), 20, maxPageLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLimitParam(map[string]string{"limit": tc.param}, tc.def)
			if got != tc.want {
				t.Errorf("parseLimitParam(%q): got %d, want %d", tc.param, got, tc.want)
			}
		})
	}
}
