package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"
)

// RunLikeEscapeContract asserts that a search term containing SQL LIKE
// metacharacters (% and _) is matched literally, not as a wildcard pattern.
//
// The bug this guards: ListRoles (and every other Search filter built as
// `LIKE '%'||term||'%'`) passed the caller's search term straight into the
// pattern. A role named "100%" searched for with "100%" happened to still
// match, but searching "100_" would ALSO match it — because the "_"
// wildcard matches any single character, including the literal "%" in the
// stored name — which is not what a caller typing an underscore meant. The
// fix escapes \, % and _ in the term before building the pattern and adds
// `ESCAPE '\'` to the query.
func RunLikeEscapeContract(t *testing.T, mk MakeStore) {
	t.Helper()

	s, cleanup := mk(t)
	defer cleanup()
	ctx := context.Background()

	r := &role.Role{
		ID: id.NewRoleID(), TenantID: "t1", NamespacePath: "",
		Name: "100%", Slug: "hundred-percent",
	}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	got, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Search: "100%"})
	if err != nil {
		t.Fatalf("ListRoles Search=%q: %v", "100%", err)
	}
	if len(got) != 1 {
		t.Errorf("Search=%q: want to find the literal %%-named role, got %d rows", "100%", len(got))
	}

	got, err = s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Search: "100_"})
	if err != nil {
		t.Fatalf("ListRoles Search=%q: %v", "100_", err)
	}
	if len(got) != 0 {
		t.Errorf("Search=%q: \"_\" must not wildcard-match the role named \"100%%\", got %d rows", "100_", len(got))
	}
}
