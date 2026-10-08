package contract

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// principalFor builds a Principal carrying a tenant claim.
//
// Deliberately NOT a context helper. warden.WithTenant would compile and
// would prove nothing, because nothing on the contract path reads it: the
// handler resolves its tenant from the principal and from Deps, never from
// ctx. A test that seeded the context would pass against a handler that
// refuses every real request.
//
// It also carries a signed-in user, because tenantFrom refuses a principal
// with no identity. Tests that want the anonymous case build their own.
func principalFor(tenantID string) dashcontract.Principal {
	return dashcontract.Principal{
		User:   &dashauth.UserInfo{Subject: "tester"},
		Claims: map[string]any{"tenant_id": tenantID},
	}
}

// signedInNoTenant is a signed-in user whose principal carries no tenant
// claim: identity is settled, so a refusal can only be about the tenant.
func signedInNoTenant() dashcontract.Principal {
	return dashcontract.Principal{User: &dashauth.UserInfo{Subject: "tester"}}
}

// seedAllow creates a tenant where user:alice may read document. This
// mirrors the root package's seedAllow (dryrun_test.go), which lives in
// package warden and is not reachable from package contract.
func seedAllow(t *testing.T, s *memory.Store) {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "Reader", Slug: "reader"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	p := &permission.Permission{TenantID: "t1", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, p); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{NamespacePath: "", Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	a := &assignment.Assignment{TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "alice"}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("create assignment: %v", err)
	}
}

func TestOverviewStatsWithoutATenantRefuses(t *testing.T) {
	// An unresolvable tenant must refuse, never default. The empty string
	// matches every tenant's rows in a store ListFilter rather than none,
	// so a handler that fell back to "" would serve one tenant's dashboard
	// the counts of all of them.
	eng := testEngine(t, warden.Config{})
	h := overviewStatsHandler(Deps{Engine: eng})

	_, err := h(context.Background(), struct{}{}, signedInNoTenant())
	if err == nil {
		t.Fatal("want an error when no tenant can be resolved")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
		t.Fatalf("want CodePermissionDenied, got %v", err)
	}
}

func TestOverviewStatsIgnoresAContextScope(t *testing.T) {
	// The trap this package exists to avoid. warden.WithTenant is what the
	// templ dashboard used and it is invisible here, because nothing on the
	// contract path propagates a warden or forge scope into the handler's
	// context. A handler that read ctx would pass a test written this way
	// and refuse every real request, or worse, be "fixed" by defaulting to
	// the empty tenant.
	eng := testEngine(t, warden.Config{})
	h := overviewStatsHandler(Deps{Engine: eng})

	ctx := warden.WithTenant(context.Background(), "", "t1")
	if _, err := h(ctx, struct{}{}, signedInNoTenant()); err == nil {
		t.Fatal("a context scope must not satisfy tenant resolution on the contract path")
	}
}

func TestOverviewStatsIsScopedToItsOwnTenant(t *testing.T) {
	// The isolation test. Two tenants, different data, asked through the
	// same handler. If tenant resolution is broken in the direction that
	// leaks rather than the direction that refuses, both answers come back
	// identical and this is the test that says so.
	s := memory.New()
	ctx := context.Background()
	for _, tenant := range []string{"t1", "t2"} {
		n := 1
		if tenant == "t2" {
			n = 3
		}
		for i := 0; i < n; i++ {
			r := &role.Role{TenantID: tenant, Name: "R", Slug: fmt.Sprintf("r%d", i)}
			if err := s.CreateRole(ctx, r); err != nil {
				t.Fatalf("create role in %s: %v", tenant, err)
			}
		}
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := overviewStatsHandler(Deps{Engine: eng})

	one, err := h(ctx, struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	two, err := h(ctx, struct{}{}, principalFor("t2"))
	if err != nil {
		t.Fatalf("t2: %v", err)
	}
	if one.Roles != 1 {
		t.Errorf("t1 roles = %d, want 1", one.Roles)
	}
	if two.Roles != 3 {
		t.Errorf("t2 roles = %d, want 3", two.Roles)
	}
	if one.Roles == two.Roles {
		t.Fatal("both tenants reported the same count: tenant scoping is not being applied")
	}
}

func TestDefaultTenantIDIsUsedWhenTheClaimIsAbsent(t *testing.T) {
	// The single-tenant path. It must work without a claim, and it must not
	// widen to every tenant.
	s := memory.New()
	seedAllow(t, s)
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := overviewStatsHandler(Deps{Engine: eng, DefaultTenantID: "t1"})

	got, err := h(context.Background(), struct{}{}, signedInNoTenant())
	if err != nil {
		t.Fatalf("with DefaultTenantID: %v", err)
	}
	if got.Roles != 1 {
		t.Errorf("roles = %d, want 1", got.Roles)
	}
}

func TestNamespacesListIsScopedByIdentityNotCount(t *testing.T) {
	// Isolation asserted on identity. A count assertion passes when the
	// wrong rows come back in the right quantity, and here the rows have
	// names, so there is no excuse for counting them instead.
	s := memory.New()
	ctx := context.Background()
	for tenant, ns := range map[string]string{"t1": "eng", "t2": "billing"} {
		r := &role.Role{TenantID: tenant, NamespacePath: ns, Name: "R", Slug: "r"}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role in %s/%s: %v", tenant, ns, err)
		}
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := namespacesListHandler(Deps{Engine: eng})

	one, err := h(ctx, struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	two, err := h(ctx, struct{}{}, principalFor("t2"))
	if err != nil {
		t.Fatalf("t2: %v", err)
	}
	// Both carry the tenant root; what differs is the one real namespace.
	if !contains(one.Namespaces, "eng") || contains(one.Namespaces, "billing") {
		t.Errorf("t1 namespaces = %q, want eng and not billing", one.Namespaces)
	}
	if !contains(two.Namespaces, "billing") || contains(two.Namespaces, "eng") {
		t.Errorf("t2 namespaces = %q, want billing and not eng", two.Namespaces)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestABrokenTenantClaimRefusesRatherThanFallingBack(t *testing.T) {
	// The fallback hazard. A claim that is present and unusable must not
	// resolve to the configured default, because that answers a question
	// about one tenant with another tenant's data while every test written
	// against a single tenant stays green.
	eng := testEngine(t, warden.Config{})
	h := overviewStatsHandler(Deps{Engine: eng, DefaultTenantID: "t1"})

	for name, claim := range map[string]any{
		"empty string": "",
		"wrong type":   12345,
		"nil":          nil,
	} {
		t.Run(name, func(t *testing.T) {
			p := dashcontract.Principal{User: &dashauth.UserInfo{Subject: "tester"}, Claims: map[string]any{"tenant_id": claim}}
			_, err := h(context.Background(), struct{}{}, p)
			if err == nil {
				t.Fatalf("a %s tenant claim must refuse, not fall back to DefaultTenantID", name)
			}
		})
	}
}

func TestAClaimBeatsTheConfiguredDefault(t *testing.T) {
	s := memory.New()
	seedAllow(t, s) // one role in t1, none in t2
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	h := overviewStatsHandler(Deps{Engine: eng, DefaultTenantID: "t1"})

	got, err := h(context.Background(), struct{}{}, principalFor("t2"))
	if err != nil {
		t.Fatalf("t2 claim over t1 default: %v", err)
	}
	if got.Roles != 0 {
		t.Errorf("roles = %d, want 0: the claim must win over the default", got.Roles)
	}
}

func TestOverviewStatsCountsEachEntity(t *testing.T) {
	s := memory.New()
	seedAllow(t, s) // one role, one permission, one assignment
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	h := overviewStatsHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}

	if got.Roles != 1 || got.Permissions != 1 || got.Assignments != 1 {
		t.Errorf("counts = %+v, want 1 role, 1 permission, 1 assignment", got)
	}
	if got.Policies != 0 || got.Relations != 0 || got.ResourceTypes != 0 {
		t.Errorf("unseeded counts = %+v, want zero", got)
	}
}

func TestNamespacesListIncludesTheTenantRoot(t *testing.T) {
	s := memory.New()
	seedAllow(t, s) // seeded at the tenant root, namespace ""
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	h := namespacesListHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("namespaces.list: %v", err)
	}

	// The tenant root is a real namespace where things live, and the filter
	// needs it as a selectable option distinct from "all namespaces".
	var hasRoot bool
	for _, ns := range got.Namespaces {
		if ns == "" {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Errorf("namespaces = %q, want the tenant root \"\" present", got.Namespaces)
	}
}

func TestNamespacesListIsSortedAndDeduplicated(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	for i, ns := range []string{"eng/platform", "eng", "eng/platform", "billing"} {
		r := &role.Role{TenantID: "t1", NamespacePath: ns, Name: "R", Slug: fmt.Sprintf("r%d", i)}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("create role in %q: %v", ns, err)
		}
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	h := namespacesListHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("namespaces.list: %v", err)
	}

	want := []string{"", "billing", "eng", "eng/platform"}
	if len(got.Namespaces) != len(want) {
		t.Fatalf("namespaces = %q, want %q", got.Namespaces, want)
	}
	for i := range want {
		if got.Namespaces[i] != want[i] {
			t.Fatalf("namespaces = %q, want %q", got.Namespaces, want)
		}
	}
}

// A leaf namespace where checks run may hold no role, grant or assignment,
// so the check log is the only place it shows up.
func TestNamespacesListIncludesNamespacesOnRecentCheckLogRows(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []*checklog.Entry{
		{TenantID: "t1", NamespacePath: "eng/platform/leaf", SubjectKind: "user", SubjectID: "alice", Action: "read", ResourceType: "document", Decision: "allow", CreatedAt: now},
		// Another tenant's row is not this tenant's namespace.
		{TenantID: "t2", NamespacePath: "billing", SubjectKind: "user", SubjectID: "alice", Action: "read", ResourceType: "document", Decision: "allow", CreatedAt: now},
	}
	for _, e := range rows {
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("create check log: %v", err)
		}
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := namespacesListHandler(Deps{Engine: eng})(ctx, struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("namespaces.list: %v", err)
	}
	if !contains(got.Namespaces, "eng/platform/leaf") {
		t.Errorf("namespaces = %q, want the check log's eng/platform/leaf", got.Namespaces)
	}
	if contains(got.Namespaces, "billing") {
		t.Errorf("namespaces = %q, want none of t2's", got.Namespaces)
	}
}

// Check never validates a namespace, so a check log row can carry a path
// every namespace filter refuses. Listing it would offer a filter option
// that fails when picked.
func TestNamespacesListSkipsInvalidCheckLogNamespaces(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, ns := range []string{"eng/system", "ops/leaf"} {
		e := &checklog.Entry{TenantID: "t1", NamespacePath: ns, SubjectKind: "user", SubjectID: "alice",
			Action: "read", ResourceType: "document", Decision: "allow", CreatedAt: now}
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("create check log: %v", err)
		}
	}
	if validateNamespace("eng/system") == nil {
		t.Fatal("eng/system is valid, so this test proves nothing")
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := namespacesListHandler(Deps{Engine: eng})(ctx, struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("namespaces.list: %v", err)
	}
	if contains(got.Namespaces, "eng/system") {
		t.Errorf("namespaces = %q, want the reserved eng/system left out", got.Namespaces)
	}
	if !contains(got.Namespaces, "ops/leaf") {
		t.Errorf("namespaces = %q, want the valid ops/leaf listed", got.Namespaces)
	}
}

// Stores list newest first and the scan reads the newest namespaceScanLimit
// rows, so a namespace seen only on an older row is not listed.
func TestNamespacesListScansOnlyTheNewestCheckLogRows(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < namespaceScanLimit; i++ {
		e := &checklog.Entry{
			TenantID: "t1", NamespacePath: "hot", SubjectKind: "user", SubjectID: "alice",
			Action: "read", ResourceType: "document", Decision: "allow",
			CreatedAt: now.Add(-time.Duration(i) * time.Second),
		}
		if err := s.CreateCheckLog(ctx, e); err != nil {
			t.Fatalf("create check log: %v", err)
		}
	}
	old := &checklog.Entry{
		TenantID: "t1", NamespacePath: "old", SubjectKind: "user", SubjectID: "alice",
		Action: "read", ResourceType: "document", Decision: "allow",
		CreatedAt: now.Add(-24 * time.Hour),
	}
	if err := s.CreateCheckLog(ctx, old); err != nil {
		t.Fatalf("create check log: %v", err)
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	got, err := namespacesListHandler(Deps{Engine: eng})(ctx, struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("namespaces.list: %v", err)
	}
	if !contains(got.Namespaces, "hot") {
		t.Errorf("namespaces = %q, want hot, on the newest %d rows", got.Namespaces, namespaceScanLimit)
	}
	if contains(got.Namespaces, "old") {
		t.Errorf("namespaces = %q, want no old: it is beyond the newest %d rows", got.Namespaces, namespaceScanLimit)
	}
}
