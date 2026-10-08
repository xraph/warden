package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
	"github.com/xraph/forge/extensions/dashboard/contract/transport"
)

// wantPolicies is the intent to (action, resource) table the delegate must
// enforce. It is written out here on purpose, independent of the table in
// authz.go, so a change to either side shows up as a failing test rather
// than as two files that quietly agree.
var wantPolicies = map[string]struct{ action, resource string }{
	"config.detail":               {"read", "warden:config"},
	"overview.stats":              {"read", "warden:overview"},
	"overview.recentChecks":       {"read_audit", "warden:check_log"},
	"checkLogs.list":              {"read_audit", "warden:check_log"},
	"checkLogs.detail":            {"read_audit", "warden:check_log"},
	"namespaces.list":             {"read", "warden:overview"},
	"roles.list":                  {"read", "warden:role"},
	"roles.detail":                {"read", "warden:role"},
	"roles.create":                {"manage", "warden:role"},
	"roles.update":                {"manage", "warden:role"},
	"roles.delete":                {"manage", "warden:role"},
	"roles.attachPermission":      {"manage", "warden:role"},
	"roles.detachPermission":      {"manage", "warden:role"},
	"roles.setPermissions":        {"manage", "warden:role"},
	"permissions.list":            {"read", "warden:permission"},
	"permissions.detail":          {"read", "warden:permission"},
	"permissions.create":          {"manage", "warden:permission"},
	"permissions.update":          {"manage", "warden:permission"},
	"permissions.delete":          {"manage", "warden:permission"},
	"assignments.list":            {"read", "warden:assignment"},
	"assignments.expiring":        {"read", "warden:assignment"},
	"assignments.create":          {"manage", "warden:assignment"},
	"assignments.delete":          {"manage", "warden:assignment"},
	"relations.list":              {"read", "warden:relation"},
	"relations.create":            {"manage", "warden:relation"},
	"relations.delete":            {"manage", "warden:relation"},
	"relations.expand":            {"read", "warden:relation"},
	"resourceTypes.list":          {"read", "warden:resourcetype"},
	"resourceTypes.detail":        {"read", "warden:resourcetype"},
	"resourceTypes.create":        {"manage", "warden:resourcetype"},
	"resourceTypes.update":        {"manage", "warden:resourcetype"},
	"resourceTypes.delete":        {"manage", "warden:resourcetype"},
	"resourceTypes.graph":         {"read", "warden:resourcetype"},
	"policies.list":               {"read", "warden:policy"},
	"policies.detail":             {"read", "warden:policy"},
	"policies.validate":           {"read", "warden:policy"},
	"policies.create":             {"manage", "warden:policy"},
	"policies.update":             {"manage", "warden:policy"},
	"policies.setActive":          {"manage", "warden:policy"},
	"policies.delete":             {"manage", "warden:policy"},
	"maintenance.run":             {"manage", "warden:maintenance"},
	"maintenance.cacheInvalidate": {"manage", "warden:maintenance"},
	"playground.explain":          {"check", "warden:authz"},
	"playground.batchCheck":       {"check", "warden:authz"},
	"subjects.detail":             {"read", "warden:assignment"},
	// The gate checks one grant; the handlers check the other four reads.
	"schema.export": {"read", "warden:role"},
	"schema.plan":   {"read", "warden:role"},
	// The gate checks one grant; the handler checks the other four manages.
	"schema.apply": {"manage", "warden:role"},
}

// grantUser gives subject exactly the named "<resource>:<action>"
// permissions in tenant t1 through a dedicated role.
func grantUser(t *testing.T, s *memory.Store, subject string, perms ...string) {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", Name: "R-" + subject, Slug: "r-" + subject}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	for _, name := range perms {
		res, act := splitPerm(t, name)
		if _, err := s.GetPermissionByName(ctx, "t1", "", name); err != nil {
			if err := s.CreatePermission(ctx, &permission.Permission{
				TenantID: "t1", Name: name, Resource: res, Action: act,
			}); err != nil {
				t.Fatalf("create permission %s: %v", name, err)
			}
		}
		if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: name}); err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: subject,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
}

func splitPerm(t *testing.T, name string) (resource, action string) {
	t.Helper()
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == ':' {
			return name[:i], name[i+1:]
		}
	}
	t.Fatalf("permission %q has no action", name)
	return "", ""
}

func userPrincipal(subject string) dashcontract.Principal {
	return dashcontract.PrincipalFor(&dashauth.UserInfo{Subject: subject})
}

func authorize(t *testing.T, a dashcontract.Warden, p dashcontract.Principal, intent string) (dashcontract.Decision, error) {
	t.Helper()
	return a.Authorize(context.Background(), p, dashcontract.Action{Contributor: contributorName, Intent: intent})
}

func TestEveryIntentIsGatedByTheEngineDelegate(t *testing.T) {
	m := loadManifest(t)
	if len(m.Intents) != len(wantPolicies) {
		t.Fatalf("manifest declares %d intents, the policy table has %d", len(m.Intents), len(wantPolicies))
	}
	for _, in := range m.Intents {
		if in.Requires.Warden != wardenDelegateName {
			t.Errorf("%s: requires.warden = %q, want %q: an intent with no delegate is served to anyone",
				in.Name, in.Requires.Warden, wardenDelegateName)
		}
		if _, ok := wantPolicies[in.Name]; !ok {
			t.Errorf("%s has no entry in the expected policy table", in.Name)
		}
	}
}

func TestManifestFailsValidationWithoutTheDelegate(t *testing.T) {
	m := loadManifest(t)
	if err := loader.Validate(m, dashcontract.NewWardenRegistry()); err == nil {
		t.Fatal("manifest validated against a registry without the delegate; the requires entries are not being checked")
	}
}

func TestDelegateMapsEveryIntentToItsActionAndResource(t *testing.T) {
	for intent, want := range wantPolicies {
		intent, want := intent, want
		t.Run(intent, func(t *testing.T) {
			s := memory.New()
			grantUser(t, s, "granted", want.resource+":"+want.action)
			// Holds every other permission in the table but this one, so a
			// mapping that pointed at a neighbour would still be caught.
			var others []string
			for _, p := range wantPolicies {
				name := p.resource + ":" + p.action
				if name != want.resource+":"+want.action {
					others = append(others, name)
				}
			}
			grantUser(t, s, "others", others...)
			a := newEngineAuthorizer(Deps{Engine: engineOver(t, s), DefaultTenantID: "t1"})

			dec, err := authorize(t, a, userPrincipal("granted"), intent)
			if err != nil || !dec.Allow {
				t.Fatalf("holder of %s:%s refused %s: dec=%+v err=%v", want.resource, want.action, intent, dec, err)
			}
			dec, err = authorize(t, a, userPrincipal("others"), intent)
			if err == nil && dec.Allow {
				t.Fatalf("%s allowed without %s:%s", intent, want.resource, want.action)
			}
			dec, err = authorize(t, a, userPrincipal("nobody"), intent)
			if err == nil && dec.Allow {
				t.Fatalf("%s allowed for a user with no role", intent)
			}
		})
	}
}

func TestDelegateFailsClosed(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "admin", "warden:role:manage")
	eng := engineOver(t, s)

	cases := []struct {
		name string
		deps Deps
		p    dashcontract.Principal
		act  dashcontract.Action
	}{
		{"no user", Deps{Engine: eng, DefaultTenantID: "t1"}, dashcontract.Principal{},
			dashcontract.Action{Contributor: contributorName, Intent: "roles.create"}},
		{"user with empty subject", Deps{Engine: eng, DefaultTenantID: "t1"},
			dashcontract.Principal{User: &dashauth.UserInfo{}},
			dashcontract.Action{Contributor: contributorName, Intent: "roles.create"}},
		{"no tenant", Deps{Engine: eng}, userPrincipal("admin"),
			dashcontract.Action{Contributor: contributorName, Intent: "roles.create"}},
		{"unknown intent", Deps{Engine: eng, DefaultTenantID: "t1"}, userPrincipal("admin"),
			dashcontract.Action{Contributor: contributorName, Intent: "roles.explode"}},
		{"foreign contributor", Deps{Engine: eng, DefaultTenantID: "t1"}, userPrincipal("admin"),
			dashcontract.Action{Contributor: "other", Intent: "roles.create"}},
		{"nil engine", Deps{DefaultTenantID: "t1"}, userPrincipal("admin"),
			dashcontract.Action{Contributor: contributorName, Intent: "roles.create"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := newEngineAuthorizer(tc.deps)
			dec, err := a.Authorize(context.Background(), tc.p, tc.act)
			if err == nil && dec.Allow {
				t.Fatalf("%s was allowed", tc.name)
			}
		})
	}
}

// TestDelegateUsesTheResolvedTenant proves the check runs against the
// caller's tenant. A user who is admin in t2 is nobody in t1.
func TestDelegateUsesTheResolvedTenant(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t2", Name: "Admin", Slug: "admin"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePermission(ctx, &permission.Permission{TenantID: "t2", Name: "warden:role:manage", Resource: "warden:role", Action: "manage"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachPermission(ctx, "t2", r.ID, permission.Ref{Name: "warden:role:manage"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{TenantID: "t2", RoleID: r.ID, SubjectKind: "user", SubjectID: "eve"}); err != nil {
		t.Fatal(err)
	}
	a := newEngineAuthorizer(Deps{Engine: engineOver(t, s), DefaultTenantID: "t1"})
	dec, err := authorize(t, a, userPrincipal("eve"), "roles.create")
	if err == nil && dec.Allow {
		t.Fatal("a t2 admin was allowed to manage roles in t1")
	}
}

// contractServer wires the real Register onto the real transport, so the
// test crosses the same seam a browser does: manifest requires, the warden
// registry, the dispatcher.
func contractServer(t *testing.T, deps Deps) http.Handler {
	t.Helper()
	reg := dashcontract.NewRegistry()
	wreg := dashcontract.NewWardenRegistry()
	d := dispatcher.New(nil)
	if err := Register(d, reg, wreg, deps); err != nil {
		t.Fatalf("register: %v", err)
	}
	return transport.NewHandler(reg, wreg, d, nil)
}

func post(t *testing.T, h http.Handler, user *dashauth.UserInfo, intent string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(dashcontract.Request{
		Envelope: "v1", Kind: dashcontract.KindCommand,
		Contributor: contributorName, Intent: intent, IntentVersion: 1,
		CSRF: "c", IdempotencyKey: "k-" + intent, Payload: raw,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/dashboard/v1", bytes.NewReader(body))
	if user != nil {
		req = req.WithContext(dashauth.WithUser(req.Context(), user))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestTransportRefusesAMutationWithoutTheManagePermission(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "admin", "warden:role:manage")
	grantUser(t, s, "reader", "warden:role:read")
	eng := engineOver(t, s)
	h := contractServer(t, Deps{Engine: eng, DefaultTenantID: "t1"})
	in := RoleCreateInput{Name: "Ops", Slug: "ops"}

	// No user at all: the case the finding is about. A dashboard with auth
	// disabled, or a request that omitted the session cookie.
	if w := post(t, h, nil, "roles.create", in); w.Code != http.StatusForbidden {
		t.Fatalf("anonymous roles.create: status %d, want 403; body %s", w.Code, w.Body)
	}
	// Signed in, but only allowed to read.
	if w := post(t, h, &dashauth.UserInfo{Subject: "reader"}, "roles.create", in); w.Code != http.StatusForbidden {
		t.Fatalf("reader roles.create: status %d, want 403; body %s", w.Code, w.Body)
	}
	if _, err := s.GetRoleBySlug(context.Background(), "t1", "", "ops"); err == nil {
		t.Fatal("a refused roles.create still wrote the role")
	}

	w := post(t, h, &dashauth.UserInfo{Subject: "admin"}, "roles.create", in)
	if w.Code != http.StatusOK {
		t.Fatalf("admin roles.create: status %d, want 200; body %s", w.Code, w.Body)
	}
	if _, err := s.GetRoleBySlug(context.Background(), "t1", "", "ops"); err != nil {
		t.Fatalf("admin roles.create wrote nothing: %v", err)
	}
}

func TestTransportGatesMaintenanceBehindItsOwnPermission(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "roleadmin", "warden:role:manage", "warden:permission:manage")
	grantUser(t, s, "ops", "warden:maintenance:manage")
	h := contractServer(t, Deps{Engine: engineOver(t, s), DefaultTenantID: "t1"})

	if w := post(t, h, &dashauth.UserInfo{Subject: "roleadmin"}, "maintenance.run", struct{}{}); w.Code != http.StatusForbidden {
		t.Fatalf("role admin maintenance.run: status %d, want 403", w.Code)
	}
	if w := post(t, h, nil, "maintenance.cacheInvalidate", CacheInvalidateInput{}); w.Code != http.StatusForbidden {
		t.Fatalf("anonymous maintenance.cacheInvalidate: status %d, want 403", w.Code)
	}
	if w := post(t, h, &dashauth.UserInfo{Subject: "ops"}, "maintenance.run", struct{}{}); w.Code != http.StatusOK {
		t.Fatalf("ops maintenance.run: status %d, want 200; body %s", w.Code, w.Body)
	}
}

func TestTransportGatesQueriesToo(t *testing.T) {
	s := memory.New()
	grantUser(t, s, "reader", "warden:role:read")
	h := contractServer(t, Deps{Engine: engineOver(t, s), DefaultTenantID: "t1"})

	query := func(user *dashauth.UserInfo, intent string) int {
		body, _ := json.Marshal(dashcontract.Request{
			Envelope: "v1", Kind: dashcontract.KindQuery,
			Contributor: contributorName, Intent: intent, IntentVersion: 1,
			Payload: json.RawMessage(`{}`),
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/dashboard/v1", bytes.NewReader(body))
		if user != nil {
			req = req.WithContext(dashauth.WithUser(req.Context(), user))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if got := query(nil, "roles.list"); got != http.StatusForbidden {
		t.Errorf("anonymous roles.list: status %d, want 403", got)
	}
	if got := query(&dashauth.UserInfo{Subject: "reader"}, "roles.list"); got != http.StatusOK {
		t.Errorf("reader roles.list: status %d, want 200", got)
	}
	if got := query(&dashauth.UserInfo{Subject: "reader"}, "permissions.list"); got != http.StatusForbidden {
		t.Errorf("reader permissions.list: status %d, want 403", got)
	}
	if got := query(&dashauth.UserInfo{Subject: "reader"}, "config.detail"); got != http.StatusForbidden {
		t.Errorf("reader config.detail: status %d, want 403", got)
	}
}
