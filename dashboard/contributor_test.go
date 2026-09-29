package dashboard

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

const testBasePath = "/warden-test"

// newTestContributor builds a Contributor over a fresh memory-store-backed
// engine, mounted at testBasePath, the same way extension.go's
// DashboardContributor wires the real one.
func newTestContributor(t *testing.T) *Contributor {
	t.Helper()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return New(NewManifest(eng, nil), eng, nil, testBasePath)
}

// renderPage renders route with a tenant resolved into ctx and returns the
// rendered HTML.
func renderPage(t *testing.T, c *Contributor, route string) string {
	t.Helper()
	ctx := warden.WithTenant(context.Background(), "app1", "t1")
	comp, err := c.RenderPage(ctx, route, contributor.Params{})
	if err != nil {
		t.Fatalf("RenderPage(%q): %v", route, err)
	}
	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		t.Fatalf("Render(%q): %v", route, err)
	}
	return buf.String()
}

// TestDashboardForms_PostToConfiguredBasePath is the fix-round assertion:
// the four forms ported from hard-coded /v1/... paths (role, permission,
// assignment, relation) must post to <basePath>/v1/<entity>, not a bare
// /v1/<entity> that only works when the warden API happens to be mounted
// at the host application's root.
func TestDashboardForms_PostToConfiguredBasePath(t *testing.T) {
	c := newTestContributor(t)

	cases := []struct {
		route  string
		wantHx string
	}{
		{"/roles", `hx-post="` + testBasePath + `/v1/roles"`},
		{"/permissions", `hx-post="` + testBasePath + `/v1/permissions"`},
		{"/assignments", `hx-post="` + testBasePath + `/v1/assignments"`},
		{"/relations", `hx-post="` + testBasePath + `/v1/relations"`},
	}

	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			html := renderPage(t, c, tc.route)
			if !strings.Contains(html, tc.wantHx) {
				t.Fatalf("%s: rendered page does not contain %q\nhtml: %s", tc.route, tc.wantHx, html)
			}
			// And the un-prefixed bare form must not appear: that would
			// mean the base path was dropped somewhere in the chain.
			bareForm := `hx-post="/v1/`
			if strings.Contains(html, bareForm) {
				t.Fatalf("%s: rendered page still contains an un-prefixed hx-post", tc.route)
			}
		})
	}
}

// TestDashboardOverview_CreateDialogsUseBasePath covers the overview
// page's own copies of the four create dialogs (OverviewPage embeds all
// four directly, separately from the per-entity list pages above).
func TestDashboardOverview_CreateDialogsUseBasePath(t *testing.T) {
	c := newTestContributor(t)
	html := renderPage(t, c, "/")

	for _, entity := range []string{"roles", "permissions", "assignments", "relations"} {
		want := `hx-post="` + testBasePath + `/v1/` + entity + `"`
		if !strings.Contains(html, want) {
			t.Errorf("overview page missing %q", want)
		}
	}
}

// TestDashboardRoleDetail_EditFormUsesBasePath covers RoleEditDialog,
// which posts to a per-role URL (PUT) rather than the collection URL the
// create dialogs use.
func TestDashboardRoleDetail_EditFormUsesBasePath(t *testing.T) {
	c := newTestContributor(t)
	ctx := warden.WithTenant(context.Background(), "app1", "t1")

	r := &role.Role{
		ID:        id.NewRoleID(),
		TenantID:  "t1",
		Name:      "Editor",
		Slug:      "editor",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := c.engine.Store().CreateRole(ctx, r); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	comp, err := c.RenderPage(ctx, "/roles/detail", contributor.Params{
		PathParams: map[string]string{"id": r.ID.String()},
	})
	if err != nil {
		t.Fatalf("RenderPage(/roles/detail): %v", err)
	}
	var buf bytes.Buffer
	if err := comp.Render(ctx, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	wantPrefix := testBasePath + "/v1/roles/" + r.ID.String()
	if !strings.Contains(out, wantPrefix) {
		t.Fatalf("role detail page's edit form does not reference %q\nhtml: %s", wantPrefix, out)
	}
}

// TestDashboardDeleteDialogs_UseBasePath covers the ConfirmDialog behind each
// row's delete button. The forms were base-pathed in an earlier round, but
// these endpoints kept a bare /v1/... prefix, so on any host that mounts
// warden below the root the confirm button sent the request to the wrong
// place.
func TestDashboardDeleteDialogs_UseBasePath(t *testing.T) {
	c := newTestContributor(t)
	ctx := warden.WithTenant(context.Background(), "app1", "t1")
	s := c.engine.Store()

	r := &role.Role{ID: id.NewRoleID(), TenantID: "t1", Name: "Editor", Slug: "editor", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	pm := &permission.Permission{ID: id.NewPermissionID(), TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreatePermission(ctx, pm); err != nil {
		t.Fatalf("seed permission: %v", err)
	}
	a := &assignment.Assignment{ID: id.NewAssignmentID(), TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "u1", CreatedAt: time.Now()}
	if err := s.CreateAssignment(ctx, a); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	tp := &relation.Tuple{ID: id.NewRelationID(), TenantID: "t1", ObjectType: "doc", ObjectID: "1", Relation: "viewer", SubjectType: "user", SubjectID: "u1", CreatedAt: time.Now()}
	if err := s.CreateRelation(ctx, tp); err != nil {
		t.Fatalf("seed relation: %v", err)
	}

	cases := []struct {
		name  string
		route string
		want  string
	}{
		{"roles list", "/roles", `hx-delete="` + testBasePath + `/v1/roles/` + r.ID.String() + `"`},
		{"permissions list", "/permissions", `hx-delete="` + testBasePath + `/v1/permissions/` + pm.ID.String() + `"`},
		{"assignments list", "/assignments", `hx-delete="` + testBasePath + `/v1/assignments/` + a.ID.String() + `"`},
		{"relations list", "/relations", testBasePath + `/v1/relations/delete"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html := renderPage(t, c, tc.route)
			if !strings.Contains(html, tc.want) {
				t.Fatalf("%s: rendered page does not contain %q\nhtml: %s", tc.name, tc.want, html)
			}
			for _, bare := range []string{`hx-delete="/v1/`, `hx-post="/v1/`} {
				if strings.Contains(html, bare) {
					t.Fatalf("%s: rendered page still contains an un-prefixed %s", tc.name, bare)
				}
			}
		})
	}

	t.Run("role detail", func(t *testing.T) {
		comp, err := c.RenderPage(ctx, "/roles/detail", contributor.Params{PathParams: map[string]string{"id": r.ID.String()}})
		if err != nil {
			t.Fatalf("RenderPage: %v", err)
		}
		var buf bytes.Buffer
		if err := comp.Render(ctx, &buf); err != nil {
			t.Fatalf("Render: %v", err)
		}
		html := buf.String()
		want := `hx-delete="` + testBasePath + `/v1/roles/` + r.ID.String() + `"`
		if !strings.Contains(html, want) {
			t.Fatalf("role detail does not contain %q\nhtml: %s", want, html)
		}
		if strings.Contains(html, `hx-delete="/v1/`) {
			t.Fatal("role detail still contains an un-prefixed hx-delete")
		}
	})
}
