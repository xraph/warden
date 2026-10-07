package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// The engine checks a grant by joining resource and action with ':', so
// (warden, role:manage) and (warden:role, manage) would be the same grant.
// permissions.create refuses an action with a ':'; a resource keeps its.
func TestPermissionsCreateRefusesAColonInTheAction(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	h := permissionsCreateHandler(Deps{Engine: engineOver(t, s)})

	for _, in := range []PermissionCreateInput{
		{Resource: "warden", Action: "role:manage"},
		{Name: "warden:role:manage", Resource: "warden", Action: "role:manage"},
		{Resource: "doc", Action: ":"},
	} {
		_, err := h(ctx, in, principalFor("t1"))
		var ce *dashcontract.Error
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Fatalf("create %+v: want CodeBadRequest, got %v", in, err)
		}
		want := `action "` + in.Action + `" contains ':': the engine joins resource and action with ':', so an action may not contain one`
		if ce.Message != want {
			t.Errorf("create %+v message\n got: %s\nwant: %s", in, ce.Message, want)
		}
	}
	all, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("a refused create wrote %d permissions", len(all))
	}
}

func TestPermissionsCreateTakesAColonInTheResourceAndTheWildcardAction(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	h := permissionsCreateHandler(Deps{Engine: engineOver(t, s)})

	for _, in := range []PermissionCreateInput{
		{Resource: "warden:role", Action: "manage"},
		{Resource: "warden:role", Action: "*"},
		{Resource: "document", Action: "read"},
	} {
		if _, err := h(ctx, in, principalFor("t1")); err != nil {
			t.Errorf("create %+v: %v", in, err)
		}
	}
}

// A permission stored before the rule, with a ':' in its action, is left
// alone: it lists, reads, checks and deletes as before.
func TestPermissionsAStoredColonActionStillLoadsChecksAndDeletes(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	eng := engineOver(t, s)
	deps := Deps{Engine: eng}
	pm := seedPermission(t, s, "warden:role:manage", "warden", "role:manage")

	list, err := permissionsListHandler(deps)(ctx, PermissionsListInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.list: %v", err)
	}
	if list.Total != 1 || list.Items[0].Action != "role:manage" {
		t.Fatalf("list = %+v, want the stored permission with action role:manage", list.Items)
	}
	detail, err := permissionsDetailHandler(deps)(ctx, PermissionDetailInput{ID: pm.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("permissions.detail: %v", err)
	}
	if detail.Resource != "warden" || detail.Action != "role:manage" {
		t.Errorf("detail = %s / %s, want warden / role:manage", detail.Resource, detail.Action)
	}

	r := seedRoles(t, s, "", "admin")[0]
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		TenantID: "t1", RoleID: r.ID, SubjectKind: "user", SubjectID: "alice",
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	res, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
		Action:   warden.Action{Name: "role:manage"},
		Resource: warden.Resource{Type: "warden", ID: "x"},
		TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("check on the stored grant was denied: %+v", res)
	}

	if err := s.DetachPermission(ctx, "t1", r.ID, permission.Ref{Name: pm.Name}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := permissionsDeleteHandler(deps)(ctx, PermissionDeleteInput{ID: pm.ID.String()}, principalFor("t1")); err != nil {
		t.Fatalf("permissions.delete: %v", err)
	}
	if _, err := s.GetPermission(ctx, "t1", pm.ID); err == nil {
		t.Fatal("the stored permission is still there after delete")
	}
}
