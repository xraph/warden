package dsl

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/store/memory"
)

func permissionCount(t *testing.T, s *memory.Store) int {
	t.Helper()
	rows, err := s.ListPermissions(context.Background(), &permission.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func seedColonAction(t *testing.T, s *memory.Store) {
	t.Helper()
	pm := &permission.Permission{TenantID: "t1", Name: "warden:role:manage", Resource: "warden", Action: "role:manage"}
	if err := s.CreatePermission(context.Background(), pm); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// The engine checks a grant by joining resource and action with ':', so a
// source that would write an action with a ':' is refused at plan, and a
// real apply writes nothing: not the permission and not the role beside it.
func TestApply_AColonInAPermissionActionIsRefusedAtPlan(t *testing.T) {
	const msg = `permission "warden:role:manage": action "role:manage" contains ':': the engine joins resource and action with ':', so an action may not contain one`
	for _, tc := range []struct {
		name, decl, want string
	}{
		{
			"shorthand with a quoted action",
			`permission "warden:role:manage" ("warden" : "role:manage")`,
			"test.warden:2:1: " + msg,
		},
		{
			"block with a quoted action",
			"permission \"warden:role:manage\" {\n    resource = \"warden\"\n    action = \"role:manage\"\n}",
			"test.warden:2:1: " + msg,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			src := "warden config 1\n" + tc.decl + "\nrole admin {\n    name = \"Admin\"\n}\n"
			planErr, applyErr := applyBoth(t, s, src, false)
			for name, err := range map[string]error{"plan": planErr, "apply": applyErr} {
				var derr *DiagnosticError
				if !errors.As(err, &derr) {
					t.Fatalf("%s: err = %v, want a DiagnosticError", name, err)
				}
				if err.Error() != tc.want {
					t.Errorf("%s:\n got %s\nwant %s", name, err.Error(), tc.want)
				}
			}
			if n := permissionCount(t, s); n != 0 {
				t.Errorf("stored %d permissions, want 0", n)
			}
			if _, err := s.GetRoleBySlug(context.Background(), "t1", "", "admin"); err == nil {
				t.Error("the refused apply wrote the role")
			}
		})
	}
}

// A permission written as its name alone splits at the last ':', because a
// resource may hold one and an action may not: "warden:role:manage" is the
// resource warden:role and the action manage.
func TestParse_ANamedPermissionSplitsAtTheLastColon(t *testing.T) {
	prog := mustParse(t, "warden config 1\npermission \"warden:role:manage\"\npermission \"warden:*\"\npermission \"*:*\"\n")
	want := [][2]string{{"warden:role", "manage"}, {"warden", "*"}, {"*", "*"}}
	for i, p := range prog.Permissions {
		if p.Resource != want[i][0] || p.Action != want[i][1] {
			t.Errorf("%s: resource %q action %q, want %q %q", p.Name, p.Resource, p.Action, want[i][0], want[i][1])
		}
	}

	s := memory.New()
	planErr, applyErr := applyBoth(t, s, "warden config 1\npermission \"warden:role:manage\"\n", false)
	if planErr != nil || applyErr != nil {
		t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
	}
	got, err := s.GetPermissionByName(context.Background(), "t1", "", "warden:role:manage")
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource != "warden:role" || got.Action != "manage" {
		t.Errorf("stored resource %q action %q, want warden:role manage", got.Resource, got.Action)
	}
}

// A permission stored before the rule, with a ':' in its action, is left
// alone: exporting and applying it back is a no-op, a description change
// applies, prune deletes it, and only a change to a new ':' action is
// refused.
func TestApply_AStoredColonActionIsLeftAlone(t *testing.T) {
	ctx := context.Background()

	t.Run("export and apply back is a no-op", func(t *testing.T) {
		s := memory.New()
		seedColonAction(t, s)
		prog, err := BuildProgram(ctx, engineOverStore(t, s), ExportOptions{TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		src := Format(prog)
		eng := engineOverStore(t, s)
		for _, dry := range []bool{true, false} {
			res, err := Apply(ctx, eng, mustParse(t, src), ApplyOptions{TenantID: "t1", DryRun: dry, Prune: true})
			if err != nil {
				t.Fatalf("dry run %v: %v\nsource:\n%s", dry, err, src)
			}
			if len(res.Created)+len(res.Updated)+len(res.Deleted) != 0 {
				t.Errorf("dry run %v: %+v, want no change", dry, res)
			}
		}
	})

	t.Run("a description change applies and keeps the action", func(t *testing.T) {
		s := memory.New()
		seedColonAction(t, s)
		src := "warden config 1\npermission \"warden:role:manage\" {\n    resource = \"warden\"\n    action = \"role:manage\"\n    description = \"Manage roles\"\n}\n"
		planErr, applyErr := applyBoth(t, s, src, false)
		if planErr != nil || applyErr != nil {
			t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
		}
		got, err := s.GetPermissionByName(ctx, "t1", "", "warden:role:manage")
		if err != nil {
			t.Fatal(err)
		}
		if got.Description != "Manage roles" || got.Action != "role:manage" {
			t.Errorf("stored %+v, want the new description and action role:manage", got)
		}
	})

	t.Run("prune deletes it", func(t *testing.T) {
		s := memory.New()
		seedColonAction(t, s)
		planErr, applyErr := applyBoth(t, s, "warden config 1\npermission \"doc:read\" (doc : read)\n", true)
		if planErr != nil || applyErr != nil {
			t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
		}
		if _, err := s.GetPermissionByName(ctx, "t1", "", "warden:role:manage"); err == nil {
			t.Error("prune left the stored permission")
		}
	})

	t.Run("a change to another ':' action is refused", func(t *testing.T) {
		s := memory.New()
		seedColonAction(t, s)
		src := "warden config 1\npermission \"warden:role:manage\" (\"warden\" : \"role:admin\")\n"
		planErr, applyErr := applyBoth(t, s, src, false)
		want := `test.warden:2:1: permission "warden:role:manage": action "role:admin" contains ':': the engine joins resource and action with ':', so an action may not contain one`
		for name, err := range map[string]error{"plan": planErr, "apply": applyErr} {
			if err == nil || err.Error() != want {
				t.Errorf("%s:\n got %v\nwant %s", name, err, want)
			}
		}
		got, err := s.GetPermissionByName(ctx, "t1", "", "warden:role:manage")
		if err != nil {
			t.Fatal(err)
		}
		if got.Action != "role:manage" {
			t.Errorf("stored action %q, want role:manage untouched", got.Action)
		}
	})
}
