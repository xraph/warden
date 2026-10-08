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

// A block that sets only one of resource and action takes the other from
// the name, and is refused when the name does not hold the one it set, so
// the block never grants something its name does not say.
func TestParse_APermissionBlockWithOneFieldTakesTheOtherFromTheName(t *testing.T) {
	taken := []struct {
		name, body, resource, action string
	}{
		{"resource only", `resource = "warden:role"`, "warden:role", "manage"},
		{"resource only, shorter", `resource = "warden"`, "warden", "role:manage"},
		{"action only", `action = manage`, "warden:role", "manage"},
		{"action only, longer", `action = "role:manage"`, "warden", "role:manage"},
		{"neither", `description = "Manage roles"`, "warden:role", "manage"},
	}
	for _, tc := range taken {
		t.Run(tc.name, func(t *testing.T) {
			prog := mustParse(t, "warden config 1\npermission \"warden:role:manage\" {\n    "+tc.body+"\n}\n")
			p := prog.Permissions[0]
			if p.Resource != tc.resource || p.Action != tc.action {
				t.Errorf("resource %q action %q, want %q %q", p.Resource, p.Action, tc.resource, tc.action)
			}
		})
	}

	refused := []struct {
		name, body, want string
	}{
		{
			"resource the name does not start with",
			`resource = "other"`,
			`test.warden:2:1: permission "warden:role:manage" sets resource "other" and no action, and its name does not start with "other:", so the action cannot be taken from the name; set action too`,
		},
		{
			"action the name does not end with",
			`action = read`,
			`test.warden:2:1: permission "warden:role:manage" sets action "read" and no resource, and its name does not end with ":read", so the resource cannot be taken from the name; set resource too`,
		},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			prog, errs := Parse("test.warden", []byte("warden config 1\npermission \"warden:role:manage\" {\n    "+tc.body+"\n}\n"))
			if len(errs) != 1 || errs[0].String() != tc.want {
				t.Fatalf("errs = %v\nwant [%s]", errs, tc.want)
			}
			// An apply that runs despite the parse diagnostic, as a
			// DeclarativeOnStart load does, is refused and writes nothing.
			s := memory.New()
			if _, err := Apply(context.Background(), engineOverStore(t, s), prog, ApplyOptions{TenantID: "t1"}); err == nil {
				t.Error("apply of the refused block succeeded")
			}
			if n := permissionCount(t, s); n != 0 {
				t.Errorf("stored %d permissions, want 0", n)
			}
		})
	}
}

// The legacy carve-out holds only when resource and action are both
// unchanged: moving a stored ':' action to another resource changes the
// grant, so it is refused.
func TestApply_AStoredColonActionCannotMoveToAnotherResource(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	seedColonAction(t, s)
	src := "warden config 1\npermission \"warden:role:manage\" (other : \"role:manage\")\n"
	planErr, applyErr := applyBoth(t, s, src, false)
	want := `test.warden:2:1: permission "warden:role:manage": action "role:manage" contains ':': the engine joins resource and action with ':', so an action may not contain one`
	for name, err := range map[string]error{"plan": planErr, "apply": applyErr} {
		if err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", name, err, want)
		}
	}
	got, err := s.GetPermissionByName(ctx, "t1", "", "warden:role:manage")
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource != "warden" || got.Action != "role:manage" {
		t.Errorf("stored %s / %s, want warden / role:manage untouched", got.Resource, got.Action)
	}
}

func TestWarnings_ReportAColonAction(t *testing.T) {
	prog := mustParse(t, "warden config 1\npermission \"doc:read\" (doc : read)\npermission \"warden:role:manage\" (\"warden\" : \"role:manage\")\n")
	ws := Warnings(prog)
	want := `test.warden:3:1: permission "warden:role:manage" has action "role:manage", which contains ':'; the engine joins resource and action with ':', so apply refuses it unless the store already holds this permission with exactly this resource and action`
	if len(ws) != 1 || ws[0].String() != want {
		t.Fatalf("warnings = %v\nwant [%s]", ws, want)
	}
	if errs := Resolve(prog); len(errs) != 0 {
		t.Errorf("resolve reported %v; a ':' action is a warning, not an error", errs)
	}
}

// A block that names resource or action with a value that is not a name
// (action = 123) leaves that field empty rather than taking it from the
// permission's name, so the parse diagnostic is never the only refusal:
// Resolve refuses the declaration too, and an apply that runs despite the
// parse diagnostic (a DeclarativeOnStart load) writes nothing.
func TestParse_APermissionBlockWithAMalformedFieldTakesNothingFromTheName(t *testing.T) {
	cases := []struct {
		name, body       string
		resource, action string
	}{
		{"resource set, action malformed", "resource = \"warden:role\"\n    action = 123", "warden:role", ""},
		{"action set, resource malformed", "resource = 123\n    action = manage", "", "manage"},
		{"action malformed alone", "action = 123", "warden:role", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, errs := Parse("test.warden", []byte("warden config 1\npermission \"warden:role:manage\" {\n    "+tc.body+"\n}\n"))
			if len(errs) == 0 {
				t.Fatal("parse accepted a malformed field")
			}
			p := prog.Permissions[0]
			if p.Resource != tc.resource || p.Action != tc.action {
				t.Errorf("resource %q action %q, want %q %q", p.Resource, p.Action, tc.resource, tc.action)
			}
			if rerrs := Resolve(prog); len(rerrs) == 0 {
				t.Error("resolve accepted the declaration")
			}
			s := memory.New()
			if _, err := Apply(context.Background(), engineOverStore(t, s), prog, ApplyOptions{TenantID: "t1"}); err == nil {
				t.Error("apply of the malformed block succeeded")
			}
			if n := permissionCount(t, s); n != 0 {
				t.Errorf("stored %d permissions, want 0", n)
			}
		})
	}
}
