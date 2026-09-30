package dsl

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// seedSystemWorld stores, in tenant t1, a system permission and a system
// role that holds it, next to an ordinary permission and role, and returns
// the tenant exported as source. The export plans empty, so each case below
// is one edit away from a no-op.
func seedSystemWorld(t *testing.T) (*warden.Engine, *memory.Store, string) {
	t.Helper()
	ctx := context.Background()
	eng, s := newTestEngine(t)
	for _, p := range []*permission.Permission{
		{TenantID: "t1", Name: "sys:read", Resource: "sys", Action: "read", IsSystem: true},
		{TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"},
		{TenantID: "t1", Name: "doc:write", Resource: "doc", Action: "write"},
	} {
		if err := s.CreatePermission(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	admin := &role.Role{TenantID: "t1", Name: "Admin", Slug: "admin", IsSystem: true}
	viewer := &role.Role{TenantID: "t1", Name: "Viewer", Slug: "viewer"}
	for _, r := range []*role.Role{admin, viewer} {
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetRolePermissions(ctx, "t1", admin.ID, []permission.Ref{{Name: "sys:read"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePermissions(ctx, "t1", viewer.ID, []permission.Ref{{Name: "doc:read"}}); err != nil {
		t.Fatal(err)
	}
	prog, err := BuildProgram(ctx, eng, ExportOptions{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	return eng, s, Format(prog)
}

// snapshotT1 captures tenant t1's roles, grants, permissions and tuples in
// full, so a test can prove an apply wrote nothing.
func snapshotT1(t *testing.T, s *memory.Store) string {
	t.Helper()
	ctx := context.Background()
	roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: "t1", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	grants := map[string][]string{}
	for _, r := range roles {
		ps, gErr := s.ListRolePermissions(ctx, "t1", r.ID)
		if gErr != nil {
			t.Fatal(gErr)
		}
		for _, p := range ps {
			grants[r.Slug] = append(grants[r.Slug], p.NamespacePath+"/"+p.Name)
		}
		sort.Strings(grants[r.Slug])
	}
	perms, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: "t1", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: "t1", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]any{roles, grants, perms, tuples})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// lineOf returns the 1-based line of the first line of src that starts with
// prefix.
func lineOf(t *testing.T, src, prefix string) int {
	t.Helper()
	for i, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, prefix) {
			return i + 1
		}
	}
	t.Fatalf("no line starts with %q in:\n%s", prefix, src)
	return 0
}

// replaceOnce edits src and fails when old is not in it exactly once.
func replaceOnce(t *testing.T, src, old, new string) string {
	t.Helper()
	if n := strings.Count(src, old); n != 1 {
		t.Fatalf("%q occurs %d times in:\n%s", old, n, src)
	}
	return strings.Replace(src, old, new, 1)
}

func TestApply_ProtectSystemRefusesEveryChangeToASystemEntity(t *testing.T) {
	_, _, exported := seedSystemWorld(t)

	for _, tc := range []struct {
		name  string
		edit  func(t *testing.T, src string) string
		prune bool
		// at is the prefix of the line the diagnostic stands on.
		at, want string
	}{
		{
			name: "an update to a system permission",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "permission \"sys:read\" {\n", "permission \"sys:read\" {\n    description = \"renamed\"\n")
			},
			at:   `permission "sys:read"`,
			want: `"sys:read" is a system permission and cannot be changed or deleted`,
		},
		{
			name: "an update to a system role",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, `name = "Admin"`, `name = "Owner"`)
			},
			at:   "role admin",
			want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "a change to a system role's grants",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, `grants = ["sys:read"]`, `grants = ["sys:read", "doc:write"]`)
			},
			at:   "role admin",
			want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "source that clears is_system on a role",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "role admin {\n    name = \"Admin\"\n    is_system = true\n", "role admin {\n    name = \"Admin\"\n")
			},
			at:   "role admin",
			want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "source that clears is_system on a permission",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "    is_system = true\n}\n\nrole", "}\n\nrole")
			},
			at:   `permission "sys:read"`,
			want: `"sys:read" is a system permission and cannot be changed or deleted`,
		},
		{
			name: "source that sets is_system on a role",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, "role viewer {\n    name = \"Viewer\"\n", "role viewer {\n    name = \"Viewer\"\n    is_system = true\n")
			},
			at:   "role viewer",
			want: `"viewer" is not a system role, and source cannot make it one`,
		},
		{
			name: "source that sets is_system on a permission",
			edit: func(t *testing.T, src string) string {
				return replaceOnce(t, src, `permission "doc:read" (doc : read)`, "permission \"doc:read\" {\n    resource = doc\n    action = read\n    is_system = true\n}")
			},
			at:   `permission "doc:read"`,
			want: `"doc:read" is not a system permission, and source cannot make it one`,
		},
		{
			name: "creating a system role",
			edit: func(t *testing.T, src string) string {
				return src + "\nrole root {\n    is_system = true\n}\n"
			},
			at:   "role root",
			want: `"root" cannot be created as a system role`,
		},
		{
			name: "creating a system permission",
			edit: func(t *testing.T, src string) string {
				return src + "\npermission \"sys:write\" {\n    resource = sys\n    action = write\n    is_system = true\n}\n"
			},
			at:   `permission "sys:write"`,
			want: `"sys:write" cannot be created as a system permission`,
		},
		{
			name: "pruning a system permission",
			edit: func(t *testing.T, src string) string {
				// The system role stops granting it too, or the grant
				// would be refused first as unknown.
				src = replaceOnce(t, src, `grants = ["sys:read"]`, `grants = []`)
				start := strings.Index(src, "permission \"sys:read\" {")
				end := start + strings.Index(src[start:], "}\n") + 2
				return src[:start] + src[end:]
			},
			prune: true,
			// Nothing declares it, so the refusal stands where the source
			// first covers the root.
			at:   "permission ",
			want: `"sys:read" is a system permission and cannot be changed or deleted, and prune would delete it`,
		},
		{
			name: "pruning a system role",
			edit: func(t *testing.T, src string) string {
				start := strings.Index(src, "role admin {")
				end := start + strings.Index(src[start:], "}\n") + 2
				return src[:start] + src[end:]
			},
			prune: true,
			at:    "permission ",
			want:  `"admin" is a system role and cannot be changed or deleted, and prune would delete it`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.edit(t, exported)
			prog := mustParse(t, src)
			line := lineOf(t, src, tc.at)
			for _, dry := range []bool{true, false} {
				eng, s, _ := seedSystemWorld(t)
				before := snapshotT1(t, s)
				res, err := Apply(context.Background(), eng, prog, ApplyOptions{
					TenantID: "t1", DryRun: dry, Prune: tc.prune, ProtectSystem: true,
				})
				var derr *DiagnosticError
				if !errors.As(err, &derr) {
					t.Fatalf("dry=%v: err = %v (result %+v), want a DiagnosticError\n%s", dry, err, res, src)
				}
				if len(derr.Diags) != 1 || derr.Diags[0].Msg != tc.want || derr.Diags[0].Pos.Line != line {
					t.Errorf("dry=%v: diagnostics = %v, want %q on line %d", dry, derr.Diags, tc.want, line)
				}
				if res != nil && len(res.Created)+len(res.Updated)+len(res.Deleted) != 0 {
					t.Errorf("dry=%v: a refused apply reports writes: %+v", dry, res)
				}
				if after := snapshotT1(t, s); after != before {
					t.Errorf("dry=%v: a refused apply changed the store", dry)
				}
			}
		})
	}
}

// TestApply_ProtectSystemLetsTheUnchangedSystemEntitiesThrough checks the
// guard refuses changes, not the mere presence of system entities: the
// export and an edit elsewhere still apply.
func TestApply_ProtectSystemLetsTheUnchangedSystemEntitiesThrough(t *testing.T) {
	eng, _, exported := seedSystemWorld(t)
	for _, prune := range []bool{false, true} {
		res, err := Apply(context.Background(), eng, mustParse(t, exported), ApplyOptions{
			TenantID: "t1", DryRun: true, Prune: prune, ProtectSystem: true,
		})
		if err != nil || len(res.Created)+len(res.Updated)+len(res.Deleted) != 0 {
			t.Fatalf("prune=%v: the unedited export does not plan empty: %v %+v\n%s", prune, err, res, exported)
		}
	}
	edited := replaceOnce(t, exported, `name = "Viewer"`, `name = "Reader"`)
	res, err := Apply(context.Background(), eng, mustParse(t, edited), ApplyOptions{TenantID: "t1", ProtectSystem: true})
	if err != nil || !reflect.DeepEqual(res.Updated, []string{"~ role//viewer (name)"}) {
		t.Fatalf("an edit to an ordinary role: %v %+v", err, res)
	}
}

// TestApply_WithoutProtectSystemKeepsTodaysBehaviour pins the CLI and the
// declarative loader: they own the system entities they declare, so an
// update applies, and prune skips a system role.
func TestApply_WithoutProtectSystemKeepsTodaysBehaviour(t *testing.T) {
	ctx := context.Background()
	eng, s, exported := seedSystemWorld(t)
	edited := replaceOnce(t, exported, `name = "Admin"`, `name = "Owner"`)
	if _, err := Apply(ctx, eng, mustParse(t, edited), ApplyOptions{TenantID: "t1"}); err != nil {
		t.Fatalf("an unprotected apply refused a system role update: %v", err)
	}
	r, err := s.GetRoleBySlug(ctx, "t1", "", "admin")
	if err != nil || r.Name != "Owner" {
		t.Fatalf("the update was not written: %v %+v", err, r)
	}

	start := strings.Index(edited, "role admin {")
	end := start + strings.Index(edited[start:], "}\n") + 2
	res, err := Apply(ctx, eng, mustParse(t, edited[:start]+edited[end:]), ApplyOptions{TenantID: "t1", Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRoleBySlug(ctx, "t1", "", "admin"); err != nil {
		t.Errorf("an unprotected prune deleted the system role: %v (deleted %v)", err, res.Deleted)
	}
}

// TestApply_PruningAGrantedPermissionPlansWhatItApplies is the probe that
// found a false divergence: a role holding a grant on a permission the same
// apply prunes planned `~ (grants)`, but the real apply found the grant
// already gone with the permission and wrote nothing for the role.
func TestApply_PruningAGrantedPermissionPlansWhatItApplies(t *testing.T) {
	ctx := context.Background()
	eng, s, exported := seedSystemWorld(t)
	// viewer holds doc:read. The source drops doc:read, and viewer's
	// grants with it, and prunes.
	src := replaceOnce(t, exported, "permission \"doc:read\" (doc : read)\n", "")
	src = replaceOnce(t, src, `grants = ["doc:read"]`, `grants = []`)
	prog := mustParse(t, src)

	plan, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1", DryRun: true, Prune: true, ProtectSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(ctx, eng, prog, ApplyOptions{TenantID: "t1", Prune: true, ProtectSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, got) {
		t.Errorf("the plan and the apply differ:\nplan  %+v\napply %+v", plan, got)
	}
	if !reflect.DeepEqual(got.Deleted, []string{"- permission//doc:read"}) || len(got.Updated) != 0 {
		t.Errorf("result = %+v, want only the permission deleted", got)
	}
	if _, err := s.GetPermissionByName(ctx, "t1", "", "doc:read"); err == nil {
		t.Error("the pruned permission survived")
	}
}

func TestResolve_RefusesADuplicateRelationTupleAtTheSecondLine(t *testing.T) {
	src := "warden config 1\n\nrelation doc:readme viewer = user:alice\nrelation doc:readme viewer = group:eng#member\nrelation doc:readme viewer = user:alice\n\nnamespace \"eng\" {\n    relation doc:readme viewer = user:alice\n}\n"
	diags := Resolve(mustParse(t, src))
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %v, want exactly the repeated root line (the eng tuple is another row)", diags)
	}
	want := "relation doc:readme viewer = user:alice already declared at test.warden:3:1"
	if diags[0].Msg != want || diags[0].Pos.Line != 5 || diags[0].Pos.Col != 1 {
		t.Errorf("diagnostic = %s, want %q at 5:1", diags[0], want)
	}
}
