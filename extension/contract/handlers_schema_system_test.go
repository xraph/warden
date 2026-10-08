package contract

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedSystemSchema stores a system permission and a system role that holds
// it, next to an ordinary permission and role that holds it, in tenant t1.
func seedSystemSchema(t *testing.T) *memory.Store {
	t.Helper()
	ctx := context.Background()
	s := memory.New()
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
	return s
}

// cut removes the block that starts with head, through its closing brace.
func cut(t *testing.T, src, head string) string {
	t.Helper()
	start := strings.Index(src, head)
	if start < 0 {
		t.Fatalf("no %q in:\n%s", head, src)
	}
	end := start + strings.Index(src[start:], "}\n") + 2
	return src[:start] + src[end:]
}

func swap(t *testing.T, src, old, repl string) string {
	t.Helper()
	if n := strings.Count(src, old); n != 1 {
		t.Fatalf("%q occurs %d times in:\n%s", old, n, src)
	}
	return strings.Replace(src, old, repl, 1)
}

func firstLineWith(t *testing.T, src, prefix string) int {
	t.Helper()
	for i, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, prefix) {
			return i + 1
		}
	}
	t.Fatalf("no line starts with %q in:\n%s", prefix, src)
	return 0
}

// TestSchemaRefusesEveryChangeToASystemEntity is the security fix: no store
// checks IsSystem, so schema.plan and schema.apply hold the same line the
// role and permission pages hold through immutable.go. Each case is one
// edit of the tenant's own export.
func TestSchemaRefusesEveryChangeToASystemEntity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(t *testing.T, src string) string
		prune bool
		at    string
		want  string
	}{
		{
			name: "an update to a system role",
			edit: func(t *testing.T, src string) string { return swap(t, src, `name = "Admin"`, `name = "Owner"`) },
			at:   "role admin", want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "a change to a system role's grants",
			edit: func(t *testing.T, src string) string {
				return swap(t, src, `grants = ["sys:read"]`, `grants = ["sys:read", "doc:write"]`)
			},
			at: "role admin", want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "an update to a system permission",
			edit: func(t *testing.T, src string) string {
				return swap(t, src, "permission \"sys:read\" {\n", "permission \"sys:read\" {\n    description = \"renamed\"\n")
			},
			at: `permission "sys:read"`, want: `"sys:read" is a system permission and cannot be changed or deleted`,
		},
		{
			name: "source that clears is_system",
			edit: func(t *testing.T, src string) string {
				return swap(t, src, "role admin {\n    name = \"Admin\"\n    is_system = true\n", "role admin {\n    name = \"Admin\"\n")
			},
			at: "role admin", want: `"admin" is a system role and cannot be changed or deleted`,
		},
		{
			name: "source that sets is_system",
			edit: func(t *testing.T, src string) string {
				return swap(t, src, "role viewer {\n    name = \"Viewer\"\n", "role viewer {\n    name = \"Viewer\"\n    is_system = true\n")
			},
			at: "role viewer", want: `"viewer" is not a system role, and source cannot make it one`,
		},
		{
			name: "creating a system role",
			edit: func(_ *testing.T, src string) string { return src + "\nrole root {\n    is_system = true\n}\n" },
			at:   "role root", want: `"root" cannot be created as a system role`,
		},
		{
			name: "creating a system permission",
			edit: func(_ *testing.T, src string) string {
				return src + "\npermission \"sys:write\" {\n    resource = sys\n    action = write\n    is_system = true\n}\n"
			},
			at: `permission "sys:write"`, want: `"sys:write" cannot be created as a system permission`,
		},
		{
			name: "pruning a system permission",
			edit: func(t *testing.T, src string) string {
				return cut(t, swap(t, src, `grants = ["sys:read"]`, `grants = []`), "permission \"sys:read\" {")
			},
			prune: true,
			at:    "permission ", want: `"sys:read" is a system permission and cannot be changed or deleted, and prune would delete it`,
		},
		{
			name:  "pruning a system role",
			edit:  func(t *testing.T, src string) string { return cut(t, src, "role admin {") },
			prune: true,
			at:    "permission ", want: `"admin" is a system role and cannot be changed or deleted, and prune would delete it`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := seedSystemSchema(t)
			h := newSchemaHarness(t, s)
			exported := h.export(SchemaExportInput{})
			if clean := h.plan(exported.Source, tc.prune); !clean.Valid || len(clean.Created)+len(clean.Updated)+len(clean.Deleted) != 0 {
				t.Fatalf("setup: the unedited export does not plan empty: %+v\n%s", clean, exported.Source)
			}
			src := tc.edit(t, exported.Source)
			line := firstLineWith(t, src, tc.at)
			before := storeSnapshot(t, s)

			plan := h.plan(src, tc.prune)
			if plan.Valid || len(plan.Diagnostics) != 1 {
				t.Fatalf("schema.plan: valid=%v diagnostics %+v, want one refusal\n%s", plan.Valid, plan.Diagnostics, src)
			}
			if d := plan.Diagnostics[0]; d.Message != tc.want || d.Line != line {
				t.Errorf("schema.plan: diagnostic %+v, want %q on line %d", d, tc.want, line)
			}

			// There is no valid digest to send, so try the obvious ones.
			for _, digest := range []string{"", "deadbeef", plan.Digest} {
				_, err := h.applyRaw(src, tc.prune, digest)
				ce := refusal(t, err, dashcontract.CodeBadRequest)
				if !strings.Contains(ce.Message, tc.want) {
					t.Errorf("schema.apply: message %q, want it to carry %q", ce.Message, tc.want)
				}
			}
			if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
				t.Error("a refused apply changed the store")
			}
		})
	}
}

// TestSchemaApplyOfAPrunedGrantDoesNotDiverge is the first probe: a role
// that holds a grant on a permission the same apply prunes used to plan
// `~ (grants)` and apply as a no-op, reporting diverged with nothing else
// writing.
func TestSchemaApplyOfAPrunedGrantDoesNotDiverge(t *testing.T) {
	s := seedSystemSchema(t)
	h := newSchemaHarness(t, s)
	src := h.export(SchemaExportInput{}).Source
	src = swap(t, src, "permission \"doc:read\" (doc : read)\n", "")
	src = swap(t, src, `grants = ["doc:read"]`, `grants = []`)

	plan, got := h.apply(src, true)
	if got.Diverged {
		t.Errorf("diverged with no concurrent change: plan %+v, apply %+v", plan, got)
	}
	if !reflect.DeepEqual(plan.Updated, got.Updated) || !reflect.DeepEqual(plan.Deleted, got.Deleted) {
		t.Errorf("plan %+v, apply %+v", plan, got)
	}
	if !reflect.DeepEqual(got.Deleted, []string{"- permission//doc:read"}) || len(got.Updated) != 0 {
		t.Errorf("result = %+v, want only the permission deleted", got)
	}
}

// TestSchemaApplyOfARelationLineDoesNotDivergeAndARepeatIsRefused is the
// second probe: a relation line written twice planned two creations and
// applied one.
func TestSchemaApplyOfARelationLineDoesNotDivergeAndARepeatIsRefused(t *testing.T) {
	s := seedSystemSchema(t)
	h := newSchemaHarness(t, s)
	base := h.export(SchemaExportInput{}).Source
	const line = "relation doc:readme viewer = user:alice\n"

	repeated := base + "\n" + line + line
	before := storeSnapshot(t, s)
	plan := h.plan(repeated, false)
	want := "relation doc:readme viewer = user:alice already declared at "
	if plan.Valid || len(plan.Diagnostics) != 1 || !strings.HasPrefix(plan.Diagnostics[0].Message, want) {
		t.Fatalf("a repeated relation line: %+v, want one diagnostic starting %q", plan, want)
	}
	if got, wantLine := plan.Diagnostics[0].Line, strings.Count(repeated, "\n"); got != wantLine {
		t.Errorf("the diagnostic is on line %d, want the second line, %d", got, wantLine)
	}
	_, err := h.applyRaw(repeated, false, plan.Digest)
	refusal(t, err, dashcontract.CodeBadRequest)
	if after := storeSnapshot(t, s); !reflect.DeepEqual(before, after) {
		t.Error("a refused apply changed the store")
	}

	once := base + "\n" + line
	planned, got := h.apply(once, false)
	if got.Diverged || !reflect.DeepEqual(planned.Created, got.Created) {
		t.Errorf("one relation line: plan %+v, apply %+v", planned, got)
	}
}
