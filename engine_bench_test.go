package warden

import (
	"context"
	"strconv"
	"testing"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

// BenchmarkCheckWithNamespace measures the per-ancestor-level overhead of a
// Check call when the subject's role lives at the tenant root and the call
// happens at varying namespace depths. Each depth-N call walks N+1 namespace
// entries when resolving roles. Target in the plan: ≤ 50 µs per ancestor
// level on top of the depth-0 baseline.
func BenchmarkCheckWithNamespace(b *testing.B) {
	for _, depth := range []int{0, 1, 4, 8} {
		b.Run("depth/"+strconv.Itoa(depth), func(b *testing.B) {
			ctx := WithTenant(context.Background(), "app1", "t1")
			s := memory.New()
			eng, err := NewEngine(WithStore(s))
			if err != nil {
				b.Fatal(err)
			}

			// Build a namespace path of the requested depth: "n0/n1/.../n{depth-1}".
			nsPath := ""
			for i := 0; i < depth; i++ {
				if nsPath == "" {
					nsPath = "n" + strconv.Itoa(i)
				} else {
					nsPath = nsPath + "/n" + strconv.Itoa(i)
				}
			}

			// Role + assignment live at the tenant root so ancestor walk traverses every level.
			roleID := id.NewRoleID()
			permID := id.NewPermissionID()
			_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "t1", Name: "viewer", Slug: "viewer"})
			_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"})
			_ = s.AttachPermission(ctx, roleID, permID)
			_ = s.CreateAssignment(ctx, &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleID, SubjectKind: "user", SubjectID: "u1",
			})

			callCtx := WithNamespace(ctx, nsPath)
			req := &CheckRequest{
				Subject:  Subject{Kind: SubjectUser, ID: "u1"},
				Action:   Action{Name: "read"},
				Resource: Resource{Type: "doc", ID: "d1"},
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := eng.Check(callCtx, req)
				if err != nil {
					b.Fatal(err)
				}
				if !result.Allowed {
					b.Fatalf("expected allow at depth %d, got %s", depth, result.Decision)
				}
			}
		})
	}
}

// BenchmarkRoleInheritance measures Check throughput for a subject assigned a
// role whose parent chain is N deep. The chain is built leaf-first so the
// terminal role has the granting permission, forcing the walker to traverse
// every level. Targets in the plan: depth-10 ≤ 200 µs against in-memory store.
func BenchmarkRoleInheritance(b *testing.B) {
	for _, depth := range []int{1, 5, 10, 20} {
		b.Run("depth/"+strconv.Itoa(depth), func(b *testing.B) {
			ctx := WithTenant(context.Background(), "app1", "t1")
			s := memory.New()
			eng, err := NewEngine(WithStore(s))
			if err != nil {
				b.Fatal(err)
			}

			// Build chain: r0 ← r1 ← r2 ← ... ← r{depth}.
			// Subject is assigned r{depth} (deepest leaf).
			// Permission is attached to r0 (root) so the walker must traverse all parents.
			roleIDs := make([]id.RoleID, depth+1)
			for i := range roleIDs {
				roleIDs[i] = id.NewRoleID()
			}
			permID := id.NewPermissionID()
			_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"})

			for i := 0; i <= depth; i++ {
				slug := "role-" + strconv.Itoa(i)
				r := &role.Role{ID: roleIDs[i], TenantID: "t1", Name: slug, Slug: slug}
				if i > 0 {
					r.ParentSlug = "role-" + strconv.Itoa(i-1)
				}
				_ = s.CreateRole(ctx, r)
			}
			_ = s.AttachPermission(ctx, roleIDs[0], permID)

			_ = s.CreateAssignment(ctx, &assignment.Assignment{
				ID: id.NewAssignmentID(), TenantID: "t1", RoleID: roleIDs[depth], SubjectKind: "user", SubjectID: "u1",
			})

			req := &CheckRequest{
				Subject:  Subject{Kind: SubjectUser, ID: "u1"},
				Action:   Action{Name: "read"},
				Resource: Resource{Type: "doc", ID: "d1"},
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := eng.Check(ctx, req)
				if err != nil {
					b.Fatal(err)
				}
				if !result.Allowed {
					b.Fatalf("expected allow at depth %d, got %s", depth, result.Decision)
				}
			}
		})
	}
}
