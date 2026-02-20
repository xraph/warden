// Example: pure RBAC with role inheritance.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"
)

func main() {
	ctx := warden.WithTenant(context.Background(), "app", "t1")
	s := memory.New()

	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		log.Fatal(err)
	}

	// Create role hierarchy: editor inherits from viewer.
	viewerID := id.NewRoleID()
	editorID := id.NewRoleID()
	readPerm := id.NewPermissionID()
	writePerm := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: viewerID, TenantID: "t1", Name: "viewer", Slug: "viewer"})
	_ = s.CreateRole(ctx, &role.Role{ID: editorID, TenantID: "t1", Name: "editor", Slug: "editor", ParentID: &viewerID})

	_ = s.CreatePermission(ctx, &permission.Permission{ID: readPerm, TenantID: "t1", Name: "doc:read", Resource: "doc", Action: "read"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: writePerm, TenantID: "t1", Name: "doc:write", Resource: "doc", Action: "write"})

	// Viewer can read; editor can write (and inherits read).
	_ = s.AttachPermission(ctx, viewerID, readPerm)
	_ = s.AttachPermission(ctx, editorID, writePerm)

	// Assign editor role to Alice.
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "t1",
		RoleID: editorID, SubjectKind: "user", SubjectID: "alice",
	})

	// Alice can read (inherited from viewer).
	check(eng, ctx, "alice", "read", "doc", "d1")
	// Alice can write (direct editor permission).
	check(eng, ctx, "alice", "write", "doc", "d1")
	// Alice cannot delete (no such permission).
	check(eng, ctx, "alice", "delete", "doc", "d1")
}

func check(eng *warden.Engine, ctx context.Context, userID, action, resType, resID string) {
	result, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: userID},
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resType, ID: resID},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s %s %s:%s → %v (%s)\n", userID, action, resType, resID, result.Allowed, result.Decision)
}
