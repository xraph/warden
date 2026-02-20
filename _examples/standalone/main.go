// Example: standalone Warden usage without Forge.
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
	ctx := warden.WithTenant(context.Background(), "myapp", "tenant-1")
	s := memory.New()

	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		log.Fatal(err)
	}

	// Create role and permission.
	roleID := id.NewRoleID()
	permID := id.NewPermissionID()

	_ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "tenant-1", Name: "editor", Slug: "editor"})
	_ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "tenant-1", Name: "document:read", Resource: "document", Action: "read"})
	_ = s.AttachPermission(ctx, roleID, permID)

	// Assign role to user.
	_ = s.CreateAssignment(ctx, &assignment.Assignment{
		ID: id.NewAssignmentID(), TenantID: "tenant-1",
		RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
	})

	// Check authorization.
	result, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "doc-123"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Allowed: %v (decision: %s)\n", result.Allowed, result.Decision)

	// Shorthand check.
	allowed, err := eng.CanI(ctx, warden.SubjectUser, "alice", "read", "document", "doc-123")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CanI: %v\n", allowed)
}
