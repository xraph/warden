package extension

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"
)

// bootstrapAdminSlug is the slug of the system role BootstrapAdmin
// creates. Fixed and well-known, so repeated calls are idempotent and an
// operator always knows what to look for in the role list.
const bootstrapAdminSlug = "warden-admin"

// bootstrapPermission is one (resource, action) pair BootstrapAdmin grants
// the admin role. Name is "<resource>:<action>", matching the convention
// the default authorizer expects (see api.defaultAuthorize).
type bootstrapPermission struct{ resource, action string }

// bootstrapPermissions covers every route the management API's default
// authorizer gates: manage + read on each mutable entity, plus the check
// and audit-log-read permissions. Read is included alongside manage so
// the bootstrap admin can also browse the catalog, not just mutate it.
var bootstrapPermissions = []bootstrapPermission{
	{"warden:role", "manage"},
	{"warden:permission", "manage"},
	{"warden:assignment", "manage"},
	{"warden:relation", "manage"},
	{"warden:policy", "manage"},
	{"warden:resourcetype", "manage"},
	{"warden:check_log", "read_audit"},
	{"warden:authz", "check"},
	{"warden:role", "read"},
	{"warden:permission", "read"},
	{"warden:assignment", "read"},
	{"warden:relation", "read"},
	{"warden:policy", "read"},
	{"warden:resourcetype", "read"},

	// The dashboard contract gates every intent through the same engine
	// decision (see extension/contract/authz.go). These three resources
	// exist only on that surface.
	{"warden:maintenance", "manage"},
	{"warden:config", "read"},
	{"warden:overview", "read"},
}

func (p bootstrapPermission) name() string { return p.resource + ":" + p.action }

// BootstrapAdmin creates (idempotently, by slug) a system role
// "warden-admin" in tenantID with the permissions the management API's
// default authorizer requires, and assigns it to subject.
//
// Operators call this once per tenant, typically right after Start, to
// grant themselves access to an otherwise fully locked-down management
// API: with C1's default-deny authorizer, nobody has warden:*:manage
// until something grants it, and this is that something. Safe to call
// repeatedly (idempotent on the role slug, the permission names, the
// attachments and the assignment).
func (e *Extension) BootstrapAdmin(ctx context.Context, tenantID string, subject warden.Subject) error {
	if e.eng == nil {
		return errors.New("warden: extension not initialized")
	}
	st := e.eng.Store()
	if st == nil {
		return errors.New("warden: no store configured")
	}

	now := time.Now().UTC()

	r, rerr := st.GetRoleBySlug(ctx, tenantID, "", bootstrapAdminSlug)
	if rerr != nil || r == nil {
		r = &role.Role{
			ID:          id.NewRoleID(),
			TenantID:    tenantID,
			Name:        "Warden Admin",
			Slug:        bootstrapAdminSlug,
			Description: "Bootstrap role granted full access to the warden management API.",
			IsSystem:    true,
			CreatedBy:   warden.SystemActor.ID,
			UpdatedBy:   warden.SystemActor.ID,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := st.CreateRole(ctx, r); err != nil {
			return fmt.Errorf("warden: bootstrap admin: create role: %w", err)
		}
	}

	granted, gerr := st.ListRolePermissions(ctx, tenantID, r.ID)
	if gerr != nil {
		return fmt.Errorf("warden: bootstrap admin: list role permissions: %w", gerr)
	}
	grantedNames := make(map[string]struct{}, len(granted))
	for _, gp := range granted {
		if gp.NamespacePath == "" {
			grantedNames[gp.Name] = struct{}{}
		}
	}

	for _, bp := range bootstrapPermissions {
		name := bp.name()
		p, perr := st.GetPermissionByName(ctx, tenantID, "", name)
		if perr != nil || p == nil {
			p = &permission.Permission{
				ID:        id.NewPermissionID(),
				TenantID:  tenantID,
				Name:      name,
				Resource:  bp.resource,
				Action:    bp.action,
				IsSystem:  true,
				CreatedBy: warden.SystemActor.ID,
				UpdatedBy: warden.SystemActor.ID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := st.CreatePermission(ctx, p); err != nil {
				return fmt.Errorf("warden: bootstrap admin: create permission %s: %w", name, err)
			}
		}
		if _, ok := grantedNames[name]; ok {
			continue
		}
		if err := st.AttachPermission(ctx, tenantID, r.ID, permission.Ref{Name: name}); err != nil {
			return fmt.Errorf("warden: bootstrap admin: attach %s: %w", name, err)
		}
	}

	existing, aerr := st.ListAssignments(ctx, &assignment.ListFilter{
		TenantID:    tenantID,
		RoleID:      &r.ID,
		SubjectKind: string(subject.Kind),
		SubjectID:   subject.ID,
	})
	if aerr != nil {
		return fmt.Errorf("warden: bootstrap admin: list assignments: %w", aerr)
	}
	if len(existing) > 0 {
		return nil
	}

	ass := &assignment.Assignment{
		ID:          id.NewAssignmentID(),
		TenantID:    tenantID,
		RoleID:      r.ID,
		SubjectKind: string(subject.Kind),
		SubjectID:   subject.ID,
		GrantedBy:   warden.SystemActor.ID,
		CreatedAt:   now,
	}
	if err := st.CreateAssignment(ctx, ass); err != nil {
		return fmt.Errorf("warden: bootstrap admin: assign role: %w", err)
	}
	return nil
}
