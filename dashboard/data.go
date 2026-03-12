package dashboard

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/dashboard/pages"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// ─── Helper Functions ────────────────────────────────────────────────────────

// parseIntParam extracts an integer query param with a default.
func parseIntParam(params map[string]string, key string, defaultVal int) int {
	v, ok := params[key]
	if !ok || v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

// parseBoolParam extracts a bool query param, returning nil if empty.
func parseBoolParam(params map[string]string, key string) *bool {
	v, ok := params[key]
	if !ok || v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil
	}
	return &b
}

// parseTimeParam extracts a time param from RFC3339 string.
func parseTimeParam(params map[string]string, key string) *time.Time {
	v, ok := params[key]
	if !ok || v == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil
	}
	return &t
}

// ─── Paginated Fetch Functions ───────────────────────────────────────────────

// fetchRolesPaginated returns paginated roles matching filters.
func fetchRolesPaginated(ctx context.Context, s store.Store, tenantID, search string, limit, offset int) ([]*role.Role, int64, error) {
	filter := &role.ListFilter{
		TenantID: tenantID,
		Search:   search,
		Limit:    limit,
		Offset:   offset,
	}
	roles, err := s.ListRoles(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch roles: %w", err)
	}
	total, _ := s.CountRoles(ctx, &role.ListFilter{TenantID: tenantID, Search: search})
	return roles, total, nil
}

// fetchPermissionsPaginated returns paginated permissions matching filters.
func fetchPermissionsPaginated(ctx context.Context, s store.Store, tenantID, search, resource, action string, limit, offset int) ([]*permission.Permission, int64, error) {
	filter := &permission.ListFilter{
		TenantID: tenantID,
		Search:   search,
		Resource: resource,
		Action:   action,
		Limit:    limit,
		Offset:   offset,
	}
	perms, err := s.ListPermissions(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch permissions: %w", err)
	}
	total, _ := s.CountPermissions(ctx, &permission.ListFilter{TenantID: tenantID, Search: search, Resource: resource, Action: action})
	return perms, total, nil
}

// fetchAssignmentsPaginated returns paginated assignments matching filters.
func fetchAssignmentsPaginated(ctx context.Context, s store.Store, tenantID, subjectKind, subjectID, roleIDStr string, limit, offset int) ([]*assignment.Assignment, int64, error) {
	filter := &assignment.ListFilter{
		TenantID:    tenantID,
		SubjectKind: subjectKind,
		SubjectID:   subjectID,
		Limit:       limit,
		Offset:      offset,
	}
	countFilter := &assignment.ListFilter{
		TenantID:    tenantID,
		SubjectKind: subjectKind,
		SubjectID:   subjectID,
	}
	if roleIDStr != "" {
		if rid, err := id.ParseRoleID(roleIDStr); err == nil {
			filter.RoleID = &rid
			countFilter.RoleID = &rid
		}
	}
	items, err := s.ListAssignments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch assignments: %w", err)
	}
	total, _ := s.CountAssignments(ctx, countFilter)
	return items, total, nil
}

// fetchRelationsPaginated returns paginated relation tuples matching filters.
func fetchRelationsPaginated(ctx context.Context, s store.Store, tenantID, objectType, objectID, rel, subjectType, subjectID string, limit, offset int) ([]*relation.Tuple, int64, error) {
	filter := &relation.ListFilter{
		TenantID:    tenantID,
		ObjectType:  objectType,
		ObjectID:    objectID,
		Relation:    rel,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Limit:       limit,
		Offset:      offset,
	}
	countFilter := &relation.ListFilter{
		TenantID:    tenantID,
		ObjectType:  objectType,
		ObjectID:    objectID,
		Relation:    rel,
		SubjectType: subjectType,
		SubjectID:   subjectID,
	}
	items, err := s.ListRelations(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch relations: %w", err)
	}
	total, _ := s.CountRelations(ctx, countFilter)
	return items, total, nil
}

// fetchPoliciesPaginated returns paginated policies matching filters.
func fetchPoliciesPaginated(ctx context.Context, s store.Store, tenantID, search, effectStr string, active *bool, limit, offset int) ([]*policy.Policy, int64, error) {
	filter := &policy.ListFilter{
		TenantID: tenantID,
		Search:   search,
		IsActive: active,
		Limit:    limit,
		Offset:   offset,
	}
	countFilter := &policy.ListFilter{
		TenantID: tenantID,
		Search:   search,
		IsActive: active,
	}
	if effectStr != "" {
		filter.Effect = policy.Effect(effectStr)
		countFilter.Effect = policy.Effect(effectStr)
	}
	items, err := s.ListPolicies(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch policies: %w", err)
	}
	total, _ := s.CountPolicies(ctx, countFilter)
	return items, total, nil
}

// fetchResourceTypesPaginated returns paginated resource types matching filters.
func fetchResourceTypesPaginated(ctx context.Context, s store.Store, tenantID, search string, limit, offset int) ([]*resourcetype.ResourceType, int64, error) {
	filter := &resourcetype.ListFilter{
		TenantID: tenantID,
		Search:   search,
		Limit:    limit,
		Offset:   offset,
	}
	items, err := s.ListResourceTypes(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch resource types: %w", err)
	}
	total, _ := s.CountResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID, Search: search})
	return items, total, nil
}

// fetchCheckLogsPaginated returns paginated check log entries matching filters.
func fetchCheckLogsPaginated(ctx context.Context, s store.Store, tenantID string, params map[string]string, limit, offset int) ([]*checklog.Entry, int64, error) {
	filter := &checklog.QueryFilter{
		TenantID:     tenantID,
		SubjectKind:  params["subject_kind"],
		SubjectID:    params["subject_id"],
		Action:       params["action"],
		ResourceType: params["resource_type"],
		Decision:     params["decision"],
		After:        parseTimeParam(params, "after"),
		Before:       parseTimeParam(params, "before"),
		Limit:        limit,
		Offset:       offset,
	}
	countFilter := &checklog.QueryFilter{
		TenantID:     tenantID,
		SubjectKind:  params["subject_kind"],
		SubjectID:    params["subject_id"],
		Action:       params["action"],
		ResourceType: params["resource_type"],
		Decision:     params["decision"],
		After:        parseTimeParam(params, "after"),
		Before:       parseTimeParam(params, "before"),
	}
	entries, err := s.ListCheckLogs(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("dashboard: fetch check logs: %w", err)
	}
	total, _ := s.CountCheckLogs(ctx, countFilter)
	return entries, total, nil
}

// ─── Non-Paginated Fetch Functions ───────────────────────────────────────────

// fetchRoles returns all roles for the given tenant.
func fetchRoles(ctx context.Context, s store.Store, tenantID string) ([]*role.Role, error) {
	roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch roles: %w", err)
	}
	return roles, nil
}

// fetchPermissions returns all permissions for the given tenant.
func fetchPermissions(ctx context.Context, s store.Store, tenantID string) ([]*permission.Permission, error) {
	perms, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch permissions: %w", err)
	}
	return perms, nil
}

// fetchAssignments returns all assignments for the given tenant.
func fetchAssignments(ctx context.Context, s store.Store, tenantID string) ([]*assignment.Assignment, error) {
	assignments, err := s.ListAssignments(ctx, &assignment.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch assignments: %w", err)
	}
	return assignments, nil
}

// fetchRelations returns all relation tuples for the given tenant.
func fetchRelations(ctx context.Context, s store.Store, tenantID string) ([]*relation.Tuple, error) {
	tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch relations: %w", err)
	}
	return tuples, nil
}

// fetchPolicies returns all policies for the given tenant.
func fetchPolicies(ctx context.Context, s store.Store, tenantID string) ([]*policy.Policy, error) {
	policies, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch policies: %w", err)
	}
	return policies, nil
}

// fetchResourceTypes returns all resource types for the given tenant.
func fetchResourceTypes(ctx context.Context, s store.Store, tenantID string) ([]*resourcetype.ResourceType, error) {
	types, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch resource types: %w", err)
	}
	return types, nil
}

// fetchCheckLogs returns recent check log entries for the given tenant.
func fetchCheckLogs(ctx context.Context, s store.Store, tenantID string, limit int) ([]*checklog.Entry, error) {
	if limit <= 0 {
		limit = 50
	}
	entries, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: tenantID, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("dashboard: fetch check logs: %w", err)
	}
	return entries, nil
}

// fetchRoleWithPermissions returns a role and its attached permissions.
func fetchRoleWithPermissions(ctx context.Context, s store.Store, roleID id.RoleID) (*role.Role, []*permission.Permission, error) {
	r, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("dashboard: fetch role: %w", err)
	}
	perms, err := s.ListPermissionsByRole(ctx, roleID)
	if err != nil {
		perms = nil
	}
	return r, perms, nil
}

// countEntities returns counts for all entity types.
type entityCounts struct {
	Roles         int64
	Permissions   int64
	Assignments   int64
	Relations     int64
	Policies      int64
	ResourceTypes int64
}

func fetchEntityCounts(ctx context.Context, s store.Store, tenantID string) entityCounts {
	var c entityCounts
	c.Roles, _ = s.CountRoles(ctx, &role.ListFilter{TenantID: tenantID})
	c.Permissions, _ = s.CountPermissions(ctx, &permission.ListFilter{TenantID: tenantID})
	c.Assignments, _ = s.CountAssignments(ctx, &assignment.ListFilter{TenantID: tenantID})
	c.Relations, _ = s.CountRelations(ctx, &relation.ListFilter{TenantID: tenantID})
	c.Policies, _ = s.CountPolicies(ctx, &policy.ListFilter{TenantID: tenantID})
	c.ResourceTypes, _ = s.CountResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID})
	return c
}

// formatTimeAgo returns a human-readable relative time string.
func formatTimeAgo(t time.Time) string {
	d := time.Since(t)

	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dmo ago", int(d.Hours()/(24*30)))
	default:
		return fmt.Sprintf("%dy ago", int(d.Hours()/(24*365)))
	}
}

// truncateString shortens s to max characters and appends "..." if truncated.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// enrichRoleRows fetches permission counts, resolves parent role names,
// and counts relation tuples for each role.
func enrichRoleRows(ctx context.Context, s store.Store, roles []*role.Role) []pages.RoleRow {
	rows := make([]pages.RoleRow, len(roles))

	// Build name lookup from the current page of roles.
	nameByID := make(map[string]string, len(roles))
	for _, r := range roles {
		nameByID[r.ID.String()] = r.Name
	}

	// Fetch missing parent role names not in the current page.
	for _, r := range roles {
		if r.ParentID != nil && !r.ParentID.IsNil() {
			pid := r.ParentID.String()
			if _, ok := nameByID[pid]; !ok {
				parsed, err := id.ParseRoleID(pid)
				if err != nil {
					continue
				}
				parent, err := s.GetRole(ctx, parsed)
				if err == nil && parent != nil {
					nameByID[pid] = parent.Name
				}
			}
		}
	}

	// Populate each row.
	for i, r := range roles {
		rows[i].Role = r

		// Permission count.
		if permIDs, err := s.ListRolePermissions(ctx, r.ID); err == nil {
			rows[i].PermissionCount = len(permIDs)
		}

		// Parent name resolution.
		if r.ParentID != nil && !r.ParentID.IsNil() {
			pid := r.ParentID.String()
			rows[i].ParentID = pid
			if name, ok := nameByID[pid]; ok {
				rows[i].ParentName = name
			}
		}

		// Relation tuple count (role as object + role as subject).
		rid := r.ID.String()
		objCount, _ := s.CountRelations(ctx, &relation.ListFilter{
			ObjectType: "role",
			ObjectID:   rid,
		})
		subCount, _ := s.CountRelations(ctx, &relation.ListFilter{
			SubjectType: "role",
			SubjectID:   rid,
		})
		rows[i].RelationCount = objCount + subCount
	}

	return rows
}
