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
	total, _ := s.CountRoles(ctx, &role.ListFilter{TenantID: tenantID, Search: search}) //nolint:errcheck // pagination count; 0 is acceptable on error
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
	total, _ := s.CountPermissions(ctx, &permission.ListFilter{TenantID: tenantID, Search: search, Resource: resource, Action: action}) //nolint:errcheck // pagination count
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
	total, _ := s.CountAssignments(ctx, countFilter) //nolint:errcheck // pagination count
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
	total, _ := s.CountRelations(ctx, countFilter) //nolint:errcheck // pagination count
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
	total, _ := s.CountPolicies(ctx, countFilter) //nolint:errcheck // pagination count
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
	total, _ := s.CountResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID, Search: search}) //nolint:errcheck // pagination count
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
	total, _ := s.CountCheckLogs(ctx, countFilter) //nolint:errcheck // pagination count
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
	c.Roles, _ = s.CountRoles(ctx, &role.ListFilter{TenantID: tenantID})                         //nolint:errcheck // display count
	c.Permissions, _ = s.CountPermissions(ctx, &permission.ListFilter{TenantID: tenantID})       //nolint:errcheck // display count
	c.Assignments, _ = s.CountAssignments(ctx, &assignment.ListFilter{TenantID: tenantID})       //nolint:errcheck // display count
	c.Relations, _ = s.CountRelations(ctx, &relation.ListFilter{TenantID: tenantID})             //nolint:errcheck // display count
	c.Policies, _ = s.CountPolicies(ctx, &policy.ListFilter{TenantID: tenantID})                 //nolint:errcheck // display count
	c.ResourceTypes, _ = s.CountResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID}) //nolint:errcheck // display count
	return c
}

// enrichRoleRows fetches permission counts, resolves parent role names,
// and counts relation tuples for each role.
func enrichRoleRows(ctx context.Context, s store.Store, roles []*role.Role) []pages.RoleRow {
	rows := make([]pages.RoleRow, len(roles))

	// Cache parents we resolve via GetRoleBySlug, keyed by (tenant, slug).
	type parentInfo struct {
		id   string
		name string
	}
	parentBySlug := make(map[string]parentInfo, len(roles))

	// Seed the cache from this page so we don't fetch parents that are already in scope.
	for _, r := range roles {
		parentBySlug[r.TenantID+"\x00"+r.Slug] = parentInfo{id: r.ID.String(), name: r.Name}
	}

	// Fetch missing parents not in the current page.
	for _, r := range roles {
		if r.ParentSlug == "" {
			continue
		}
		key := r.TenantID + "\x00" + r.ParentSlug
		if _, ok := parentBySlug[key]; ok {
			continue
		}
		parent, err := s.GetRoleBySlug(ctx, r.TenantID, r.ParentSlug)
		if err == nil && parent != nil {
			parentBySlug[key] = parentInfo{id: parent.ID.String(), name: parent.Name}
		}
	}

	// Populate each row.
	for i, r := range roles {
		rows[i].Role = r

		// Permission count.
		if permIDs, err := s.ListRolePermissions(ctx, r.ID); err == nil {
			rows[i].PermissionCount = len(permIDs)
		}

		// Parent resolution.
		if r.ParentSlug != "" {
			rows[i].ParentSlug = r.ParentSlug
			if info, ok := parentBySlug[r.TenantID+"\x00"+r.ParentSlug]; ok {
				rows[i].ParentID = info.id
				rows[i].ParentName = info.name
			}
		}

		// Relation tuple count (role as object + role as subject).
		rid := r.ID.String()
		objCount, _ := s.CountRelations(ctx, &relation.ListFilter{ //nolint:errcheck // display count
			ObjectType: "role",
			ObjectID:   rid,
		})
		subCount, _ := s.CountRelations(ctx, &relation.ListFilter{ //nolint:errcheck // display count
			SubjectType: "role",
			SubjectID:   rid,
		})
		rows[i].RelationCount = objCount + subCount
	}

	return rows
}
