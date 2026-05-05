// Package postgres provides a PostgreSQL implementation of the Warden
// composite store using grove ORM with Go-based migrations.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/wardenerr"
)

// Compile-time interface check.
var _ store.Store = (*Store)(nil)

// errNotFound is the sentinel for missing entities.
var errNotFound = fmt.Errorf("not found")

// Store is a PostgreSQL implementation of the composite Warden store.
type Store struct {
	db   *grove.DB
	pgdb *pgdriver.PgDB
}

// New creates a new PostgreSQL store.
func New(db *grove.DB) *Store {
	return &Store{
		db:   db,
		pgdb: pgdriver.Unwrap(db),
	}
}

// Migrate runs programmatic migrations via the grove orchestrator.
func (s *Store) Migrate(ctx context.Context) error {
	executor, err := migrate.NewExecutorFor(s.pgdb)
	if err != nil {
		return fmt.Errorf("warden: create migration executor: %w", err)
	}
	orch := migrate.NewOrchestrator(executor, Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		return fmt.Errorf("warden: migration failed: %w", err)
	}
	return nil
}

// Ping verifies the database connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.Ping(ctx)
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// ──────────────────────────────────────────────────
// Role operations
// ──────────────────────────────────────────────────

func (s *Store) CreateRole(ctx context.Context, r *role.Role) error {
	if r.ID.IsNil() {
		r.ID = id.NewRoleID()
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = now
	}
	m := roleToModel(r)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("role %q in tenant %q ns %q: %w",
				r.Slug, r.TenantID, r.NamespacePath, wardenerr.ErrDuplicateRole)
		}
		return fmt.Errorf("warden: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, roleID id.RoleID) (*role.Role, error) {
	m := new(roleModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", roleID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role %s: %w", roleID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get role: %w", err)
	}
	return roleFromModel(m), nil
}

func (s *Store) GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*role.Role, error) {
	m := new(roleModel)
	err := s.pgdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("slug = ?", slug).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role slug %q in ns %q: %w", slug, namespacePath, errNotFound)
		}
		return nil, fmt.Errorf("warden: get role by slug: %w", err)
	}
	return roleFromModel(m), nil
}

func (s *Store) UpdateRole(ctx context.Context, r *role.Role) error {
	r.UpdatedAt = time.Now().UTC()
	m := roleToModel(r)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update role: %w", err)
	}
	return nil
}

func (s *Store) DeleteRole(ctx context.Context, roleID id.RoleID) error {
	_, err := s.pgdb.NewDelete((*roleModel)(nil)).
		Where("id = ?", roleID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete role: %w", err)
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context, filter *role.ListFilter) ([]*role.Role, error) {
	var models []roleModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.IsSystem != nil {
			q = q.Where("is_system = ?", *filter.IsSystem)
		}
		if filter.IsDefault != nil {
			q = q.Where("is_default = ?", *filter.IsDefault)
		}
		if filter.ParentSlug != nil {
			q = q.Where("parent_slug = ?", *filter.ParentSlug)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		result[i] = roleFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountRoles(ctx context.Context, filter *role.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*roleModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.IsSystem != nil {
			q = q.Where("is_system = ?", *filter.IsSystem)
		}
		if filter.IsDefault != nil {
			q = q.Where("is_default = ?", *filter.IsDefault)
		}
		if filter.ParentSlug != nil {
			q = q.Where("parent_slug = ?", *filter.ParentSlug)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count roles: %w", err)
	}
	return count, nil
}

// listRolePermissionsJoinSQL walks the junction's natural keys
// (perm_namespace_path, perm_name) into warden_permissions, scoped to the
// role's tenant via the warden_roles join.
const listRolePermissionsJoinSQL = `
SELECT p.id, p.tenant_id, p.namespace_path, p.app_id, p.name, p.description,
       p.resource, p.action, p.is_system, p.metadata, p.created_at, p.updated_at
FROM warden_role_permissions rp
JOIN warden_roles r ON r.id = rp.role_id
JOIN warden_permissions p
  ON p.tenant_id = r.tenant_id
 AND p.namespace_path = rp.perm_namespace_path
 AND p.name = rp.perm_name
WHERE rp.role_id = $1
`

func (s *Store) ListRolePermissions(ctx context.Context, roleID id.RoleID) ([]*permission.Permission, error) {
	var models []permissionModel
	if err := s.pgdb.NewRaw(listRolePermissionsJoinSQL, roleID.String()).Scan(ctx, &models); err != nil {
		return nil, fmt.Errorf("warden: list role permissions: %w", err)
	}
	result := make([]*permission.Permission, 0, len(models))
	for i := range models {
		result = append(result, permissionFromModel(&models[i]))
	}
	return result, nil
}

func (s *Store) AttachPermission(ctx context.Context, roleID id.RoleID, ref permission.Ref) error {
	m := &rolePermissionModel{
		RoleID:            roleID.String(),
		PermNamespacePath: ref.NamespacePath,
		PermName:          ref.Name,
	}
	_, err := s.pgdb.NewInsert(m).
		OnConflict("(role_id, perm_namespace_path, perm_name) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: attach permission: %w", err)
	}
	return nil
}

func (s *Store) DetachPermission(ctx context.Context, roleID id.RoleID, ref permission.Ref) error {
	_, err := s.pgdb.NewDelete((*rolePermissionModel)(nil)).
		Where("role_id = ?", roleID.String()).
		Where("perm_namespace_path = ?", ref.NamespacePath).
		Where("perm_name = ?", ref.Name).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: detach permission: %w", err)
	}
	return nil
}

func (s *Store) SetRolePermissions(ctx context.Context, roleID id.RoleID, refs []permission.Ref) error {
	tx, err := s.pgdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("warden: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on error is intentional

	// Delete existing permissions for this role.
	_, err = tx.NewDelete((*rolePermissionModel)(nil)).
		Where("role_id = ?", roleID.String()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: clear role permissions: %w", err)
	}

	if len(refs) > 0 {
		models := make([]rolePermissionModel, len(refs))
		for i, ref := range refs {
			models[i] = rolePermissionModel{
				RoleID:            roleID.String(),
				PermNamespacePath: ref.NamespacePath,
				PermName:          ref.Name,
			}
		}
		_, err = tx.NewInsert(&models).Exec(ctx)
		if err != nil {
			return fmt.Errorf("warden: set role permissions: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warden: commit tx: %w", err)
	}
	return nil
}

func (s *Store) ListChildRoles(ctx context.Context, tenantID, parentSlug string) ([]*role.Role, error) {
	var models []roleModel
	err := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("parent_slug = ?", parentSlug).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list child roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		result[i] = roleFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeleteRolesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*roleModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete roles by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Permission operations
// ──────────────────────────────────────────────────

func (s *Store) CreatePermission(ctx context.Context, p *permission.Permission) error {
	if p.ID.IsNil() {
		p.ID = id.NewPermissionID()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}
	m := permissionToModel(p)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("permission %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePermission)
		}
		return fmt.Errorf("warden: create permission: %w", err)
	}
	return nil
}

func (s *Store) GetPermission(ctx context.Context, permID id.PermissionID) (*permission.Permission, error) {
	m := new(permissionModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", permID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("permission %s: %w", permID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get permission: %w", err)
	}
	return permissionFromModel(m), nil
}

func (s *Store) GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*permission.Permission, error) {
	m := new(permissionModel)
	err := s.pgdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("permission %q in ns %q: %w", name, namespacePath, errNotFound)
		}
		return nil, fmt.Errorf("warden: get permission by name: %w", err)
	}
	return permissionFromModel(m), nil
}

func (s *Store) UpdatePermission(ctx context.Context, p *permission.Permission) error {
	p.UpdatedAt = time.Now().UTC()
	m := permissionToModel(p)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update permission: %w", err)
	}
	return nil
}

func (s *Store) DeletePermission(ctx context.Context, permID id.PermissionID) error {
	_, err := s.pgdb.NewDelete((*permissionModel)(nil)).
		Where("id = ?", permID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permission: %w", err)
	}
	return nil
}

func (s *Store) ListPermissions(ctx context.Context, filter *permission.ListFilter) ([]*permission.Permission, error) {
	var models []permissionModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Resource != "" {
			q = q.Where("resource = ?", filter.Resource)
		}
		if filter.Action != "" {
			q = q.Where("action = ?", filter.Action)
		}
		if filter.IsSystem != nil {
			q = q.Where("is_system = ?", *filter.IsSystem)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions: %w", err)
	}
	result := make([]*permission.Permission, len(models))
	for i := range models {
		result[i] = permissionFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountPermissions(ctx context.Context, filter *permission.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*permissionModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Resource != "" {
			q = q.Where("resource = ?", filter.Resource)
		}
		if filter.Action != "" {
			q = q.Where("action = ?", filter.Action)
		}
		if filter.IsSystem != nil {
			q = q.Where("is_system = ?", *filter.IsSystem)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count permissions: %w", err)
	}
	return count, nil
}

func (s *Store) ListPermissionsByRole(ctx context.Context, roleID id.RoleID) ([]*permission.Permission, error) {
	return s.ListRolePermissions(ctx, roleID)
}

const listPermissionsBySubjectSQL = `
SELECT DISTINCT p.id, p.tenant_id, p.namespace_path, p.app_id, p.name, p.description,
       p.resource, p.action, p.is_system, p.metadata, p.created_at, p.updated_at
FROM warden_assignments a
JOIN warden_role_permissions rp ON rp.role_id = a.role_id
JOIN warden_permissions p
  ON p.tenant_id = a.tenant_id
 AND p.namespace_path = rp.perm_namespace_path
 AND p.name = rp.perm_name
WHERE a.tenant_id = $1
  AND a.subject_kind = $2
  AND a.subject_id = $3
`

func (s *Store) ListPermissionsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]*permission.Permission, error) {
	var models []permissionModel
	if err := s.pgdb.NewRaw(listPermissionsBySubjectSQL, tenantID, subjectKind, subjectID).Scan(ctx, &models); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	result := make([]*permission.Permission, 0, len(models))
	for i := range models {
		result = append(result, permissionFromModel(&models[i]))
	}
	return result, nil
}

func (s *Store) DeletePermissionsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*permissionModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permissions by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Assignment operations
// ──────────────────────────────────────────────────

func (s *Store) CreateAssignment(ctx context.Context, a *assignment.Assignment) error {
	if a.ID.IsNil() {
		a.ID = id.NewAssignmentID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	m := assignmentToModel(a)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("assignment role=%s subject=%s:%s in tenant %q ns %q: %w",
				a.RoleID, a.SubjectKind, a.SubjectID, a.TenantID, a.NamespacePath,
				wardenerr.ErrDuplicateAssignment)
		}
		return fmt.Errorf("warden: create assignment: %w", err)
	}
	return nil
}

func (s *Store) GetAssignment(ctx context.Context, assID id.AssignmentID) (*assignment.Assignment, error) {
	m := new(assignmentModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", assID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("assignment %s: %w", assID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get assignment: %w", err)
	}
	return assignmentFromModel(m), nil
}

func (s *Store) DeleteAssignment(ctx context.Context, assID id.AssignmentID) error {
	_, err := s.pgdb.NewDelete((*assignmentModel)(nil)).
		Where("id = ?", assID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignment: %w", err)
	}
	return nil
}

func (s *Store) ListAssignments(ctx context.Context, filter *assignment.ListFilter) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.RoleID != nil {
			q = q.Where("role_id = ?", filter.RoleID.String())
		}
		if filter.SubjectKind != "" {
			q = q.Where("subject_kind = ?", filter.SubjectKind)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.ResourceType != "" {
			q = q.Where("resource_type = ?", filter.ResourceType)
		}
		if filter.ResourceID != "" {
			q = q.Where("resource_id = ?", filter.ResourceID)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list assignments: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		result[i] = assignmentFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountAssignments(ctx context.Context, filter *assignment.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*assignmentModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.RoleID != nil {
			q = q.Where("role_id = ?", filter.RoleID.String())
		}
		if filter.SubjectKind != "" {
			q = q.Where("subject_kind = ?", filter.SubjectKind)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.ResourceType != "" {
			q = q.Where("resource_type = ?", filter.ResourceType)
		}
		if filter.ResourceID != "" {
			q = q.Where("resource_id = ?", filter.ResourceID)
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count assignments: %w", err)
	}
	return count, nil
}

func (s *Store) ListRolesForSubject(ctx context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID string) ([]id.RoleID, error) {
	var models []assignmentModel
	q := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Where("resource_type = ''")
	if len(namespacePaths) > 0 {
		q = q.Where("namespace_path IN (?)", namespacePaths)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list roles for subject: %w", err)
	}
	result := make([]id.RoleID, 0, len(models))
	for _, m := range models {
		rid, err := id.ParseRoleID(m.RoleID)
		if err == nil {
			result = append(result, rid)
		}
	}
	return result, nil
}

func (s *Store) ListRolesForSubjectOnResource(ctx context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error) {
	var models []assignmentModel
	q := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Where("resource_type = ?", resourceType).
		Where("resource_id = ?", resourceID)
	if len(namespacePaths) > 0 {
		q = q.Where("namespace_path IN (?)", namespacePaths)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list roles for subject on resource: %w", err)
	}
	result := make([]id.RoleID, 0, len(models))
	for _, m := range models {
		rid, err := id.ParseRoleID(m.RoleID)
		if err == nil {
			result = append(result, rid)
		}
	}
	return result, nil
}

func (s *Store) ListSubjectsForRole(ctx context.Context, roleID id.RoleID) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	err := s.pgdb.NewSelect(&models).
		Where("role_id = ?", roleID.String()).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list subjects for role: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		result[i] = assignmentFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeleteExpiredAssignments(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.pgdb.NewDelete((*assignmentModel)(nil)).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: delete expired assignments: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: delete expired assignments rows: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteAssignmentsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) error {
	_, err := s.pgdb.NewDelete((*assignmentModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by subject: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByRole(ctx context.Context, roleID id.RoleID) error {
	_, err := s.pgdb.NewDelete((*assignmentModel)(nil)).
		Where("role_id = ?", roleID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by role: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*assignmentModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Relation (tuple) operations
// ──────────────────────────────────────────────────

func (s *Store) CreateRelation(ctx context.Context, t *relation.Tuple) error {
	if t.ID.IsNil() {
		t.ID = id.NewRelationID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m := relationToModel(t)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("relation %s:%s#%s@%s:%s in tenant %q: %w",
				t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID,
				t.TenantID, wardenerr.ErrDuplicateRelation)
		}
		return fmt.Errorf("warden: create relation: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelation(ctx context.Context, relID id.RelationID) error {
	_, err := s.pgdb.NewDelete((*relationModel)(nil)).
		Where("id = ?", relID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationTuple(ctx context.Context, tenantID, namespacePath, objectType, objectID, rel, subjectType, subjectID string) error {
	_, err := s.pgdb.NewDelete((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation tuple: %w", err)
	}
	return nil
}

func (s *Store) ListRelations(ctx context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error) {
	var models []relationModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.ObjectType != "" {
			q = q.Where("object_type = ?", filter.ObjectType)
		}
		if filter.ObjectID != "" {
			q = q.Where("object_id = ?", filter.ObjectID)
		}
		if filter.Relation != "" {
			q = q.Where("relation = ?", filter.Relation)
		}
		if filter.SubjectType != "" {
			q = q.Where("subject_type = ?", filter.SubjectType)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.SubjectRelation != "" {
			q = q.Where("subject_relation = ?", filter.SubjectRelation)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relations: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountRelations(ctx context.Context, filter *relation.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*relationModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.ObjectType != "" {
			q = q.Where("object_type = ?", filter.ObjectType)
		}
		if filter.ObjectID != "" {
			q = q.Where("object_id = ?", filter.ObjectID)
		}
		if filter.Relation != "" {
			q = q.Where("relation = ?", filter.Relation)
		}
		if filter.SubjectType != "" {
			q = q.Where("subject_type = ?", filter.SubjectType)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.SubjectRelation != "" {
			q = q.Where("subject_relation = ?", filter.SubjectRelation)
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count relations: %w", err)
	}
	return count, nil
}

func (s *Store) ListRelationSubjects(ctx context.Context, tenantID, namespacePath, objectType, objectID, rel string) ([]*relation.Tuple, error) {
	var models []relationModel
	err := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list relation subjects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) ListRelationObjects(ctx context.Context, tenantID, namespacePath, subjectType, subjectID, rel string) ([]*relation.Tuple, error) {
	var models []relationModel
	err := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Where("relation = ?", rel).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list relation objects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CheckDirectRelation(ctx context.Context, tenantID, namespacePath, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	count, err := s.pgdb.NewSelect((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("warden: check direct relation: %w", err)
	}
	return count > 0, nil
}

func (s *Store) DeleteRelationsByObject(ctx context.Context, tenantID, objectType, objectID string) error {
	_, err := s.pgdb.NewDelete((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by object: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationsBySubject(ctx context.Context, tenantID, subjectType, subjectID string) error {
	_, err := s.pgdb.NewDelete((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by subject: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Policy operations (ABAC)
// ──────────────────────────────────────────────────

func (s *Store) CreatePolicy(ctx context.Context, p *policy.Policy) error {
	if p.ID.IsNil() {
		p.ID = id.NewPolicyID()
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}
	m := policyToModel(p)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("policy %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
		}
		return fmt.Errorf("warden: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, polID id.PolicyID) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", polID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("policy %s: %w", polID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get policy: %w", err)
	}
	return policyFromModel(m), nil
}

func (s *Store) GetPolicyByName(ctx context.Context, tenantID, namespacePath, name string) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.pgdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("policy %q in ns %q: %w", name, namespacePath, errNotFound)
		}
		return nil, fmt.Errorf("warden: get policy by name: %w", err)
	}
	return policyFromModel(m), nil
}

func (s *Store) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	p.UpdatedAt = time.Now().UTC()
	m := policyToModel(p)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update policy: %w", err)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	_, err := s.pgdb.NewDelete((*policyModel)(nil)).
		Where("id = ?", polID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	var models []policyModel
	q := s.pgdb.NewSelect(&models).OrderExpr("priority ASC, created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Effect != "" {
			q = q.Where("effect = ?", string(filter.Effect))
		}
		if filter.IsActive != nil {
			q = q.Where("is_active = ?", *filter.IsActive)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		result[i] = policyFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountPolicies(ctx context.Context, filter *policy.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*policyModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Effect != "" {
			q = q.Where("effect = ?", string(filter.Effect))
		}
		if filter.IsActive != nil {
			q = q.Where("is_active = ?", *filter.IsActive)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count policies: %w", err)
	}
	return count, nil
}

func (s *Store) ListActivePolicies(ctx context.Context, tenantID string, namespacePaths []string) ([]*policy.Policy, error) {
	var models []policyModel
	q := s.pgdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("is_active = ?", true)
	if len(namespacePaths) > 0 {
		q = q.Where("namespace_path IN (?)", namespacePaths)
	}
	q = q.OrderExpr("priority ASC")
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list active policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		result[i] = policyFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) SetPolicyVersion(ctx context.Context, polID id.PolicyID, version int) error {
	_, err := s.pgdb.NewUpdate((*policyModel)(nil)).
		Set("version = ?", version).
		Set("updated_at = ?", time.Now().UTC()).
		Where("id = ?", polID.String()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: set policy version: %w", err)
	}
	return nil
}

func (s *Store) DeletePoliciesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*policyModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policies by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Resource type operations (ReBAC schema)
// ──────────────────────────────────────────────────

func (s *Store) CreateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	if rt.ID.IsNil() {
		rt.ID = id.NewResourceTypeID()
	}
	now := time.Now().UTC()
	if rt.CreatedAt.IsZero() {
		rt.CreatedAt = now
	}
	if rt.UpdatedAt.IsZero() {
		rt.UpdatedAt = now
	}
	m := resourceTypeToModel(rt)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("resource type %q in tenant %q ns %q: %w",
				rt.Name, rt.TenantID, rt.NamespacePath, wardenerr.ErrDuplicateResourceType)
		}
		return fmt.Errorf("warden: create resource type: %w", err)
	}
	return nil
}

func (s *Store) GetResourceType(ctx context.Context, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	m := new(resourceTypeModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", rtID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("resource type %s: %w", rtID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type: %w", err)
	}
	return resourceTypeFromModel(m), nil
}

func (s *Store) GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*resourcetype.ResourceType, error) {
	m := new(resourceTypeModel)
	err := s.pgdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("resource type %q in ns %q: %w", name, namespacePath, errNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type by name: %w", err)
	}
	return resourceTypeFromModel(m), nil
}

func (s *Store) UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	rt.UpdatedAt = time.Now().UTC()
	m := resourceTypeToModel(rt)
	_, err := s.pgdb.NewUpdate(m).WherePK().Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update resource type: %w", err)
	}
	return nil
}

func (s *Store) DeleteResourceType(ctx context.Context, rtID id.ResourceTypeID) error {
	_, err := s.pgdb.NewDelete((*resourceTypeModel)(nil)).
		Where("id = ?", rtID.String()).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource type: %w", err)
	}
	return nil
}

func (s *Store) ListResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	var models []resourceTypeModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list resource types: %w", err)
	}
	result := make([]*resourcetype.ResourceType, len(models))
	for i := range models {
		result[i] = resourceTypeFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) (int64, error) {
	q := s.pgdb.NewSelect((*resourceTypeModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Search+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count resource types: %w", err)
	}
	return count, nil
}

func (s *Store) DeleteResourceTypesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*resourceTypeModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource types by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Check log operations
// ──────────────────────────────────────────────────

func (s *Store) CreateCheckLog(ctx context.Context, e *checklog.Entry) error {
	if e.ID.IsNil() {
		e.ID = id.NewCheckLogID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m := checkLogToModel(e)
	_, err := s.pgdb.NewInsert(m).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: create check log: %w", err)
	}
	return nil
}

func (s *Store) GetCheckLog(ctx context.Context, logID id.CheckLogID) (*checklog.Entry, error) {
	m := new(checkLogModel)
	err := s.pgdb.NewSelect(m).Where("id = ?", logID.String()).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("check log %s: %w", logID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get check log: %w", err)
	}
	return checkLogFromModel(m), nil
}

func (s *Store) ListCheckLogs(ctx context.Context, filter *checklog.QueryFilter) ([]*checklog.Entry, error) {
	var models []checkLogModel
	q := s.pgdb.NewSelect(&models).OrderExpr("created_at DESC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.SubjectKind != "" {
			q = q.Where("subject_kind = ?", filter.SubjectKind)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.Action != "" {
			q = q.Where("action = ?", filter.Action)
		}
		if filter.ResourceType != "" {
			q = q.Where("resource_type = ?", filter.ResourceType)
		}
		if filter.ResourceID != "" {
			q = q.Where("resource_id = ?", filter.ResourceID)
		}
		if filter.Decision != "" {
			q = q.Where("decision = ?", filter.Decision)
		}
		if filter.After != nil {
			q = q.Where("created_at >= ?", *filter.After)
		}
		if filter.Before != nil {
			q = q.Where("created_at <= ?", *filter.Before)
		}
		if filter.Limit > 0 {
			q = q.Limit(filter.Limit)
		}
		if filter.Offset > 0 {
			q = q.Offset(filter.Offset)
		}
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list check logs: %w", err)
	}
	result := make([]*checklog.Entry, len(models))
	for i := range models {
		result[i] = checkLogFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CountCheckLogs(ctx context.Context, filter *checklog.QueryFilter) (int64, error) {
	q := s.pgdb.NewSelect((*checkLogModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.SubjectKind != "" {
			q = q.Where("subject_kind = ?", filter.SubjectKind)
		}
		if filter.SubjectID != "" {
			q = q.Where("subject_id = ?", filter.SubjectID)
		}
		if filter.Action != "" {
			q = q.Where("action = ?", filter.Action)
		}
		if filter.ResourceType != "" {
			q = q.Where("resource_type = ?", filter.ResourceType)
		}
		if filter.ResourceID != "" {
			q = q.Where("resource_id = ?", filter.ResourceID)
		}
		if filter.Decision != "" {
			q = q.Where("decision = ?", filter.Decision)
		}
		if filter.After != nil {
			q = q.Where("created_at >= ?", *filter.After)
		}
		if filter.Before != nil {
			q = q.Where("created_at <= ?", *filter.Before)
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count check logs: %w", err)
	}
	return count, nil
}

func (s *Store) PurgeCheckLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.pgdb.NewDelete((*checkLogModel)(nil)).
		Where("created_at < ?", before).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs rows: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteCheckLogsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.pgdb.NewDelete((*checkLogModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete check logs by tenant: %w", err)
	}
	return nil
}
