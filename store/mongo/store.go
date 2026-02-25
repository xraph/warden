package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	mongod "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store"
)

// Collection name constants.
const (
	colRoles           = "warden_roles"
	colPermissions     = "warden_permissions"
	colRolePermissions = "warden_role_permissions"
	colAssignments     = "warden_assignments"
	colRelations       = "warden_relations"
	colPolicies        = "warden_policies"
	colResourceTypes   = "warden_resource_types"
	colCheckLogs       = "warden_check_logs"
)

// Compile-time interface check.
var _ store.Store = (*Store)(nil)

// errNotFound is the sentinel for missing entities.
var errNotFound = fmt.Errorf("not found")

// Store is a MongoDB implementation of the composite Warden store.
type Store struct {
	db  *grove.DB
	mdb *mongodriver.MongoDB
}

// New creates a new MongoDB store backed by Grove ORM.
func New(db *grove.DB) *Store {
	return &Store{
		db:  db,
		mdb: mongodriver.Unwrap(db),
	}
}

// Migrate creates indexes for all warden collections.
func (s *Store) Migrate(ctx context.Context) error {
	indexes := migrationIndexes()
	for col, models := range indexes {
		if len(models) == 0 {
			continue
		}
		_, err := s.mdb.Collection(col).Indexes().CreateMany(ctx, models)
		if err != nil {
			return fmt.Errorf("warden/mongo: migrate %s indexes: %w", col, err)
		}
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

// now returns the current UTC time.
func now() time.Time {
	return time.Now().UTC()
}

// isNoDocuments checks if an error wraps mongo.ErrNoDocuments.
func isNoDocuments(err error) bool {
	return errors.Is(err, mongod.ErrNoDocuments)
}

// migrationIndexes returns the index definitions for all warden collections.
func migrationIndexes() map[string][]mongod.IndexModel {
	return map[string][]mongod.IndexModel{
		colRoles: {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "slug", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "parent_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "is_system", Value: 1}}},
		},
		colPermissions: {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "resource", Value: 1}, {Key: "action", Value: 1}}},
		},
		colRolePermissions: {
			{
				Keys:    bson.D{{Key: "role_id", Value: 1}, {Key: "permission_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "role_id", Value: 1}}},
			{Keys: bson.D{{Key: "permission_id", Value: 1}}},
		},
		colAssignments: {
			{
				Keys: bson.D{
					{Key: "tenant_id", Value: 1},
					{Key: "role_id", Value: 1},
					{Key: "subject_kind", Value: 1},
					{Key: "subject_id", Value: 1},
					{Key: "resource_type", Value: 1},
					{Key: "resource_id", Value: 1},
				},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_kind", Value: 1}, {Key: "subject_id", Value: 1}}},
			{Keys: bson.D{{Key: "role_id", Value: 1}}},
			{Keys: bson.D{{Key: "expires_at", Value: 1}}},
		},
		colRelations: {
			{
				Keys: bson.D{
					{Key: "tenant_id", Value: 1},
					{Key: "object_type", Value: 1},
					{Key: "object_id", Value: 1},
					{Key: "relation", Value: 1},
					{Key: "subject_type", Value: 1},
					{Key: "subject_id", Value: 1},
					{Key: "subject_relation", Value: 1},
				},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "object_type", Value: 1}, {Key: "object_id", Value: 1}, {Key: "relation", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_type", Value: 1}, {Key: "subject_id", Value: 1}, {Key: "relation", Value: 1}}},
		},
		colPolicies: {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "is_active", Value: 1}, {Key: "priority", Value: 1}}},
		},
		colResourceTypes: {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
		},
		colCheckLogs: {
			{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_kind", Value: 1}, {Key: "subject_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "resource_type", Value: 1}, {Key: "resource_id", Value: 1}}},
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "decision", Value: 1}}},
			{Keys: bson.D{{Key: "created_at", Value: -1}}},
		},
	}
}

// ──────────────────────────────────────────────────
// Role operations
// ──────────────────────────────────────────────────

func (s *Store) CreateRole(ctx context.Context, r *role.Role) error {
	t := now()
	r.CreatedAt = t
	r.UpdatedAt = t
	m := roleToModel(r)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, roleID id.RoleID) (*role.Role, error) {
	var m roleModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": roleID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("role %s: %w", roleID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get role: %w", err)
	}
	return roleFromModel(&m), nil
}

func (s *Store) GetRoleBySlug(ctx context.Context, tenantID, slug string) (*role.Role, error) {
	var m roleModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "slug": slug}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("role slug %q: %w", slug, errNotFound)
		}
		return nil, fmt.Errorf("warden: get role by slug: %w", err)
	}
	return roleFromModel(&m), nil
}

func (s *Store) UpdateRole(ctx context.Context, r *role.Role) error {
	r.UpdatedAt = now()
	m := roleToModel(r)
	res, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"_id": m.ID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update role: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("role %s: %w", r.ID, errNotFound)
	}
	return nil
}

func (s *Store) DeleteRole(ctx context.Context, roleID id.RoleID) error {
	_, err := s.mdb.NewDelete((*roleModel)(nil)).
		Filter(bson.M{"_id": roleID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete role: %w", err)
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context, filter *role.ListFilter) ([]*role.Role, error) {
	var models []roleModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.IsSystem != nil {
			f["is_system"] = *filter.IsSystem
		}
		if filter.IsDefault != nil {
			f["is_default"] = *filter.IsDefault
		}
		if filter.ParentID != nil {
			f["parent_id"] = filter.ParentID.String()
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.IsSystem != nil {
			f["is_system"] = *filter.IsSystem
		}
		if filter.IsDefault != nil {
			f["is_default"] = *filter.IsDefault
		}
		if filter.ParentID != nil {
			f["parent_id"] = filter.ParentID.String()
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	count, err := s.mdb.NewFind((*roleModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count roles: %w", err)
	}
	return count, nil
}

func (s *Store) ListRolePermissions(ctx context.Context, roleID id.RoleID) ([]id.PermissionID, error) {
	var models []rolePermissionModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"role_id": roleID.String()}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list role permissions: %w", err)
	}
	result := make([]id.PermissionID, 0, len(models))
	for _, m := range models {
		pid, err := id.ParsePermissionID(m.PermissionID)
		if err == nil {
			result = append(result, pid)
		}
	}
	return result, nil
}

func (s *Store) AttachPermission(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error {
	m := &rolePermissionModel{
		RoleID:       roleID.String(),
		PermissionID: permID.String(),
	}
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	if err != nil {
		if mongod.IsDuplicateKeyError(err) {
			return nil // already attached
		}
		return fmt.Errorf("warden: attach permission: %w", err)
	}
	return nil
}

func (s *Store) DetachPermission(ctx context.Context, roleID id.RoleID, permID id.PermissionID) error {
	_, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Filter(bson.M{"role_id": roleID.String(), "permission_id": permID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: detach permission: %w", err)
	}
	return nil
}

func (s *Store) SetRolePermissions(ctx context.Context, roleID id.RoleID, permIDs []id.PermissionID) error {
	// Delete all existing role permissions.
	_, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Many().
		Filter(bson.M{"role_id": roleID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: clear role permissions: %w", err)
	}

	// Insert new permissions.
	if len(permIDs) > 0 {
		models := make([]rolePermissionModel, len(permIDs))
		for i, pid := range permIDs {
			models[i] = rolePermissionModel{
				RoleID:       roleID.String(),
				PermissionID: pid.String(),
			}
		}
		if _, err := s.mdb.NewInsert(&models).Exec(ctx); err != nil {
			return fmt.Errorf("warden: set role permissions: %w", err)
		}
	}
	return nil
}

func (s *Store) ListChildRoles(ctx context.Context, parentID id.RoleID) ([]*role.Role, error) {
	var models []roleModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"parent_id": parentID.String()}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list child roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		result[i] = roleFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeleteRolesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*roleModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete roles by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Permission operations
// ──────────────────────────────────────────────────

func (s *Store) CreatePermission(ctx context.Context, p *permission.Permission) error {
	t := now()
	p.CreatedAt = t
	p.UpdatedAt = t
	m := permissionToModel(p)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create permission: %w", err)
	}
	return nil
}

func (s *Store) GetPermission(ctx context.Context, permID id.PermissionID) (*permission.Permission, error) {
	var m permissionModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": permID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("permission %s: %w", permID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get permission: %w", err)
	}
	return permissionFromModel(&m), nil
}

func (s *Store) GetPermissionByName(ctx context.Context, tenantID, name string) (*permission.Permission, error) {
	var m permissionModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("permission %q: %w", name, errNotFound)
		}
		return nil, fmt.Errorf("warden: get permission by name: %w", err)
	}
	return permissionFromModel(&m), nil
}

func (s *Store) UpdatePermission(ctx context.Context, p *permission.Permission) error {
	p.UpdatedAt = now()
	m := permissionToModel(p)
	res, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"_id": m.ID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update permission: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("permission %s: %w", p.ID, errNotFound)
	}
	return nil
}

func (s *Store) DeletePermission(ctx context.Context, permID id.PermissionID) error {
	_, err := s.mdb.NewDelete((*permissionModel)(nil)).
		Filter(bson.M{"_id": permID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permission: %w", err)
	}
	return nil
}

func (s *Store) ListPermissions(ctx context.Context, filter *permission.ListFilter) ([]*permission.Permission, error) {
	var models []permissionModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Resource != "" {
			f["resource"] = filter.Resource
		}
		if filter.Action != "" {
			f["action"] = filter.Action
		}
		if filter.IsSystem != nil {
			f["is_system"] = *filter.IsSystem
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Resource != "" {
			f["resource"] = filter.Resource
		}
		if filter.Action != "" {
			f["action"] = filter.Action
		}
		if filter.IsSystem != nil {
			f["is_system"] = *filter.IsSystem
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	count, err := s.mdb.NewFind((*permissionModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count permissions: %w", err)
	}
	return count, nil
}

func (s *Store) ListPermissionsByRole(ctx context.Context, roleID id.RoleID) ([]*permission.Permission, error) {
	// Query the role_permissions collection for permission IDs.
	var rpModels []rolePermissionModel
	if err := s.mdb.NewFind(&rpModels).
		Filter(bson.M{"role_id": roleID.String()}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by role: %w", err)
	}
	if len(rpModels) == 0 {
		return []*permission.Permission{}, nil
	}

	permIDs := make([]string, len(rpModels))
	for i, rp := range rpModels {
		permIDs[i] = rp.PermissionID
	}

	var models []permissionModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"_id": bson.M{"$in": permIDs}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by role: %w", err)
	}
	result := make([]*permission.Permission, len(models))
	for i := range models {
		result[i] = permissionFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) ListPermissionsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]*permission.Permission, error) {
	// Step 1: Find all role IDs assigned to the subject.
	var assignModels []assignmentModel
	if err := s.mdb.NewFind(&assignModels).
		Filter(bson.M{
			"tenant_id":    tenantID,
			"subject_kind": subjectKind,
			"subject_id":   subjectID,
		}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	if len(assignModels) == 0 {
		return []*permission.Permission{}, nil
	}

	roleIDs := make([]string, len(assignModels))
	for i, a := range assignModels {
		roleIDs[i] = a.RoleID
	}

	// Step 2: Find all permission IDs for those roles.
	var rpModels []rolePermissionModel
	if err := s.mdb.NewFind(&rpModels).
		Filter(bson.M{"role_id": bson.M{"$in": roleIDs}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	if len(rpModels) == 0 {
		return []*permission.Permission{}, nil
	}

	// Deduplicate.
	seen := make(map[string]struct{})
	permIDs := make([]string, 0, len(rpModels))
	for _, rp := range rpModels {
		if _, exists := seen[rp.PermissionID]; !exists {
			seen[rp.PermissionID] = struct{}{}
			permIDs = append(permIDs, rp.PermissionID)
		}
	}

	// Step 3: Load the permissions.
	var models []permissionModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"_id": bson.M{"$in": permIDs}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	result := make([]*permission.Permission, len(models))
	for i := range models {
		result[i] = permissionFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeletePermissionsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*permissionModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permissions by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Assignment operations
// ──────────────────────────────────────────────────

func (s *Store) CreateAssignment(ctx context.Context, a *assignment.Assignment) error {
	a.CreatedAt = now()
	m := assignmentToModel(a)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create assignment: %w", err)
	}
	return nil
}

func (s *Store) GetAssignment(ctx context.Context, assID id.AssignmentID) (*assignment.Assignment, error) {
	var m assignmentModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": assID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("assignment %s: %w", assID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get assignment: %w", err)
	}
	return assignmentFromModel(&m), nil
}

func (s *Store) DeleteAssignment(ctx context.Context, assID id.AssignmentID) error {
	_, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Filter(bson.M{"_id": assID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignment: %w", err)
	}
	return nil
}

func (s *Store) ListAssignments(ctx context.Context, filter *assignment.ListFilter) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.RoleID != nil {
			f["role_id"] = filter.RoleID.String()
		}
		if filter.SubjectKind != "" {
			f["subject_kind"] = filter.SubjectKind
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.ResourceType != "" {
			f["resource_type"] = filter.ResourceType
		}
		if filter.ResourceID != "" {
			f["resource_id"] = filter.ResourceID
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.RoleID != nil {
			f["role_id"] = filter.RoleID.String()
		}
		if filter.SubjectKind != "" {
			f["subject_kind"] = filter.SubjectKind
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.ResourceType != "" {
			f["resource_type"] = filter.ResourceType
		}
		if filter.ResourceID != "" {
			f["resource_id"] = filter.ResourceID
		}
	}
	count, err := s.mdb.NewFind((*assignmentModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count assignments: %w", err)
	}
	return count, nil
}

func (s *Store) ListRolesForSubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]id.RoleID, error) {
	var models []assignmentModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":     tenantID,
			"subject_kind":  subjectKind,
			"subject_id":    subjectID,
			"resource_type": "",
		}).
		Scan(ctx); err != nil {
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

func (s *Store) ListRolesForSubjectOnResource(ctx context.Context, tenantID, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error) {
	var models []assignmentModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":     tenantID,
			"subject_kind":  subjectKind,
			"subject_id":    subjectID,
			"resource_type": resourceType,
			"resource_id":   resourceID,
		}).
		Scan(ctx); err != nil {
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
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"role_id": roleID.String()}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list subjects for role: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		result[i] = assignmentFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) DeleteExpiredAssignments(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{
			"expires_at": bson.M{
				"$ne": nil,
				"$lt": t,
			},
		}).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: delete expired assignments: %w", err)
	}
	return res.DeletedCount(), nil
}

func (s *Store) DeleteAssignmentsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) error {
	_, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":    tenantID,
			"subject_kind": subjectKind,
			"subject_id":   subjectID,
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by subject: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByRole(ctx context.Context, roleID id.RoleID) error {
	_, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{"role_id": roleID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by role: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Relation (tuple) operations
// ──────────────────────────────────────────────────

func (s *Store) CreateRelation(ctx context.Context, t *relation.Tuple) error {
	t.CreatedAt = now()
	m := relationToModel(t)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create relation: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelation(ctx context.Context, relID id.RelationID) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Filter(bson.M{"_id": relID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationTuple(ctx context.Context, tenantID, objectType, objectID, rel, subjectType, subjectID string) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":    tenantID,
			"object_type":  objectType,
			"object_id":    objectID,
			"relation":     rel,
			"subject_type": subjectType,
			"subject_id":   subjectID,
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation tuple: %w", err)
	}
	return nil
}

func (s *Store) ListRelations(ctx context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error) {
	var models []relationModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.ObjectType != "" {
			f["object_type"] = filter.ObjectType
		}
		if filter.ObjectID != "" {
			f["object_id"] = filter.ObjectID
		}
		if filter.Relation != "" {
			f["relation"] = filter.Relation
		}
		if filter.SubjectType != "" {
			f["subject_type"] = filter.SubjectType
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.SubjectRelation != "" {
			f["subject_relation"] = filter.SubjectRelation
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.ObjectType != "" {
			f["object_type"] = filter.ObjectType
		}
		if filter.ObjectID != "" {
			f["object_id"] = filter.ObjectID
		}
		if filter.Relation != "" {
			f["relation"] = filter.Relation
		}
		if filter.SubjectType != "" {
			f["subject_type"] = filter.SubjectType
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.SubjectRelation != "" {
			f["subject_relation"] = filter.SubjectRelation
		}
	}
	count, err := s.mdb.NewFind((*relationModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count relations: %w", err)
	}
	return count, nil
}

func (s *Store) ListRelationSubjects(ctx context.Context, tenantID, objectType, objectID, rel string) ([]*relation.Tuple, error) {
	var models []relationModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":   tenantID,
			"object_type": objectType,
			"object_id":   objectID,
			"relation":    rel,
		}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relation subjects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) ListRelationObjects(ctx context.Context, tenantID, subjectType, subjectID, rel string) ([]*relation.Tuple, error) {
	var models []relationModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":    tenantID,
			"subject_type": subjectType,
			"subject_id":   subjectID,
			"relation":     rel,
		}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relation objects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CheckDirectRelation(ctx context.Context, tenantID, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	count, err := s.mdb.NewFind((*relationModel)(nil)).
		Filter(bson.M{
			"tenant_id":    tenantID,
			"object_type":  objectType,
			"object_id":    objectID,
			"relation":     rel,
			"subject_type": subjectType,
			"subject_id":   subjectID,
		}).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("warden: check direct relation: %w", err)
	}
	return count > 0, nil
}

func (s *Store) DeleteRelationsByObject(ctx context.Context, tenantID, objectType, objectID string) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":   tenantID,
			"object_type": objectType,
			"object_id":   objectID,
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by object: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationsBySubject(ctx context.Context, tenantID, subjectType, subjectID string) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":    tenantID,
			"subject_type": subjectType,
			"subject_id":   subjectID,
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by subject: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelationsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relations by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Policy operations (ABAC)
// ──────────────────────────────────────────────────

func (s *Store) CreatePolicy(ctx context.Context, p *policy.Policy) error {
	t := now()
	p.CreatedAt = t
	p.UpdatedAt = t
	m := policyToModel(p)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, polID id.PolicyID) (*policy.Policy, error) {
	var m policyModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": polID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("policy %s: %w", polID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get policy: %w", err)
	}
	return policyFromModel(&m), nil
}

func (s *Store) GetPolicyByName(ctx context.Context, tenantID, name string) (*policy.Policy, error) {
	var m policyModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("policy %q: %w", name, errNotFound)
		}
		return nil, fmt.Errorf("warden: get policy by name: %w", err)
	}
	return policyFromModel(&m), nil
}

func (s *Store) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	p.UpdatedAt = now()
	m := policyToModel(p)
	res, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"_id": m.ID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update policy: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("policy %s: %w", p.ID, errNotFound)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, polID id.PolicyID) error {
	_, err := s.mdb.NewDelete((*policyModel)(nil)).
		Filter(bson.M{"_id": polID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policy: %w", err)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	var models []policyModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Effect != "" {
			f["effect"] = string(filter.Effect)
		}
		if filter.IsActive != nil {
			f["is_active"] = *filter.IsActive
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "priority", Value: 1}, {Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Effect != "" {
			f["effect"] = string(filter.Effect)
		}
		if filter.IsActive != nil {
			f["is_active"] = *filter.IsActive
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	count, err := s.mdb.NewFind((*policyModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count policies: %w", err)
	}
	return count, nil
}

func (s *Store) ListActivePolicies(ctx context.Context, tenantID string) ([]*policy.Policy, error) {
	var models []policyModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id": tenantID,
			"is_active": true,
		}).
		Sort(bson.D{{Key: "priority", Value: 1}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list active policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		result[i] = policyFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) SetPolicyVersion(ctx context.Context, polID id.PolicyID, version int) error {
	res, err := s.mdb.NewUpdate((*policyModel)(nil)).
		Filter(bson.M{"_id": polID.String()}).
		Set("version", version).
		Set("updated_at", now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: set policy version: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("policy %s: %w", polID, errNotFound)
	}
	return nil
}

func (s *Store) DeletePoliciesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*policyModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policies by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Resource type operations (ReBAC schema)
// ──────────────────────────────────────────────────

func (s *Store) CreateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	t := now()
	rt.CreatedAt = t
	rt.UpdatedAt = t
	m := resourceTypeToModel(rt)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create resource type: %w", err)
	}
	return nil
}

func (s *Store) GetResourceType(ctx context.Context, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	var m resourceTypeModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": rtID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("resource type %s: %w", rtID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type: %w", err)
	}
	return resourceTypeFromModel(&m), nil
}

func (s *Store) GetResourceTypeByName(ctx context.Context, tenantID, name string) (*resourcetype.ResourceType, error) {
	var m resourceTypeModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("resource type %q: %w", name, errNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type by name: %w", err)
	}
	return resourceTypeFromModel(&m), nil
}

func (s *Store) UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	rt.UpdatedAt = now()
	m := resourceTypeToModel(rt)
	res, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"_id": m.ID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update resource type: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("resource type %s: %w", rt.ID, errNotFound)
	}
	return nil
}

func (s *Store) DeleteResourceType(ctx context.Context, rtID id.ResourceTypeID) error {
	_, err := s.mdb.NewDelete((*resourceTypeModel)(nil)).
		Filter(bson.M{"_id": rtID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource type: %w", err)
	}
	return nil
}

func (s *Store) ListResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	var models []resourceTypeModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: 1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.Search != "" {
			f["name"] = bson.M{"$regex": filter.Search, "$options": "i"}
		}
	}
	count, err := s.mdb.NewFind((*resourceTypeModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count resource types: %w", err)
	}
	return count, nil
}

func (s *Store) DeleteResourceTypesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*resourceTypeModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource types by tenant: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────
// Check log operations
// ──────────────────────────────────────────────────

func (s *Store) CreateCheckLog(ctx context.Context, e *checklog.Entry) error {
	e.CreatedAt = now()
	m := checkLogToModel(e)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create check log: %w", err)
	}
	return nil
}

func (s *Store) GetCheckLog(ctx context.Context, logID id.CheckLogID) (*checklog.Entry, error) {
	var m checkLogModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"_id": logID.String()}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("check log %s: %w", logID, errNotFound)
		}
		return nil, fmt.Errorf("warden: get check log: %w", err)
	}
	return checkLogFromModel(&m), nil
}

func (s *Store) ListCheckLogs(ctx context.Context, filter *checklog.QueryFilter) ([]*checklog.Entry, error) {
	var models []checkLogModel
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.SubjectKind != "" {
			f["subject_kind"] = filter.SubjectKind
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.Action != "" {
			f["action"] = filter.Action
		}
		if filter.ResourceType != "" {
			f["resource_type"] = filter.ResourceType
		}
		if filter.ResourceID != "" {
			f["resource_id"] = filter.ResourceID
		}
		if filter.Decision != "" {
			f["decision"] = filter.Decision
		}
		if filter.After != nil || filter.Before != nil {
			dateFilter := bson.M{}
			if filter.After != nil {
				dateFilter["$gte"] = *filter.After
			}
			if filter.Before != nil {
				dateFilter["$lte"] = *filter.Before
			}
			f["created_at"] = dateFilter
		}
	}
	q := s.mdb.NewFind(&models).
		Filter(f).
		Sort(bson.D{{Key: "created_at", Value: -1}})
	if filter != nil {
		if filter.Limit > 0 {
			q = q.Limit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			q = q.Skip(int64(filter.Offset))
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
	f := bson.M{}
	if filter != nil {
		if filter.TenantID != "" {
			f["tenant_id"] = filter.TenantID
		}
		if filter.SubjectKind != "" {
			f["subject_kind"] = filter.SubjectKind
		}
		if filter.SubjectID != "" {
			f["subject_id"] = filter.SubjectID
		}
		if filter.Action != "" {
			f["action"] = filter.Action
		}
		if filter.ResourceType != "" {
			f["resource_type"] = filter.ResourceType
		}
		if filter.ResourceID != "" {
			f["resource_id"] = filter.ResourceID
		}
		if filter.Decision != "" {
			f["decision"] = filter.Decision
		}
		if filter.After != nil || filter.Before != nil {
			dateFilter := bson.M{}
			if filter.After != nil {
				dateFilter["$gte"] = *filter.After
			}
			if filter.Before != nil {
				dateFilter["$lte"] = *filter.Before
			}
			f["created_at"] = dateFilter
		}
	}
	count, err := s.mdb.NewFind((*checkLogModel)(nil)).
		Filter(f).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count check logs: %w", err)
	}
	return count, nil
}

func (s *Store) PurgeCheckLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.mdb.NewDelete((*checkLogModel)(nil)).
		Many().
		Filter(bson.M{"created_at": bson.M{"$lt": before}}).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs: %w", err)
	}
	return res.DeletedCount(), nil
}

func (s *Store) DeleteCheckLogsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.mdb.NewDelete((*checkLogModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete check logs by tenant: %w", err)
	}
	return nil
}
