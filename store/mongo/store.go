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
	"github.com/xraph/warden/wardenerr"
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

// defaultFanout caps a relation hop or an access-review page when the caller
// passes 0.
const defaultFanout = 1000

// fanoutLimit resolves a caller-supplied limit: 0 (or negative) means the
// default.
func fanoutLimit(limit int) int {
	if limit <= 0 {
		return defaultFanout
	}
	return limit
}

// byID builds the filter every by-ID operation uses. The tenant is part of
// the key, so a document owned by someone else simply does not match.
func byID(tenantID, docID string) bson.M {
	return bson.M{"_id": docID, "tenant_id": tenantID}
}

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
			{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "parent_slug", Value: 1}}},
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
				Keys: bson.D{
					{Key: "role_id", Value: 1},
					{Key: "perm_namespace_path", Value: 1},
					{Key: "perm_name", Value: 1},
				},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "role_id", Value: 1}}},
			{Keys: bson.D{{Key: "perm_namespace_path", Value: 1}, {Key: "perm_name", Value: 1}}},
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
	if r.ID.IsNil() {
		r.ID = id.NewRoleID()
	}
	t := now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = t
	}
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = t
	}
	m := roleToModel(r)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, tenantID string, roleID id.RoleID) (*role.Role, error) {
	var m roleModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, roleID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("warden: get role: %w", err)
	}
	return roleFromModel(&m), nil
}

func (s *Store) GetRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) ([]*role.Role, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	var models []roleModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"tenant_id": tenantID, "_id": bson.M{"$in": roleIDStrings(roleIDs)}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: get roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		result[i] = roleFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*role.Role, error) {
	var m roleModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "namespace_path": namespacePath, "slug": slug}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("role slug %q in ns %q: %w", slug, namespacePath, wardenerr.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("warden: get role by slug: %w", err)
	}
	return roleFromModel(&m), nil
}

func (s *Store) UpdateRole(ctx context.Context, r *role.Role) error {
	r.UpdatedAt = now()
	m := roleToModel(r)
	res, err := s.mdb.NewUpdate(m).
		Filter(byID(r.TenantID, m.ID)).
		SetUpdate(bson.M{"$set": roleUpdateDoc(m)}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update role: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("role %s: %w", r.ID, wardenerr.ErrRoleNotFound)
	}
	return nil
}

// DeleteRole removes a role and the rows that hang off it. Mongo has no
// foreign keys, so the grants and assignments are cleaned up here.
func (s *Store) DeleteRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	res, err := s.mdb.NewDelete((*roleModel)(nil)).
		Filter(byID(tenantID, roleID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete role: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	if _, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Many().
		Filter(bson.M{"role_id": roleID.String()}).
		Exec(ctx); err != nil {
		return fmt.Errorf("warden: delete role grants: %w", err)
	}
	if _, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID, "role_id": roleID.String()}).
		Exec(ctx); err != nil {
		return fmt.Errorf("warden: delete role assignments: %w", err)
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
		if filter.ParentSlug != nil {
			f["parent_slug"] = *filter.ParentSlug
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
		if filter.ParentSlug != nil {
			f["parent_slug"] = *filter.ParentSlug
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

// ListRolePermissions walks the junction's natural keys (perm_namespace_path,
// perm_name) into the permissions collection, scoped to the role's tenant.
// Mongo doesn't have JOINs, so we do the lookup in two steps: junction
// rows for this role, then a single permissions Find with $in.
func (s *Store) ListRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	byRole, err := s.ListRolePermissionsForRoles(ctx, tenantID, []id.RoleID{roleID})
	if err != nil {
		return nil, err
	}
	return byRole[roleID], nil
}

// ListRolePermissionsForRoles resolves the grants of several roles at once.
// Mongo has no JOINs, so it runs in three steps: the roles that really are in
// the tenant, their junction rows, then one permissions lookup for every
// distinct natural key those rows name.
func (s *Store) ListRolePermissionsForRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	result := make(map[id.RoleID][]*permission.Permission, len(roleIDs))
	if len(roleIDs) == 0 {
		return result, nil
	}
	owned, err := s.GetRoles(ctx, tenantID, roleIDs)
	if err != nil {
		return nil, err
	}
	if len(owned) == 0 {
		return result, nil
	}
	ownedIDs := make([]string, len(owned))
	for i, r := range owned {
		ownedIDs[i] = r.ID.String()
	}

	var rps []rolePermissionModel
	if err := s.mdb.NewFind(&rps).
		Filter(bson.M{"role_id": bson.M{"$in": ownedIDs}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list role permissions: %w", err)
	}
	if len(rps) == 0 {
		return result, nil
	}

	// One permissions lookup for every distinct (namespace_path, name) the
	// junction names, AND-merged with the tenant.
	seen := make(map[string]struct{}, len(rps))
	or := make([]bson.M, 0, len(rps))
	for _, rp := range rps {
		key := rp.PermNamespacePath + "\x00" + rp.PermName
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		or = append(or, bson.M{"namespace_path": rp.PermNamespacePath, "name": rp.PermName})
	}
	var pms []permissionModel
	if err := s.mdb.NewFind(&pms).
		Filter(bson.M{"tenant_id": tenantID, "$or": or}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list role permissions (resolve): %w", err)
	}
	byKey := make(map[string]*permission.Permission, len(pms))
	for i := range pms {
		byKey[pms[i].NamespacePath+"\x00"+pms[i].Name] = permissionFromModel(&pms[i])
	}

	for _, rp := range rps {
		p, ok := byKey[rp.PermNamespacePath+"\x00"+rp.PermName]
		if !ok {
			continue
		}
		rid, parseErr := id.ParseRoleID(rp.RoleID)
		if parseErr != nil {
			continue
		}
		result[rid] = append(result[rid], p)
	}
	return result, nil
}

// requireRole reports whether the role exists in the tenant, so the junction
// writes below cannot be aimed at someone else's role.
func (s *Store) requireRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	count, err := s.mdb.NewFind((*roleModel)(nil)).
		Filter(byID(tenantID, roleID.String())).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("warden: resolve role: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	return nil
}

func (s *Store) AttachPermission(ctx context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error {
	if err := s.requireRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	m := &rolePermissionModel{
		RoleID:            roleID.String(),
		PermNamespacePath: ref.NamespacePath,
		PermName:          ref.Name,
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

func (s *Store) DetachPermission(ctx context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error {
	if err := s.requireRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	_, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Filter(bson.M{
			"role_id":             roleID.String(),
			"perm_namespace_path": ref.NamespacePath,
			"perm_name":           ref.Name,
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: detach permission: %w", err)
	}
	return nil
}

func (s *Store) SetRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID, refs []permission.Ref) error {
	if err := s.requireRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	// Delete all existing role permissions.
	_, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Many().
		Filter(bson.M{"role_id": roleID.String()}).
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
		if _, err := s.mdb.NewInsert(&models).Exec(ctx); err != nil {
			return fmt.Errorf("warden: set role permissions: %w", err)
		}
	}
	return nil
}

func (s *Store) ListChildRoles(ctx context.Context, tenantID, parentSlug string) ([]*role.Role, error) {
	var models []roleModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"tenant_id": tenantID, "parent_slug": parentSlug}).
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
	if p.ID.IsNil() {
		p.ID = id.NewPermissionID()
	}
	t := now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = t
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = t
	}
	m := permissionToModel(p)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create permission: %w", err)
	}
	return nil
}

func (s *Store) GetPermission(ctx context.Context, tenantID string, permID id.PermissionID) (*permission.Permission, error) {
	var m permissionModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, permID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("warden: get permission: %w", err)
	}
	return permissionFromModel(&m), nil
}

func (s *Store) GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*permission.Permission, error) {
	var m permissionModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "namespace_path": namespacePath, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("permission %q in ns %q: %w", name, namespacePath, wardenerr.ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("warden: get permission by name: %w", err)
	}
	return permissionFromModel(&m), nil
}

func (s *Store) UpdatePermission(ctx context.Context, p *permission.Permission) error {
	p.UpdatedAt = now()
	m := permissionToModel(p)
	res, err := s.mdb.NewUpdate(m).
		Filter(byID(p.TenantID, m.ID)).
		SetUpdate(bson.M{"$set": permissionUpdateDoc(m)}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update permission: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("permission %s: %w", p.ID, wardenerr.ErrPermissionNotFound)
	}
	return nil
}

// DeletePermission removes a permission and the junction rows that grant it.
// The junction stores the permission's natural key, not its ID, so the grants
// are matched on (namespace_path, name) and narrowed to the tenant's roles.
func (s *Store) DeletePermission(ctx context.Context, tenantID string, permID id.PermissionID) error {
	p, err := s.GetPermission(ctx, tenantID, permID)
	if err != nil {
		return err
	}
	res, err := s.mdb.NewDelete((*permissionModel)(nil)).
		Filter(byID(tenantID, permID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permission: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
	}

	var roles []roleModel
	if err := s.mdb.NewFind(&roles).
		Filter(bson.M{"tenant_id": tenantID}).
		Scan(ctx); err != nil {
		return fmt.Errorf("warden: delete permission grants: %w", err)
	}
	if len(roles) == 0 {
		return nil
	}
	roleIDs := make([]string, len(roles))
	for i := range roles {
		roleIDs[i] = roles[i].ID
	}
	if _, err := s.mdb.NewDelete((*rolePermissionModel)(nil)).
		Many().
		Filter(bson.M{
			"role_id":             bson.M{"$in": roleIDs},
			"perm_namespace_path": p.NamespacePath,
			"perm_name":           p.Name,
		}).
		Exec(ctx); err != nil {
		return fmt.Errorf("warden: delete permission grants: %w", err)
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

func (s *Store) ListPermissionsByRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	return s.ListRolePermissions(ctx, tenantID, roleID)
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

	// Step 2: Find all (perm_namespace_path, perm_name) refs for those roles.
	var rpModels []rolePermissionModel
	if err := s.mdb.NewFind(&rpModels).
		Filter(bson.M{"role_id": bson.M{"$in": roleIDs}}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	if len(rpModels) == 0 {
		return []*permission.Permission{}, nil
	}

	// Deduplicate by (namespace_path, name).
	seen := make(map[string]struct{})
	or := make([]bson.M, 0, len(rpModels))
	for _, rp := range rpModels {
		key := rp.PermNamespacePath + "\x00" + rp.PermName
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		or = append(or, bson.M{"namespace_path": rp.PermNamespacePath, "name": rp.PermName})
	}

	// Step 3: Load the permissions in this tenant matching the natural keys.
	var models []permissionModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"tenant_id": tenantID, "$or": or}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	result := make([]*permission.Permission, 0, len(models))
	for i := range models {
		result = append(result, permissionFromModel(&models[i]))
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
	if a.ID.IsNil() {
		a.ID = id.NewAssignmentID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now()
	}
	m := assignmentToModel(a)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create assignment: %w", err)
	}
	return nil
}

func (s *Store) GetAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) (*assignment.Assignment, error) {
	var m assignmentModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, assID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
		}
		return nil, fmt.Errorf("warden: get assignment: %w", err)
	}
	return assignmentFromModel(&m), nil
}

func (s *Store) DeleteAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) error {
	res, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Filter(byID(tenantID, assID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignment: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
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

func (s *Store) ListRolesForSubject(ctx context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID string) ([]id.RoleID, error) {
	var models []assignmentModel
	filter := bson.M{
		"tenant_id":     tenantID,
		"subject_kind":  subjectKind,
		"subject_id":    subjectID,
		"resource_type": "",
	}
	if len(namespacePaths) > 0 {
		filter["namespace_path"] = bson.M{"$in": namespacePaths}
	}
	if err := s.mdb.NewFind(&models).Filter(filter).Scan(ctx); err != nil {
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
	filter := bson.M{
		"tenant_id":     tenantID,
		"subject_kind":  subjectKind,
		"subject_id":    subjectID,
		"resource_type": resourceType,
		"resource_id":   resourceID,
	}
	if len(namespacePaths) > 0 {
		filter["namespace_path"] = bson.M{"$in": namespacePaths}
	}
	if err := s.mdb.NewFind(&models).Filter(filter).Scan(ctx); err != nil {
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

func (s *Store) ListSubjectsForRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{"tenant_id": tenantID, "role_id": roleID.String()}).
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

func (s *Store) ListExpiringAssignments(ctx context.Context, tenantID string, before time.Time, limit int) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":  tenantID,
			"expires_at": bson.M{"$ne": nil, "$lt": before},
		}).
		Sort(bson.D{{Key: "expires_at", Value: 1}}).
		Limit(int64(fanoutLimit(limit))).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list expiring assignments: %w", err)
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

func (s *Store) DeleteAssignmentsByRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	_, err := s.mdb.NewDelete((*assignmentModel)(nil)).
		Many().
		Filter(bson.M{"tenant_id": tenantID, "role_id": roleID.String()}).
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
	if t.ID.IsNil() {
		t.ID = id.NewRelationID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now()
	}
	m := relationToModel(t)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create relation: %w", err)
	}
	return nil
}

func (s *Store) DeleteRelation(ctx context.Context, tenantID string, relID id.RelationID) error {
	res, err := s.mdb.NewDelete((*relationModel)(nil)).
		Filter(byID(tenantID, relID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("relation %s: %w", relID, wardenerr.ErrRelationNotFound)
	}
	return nil
}

func (s *Store) DeleteRelationTuple(ctx context.Context, tenantID, namespacePath, objectType, objectID, rel, subjectType, subjectID string) error {
	_, err := s.mdb.NewDelete((*relationModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":      tenantID,
			"namespace_path": namespacePath,
			"object_type":    objectType,
			"object_id":      objectID,
			"relation":       rel,
			"subject_type":   subjectType,
			"subject_id":     subjectID,
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

func (s *Store) ListRelationSubjects(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel string, limit int) ([]*relation.Tuple, error) {
	var models []relationModel
	filter := bson.M{
		"tenant_id":   tenantID,
		"object_type": objectType,
		"object_id":   objectID,
		"relation":    rel,
	}
	if len(namespacePaths) > 0 {
		filter["namespace_path"] = bson.M{"$in": namespacePaths}
	}
	if err := s.mdb.NewFind(&models).
		Filter(filter).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Limit(int64(fanoutLimit(limit))).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relation subjects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) ListRelationObjects(ctx context.Context, tenantID, namespacePath, subjectType, subjectID, rel string, limit int) ([]*relation.Tuple, error) {
	var models []relationModel
	if err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"tenant_id":      tenantID,
			"namespace_path": namespacePath,
			"subject_type":   subjectType,
			"subject_id":     subjectID,
			"relation":       rel,
		}).
		Sort(bson.D{{Key: "created_at", Value: 1}}).
		Limit(int64(fanoutLimit(limit))).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relation objects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		result[i] = relationFromModel(&models[i])
	}
	return result, nil
}

func (s *Store) CheckDirectRelation(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	filter := bson.M{
		"tenant_id":    tenantID,
		"object_type":  objectType,
		"object_id":    objectID,
		"relation":     rel,
		"subject_type": subjectType,
		"subject_id":   subjectID,
	}
	if len(namespacePaths) > 0 {
		filter["namespace_path"] = bson.M{"$in": namespacePaths}
	}
	count, err := s.mdb.NewFind((*relationModel)(nil)).
		Filter(filter).
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
	if p.ID.IsNil() {
		p.ID = id.NewPolicyID()
	}
	t := now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = t
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = t
	}
	m := policyToModel(p)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, tenantID string, polID id.PolicyID) (*policy.Policy, error) {
	var m policyModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, polID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("warden: get policy: %w", err)
	}
	return policyFromModel(&m), nil
}

func (s *Store) GetPolicyByName(ctx context.Context, tenantID, namespacePath, name string) (*policy.Policy, error) {
	var m policyModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "namespace_path": namespacePath, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("policy %q in ns %q: %w", name, namespacePath, wardenerr.ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("warden: get policy by name: %w", err)
	}
	return policyFromModel(&m), nil
}

func (s *Store) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	p.UpdatedAt = now()
	m := policyToModel(p)
	res, err := s.mdb.NewUpdate(m).
		Filter(byID(p.TenantID, m.ID)).
		SetUpdate(bson.M{"$set": policyUpdateDoc(m)}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update policy: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("policy %s: %w", p.ID, wardenerr.ErrPolicyNotFound)
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, tenantID string, polID id.PolicyID) error {
	res, err := s.mdb.NewDelete((*policyModel)(nil)).
		Filter(byID(tenantID, polID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policy: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
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

func (s *Store) ListActivePolicies(ctx context.Context, tenantID string, namespacePaths []string) ([]*policy.Policy, error) {
	var models []policyModel
	filter := bson.M{
		"tenant_id": tenantID,
		"is_active": true,
	}
	if len(namespacePaths) > 0 {
		filter["namespace_path"] = bson.M{"$in": namespacePaths}
	}
	if err := s.mdb.NewFind(&models).
		Filter(filter).
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

func (s *Store) SetPolicyVersion(ctx context.Context, tenantID string, polID id.PolicyID, version int) error {
	res, err := s.mdb.NewUpdate((*policyModel)(nil)).
		Filter(byID(tenantID, polID.String())).
		Set("version", version).
		Set("updated_at", now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: set policy version: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
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
	if rt.ID.IsNil() {
		rt.ID = id.NewResourceTypeID()
	}
	t := now()
	if rt.CreatedAt.IsZero() {
		rt.CreatedAt = t
	}
	if rt.UpdatedAt.IsZero() {
		rt.UpdatedAt = t
	}
	m := resourceTypeToModel(rt)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create resource type: %w", err)
	}
	return nil
}

func (s *Store) GetResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	var m resourceTypeModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, rtID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type: %w", err)
	}
	return resourceTypeFromModel(&m), nil
}

func (s *Store) GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*resourcetype.ResourceType, error) {
	var m resourceTypeModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"tenant_id": tenantID, "namespace_path": namespacePath, "name": name}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("resource type %q in ns %q: %w", name, namespacePath, wardenerr.ErrResourceTypeNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type by name: %w", err)
	}
	return resourceTypeFromModel(&m), nil
}

func (s *Store) UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	rt.UpdatedAt = now()
	m := resourceTypeToModel(rt)
	res, err := s.mdb.NewUpdate(m).
		Filter(byID(rt.TenantID, m.ID)).
		SetUpdate(bson.M{"$set": resourceTypeUpdateDoc(m)}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update resource type: %w", err)
	}
	if res.MatchedCount() == 0 {
		return fmt.Errorf("resource type %s: %w", rt.ID, wardenerr.ErrResourceTypeNotFound)
	}
	return nil
}

func (s *Store) DeleteResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) error {
	res, err := s.mdb.NewDelete((*resourceTypeModel)(nil)).
		Filter(byID(tenantID, rtID.String())).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource type: %w", err)
	}
	if res.DeletedCount() == 0 {
		return fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
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
	if e.ID.IsNil() {
		e.ID = id.NewCheckLogID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now()
	}
	m := checkLogToModel(e)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create check log: %w", err)
	}
	return nil
}

func (s *Store) GetCheckLog(ctx context.Context, tenantID string, logID id.CheckLogID) (*checklog.Entry, error) {
	var m checkLogModel
	err := s.mdb.NewFind(&m).
		Filter(byID(tenantID, logID.String())).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, fmt.Errorf("check log %s: %w", logID, wardenerr.ErrCheckLogNotFound)
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

func (s *Store) DeleteCheckLogsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) (int64, error) {
	res, err := s.mdb.NewDelete((*checkLogModel)(nil)).
		Many().
		Filter(bson.M{
			"tenant_id":    tenantID,
			"subject_kind": subjectKind,
			"subject_id":   subjectID,
		}).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: delete check logs by subject: %w", err)
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

// roleIDStrings renders role IDs for an "$in" filter.
func roleIDStrings(roleIDs []id.RoleID) []string {
	out := make([]string, len(roleIDs))
	for i, rid := range roleIDs {
		out[i] = rid.String()
	}
	return out
}
