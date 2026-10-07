package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/driver"
	"github.com/xraph/grove/drivers/sqlitedriver"
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

// nowFunc returns the current time. Tests override it to pin "now" when
// asserting expiry behavior without sleeping.
var nowFunc = time.Now

// defaultFanout caps a relation hop or an access-review page when the caller
// passes 0.
const defaultFanout = 1000

// defaultListLimit caps any List* call that did not ask for a specific
// limit, so an unbounded filter (or none at all) can't pull an entire table
// into memory in one round trip.
const defaultListLimit = 1000

// listLimit resolves a caller-supplied filter limit: <= 0 means the default.
func listLimit(limit int) int {
	if limit <= 0 {
		return defaultListLimit
	}
	return limit
}

// escapeLike escapes the three characters that are significant to SQLite's
// LIKE operator (the escape character itself, then the two wildcards) so a
// caller-supplied search term is matched literally. Every LIKE built from
// caller input pairs this with "ESCAPE '\'" in the query.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// fanoutLimit resolves a caller-supplied limit: 0 (or negative) means the
// default.
func fanoutLimit(limit int) int {
	if limit <= 0 {
		return defaultFanout
	}
	return limit
}

// rowsChanged reports how many rows a write touched. A driver that cannot
// answer is treated as "nothing changed" so the caller returns not-found
// rather than silently reporting success.
func rowsChanged(res driver.Result) int64 {
	if res == nil {
		return 0
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return n
}

// Columns an UPDATE is allowed to write, per table. tenant_id is absent by
// design: an update matches on (id, tenant_id), so writing tenant_id could
// only ever be a no-op or a tenant move, and a tenant move is not something
// this API offers. created_at is absent for the same reason the memory store
// preserves it.
var (
	roleUpdateColumns = []string{
		"namespace_path", "app_id", "name", "description", "slug",
		"is_system", "is_default", "parent_slug", "max_members", "metadata",
		"updated_by", "updated_at",
	}
	permissionUpdateColumns = []string{
		"namespace_path", "app_id", "name", "description", "resource",
		"action", "is_system", "metadata", "updated_by", "updated_at",
	}
	policyUpdateColumns = []string{
		"namespace_path", "app_id", "name", "description", "effect",
		"priority", "is_active", "not_before", "not_after", "obligations",
		"version", "subjects", "actions", "resources", "conditions",
		"metadata", "updated_by", "updated_at",
	}
	resourceTypeUpdateColumns = []string{
		"namespace_path", "app_id", "name", "description", "relations",
		"permissions", "metadata", "updated_by", "updated_at",
	}
)

// Store is a SQLite implementation of the composite Warden store.
type Store struct {
	db  *grove.DB
	sdb *sqlitedriver.SqliteDB
}

// Option configures a Store at construction time.
type Option func(*storeConfig)

type storeConfig struct {
	busyTimeout time.Duration
}

// WithBusyTimeout returns an Option that sets SQLite's busy_timeout (how
// long a writer waits on a locked database before returning SQLITE_BUSY)
// for the connection New acquires immediately to apply it.
//
// This pragma is per-connection, and grove's sqlite driver hands out
// connections from a pool (default size 10; see sqlitedriver.SqliteDB.Open),
// so a single SET issued here is not guaranteed to reach every connection
// the pool later opens. For a guarantee that covers the whole pool, prefer
// the DSN form documented in this package's doc comment
// (file:foo.db?_pragma=busy_timeout(5000)), which modernc.org/sqlite applies
// to every physical connection at open time. WithBusyTimeout is a
// best-effort supplement for callers who only control the *grove.DB handle.
func WithBusyTimeout(d time.Duration) Option {
	return func(c *storeConfig) { c.busyTimeout = d }
}

// New creates a new SQLite store. See WithBusyTimeout for the caveats of
// setting busy_timeout after the pool already exists.
func New(db *grove.DB, opts ...Option) *Store {
	cfg := &storeConfig{}
	for _, o := range opts {
		o(cfg)
	}
	s := &Store{
		db:  db,
		sdb: sqlitedriver.Unwrap(db),
	}
	if cfg.busyTimeout > 0 {
		ms := cfg.busyTimeout.Milliseconds()
		_, _ = s.sdb.Exec(context.Background(), fmt.Sprintf("PRAGMA busy_timeout = %d", ms)) //nolint:errcheck // best-effort; see WithBusyTimeout doc
	}
	return s
}

// inPlaceholders builds an "IN (?, ?, …)" body and the matching []any args for
// vals. Grove's query builder binds one argument per "?" placeholder and does
// not expand slices, so an "IN (?)" with a []string would bind the whole slice
// to a single placeholder and fail. Callers must emit one placeholder per
// element. Only call this when len(vals) > 0 (an empty IN () is invalid SQL).
func inPlaceholders(vals []string) (placeholders string, args []any) {
	placeholders = strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")
	args = make([]any, len(vals))
	for i, v := range vals {
		args[i] = v
	}
	return placeholders, args
}

// Migrate runs programmatic migrations via the grove orchestrator.
func (s *Store) Migrate(ctx context.Context) error {
	executor, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		return fmt.Errorf("warden/sqlite: create migration executor: %w", err)
	}
	orch := migrate.NewOrchestrator(executor, Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		return fmt.Errorf("warden/sqlite: migration failed: %w", err)
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

// isNoRows checks for the standard sql.ErrNoRows sentinel.
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// isUniqueViolation reports whether err is a sqlite UNIQUE constraint
// violation. Sqlite reports these via error code 19 (SQLITE_CONSTRAINT)
// with the canonical message text "UNIQUE constraint failed". The
// grove driver wraps the underlying sqlite error, so we string-match
// rather than type-assert.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
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
	m, err := roleToModel(r)
	if err != nil {
		return fmt.Errorf("warden: create role: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("role %q in tenant %q ns %q: %w",
				r.Slug, r.TenantID, r.NamespacePath, wardenerr.ErrDuplicateRole)
		}
		return fmt.Errorf("warden: create role: %w", err)
	}
	return nil
}

func (s *Store) GetRole(ctx context.Context, tenantID string, roleID id.RoleID) (*role.Role, error) {
	m := new(roleModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", roleID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("warden: get role: %w", err)
	}
	r, err := roleFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get role: %w", err)
	}
	return r, nil
}

func (s *Store) GetRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) ([]*role.Role, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	ph, args := inPlaceholders(roleIDStrings(roleIDs))
	var models []roleModel
	err := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("id IN ("+ph+")", args...).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: get roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		r, err := roleFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: get roles: %w", err)
		}
		result[i] = r
	}
	return result, nil
}

func (s *Store) GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*role.Role, error) {
	m := new(roleModel)
	err := s.sdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("slug = ?", slug).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("role slug %q in ns %q: %w", slug, namespacePath, wardenerr.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("warden: get role by slug: %w", err)
	}
	r, err := roleFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get role by slug: %w", err)
	}
	return r, nil
}

func (s *Store) UpdateRole(ctx context.Context, r *role.Role) error {
	r.UpdatedAt = time.Now().UTC()
	m, err := roleToModel(r)
	if err != nil {
		return fmt.Errorf("warden: update role: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).
		Column(roleUpdateColumns...).
		WherePK().
		Where("tenant_id = ?", r.TenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update role: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("role %s: %w", r.ID, wardenerr.ErrRoleNotFound)
	}
	return nil
}

// DeleteRole removes a role. Assignments and grants go with it via the
// foreign-key cascades in the schema.
func (s *Store) DeleteRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	res, err := s.sdb.NewDelete((*roleModel)(nil)).
		Where("id = ?", roleID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete role: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context, filter *role.ListFilter) ([]*role.Role, error) {
	var models []roleModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		r, err := roleFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list roles: %w", err)
		}
		result[i] = r
	}
	return result, nil
}

func (s *Store) CountRoles(ctx context.Context, filter *role.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*roleModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count roles: %w", err)
	}
	return count, nil
}

// listRolePermissionsJoinSQL is the JOIN query used by ListRolePermissions
// and ListPermissionsByRole. It walks the junction's natural keys
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
WHERE rp.role_id = ?
  AND r.tenant_id = ?
`

// listRolePermissionsForRolesSQL is the batch form: the same walk for many
// roles at once, with the granting role carried through so the caller can
// group the rows in Go. The IN list is expanded by the caller.
const listRolePermissionsForRolesSQL = `
SELECT rp.role_id,
       p.id, p.tenant_id, p.namespace_path, p.app_id, p.name, p.description,
       p.resource, p.action, p.is_system, p.metadata, p.created_at, p.updated_at
FROM warden_role_permissions rp
JOIN warden_roles r ON r.id = rp.role_id
JOIN warden_permissions p
  ON p.tenant_id = r.tenant_id
 AND p.namespace_path = rp.perm_namespace_path
 AND p.name = rp.perm_name
WHERE r.tenant_id = ?
  AND rp.role_id IN (%s)
`

func (s *Store) ListRolePermissions(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	var models []permissionModel
	if err := s.sdb.NewRaw(listRolePermissionsJoinSQL, roleID.String(), tenantID).Scan(ctx, &models); err != nil {
		return nil, fmt.Errorf("warden: list role permissions: %w", err)
	}
	result := make([]*permission.Permission, 0, len(models))
	for i := range models {
		p, err := permissionFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list role permissions: %w", err)
		}
		result = append(result, p)
	}
	return result, nil
}

func (s *Store) ListRolePermissionsForRoles(ctx context.Context, tenantID string, roleIDs []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	result := make(map[id.RoleID][]*permission.Permission, len(roleIDs))
	if len(roleIDs) == 0 {
		return result, nil
	}
	ph, idArgs := inPlaceholders(roleIDStrings(roleIDs))
	args := append([]any{tenantID}, idArgs...)
	var rows []rolePermissionRow
	query := fmt.Sprintf(listRolePermissionsForRolesSQL, ph)
	if err := s.sdb.NewRaw(query, args...).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("warden: list role permissions for roles: %w", err)
	}
	for i := range rows {
		rid, parseErr := id.ParseRoleID(rows[i].RoleID)
		if parseErr != nil {
			continue
		}
		p, err := permissionFromModel(rows[i].permission())
		if err != nil {
			return nil, fmt.Errorf("warden: list role permissions for roles: %w", err)
		}
		result[rid] = append(result[rid], p)
	}
	return result, nil
}

// requireRole reports whether the role exists in the tenant, so the junction
// writes below cannot be aimed at someone else's role.
func (s *Store) requireRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	count, err := s.sdb.NewSelect((*roleModel)(nil)).
		Where("id = ?", roleID.String()).
		Where("tenant_id = ?", tenantID).
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
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("warden: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on error is intentional

	count, err := tx.NewSelect((*permissionModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", ref.NamespacePath).
		Where("name = ?", ref.Name).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("warden: resolve permission: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("permission %q in ns %q: %w", ref.Name, ref.NamespacePath, wardenerr.ErrPermissionNotFound)
	}

	m := &rolePermissionModel{
		RoleID:            roleID.String(),
		PermNamespacePath: ref.NamespacePath,
		PermName:          ref.Name,
		TenantID:          tenantID,
	}
	if _, err := tx.NewInsert(m).
		OnConflict("(role_id, perm_namespace_path, perm_name) DO NOTHING").
		Exec(ctx); err != nil {
		return fmt.Errorf("warden: attach permission: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warden: commit tx: %w", err)
	}
	return nil
}

func (s *Store) DetachPermission(ctx context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error {
	if err := s.requireRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	_, err := s.sdb.NewDelete((*rolePermissionModel)(nil)).
		Where("role_id = ?", roleID.String()).
		Where("perm_namespace_path = ?", ref.NamespacePath).
		Where("perm_name = ?", ref.Name).
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
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("warden: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on error is intentional

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
				TenantID:          tenantID,
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
	err := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("parent_slug = ?", parentSlug).
		OrderExpr("created_at ASC, id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list child roles: %w", err)
	}
	result := make([]*role.Role, len(models))
	for i := range models {
		r, err := roleFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list child roles: %w", err)
		}
		result[i] = r
	}
	return result, nil
}

func (s *Store) DeleteRolesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*roleModel)(nil)).
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
	m, err := permissionToModel(p)
	if err != nil {
		return fmt.Errorf("warden: create permission: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("permission %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePermission)
		}
		return fmt.Errorf("warden: create permission: %w", err)
	}
	return nil
}

func (s *Store) GetPermission(ctx context.Context, tenantID string, permID id.PermissionID) (*permission.Permission, error) {
	m := new(permissionModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", permID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("warden: get permission: %w", err)
	}
	p, err := permissionFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get permission: %w", err)
	}
	return p, nil
}

func (s *Store) GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*permission.Permission, error) {
	m := new(permissionModel)
	err := s.sdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("permission %q in ns %q: %w", name, namespacePath, wardenerr.ErrPermissionNotFound)
		}
		return nil, fmt.Errorf("warden: get permission by name: %w", err)
	}
	p, err := permissionFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get permission by name: %w", err)
	}
	return p, nil
}

func (s *Store) UpdatePermission(ctx context.Context, p *permission.Permission) error {
	p.UpdatedAt = time.Now().UTC()
	m, err := permissionToModel(p)
	if err != nil {
		return fmt.Errorf("warden: update permission: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).
		Column(permissionUpdateColumns...).
		WherePK().
		Where("tenant_id = ?", p.TenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update permission: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("permission %s: %w", p.ID, wardenerr.ErrPermissionNotFound)
	}
	return nil
}

// deletePermissionGrantsSQL scrubs the junction rows that grant a permission.
// The junction stores the permission's natural key, not its ID, so the rows
// have to be matched on (namespace_path, name) and narrowed to the roles of
// the deleting tenant.
const deletePermissionGrantsSQL = `
DELETE FROM warden_role_permissions
WHERE perm_namespace_path = ?
  AND perm_name = ?
  AND role_id IN (SELECT id FROM warden_roles WHERE tenant_id = ?)
`

func (s *Store) DeletePermission(ctx context.Context, tenantID string, permID id.PermissionID) error {
	p, err := s.GetPermission(ctx, tenantID, permID)
	if err != nil {
		return err
	}

	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("warden: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on error is intentional

	res, err := tx.NewDelete((*permissionModel)(nil)).
		Where("id = ?", permID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete permission: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
	}
	if _, err := tx.NewRaw(deletePermissionGrantsSQL, p.NamespacePath, p.Name, tenantID).Exec(ctx); err != nil {
		return fmt.Errorf("warden: delete permission grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warden: commit tx: %w", err)
	}
	return nil
}

func (s *Store) ListPermissions(ctx context.Context, filter *permission.ListFilter) ([]*permission.Permission, error) {
	var models []permissionModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list permissions: %w", err)
	}
	result := make([]*permission.Permission, len(models))
	for i := range models {
		p, err := permissionFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list permissions: %w", err)
		}
		result[i] = p
	}
	return result, nil
}

func (s *Store) CountPermissions(ctx context.Context, filter *permission.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*permissionModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count permissions: %w", err)
	}
	return count, nil
}

func (s *Store) ListPermissionsByRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	return s.ListRolePermissions(ctx, tenantID, roleID)
}

// listPermissionsBySubjectSQL walks assignment → role_permissions → permissions
// in a single query, returning DISTINCT rows so a permission granted via
// multiple roles isn't duplicated.
const listPermissionsBySubjectSQL = `
SELECT DISTINCT p.id, p.tenant_id, p.namespace_path, p.app_id, p.name, p.description,
       p.resource, p.action, p.is_system, p.metadata, p.created_at, p.updated_at
FROM warden_assignments a
JOIN warden_role_permissions rp ON rp.role_id = a.role_id
JOIN warden_permissions p
  ON p.tenant_id = a.tenant_id
 AND p.namespace_path = rp.perm_namespace_path
 AND p.name = rp.perm_name
WHERE a.tenant_id = ?
  AND a.subject_kind = ?
  AND a.subject_id = ?
`

func (s *Store) ListPermissionsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) ([]*permission.Permission, error) {
	var models []permissionModel
	if err := s.sdb.NewRaw(listPermissionsBySubjectSQL, tenantID, subjectKind, subjectID).Scan(ctx, &models); err != nil {
		return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
	}
	result := make([]*permission.Permission, 0, len(models))
	for i := range models {
		p, err := permissionFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list permissions by subject: %w", err)
		}
		result = append(result, p)
	}
	return result, nil
}

func (s *Store) DeletePermissionsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*permissionModel)(nil)).
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
	m, err := assignmentToModel(a)
	if err != nil {
		return fmt.Errorf("warden: create assignment: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("assignment role=%s subject=%s:%s in tenant %q ns %q: %w",
				a.RoleID, a.SubjectKind, a.SubjectID, a.TenantID, a.NamespacePath,
				wardenerr.ErrDuplicateAssignment)
		}
		return fmt.Errorf("warden: create assignment: %w", err)
	}
	return nil
}

func (s *Store) GetAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) (*assignment.Assignment, error) {
	m := new(assignmentModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", assID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
		}
		return nil, fmt.Errorf("warden: get assignment: %w", err)
	}
	a, err := assignmentFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get assignment: %w", err)
	}
	return a, nil
}

func (s *Store) DeleteAssignment(ctx context.Context, tenantID string, assID id.AssignmentID) error {
	res, err := s.sdb.NewDelete((*assignmentModel)(nil)).
		Where("id = ?", assID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignment: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
	}
	return nil
}

func (s *Store) ListAssignments(ctx context.Context, filter *assignment.ListFilter) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list assignments: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		a, err := assignmentFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list assignments: %w", err)
		}
		result[i] = a
	}
	return result, nil
}

func (s *Store) CountAssignments(ctx context.Context, filter *assignment.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*assignmentModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
	q := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Where("resource_type = ''").
		Where("(expires_at IS NULL OR expires_at > ?)", sqliteTime(nowFunc()))
	if len(namespacePaths) > 0 {
		ph, nsArgs := inPlaceholders(namespacePaths)
		q = q.Where("namespace_path IN ("+ph+")", nsArgs...)
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
	q := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Where("resource_type = ?", resourceType).
		Where("resource_id = ?", resourceID).
		Where("(expires_at IS NULL OR expires_at > ?)", sqliteTime(nowFunc()))
	if len(namespacePaths) > 0 {
		ph, nsArgs := inPlaceholders(namespacePaths)
		q = q.Where("namespace_path IN ("+ph+")", nsArgs...)
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

func (s *Store) ListSubjectsForRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	err := s.sdb.NewSelect(&models).
		Where("role_id = ?", roleID.String()).
		Where("tenant_id = ?", tenantID).
		OrderExpr("created_at ASC, id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list subjects for role: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		a, err := assignmentFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list subjects for role: %w", err)
		}
		result[i] = a
	}
	return result, nil
}

func (s *Store) ListExpiringAssignments(ctx context.Context, tenantID string, before time.Time, limit int) ([]*assignment.Assignment, error) {
	var models []assignmentModel
	err := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", sqliteTime(before)).
		OrderExpr("expires_at ASC, id ASC").
		Limit(fanoutLimit(limit)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list expiring assignments: %w", err)
	}
	result := make([]*assignment.Assignment, len(models))
	for i := range models {
		a, err := assignmentFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list expiring assignments: %w", err)
		}
		result[i] = a
	}
	return result, nil
}

func (s *Store) DeleteExpiredAssignments(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.sdb.NewDelete((*assignmentModel)(nil)).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", sqliteTime(now)).
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

func (s *Store) DeleteExpiredAssignmentsForTenant(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("warden: delete expired assignments for tenant: %w", wardenerr.ErrTenantRequired)
	}
	res, err := s.sdb.NewDelete((*assignmentModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", sqliteTime(now)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: delete expired assignments for tenant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: delete expired assignments for tenant rows: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteAssignmentsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) error {
	_, err := s.sdb.NewDelete((*assignmentModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by subject: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByRole(ctx context.Context, tenantID string, roleID id.RoleID) error {
	_, err := s.sdb.NewDelete((*assignmentModel)(nil)).
		Where("role_id = ?", roleID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete assignments by role: %w", err)
	}
	return nil
}

func (s *Store) DeleteAssignmentsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*assignmentModel)(nil)).
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
	m, err := relationToModel(t)
	if err != nil {
		return fmt.Errorf("warden: create relation: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("relation %s:%s#%s@%s:%s in tenant %q: %w",
				t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID,
				t.TenantID, wardenerr.ErrDuplicateRelation)
		}
		return fmt.Errorf("warden: create relation: %w", err)
	}
	return nil
}

func (s *Store) GetRelation(ctx context.Context, tenantID string, relID id.RelationID) (*relation.Tuple, error) {
	m := new(relationModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", relID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("relation %s: %w", relID, wardenerr.ErrRelationNotFound)
		}
		return nil, fmt.Errorf("warden: get relation: %w", err)
	}
	t, err := relationFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get relation: %w", err)
	}
	return t, nil
}

func (s *Store) DeleteRelation(ctx context.Context, tenantID string, relID id.RelationID) error {
	res, err := s.sdb.NewDelete((*relationModel)(nil)).
		Where("id = ?", relID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("relation %s: %w", relID, wardenerr.ErrRelationNotFound)
	}
	return nil
}

func (s *Store) DeleteRelationTuple(ctx context.Context, tenantID, namespacePath, objectType, objectID, rel, subjectType, subjectID, subjectRelation string) error {
	// subject_relation is NOT NULL DEFAULT '', so an empty subjectRelation
	// matches the direct tuple only.
	_, err := s.sdb.NewDelete((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Where("subject_relation = ?", subjectRelation).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete relation tuple: %w", err)
	}
	return nil
}

func (s *Store) ListRelations(ctx context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error) {
	var models []relationModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list relations: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		t, err := relationFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list relations: %w", err)
		}
		result[i] = t
	}
	return result, nil
}

func (s *Store) CountRelations(ctx context.Context, filter *relation.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*relationModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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

func (s *Store) ListRelationSubjects(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel string, limit int) ([]*relation.Tuple, error) {
	var models []relationModel
	q := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel)
	if len(namespacePaths) > 0 {
		ph, nsArgs := inPlaceholders(namespacePaths)
		q = q.Where("namespace_path IN ("+ph+")", nsArgs...)
	}
	err := q.OrderExpr("created_at ASC, id ASC").Limit(fanoutLimit(limit)).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list relation subjects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		t, err := relationFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list relation subjects: %w", err)
		}
		result[i] = t
	}
	return result, nil
}

func (s *Store) ListRelationObjects(ctx context.Context, tenantID, namespacePath, subjectType, subjectID, rel string, limit int) ([]*relation.Tuple, error) {
	var models []relationModel
	err := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID).
		Where("relation = ?", rel).
		OrderExpr("created_at ASC, id ASC").
		Limit(fanoutLimit(limit)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("warden: list relation objects: %w", err)
	}
	result := make([]*relation.Tuple, len(models))
	for i := range models {
		t, err := relationFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list relation objects: %w", err)
		}
		result[i] = t
	}
	return result, nil
}

func (s *Store) CheckDirectRelation(ctx context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	q := s.sdb.NewSelect((*relationModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("object_type = ?", objectType).
		Where("object_id = ?", objectID).
		Where("relation = ?", rel).
		Where("subject_type = ?", subjectType).
		Where("subject_id = ?", subjectID)
	if len(namespacePaths) > 0 {
		ph, nsArgs := inPlaceholders(namespacePaths)
		q = q.Where("namespace_path IN ("+ph+")", nsArgs...)
	}
	count, err := q.Count(ctx)
	if err != nil {
		return false, fmt.Errorf("warden: check direct relation: %w", err)
	}
	return count > 0, nil
}

func (s *Store) DeleteRelationsByObject(ctx context.Context, tenantID, objectType, objectID string) error {
	_, err := s.sdb.NewDelete((*relationModel)(nil)).
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
	_, err := s.sdb.NewDelete((*relationModel)(nil)).
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
	_, err := s.sdb.NewDelete((*relationModel)(nil)).
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
	m, err := policyToModel(p)
	if err != nil {
		return fmt.Errorf("warden: create policy: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("policy %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
		}
		return fmt.Errorf("warden: create policy: %w", err)
	}
	return nil
}

func (s *Store) GetPolicy(ctx context.Context, tenantID string, polID id.PolicyID) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", polID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("warden: get policy: %w", err)
	}
	p, err := policyFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get policy: %w", err)
	}
	return p, nil
}

func (s *Store) GetPolicyByName(ctx context.Context, tenantID, namespacePath, name string) (*policy.Policy, error) {
	m := new(policyModel)
	err := s.sdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("policy %q in ns %q: %w", name, namespacePath, wardenerr.ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("warden: get policy by name: %w", err)
	}
	p, err := policyFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get policy by name: %w", err)
	}
	return p, nil
}

func (s *Store) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	p.UpdatedAt = time.Now().UTC()
	m, err := policyToModel(p)
	if err != nil {
		return fmt.Errorf("warden: update policy: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).
		Column(policyUpdateColumns...).
		WherePK().
		Where("tenant_id = ?", p.TenantID).
		Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("policy %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
		}
		return fmt.Errorf("warden: update policy: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("policy %s: %w", p.ID, wardenerr.ErrPolicyNotFound)
	}
	return nil
}

// UpdatePolicyIfVersion writes p as UpdatePolicy does, only if the stored
// policy is at version expected. The version check is part of the UPDATE's
// WHERE clause, so the comparison and the write are one statement. When no
// row changes, a read picks the error: not found if the policy is absent
// from p's tenant, a version conflict otherwise. That read only chooses the
// error; the refusal itself was atomic.
//
// p.UpdatedAt is set only once the write has happened, so a refused caller's
// struct does not claim a write that did not happen.
func (s *Store) UpdatePolicyIfVersion(ctx context.Context, p *policy.Policy, expected int) error {
	now := time.Now().UTC()
	next := *p
	next.UpdatedAt = now
	m, err := policyToModel(&next)
	if err != nil {
		return fmt.Errorf("warden: update policy: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).
		Column(policyUpdateColumns...).
		WherePK().
		Where("tenant_id = ?", p.TenantID).
		Where("version = ?", expected).
		Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("policy %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
		}
		return fmt.Errorf("warden: update policy: %w", err)
	}
	if rowsChanged(res) == 0 {
		if _, err := s.GetPolicy(ctx, p.TenantID, p.ID); err != nil {
			return err
		}
		return fmt.Errorf("policy %s, expected version %d: %w", p.ID, expected, wardenerr.ErrPolicyVersionConflict)
	}
	p.UpdatedAt = now
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, tenantID string, polID id.PolicyID) error {
	res, err := s.sdb.NewDelete((*policyModel)(nil)).
		Where("id = ?", polID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete policy: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
	}
	return nil
}

func (s *Store) ListPolicies(ctx context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	var models []policyModel
	q := s.sdb.NewSelect(&models).OrderExpr("priority ASC, created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
		}
		if filter.Effect != "" {
			q = q.Where("effect = ?", string(filter.Effect))
		}
		if filter.IsActive != nil {
			q = q.Where("is_active = ?", *filter.IsActive)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		p, err := policyFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list policies: %w", err)
		}
		result[i] = p
	}
	return result, nil
}

func (s *Store) CountPolicies(ctx context.Context, filter *policy.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*policyModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
		}
		if filter.Effect != "" {
			q = q.Where("effect = ?", string(filter.Effect))
		}
		if filter.IsActive != nil {
			q = q.Where("is_active = ?", *filter.IsActive)
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
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
	q := s.sdb.NewSelect(&models).
		Where("tenant_id = ?", tenantID).
		Where("is_active = ?", true)
	if len(namespacePaths) > 0 {
		ph, nsArgs := inPlaceholders(namespacePaths)
		q = q.Where("namespace_path IN ("+ph+")", nsArgs...)
	}
	q = q.OrderExpr("priority ASC, created_at ASC, id ASC")
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list active policies: %w", err)
	}
	result := make([]*policy.Policy, len(models))
	for i := range models {
		p, err := policyFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list active policies: %w", err)
		}
		result[i] = p
	}
	return result, nil
}

func (s *Store) SetPolicyVersion(ctx context.Context, tenantID string, polID id.PolicyID, version int) error {
	res, err := s.sdb.NewUpdate((*policyModel)(nil)).
		Set("version = ?", version).
		Set("updated_at = ?", sqliteTime(time.Now().UTC())).
		Where("id = ?", polID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: set policy version: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
	}
	return nil
}

func (s *Store) DeletePoliciesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*policyModel)(nil)).
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
	m, err := resourceTypeToModel(rt)
	if err != nil {
		return fmt.Errorf("warden: create resource type: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("resource type %q in tenant %q ns %q: %w",
				rt.Name, rt.TenantID, rt.NamespacePath, wardenerr.ErrDuplicateResourceType)
		}
		return fmt.Errorf("warden: create resource type: %w", err)
	}
	return nil
}

func (s *Store) GetResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	m := new(resourceTypeModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", rtID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type: %w", err)
	}
	rt, err := resourceTypeFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get resource type: %w", err)
	}
	return rt, nil
}

func (s *Store) GetResourceTypeByName(ctx context.Context, tenantID, namespacePath, name string) (*resourcetype.ResourceType, error) {
	m := new(resourceTypeModel)
	err := s.sdb.NewSelect(m).
		Where("tenant_id = ?", tenantID).
		Where("namespace_path = ?", namespacePath).
		Where("name = ?", name).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("resource type %q in ns %q: %w", name, namespacePath, wardenerr.ErrResourceTypeNotFound)
		}
		return nil, fmt.Errorf("warden: get resource type by name: %w", err)
	}
	rt, err := resourceTypeFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get resource type by name: %w", err)
	}
	return rt, nil
}

func (s *Store) UpdateResourceType(ctx context.Context, rt *resourcetype.ResourceType) error {
	rt.UpdatedAt = time.Now().UTC()
	m, err := resourceTypeToModel(rt)
	if err != nil {
		return fmt.Errorf("warden: update resource type: %w", err)
	}
	res, err := s.sdb.NewUpdate(m).
		Column(resourceTypeUpdateColumns...).
		WherePK().
		Where("tenant_id = ?", rt.TenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: update resource type: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("resource type %s: %w", rt.ID, wardenerr.ErrResourceTypeNotFound)
	}
	return nil
}

func (s *Store) DeleteResourceType(ctx context.Context, tenantID string, rtID id.ResourceTypeID) error {
	res, err := s.sdb.NewDelete((*resourceTypeModel)(nil)).
		Where("id = ?", rtID.String()).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete resource type: %w", err)
	}
	if rowsChanged(res) == 0 {
		return fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
	}
	return nil
}

func (s *Store) ListResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	var models []resourceTypeModel
	q := s.sdb.NewSelect(&models).OrderExpr("created_at ASC, id ASC")
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list resource types: %w", err)
	}
	result := make([]*resourcetype.ResourceType, len(models))
	for i := range models {
		rt, err := resourceTypeFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list resource types: %w", err)
		}
		result[i] = rt
	}
	return result, nil
}

func (s *Store) CountResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) (int64, error) {
	q := s.sdb.NewSelect((*resourceTypeModel)(nil))
	if filter != nil {
		if filter.TenantID != "" {
			q = q.Where("tenant_id = ?", filter.TenantID)
		}
		if filter.NamespacePath != nil {
			q = q.Where("namespace_path = ?", *filter.NamespacePath)
		}
		if filter.NamespacePrefix != "" {
			q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
				filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
		}
		if filter.Search != "" {
			q = q.Where("LOWER(name) LIKE LOWER(?) ESCAPE '\\'", "%"+escapeLike(filter.Search)+"%")
		}
	}
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count resource types: %w", err)
	}
	return count, nil
}

func (s *Store) DeleteResourceTypesByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*resourceTypeModel)(nil)).
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
	m, err := checkLogToModel(e)
	if err != nil {
		return fmt.Errorf("warden: create check log: %w", err)
	}
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("warden: create check log: %w", err)
	}
	return nil
}

func (s *Store) GetCheckLog(ctx context.Context, tenantID string, logID id.CheckLogID) (*checklog.Entry, error) {
	m := new(checkLogModel)
	err := s.sdb.NewSelect(m).
		Where("id = ?", logID.String()).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("check log %s: %w", logID, wardenerr.ErrCheckLogNotFound)
		}
		return nil, fmt.Errorf("warden: get check log: %w", err)
	}
	e, err := checkLogFromModel(m)
	if err != nil {
		return nil, fmt.Errorf("warden: get check log: %w", err)
	}
	return e, nil
}

// whereCheckLogs applies a QueryFilter's predicates. ListCheckLogs and
// CountCheckLogs both build from it, so a pager's total always counts the
// rows the list would return.
func whereCheckLogs(q *sqlitedriver.SelectQuery, filter *checklog.QueryFilter) *sqlitedriver.SelectQuery {
	if filter == nil {
		return q
	}
	if filter.TenantID != "" {
		q = q.Where("tenant_id = ?", filter.TenantID)
	}
	if filter.NamespacePath != nil {
		q = q.Where("namespace_path = ?", *filter.NamespacePath)
	}
	if filter.NamespacePrefix != "" {
		q = q.Where("(namespace_path = ? OR namespace_path LIKE ? ESCAPE '\\')",
			filter.NamespacePrefix, escapeLike(filter.NamespacePrefix)+"/%")
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
		q = q.Where("created_at >= ?", sqliteTime(*filter.After))
	}
	if filter.Before != nil {
		q = q.Where("created_at <= ?", sqliteTime(*filter.Before))
	}
	if filter.Cached != nil {
		if *filter.Cached {
			q = q.Where("cached = 1")
		} else {
			q = q.Where("cached = 0")
		}
	}
	return q
}

func (s *Store) ListCheckLogs(ctx context.Context, filter *checklog.QueryFilter) ([]*checklog.Entry, error) {
	var models []checkLogModel
	q := whereCheckLogs(s.sdb.NewSelect(&models).OrderExpr("created_at DESC, id DESC"), filter)
	reqLimit, reqOffset := 0, 0
	if filter != nil {
		reqLimit, reqOffset = filter.Limit, filter.Offset
	}
	q = q.Limit(listLimit(reqLimit))
	if reqOffset > 0 {
		q = q.Offset(reqOffset)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("warden: list check logs: %w", err)
	}
	result := make([]*checklog.Entry, len(models))
	for i := range models {
		e, err := checkLogFromModel(&models[i])
		if err != nil {
			return nil, fmt.Errorf("warden: list check logs: %w", err)
		}
		result[i] = e
	}
	return result, nil
}

func (s *Store) CountCheckLogs(ctx context.Context, filter *checklog.QueryFilter) (int64, error) {
	q := whereCheckLogs(s.sdb.NewSelect((*checkLogModel)(nil)), filter)
	count, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: count check logs: %w", err)
	}
	return count, nil
}

func (s *Store) PurgeCheckLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.sdb.NewDelete((*checkLogModel)(nil)).
		Where("created_at < ?", sqliteTime(before)).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs rows: %w", err)
	}
	return n, nil
}

func (s *Store) PurgeCheckLogsForTenant(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("warden: purge check logs for tenant: %w", wardenerr.ErrTenantRequired)
	}
	res, err := s.sdb.NewDelete((*checkLogModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("created_at < ?", sqliteTime(before)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs for tenant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: purge check logs for tenant rows: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteCheckLogsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) (int64, error) {
	res, err := s.sdb.NewDelete((*checkLogModel)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("subject_kind = ?", subjectKind).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("warden: delete check logs by subject: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("warden: delete check logs by subject rows: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteCheckLogsByTenant(ctx context.Context, tenantID string) error {
	_, err := s.sdb.NewDelete((*checkLogModel)(nil)).
		Where("tenant_id = ?", tenantID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("warden: delete check logs by tenant: %w", err)
	}
	return nil
}

// roleIDStrings renders role IDs for an expanded IN list.
func roleIDStrings(roleIDs []id.RoleID) []string {
	out := make([]string, len(roleIDs))
	for i, rid := range roleIDs {
		out[i] = rid.String()
	}
	return out
}
