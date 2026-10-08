// Package memory provides an in-memory implementation of the Warden composite
// store. It is intended for testing and development.
package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/wardenerr"
)

// Compile-time interface checks.
var (
	_ role.Store         = (*Store)(nil)
	_ permission.Store   = (*Store)(nil)
	_ assignment.Store   = (*Store)(nil)
	_ relation.Store     = (*Store)(nil)
	_ policy.Store       = (*Store)(nil)
	_ resourcetype.Store = (*Store)(nil)
	_ checklog.Store     = (*Store)(nil)
)

// nowFunc returns the current time. Tests override it to pin "now" when
// asserting expiry behavior without sleeping.
var nowFunc = time.Now

// Store is a thread-safe in-memory store for all Warden entities.
type Store struct {
	mu sync.RWMutex

	roles       map[string]*role.Role
	permissions map[string]*permission.Permission
	// rolePermissions maps a role's typeid to the set of permission.Ref keys
	// it grants. Each ref key is `namespace_path \x00 name` — a single
	// natural-key string. The engine reads these and resolves each to a full
	// Permission record via the s.permissions map (keyed by typeid; matched
	// by tenant + namespace + name).
	rolePermissions map[string]map[string]struct{}
	assignments     map[string]*assignment.Assignment
	relations       map[string]*relation.Tuple
	policies        map[string]*policy.Policy
	resourceTypes   map[string]*resourcetype.ResourceType
	checkLogs       map[string]*checklog.Entry
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		roles:           make(map[string]*role.Role),
		permissions:     make(map[string]*permission.Permission),
		rolePermissions: make(map[string]map[string]struct{}),
		assignments:     make(map[string]*assignment.Assignment),
		relations:       make(map[string]*relation.Tuple),
		policies:        make(map[string]*policy.Policy),
		resourceTypes:   make(map[string]*resourcetype.ResourceType),
		checkLogs:       make(map[string]*checklog.Entry),
	}
}

// Migrate is a no-op for the memory store.
func (s *Store) Migrate(_ context.Context) error { return nil }

// Ping is a no-op for the memory store.
func (s *Store) Ping(_ context.Context) error { return nil }

// Close is a no-op for the memory store.
func (s *Store) Close() error { return nil }

// ──────────────────────────────────────────────────
// Role Store
// ──────────────────────────────────────────────────

func (s *Store) CreateRole(_ context.Context, r *role.Role) error {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.roles {
		if existing.TenantID == r.TenantID &&
			existing.NamespacePath == r.NamespacePath &&
			existing.Slug == r.Slug {
			return fmt.Errorf("role %q in tenant %q ns %q: %w",
				r.Slug, r.TenantID, r.NamespacePath, wardenerr.ErrDuplicateRole)
		}
	}
	s.roles[r.ID.String()] = copyRole(r)
	return nil
}

func (s *Store) GetRole(_ context.Context, tenantID string, roleID id.RoleID) (*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleID.String()]
	if !ok || r.TenantID != tenantID {
		return nil, fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	return copyRole(r), nil
}

func (s *Store) GetRoles(_ context.Context, tenantID string, roleIDs []id.RoleID) ([]*role.Role, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*role.Role, 0, len(roleIDs))
	for _, rid := range roleIDs {
		r, ok := s.roles[rid.String()]
		if !ok || r.TenantID != tenantID {
			continue
		}
		result = append(result, copyRole(r))
	}
	return result, nil
}

func (s *Store) GetRoleBySlug(_ context.Context, tenantID, namespacePath, slug string) (*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.roles {
		if r.TenantID == tenantID && r.NamespacePath == namespacePath && r.Slug == slug {
			return copyRole(r), nil
		}
	}
	return nil, fmt.Errorf("role slug %q in ns %q: %w", slug, namespacePath, wardenerr.ErrRoleNotFound)
}

func (s *Store) UpdateRole(_ context.Context, r *role.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.roles[r.ID.String()]
	if !ok || existing.TenantID != r.TenantID {
		return fmt.Errorf("role %s: %w", r.ID, wardenerr.ErrRoleNotFound)
	}
	// Copy every field except the ones an update may not move: the tenant,
	// the identity and the creation time.
	updated := copyRole(r)
	updated.TenantID = existing.TenantID
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	updated.CreatedBy = existing.CreatedBy
	s.roles[r.ID.String()] = updated
	return nil
}

func (s *Store) DeleteRole(_ context.Context, tenantID string, roleID id.RoleID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[roleID.String()]
	if !ok || r.TenantID != tenantID {
		return fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	delete(s.roles, roleID.String())
	delete(s.rolePermissions, roleID.String())
	// The SQL backends cascade assignments off the role's foreign key.
	for k, a := range s.assignments {
		if a.RoleID == roleID {
			delete(s.assignments, k)
		}
	}
	return nil
}

func (s *Store) filterRoles(filter *role.ListFilter) []*role.Role {
	result := make([]*role.Role, 0, len(s.roles))
	for _, r := range s.roles {
		if filter != nil {
			if filter.TenantID != "" && r.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && r.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(r.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.IsSystem != nil && r.IsSystem != *filter.IsSystem {
				continue
			}
			if filter.IsDefault != nil && r.IsDefault != *filter.IsDefault {
				continue
			}
			if filter.ParentSlug != nil && r.ParentSlug != *filter.ParentSlug {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(r.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyRole(r))
	}
	sortByCreatedAt(result, func(r *role.Role) (time.Time, string) { return r.CreatedAt, r.ID.String() })
	return result
}

func (s *Store) ListRoles(_ context.Context, filter *role.ListFilter) ([]*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPagination(s.filterRoles(filter), paginationOpts(filter)), nil
}

func (s *Store) CountRoles(_ context.Context, filter *role.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterRoles(filter))), nil
}

// permRefKey encodes a (namespace_path, name) pair as a single map key.
// The NUL byte makes this unambiguous since namespace path and name are
// both ASCII-safe (validated by the resolver).
func permRefKey(ref permission.Ref) string {
	return ref.NamespacePath + "\x00" + ref.Name
}

func decodePermRefKey(k string) permission.Ref {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return permission.Ref{NamespacePath: k[:i], Name: k[i+1:]}
		}
	}
	return permission.Ref{Name: k}
}

// resolveGrants returns the full Permission records a role grants. The
// caller holds at least a read lock and has already checked the role's
// tenant.
func (s *Store) resolveGrants(tenantID string, roleID id.RoleID) []*permission.Permission {
	refs := s.rolePermissions[roleID.String()]
	if len(refs) == 0 {
		return nil
	}
	result := make([]*permission.Permission, 0, len(refs))
	for k := range refs {
		ref := decodePermRefKey(k)
		for _, p := range s.permissions {
			if p.TenantID == tenantID && p.NamespacePath == ref.NamespacePath && p.Name == ref.Name {
				result = append(result, copyPermission(p))
				break
			}
		}
	}
	return result
}

func (s *Store) ListRolePermissions(_ context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleID.String()]
	if !ok || r.TenantID != tenantID {
		return nil, nil
	}
	return s.resolveGrants(tenantID, roleID), nil
}

func (s *Store) ListRolePermissionsForRoles(_ context.Context, tenantID string, roleIDs []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	result := make(map[id.RoleID][]*permission.Permission, len(roleIDs))
	if len(roleIDs) == 0 {
		return result, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rid := range roleIDs {
		r, ok := s.roles[rid.String()]
		if !ok || r.TenantID != tenantID {
			continue
		}
		if grants := s.resolveGrants(tenantID, rid); len(grants) > 0 {
			result[rid] = grants
		}
	}
	return result, nil
}

// requireRole reports whether the role exists in the tenant. The caller
// holds the write lock.
func (s *Store) requireRole(tenantID string, roleID id.RoleID) error {
	r, ok := s.roles[roleID.String()]
	if !ok || r.TenantID != tenantID {
		return fmt.Errorf("role %s: %w", roleID, wardenerr.ErrRoleNotFound)
	}
	return nil
}

// requirePermission reports whether a permission with the given natural key
// exists in the tenant, so a grant can't be attached to a permission that
// was never created (or was deleted and never recreated). The caller holds
// the write lock.
func (s *Store) requirePermission(tenantID string, ref permission.Ref) error {
	for _, p := range s.permissions {
		if p.TenantID == tenantID && p.NamespacePath == ref.NamespacePath && p.Name == ref.Name {
			return nil
		}
	}
	return fmt.Errorf("permission %q in ns %q: %w", ref.Name, ref.NamespacePath, wardenerr.ErrPermissionNotFound)
}

func (s *Store) AttachPermission(_ context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireRole(tenantID, roleID); err != nil {
		return err
	}
	if err := s.requirePermission(tenantID, ref); err != nil {
		return err
	}
	rk := roleID.String()
	if s.rolePermissions[rk] == nil {
		s.rolePermissions[rk] = make(map[string]struct{})
	}
	s.rolePermissions[rk][permRefKey(ref)] = struct{}{}
	return nil
}

func (s *Store) DetachPermission(_ context.Context, tenantID string, roleID id.RoleID, ref permission.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireRole(tenantID, roleID); err != nil {
		return err
	}
	if refs, ok := s.rolePermissions[roleID.String()]; ok {
		delete(refs, permRefKey(ref))
	}
	return nil
}

func (s *Store) SetRolePermissions(_ context.Context, tenantID string, roleID id.RoleID, refs []permission.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireRole(tenantID, roleID); err != nil {
		return err
	}
	set := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		set[permRefKey(ref)] = struct{}{}
	}
	s.rolePermissions[roleID.String()] = set
	return nil
}

func (s *Store) ListChildRoles(_ context.Context, tenantID, parentSlug string) ([]*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*role.Role
	for _, r := range s.roles {
		if r.TenantID == tenantID && r.ParentSlug != "" && r.ParentSlug == parentSlug {
			result = append(result, copyRole(r))
		}
	}
	sortByCreatedAt(result, func(r *role.Role) (time.Time, string) { return r.CreatedAt, r.ID.String() })
	return result, nil
}

func (s *Store) DeleteRolesByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, r := range s.roles {
		if r.TenantID == tenantID {
			delete(s.roles, k)
			delete(s.rolePermissions, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Permission Store
// ──────────────────────────────────────────────────

func (s *Store) CreatePermission(_ context.Context, p *permission.Permission) error {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.permissions {
		if existing.TenantID == p.TenantID &&
			existing.NamespacePath == p.NamespacePath &&
			existing.Name == p.Name {
			return fmt.Errorf("permission %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePermission)
		}
	}
	s.permissions[p.ID.String()] = copyPermission(p)
	return nil
}

func (s *Store) GetPermission(_ context.Context, tenantID string, permID id.PermissionID) (*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.permissions[permID.String()]
	if !ok || p.TenantID != tenantID {
		return nil, fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
	}
	return copyPermission(p), nil
}

func (s *Store) GetPermissionByName(_ context.Context, tenantID, namespacePath, name string) (*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.permissions {
		if p.TenantID == tenantID && p.NamespacePath == namespacePath && p.Name == name {
			return copyPermission(p), nil
		}
	}
	return nil, fmt.Errorf("permission %q in ns %q: %w", name, namespacePath, wardenerr.ErrPermissionNotFound)
}

func (s *Store) UpdatePermission(_ context.Context, p *permission.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.permissions[p.ID.String()]
	if !ok || existing.TenantID != p.TenantID {
		return fmt.Errorf("permission %s: %w", p.ID, wardenerr.ErrPermissionNotFound)
	}
	updated := copyPermission(p)
	updated.TenantID = existing.TenantID
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	updated.CreatedBy = existing.CreatedBy
	s.permissions[p.ID.String()] = updated
	return nil
}

func (s *Store) DeletePermission(_ context.Context, tenantID string, permID id.PermissionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.permissions[permID.String()]
	if !ok || p.TenantID != tenantID {
		return fmt.Errorf("permission %s: %w", permID, wardenerr.ErrPermissionNotFound)
	}
	delete(s.permissions, permID.String())
	// Scrub the junction. Grants are keyed by the permission's natural key,
	// so only roles in the same tenant can be holding this grant.
	refKey := permRefKey(permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name})
	for rk, refs := range s.rolePermissions {
		r, ok := s.roles[rk]
		if !ok || r.TenantID != tenantID {
			continue
		}
		delete(refs, refKey)
	}
	return nil
}

func (s *Store) filterPermissions(filter *permission.ListFilter) []*permission.Permission {
	result := make([]*permission.Permission, 0, len(s.permissions))
	for _, p := range s.permissions {
		if filter != nil {
			if filter.TenantID != "" && p.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && p.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(p.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.Resource != "" && p.Resource != filter.Resource {
				continue
			}
			if filter.Action != "" && p.Action != filter.Action {
				continue
			}
			if filter.IsSystem != nil && p.IsSystem != *filter.IsSystem {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyPermission(p))
	}
	sortByCreatedAt(result, func(p *permission.Permission) (time.Time, string) { return p.CreatedAt, p.ID.String() })
	return result
}

func (s *Store) ListPermissions(_ context.Context, filter *permission.ListFilter) ([]*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationPerm(s.filterPermissions(filter), paginationOptsPerm(filter)), nil
}

func (s *Store) CountPermissions(_ context.Context, filter *permission.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterPermissions(filter))), nil
}

func (s *Store) ListPermissionsByRole(ctx context.Context, tenantID string, roleID id.RoleID) ([]*permission.Permission, error) {
	return s.ListRolePermissions(ctx, tenantID, roleID)
}

func (s *Store) ListPermissionsBySubject(_ context.Context, tenantID, subjectKind, subjectID string) ([]*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Gather role IDs for this subject.
	roleIDs := make(map[string]struct{})
	for _, a := range s.assignments {
		if a.TenantID == tenantID && a.SubjectKind == subjectKind && a.SubjectID == subjectID {
			roleIDs[a.RoleID.String()] = struct{}{}
		}
	}
	// Gather permissions from those roles, deduplicating by ref.
	seen := make(map[string]struct{})
	var result []*permission.Permission
	for rid := range roleIDs {
		refs, ok := s.rolePermissions[rid]
		if !ok {
			continue
		}
		for k := range refs {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			ref := decodePermRefKey(k)
			for _, p := range s.permissions {
				if p.TenantID == tenantID && p.NamespacePath == ref.NamespacePath && p.Name == ref.Name {
					result = append(result, copyPermission(p))
					break
				}
			}
		}
	}
	return result, nil
}

func (s *Store) DeletePermissionsByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Collect refs for permissions in this tenant so we can scrub the junction.
	scrub := make(map[string]struct{})
	for k, p := range s.permissions {
		if p.TenantID == tenantID {
			scrub[permRefKey(permission.Ref{NamespacePath: p.NamespacePath, Name: p.Name})] = struct{}{}
			delete(s.permissions, k)
		}
	}
	for _, refs := range s.rolePermissions {
		for k := range scrub {
			delete(refs, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Assignment Store
// ──────────────────────────────────────────────────

func (s *Store) CreateAssignment(_ context.Context, a *assignment.Assignment) error {
	if a.ID.IsNil() {
		a.ID = id.NewAssignmentID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.assignments {
		if existing.TenantID == a.TenantID &&
			existing.NamespacePath == a.NamespacePath &&
			existing.RoleID == a.RoleID &&
			existing.SubjectKind == a.SubjectKind &&
			existing.SubjectID == a.SubjectID &&
			existing.ResourceType == a.ResourceType &&
			existing.ResourceID == a.ResourceID {
			return fmt.Errorf("assignment role=%s subject=%s:%s in tenant %q ns %q: %w",
				a.RoleID, a.SubjectKind, a.SubjectID, a.TenantID, a.NamespacePath,
				wardenerr.ErrDuplicateAssignment)
		}
	}
	s.assignments[a.ID.String()] = copyAssignment(a)
	return nil
}

func (s *Store) GetAssignment(_ context.Context, tenantID string, assID id.AssignmentID) (*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assignments[assID.String()]
	if !ok || a.TenantID != tenantID {
		return nil, fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
	}
	return copyAssignment(a), nil
}

func (s *Store) DeleteAssignment(_ context.Context, tenantID string, assID id.AssignmentID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assignments[assID.String()]
	if !ok || a.TenantID != tenantID {
		return fmt.Errorf("assignment %s: %w", assID, wardenerr.ErrAssignmentNotFound)
	}
	delete(s.assignments, assID.String())
	return nil
}

func (s *Store) filterAssignments(filter *assignment.ListFilter) []*assignment.Assignment {
	result := make([]*assignment.Assignment, 0, len(s.assignments))
	for _, a := range s.assignments {
		if filter != nil {
			if filter.TenantID != "" && a.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && a.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(a.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.SubjectKind != "" && a.SubjectKind != filter.SubjectKind {
				continue
			}
			if filter.SubjectID != "" && a.SubjectID != filter.SubjectID {
				continue
			}
			if filter.RoleID != nil && a.RoleID.String() != filter.RoleID.String() {
				continue
			}
			if filter.ResourceType != "" && a.ResourceType != filter.ResourceType {
				continue
			}
			if filter.ResourceID != "" && a.ResourceID != filter.ResourceID {
				continue
			}
		}
		result = append(result, copyAssignment(a))
	}
	sortByCreatedAt(result, func(a *assignment.Assignment) (time.Time, string) { return a.CreatedAt, a.ID.String() })
	return result
}

func (s *Store) ListAssignments(_ context.Context, filter *assignment.ListFilter) ([]*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationAssign(s.filterAssignments(filter), paginationOptsAssign(filter)), nil
}

func (s *Store) CountAssignments(_ context.Context, filter *assignment.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterAssignments(filter))), nil
}

func (s *Store) ListRolesForSubject(_ context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID string) ([]id.RoleID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nsSet := namespacePathSet(namespacePaths)
	now := nowFunc()
	var result []id.RoleID
	for _, a := range s.assignments {
		if a.TenantID != tenantID || a.SubjectKind != subjectKind || a.SubjectID != subjectID || a.ResourceType != "" {
			continue
		}
		if !nsSet.matches(a.NamespacePath) {
			continue
		}
		if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
			continue
		}
		result = append(result, a.RoleID)
	}
	return result, nil
}

func (s *Store) ListRolesForSubjectOnResource(_ context.Context, tenantID string, namespacePaths []string, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nsSet := namespacePathSet(namespacePaths)
	now := nowFunc()
	var result []id.RoleID
	for _, a := range s.assignments {
		if a.TenantID != tenantID || a.SubjectKind != subjectKind || a.SubjectID != subjectID {
			continue
		}
		if a.ResourceType != resourceType || a.ResourceID != resourceID {
			continue
		}
		if !nsSet.matches(a.NamespacePath) {
			continue
		}
		if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
			continue
		}
		result = append(result, a.RoleID)
	}
	return result, nil
}

func (s *Store) ListSubjectsForRole(_ context.Context, tenantID string, roleID id.RoleID) ([]*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rid := roleID.String()
	var result []*assignment.Assignment
	for _, a := range s.assignments {
		if a.TenantID == tenantID && a.RoleID.String() == rid {
			result = append(result, copyAssignment(a))
		}
	}
	sortByCreatedAt(result, func(a *assignment.Assignment) (time.Time, string) { return a.CreatedAt, a.ID.String() })
	return result, nil
}

func (s *Store) ListExpiringAssignments(_ context.Context, tenantID string, before time.Time, limit int) ([]*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*assignment.Assignment
	for _, a := range s.assignments {
		if a.TenantID != tenantID || a.ExpiresAt == nil || !a.ExpiresAt.Before(before) {
			continue
		}
		result = append(result, copyAssignment(a))
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].ExpiresAt.Equal(*result[j].ExpiresAt) {
			return result[i].ExpiresAt.Before(*result[j].ExpiresAt)
		}
		return result[i].ID.String() < result[j].ID.String()
	})
	if n := fanoutLimit(limit); len(result) > n {
		result = result[:n]
	}
	return result, nil
}

func (s *Store) DeleteExpiredAssignments(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, a := range s.assignments {
		if a.ExpiresAt != nil && a.ExpiresAt.Before(now) {
			delete(s.assignments, k)
			count++
		}
	}
	return count, nil
}

func (s *Store) DeleteExpiredAssignmentsForTenant(_ context.Context, tenantID string, now time.Time) (int64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("warden: delete expired assignments for tenant: %w", wardenerr.ErrTenantRequired)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, a := range s.assignments {
		if a.TenantID == tenantID && a.ExpiresAt != nil && a.ExpiresAt.Before(now) {
			delete(s.assignments, k)
			count++
		}
	}
	return count, nil
}

func (s *Store) DeleteAssignmentsBySubject(_ context.Context, tenantID, subjectKind, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, a := range s.assignments {
		if a.TenantID == tenantID && a.SubjectKind == subjectKind && a.SubjectID == subjectID {
			delete(s.assignments, k)
		}
	}
	return nil
}

func (s *Store) DeleteAssignmentsByRole(_ context.Context, tenantID string, roleID id.RoleID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rid := roleID.String()
	for k, a := range s.assignments {
		if a.TenantID == tenantID && a.RoleID.String() == rid {
			delete(s.assignments, k)
		}
	}
	return nil
}

func (s *Store) DeleteAssignmentsByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, a := range s.assignments {
		if a.TenantID == tenantID {
			delete(s.assignments, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Relation Store
// ──────────────────────────────────────────────────

func (s *Store) CreateRelation(_ context.Context, t *relation.Tuple) error {
	if t.ID.IsNil() {
		t.ID = id.NewRelationID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.relations {
		if existing.TenantID == t.TenantID &&
			existing.NamespacePath == t.NamespacePath &&
			existing.ObjectType == t.ObjectType &&
			existing.ObjectID == t.ObjectID &&
			existing.Relation == t.Relation &&
			existing.SubjectType == t.SubjectType &&
			existing.SubjectID == t.SubjectID &&
			existing.SubjectRelation == t.SubjectRelation {
			return fmt.Errorf("relation %s:%s#%s@%s:%s in tenant %q ns %q: %w",
				t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID,
				t.TenantID, t.NamespacePath, wardenerr.ErrDuplicateRelation)
		}
	}
	s.relations[t.ID.String()] = copyTuple(t)
	return nil
}

func (s *Store) GetRelation(_ context.Context, tenantID string, relID id.RelationID) (*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.relations[relID.String()]
	if !ok || t.TenantID != tenantID {
		return nil, fmt.Errorf("relation %s: %w", relID, wardenerr.ErrRelationNotFound)
	}
	return copyTuple(t), nil
}

func (s *Store) DeleteRelation(_ context.Context, tenantID string, relID id.RelationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.relations[relID.String()]
	if !ok || t.TenantID != tenantID {
		return fmt.Errorf("relation %s: %w", relID, wardenerr.ErrRelationNotFound)
	}
	delete(s.relations, relID.String())
	return nil
}

func (s *Store) DeleteRelationTuple(_ context.Context, tenantID, namespacePath, objectType, objectID, rel, subjectType, subjectID, subjectRelation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The key includes SubjectRelation exactly, so an empty one removes
	// group:eng and leaves group:eng#member. Remove every match, as the sql
	// and mongo stores do.
	for k, t := range s.relations {
		if t.TenantID == tenantID && t.NamespacePath == namespacePath && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel && t.SubjectType == subjectType && t.SubjectID == subjectID && t.SubjectRelation == subjectRelation {
			delete(s.relations, k)
		}
	}
	return nil
}

func (s *Store) filterRelations(filter *relation.ListFilter) []*relation.Tuple {
	result := make([]*relation.Tuple, 0, len(s.relations))
	for _, t := range s.relations {
		if filter != nil {
			if filter.TenantID != "" && t.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && t.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(t.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.ObjectType != "" && t.ObjectType != filter.ObjectType {
				continue
			}
			if filter.ObjectID != "" && t.ObjectID != filter.ObjectID {
				continue
			}
			if filter.Relation != "" && t.Relation != filter.Relation {
				continue
			}
			if filter.SubjectType != "" && t.SubjectType != filter.SubjectType {
				continue
			}
			if filter.SubjectID != "" && t.SubjectID != filter.SubjectID {
				continue
			}
			if filter.SubjectRelation != "" && t.SubjectRelation != filter.SubjectRelation {
				continue
			}
		}
		result = append(result, copyTuple(t))
	}
	sortByCreatedAt(result, func(t *relation.Tuple) (time.Time, string) { return t.CreatedAt, t.ID.String() })
	return result
}

func (s *Store) ListRelations(_ context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationRel(s.filterRelations(filter), paginationOptsRel(filter)), nil
}

func (s *Store) CountRelations(_ context.Context, filter *relation.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterRelations(filter))), nil
}

func (s *Store) ListRelationSubjects(_ context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel string, limit int) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nsSet := namespacePathSet(namespacePaths)
	var result []*relation.Tuple
	for _, t := range s.relations {
		if t.TenantID == tenantID && nsSet.matches(t.NamespacePath) && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel {
			result = append(result, copyTuple(t))
		}
	}
	return capTuples(result, limit), nil
}

func (s *Store) ListRelationObjects(_ context.Context, tenantID, namespacePath, subjectType, subjectID, rel string, limit int) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*relation.Tuple
	for _, t := range s.relations {
		if t.TenantID == tenantID && t.NamespacePath == namespacePath && t.SubjectType == subjectType && t.SubjectID == subjectID && t.Relation == rel {
			result = append(result, copyTuple(t))
		}
	}
	return capTuples(result, limit), nil
}

func (s *Store) CheckDirectRelation(_ context.Context, tenantID string, namespacePaths []string, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nsSet := namespacePathSet(namespacePaths)
	for _, t := range s.relations {
		if t.TenantID == tenantID && nsSet.matches(t.NamespacePath) && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel && t.SubjectType == subjectType && t.SubjectID == subjectID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) DeleteRelationsByObject(_ context.Context, tenantID, objectType, objectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.relations {
		if t.TenantID == tenantID && t.ObjectType == objectType && t.ObjectID == objectID {
			delete(s.relations, k)
		}
	}
	return nil
}

func (s *Store) DeleteRelationsBySubject(_ context.Context, tenantID, subjectType, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.relations {
		if t.TenantID == tenantID && t.SubjectType == subjectType && t.SubjectID == subjectID {
			delete(s.relations, k)
		}
	}
	return nil
}

func (s *Store) DeleteRelationsByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.relations {
		if t.TenantID == tenantID {
			delete(s.relations, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Policy Store
// ──────────────────────────────────────────────────

func (s *Store) CreatePolicy(_ context.Context, p *policy.Policy) error {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.policies {
		if existing.TenantID == p.TenantID &&
			existing.NamespacePath == p.NamespacePath &&
			existing.Name == p.Name {
			return fmt.Errorf("policy %q in tenant %q ns %q: %w",
				p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
		}
	}
	s.policies[p.ID.String()] = copyPolicy(p)
	return nil
}

func (s *Store) GetPolicy(_ context.Context, tenantID string, polID id.PolicyID) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[polID.String()]
	if !ok || p.TenantID != tenantID {
		return nil, fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
	}
	return copyPolicy(p), nil
}

func (s *Store) GetPolicyByName(_ context.Context, tenantID, namespacePath, name string) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.policies {
		if p.TenantID == tenantID && p.NamespacePath == namespacePath && p.Name == name {
			return copyPolicy(p), nil
		}
	}
	return nil, fmt.Errorf("policy %q in ns %q: %w", name, namespacePath, wardenerr.ErrPolicyNotFound)
}

// policyNameTakenLocked reports whether another policy in p's tenant and namespace
// already carries p's name. The caller holds s.mu, so the check and the write
// that follows it are one step.
func (s *Store) policyNameTakenLocked(p *policy.Policy) bool {
	for _, other := range s.policies {
		if other.ID == p.ID {
			continue
		}
		if other.TenantID == p.TenantID && other.NamespacePath == p.NamespacePath && other.Name == p.Name {
			return true
		}
	}
	return false
}

func (s *Store) UpdatePolicy(_ context.Context, p *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[p.ID.String()]
	if !ok || existing.TenantID != p.TenantID {
		return fmt.Errorf("policy %s: %w", p.ID, wardenerr.ErrPolicyNotFound)
	}
	if s.policyNameTakenLocked(p) {
		return fmt.Errorf("policy %q in tenant %q ns %q: %w",
			p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
	}
	updated := copyPolicy(p)
	updated.TenantID = existing.TenantID
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	updated.CreatedBy = existing.CreatedBy
	s.policies[p.ID.String()] = updated
	return nil
}

// UpdatePolicyIfVersion writes p as UpdatePolicy does, only if the stored
// policy is at version expected. The lookup, the comparison and the write all
// happen under one hold of s.mu, so two callers holding the same version
// cannot both win.
func (s *Store) UpdatePolicyIfVersion(_ context.Context, p *policy.Policy, expected int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[p.ID.String()]
	if !ok || existing.TenantID != p.TenantID {
		return fmt.Errorf("policy %s: %w", p.ID, wardenerr.ErrPolicyNotFound)
	}
	if existing.Version != expected {
		return fmt.Errorf("policy %s, expected version %d: %w", p.ID, expected, wardenerr.ErrPolicyVersionConflict)
	}
	if s.policyNameTakenLocked(p) {
		return fmt.Errorf("policy %q in tenant %q ns %q: %w",
			p.Name, p.TenantID, p.NamespacePath, wardenerr.ErrDuplicatePolicy)
	}
	updated := copyPolicy(p)
	updated.TenantID = existing.TenantID
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	updated.CreatedBy = existing.CreatedBy
	s.policies[p.ID.String()] = updated
	return nil
}

func (s *Store) DeletePolicy(_ context.Context, tenantID string, polID id.PolicyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[polID.String()]
	if !ok || p.TenantID != tenantID {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
	}
	delete(s.policies, polID.String())
	return nil
}

func (s *Store) filterPolicies(filter *policy.ListFilter) []*policy.Policy {
	result := make([]*policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		if filter != nil {
			if filter.TenantID != "" && p.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && p.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(p.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.Effect != "" && p.Effect != filter.Effect {
				continue
			}
			if filter.IsActive != nil && p.IsActive != *filter.IsActive {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyPolicy(p))
	}
	// Priority first, like the SQL and mongo backends: ListPolicies is the
	// evaluation order, not just a stable one.
	sortActivePolicies(result)
	return result
}

func (s *Store) ListPolicies(_ context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationPol(s.filterPolicies(filter), paginationOptsPol(filter)), nil
}

func (s *Store) CountPolicies(_ context.Context, filter *policy.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterPolicies(filter))), nil
}

func (s *Store) ListActivePolicies(_ context.Context, tenantID string, namespacePaths []string) ([]*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nsSet := namespacePathSet(namespacePaths)
	var result []*policy.Policy
	for _, p := range s.policies {
		if p.TenantID != tenantID || !p.IsActive {
			continue
		}
		if !nsSet.matches(p.NamespacePath) {
			continue
		}
		result = append(result, copyPolicy(p))
	}
	sortActivePolicies(result)
	return result, nil
}

func (s *Store) SetPolicyVersion(_ context.Context, tenantID string, polID id.PolicyID, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[polID.String()]
	if !ok || p.TenantID != tenantID {
		return fmt.Errorf("policy %s: %w", polID, wardenerr.ErrPolicyNotFound)
	}
	p.Version = version
	return nil
}

func (s *Store) DeletePoliciesByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.policies {
		if p.TenantID == tenantID {
			delete(s.policies, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Resource Type Store
// ──────────────────────────────────────────────────

func (s *Store) CreateResourceType(_ context.Context, rt *resourcetype.ResourceType) error {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.resourceTypes {
		if existing.TenantID == rt.TenantID &&
			existing.NamespacePath == rt.NamespacePath &&
			existing.Name == rt.Name {
			return fmt.Errorf("resource type %q in tenant %q ns %q: %w",
				rt.Name, rt.TenantID, rt.NamespacePath, wardenerr.ErrDuplicateResourceType)
		}
	}
	s.resourceTypes[rt.ID.String()] = copyResourceType(rt)
	return nil
}

func (s *Store) GetResourceType(_ context.Context, tenantID string, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.resourceTypes[rtID.String()]
	if !ok || rt.TenantID != tenantID {
		return nil, fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
	}
	return copyResourceType(rt), nil
}

func (s *Store) GetResourceTypeByName(_ context.Context, tenantID, namespacePath, name string) (*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rt := range s.resourceTypes {
		if rt.TenantID == tenantID && rt.NamespacePath == namespacePath && rt.Name == name {
			return copyResourceType(rt), nil
		}
	}
	return nil, fmt.Errorf("resource type %q in ns %q: %w", name, namespacePath, wardenerr.ErrResourceTypeNotFound)
}

func (s *Store) UpdateResourceType(_ context.Context, rt *resourcetype.ResourceType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.resourceTypes[rt.ID.String()]
	if !ok || existing.TenantID != rt.TenantID {
		return fmt.Errorf("resource type %s: %w", rt.ID, wardenerr.ErrResourceTypeNotFound)
	}
	updated := copyResourceType(rt)
	updated.TenantID = existing.TenantID
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt
	updated.CreatedBy = existing.CreatedBy
	s.resourceTypes[rt.ID.String()] = updated
	return nil
}

func (s *Store) DeleteResourceType(_ context.Context, tenantID string, rtID id.ResourceTypeID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.resourceTypes[rtID.String()]
	if !ok || rt.TenantID != tenantID {
		return fmt.Errorf("resource type %s: %w", rtID, wardenerr.ErrResourceTypeNotFound)
	}
	delete(s.resourceTypes, rtID.String())
	return nil
}

func (s *Store) filterResourceTypes(filter *resourcetype.ListFilter) []*resourcetype.ResourceType {
	result := make([]*resourcetype.ResourceType, 0, len(s.resourceTypes))
	for _, rt := range s.resourceTypes {
		if filter != nil {
			if filter.TenantID != "" && rt.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && rt.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(rt.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(rt.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyResourceType(rt))
	}
	sortByCreatedAt(result, func(rt *resourcetype.ResourceType) (time.Time, string) { return rt.CreatedAt, rt.ID.String() })
	return result
}

func (s *Store) ListResourceTypes(_ context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationRT(s.filterResourceTypes(filter), paginationOptsRT(filter)), nil
}

func (s *Store) CountResourceTypes(_ context.Context, filter *resourcetype.ListFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterResourceTypes(filter))), nil
}

func (s *Store) DeleteResourceTypesByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, rt := range s.resourceTypes {
		if rt.TenantID == tenantID {
			delete(s.resourceTypes, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Check Log Store
// ──────────────────────────────────────────────────

func (s *Store) CreateCheckLog(_ context.Context, e *checklog.Entry) error {
	if e.ID.IsNil() {
		e.ID = id.NewCheckLogID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkLogs[e.ID.String()] = copyCheckLog(e)
	return nil
}

func (s *Store) GetCheckLog(_ context.Context, tenantID string, logID id.CheckLogID) (*checklog.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.checkLogs[logID.String()]
	if !ok || e.TenantID != tenantID {
		return nil, fmt.Errorf("check log %s: %w", logID, wardenerr.ErrCheckLogNotFound)
	}
	return copyCheckLog(e), nil
}

func (s *Store) filterCheckLogs(filter *checklog.QueryFilter) []*checklog.Entry {
	result := make([]*checklog.Entry, 0, len(s.checkLogs))
	for _, e := range s.checkLogs {
		if filter != nil {
			if filter.TenantID != "" && e.TenantID != filter.TenantID {
				continue
			}
			if filter.NamespacePath != nil && e.NamespacePath != *filter.NamespacePath {
				continue
			}
			if filter.NamespacePrefix != "" && !nsHasPrefix(e.NamespacePath, filter.NamespacePrefix) {
				continue
			}
			if filter.SubjectKind != "" && e.SubjectKind != filter.SubjectKind {
				continue
			}
			if filter.SubjectID != "" && e.SubjectID != filter.SubjectID {
				continue
			}
			if filter.Action != "" && e.Action != filter.Action {
				continue
			}
			if filter.ResourceType != "" && e.ResourceType != filter.ResourceType {
				continue
			}
			if filter.ResourceID != "" && e.ResourceID != filter.ResourceID {
				continue
			}
			if filter.Decision != "" && e.Decision != filter.Decision {
				continue
			}
			if filter.Cached != nil && e.Cached != *filter.Cached {
				continue
			}
			if filter.After != nil && e.CreatedAt.Before(*filter.After) {
				continue
			}
			if filter.Before != nil && e.CreatedAt.After(*filter.Before) {
				continue
			}
		}
		result = append(result, copyCheckLog(e))
	}
	// Newest first, matching the other backends' created_at DESC, id DESC.
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.After(result[j].CreatedAt)
		}
		return result[i].ID.String() > result[j].ID.String()
	})
	return result
}

func (s *Store) ListCheckLogs(_ context.Context, filter *checklog.QueryFilter) ([]*checklog.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return applyPaginationCL(s.filterCheckLogs(filter), paginationOptsCL(filter)), nil
}

func (s *Store) CountCheckLogs(_ context.Context, filter *checklog.QueryFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.filterCheckLogs(filter))), nil
}

func (s *Store) PurgeCheckLogs(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, e := range s.checkLogs {
		if e.CreatedAt.Before(before) {
			delete(s.checkLogs, k)
			count++
		}
	}
	return count, nil
}

func (s *Store) PurgeCheckLogsForTenant(_ context.Context, tenantID string, before time.Time) (int64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("warden: purge check logs for tenant: %w", wardenerr.ErrTenantRequired)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, e := range s.checkLogs {
		if e.TenantID == tenantID && e.CreatedAt.Before(before) {
			delete(s.checkLogs, k)
			count++
		}
	}
	return count, nil
}

func (s *Store) DeleteCheckLogsBySubject(_ context.Context, tenantID, subjectKind, subjectID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for k, e := range s.checkLogs {
		if e.TenantID == tenantID && e.SubjectKind == subjectKind && e.SubjectID == subjectID {
			delete(s.checkLogs, k)
			count++
		}
	}
	return count, nil
}

func (s *Store) DeleteCheckLogsByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.checkLogs {
		if e.TenantID == tenantID {
			delete(s.checkLogs, k)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

// defaultFanout caps a relation hop or an access-review page when the caller
// passes 0. It matches the SQL backends so a caller sees the same truncation
// regardless of which store is behind it.
const defaultFanout = 1000

// fanoutLimit resolves a caller-supplied limit: 0 (or negative) means the
// default.
func fanoutLimit(limit int) int {
	if limit <= 0 {
		return defaultFanout
	}
	return limit
}

// nsHasPrefix reports whether path is namespace prefix or one of its descendants.
// "" matches anything; "eng" matches "eng" and "eng/...".
func nsHasPrefix(path, prefix string) bool {
	if prefix == "" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// nsMatcher matches entity namespace_path values against a set of paths.
// A nil/empty matcher matches any namespace (legacy/unscoped behavior).
type nsMatcher struct {
	paths    map[string]struct{}
	matchAny bool
}

func namespacePathSet(paths []string) nsMatcher {
	if len(paths) == 0 {
		return nsMatcher{matchAny: true}
	}
	m := nsMatcher{paths: make(map[string]struct{}, len(paths))}
	for _, p := range paths {
		m.paths[p] = struct{}{}
	}
	return m
}

func (m nsMatcher) matches(path string) bool {
	if m.matchAny {
		return true
	}
	_, ok := m.paths[path]
	return ok
}

func copyRole(r *role.Role) *role.Role {
	c := *r
	return &c
}

func copyPermission(p *permission.Permission) *permission.Permission {
	c := *p
	return &c
}

func copyAssignment(a *assignment.Assignment) *assignment.Assignment {
	c := *a
	return &c
}

func copyTuple(t *relation.Tuple) *relation.Tuple {
	c := *t
	return &c
}

func copyPolicy(p *policy.Policy) *policy.Policy {
	c := *p
	if p.Subjects != nil {
		c.Subjects = make([]policy.SubjectMatch, len(p.Subjects))
		copy(c.Subjects, p.Subjects)
	}
	if p.Actions != nil {
		c.Actions = make([]string, len(p.Actions))
		copy(c.Actions, p.Actions)
	}
	if p.Resources != nil {
		c.Resources = make([]string, len(p.Resources))
		copy(c.Resources, p.Resources)
	}
	if p.Conditions != nil {
		c.Conditions = make([]policy.Condition, len(p.Conditions))
		copy(c.Conditions, p.Conditions)
	}
	if p.Obligations != nil {
		c.Obligations = make([]string, len(p.Obligations))
		copy(c.Obligations, p.Obligations)
	}
	if p.NotBefore != nil {
		v := *p.NotBefore
		c.NotBefore = &v
	}
	if p.NotAfter != nil {
		v := *p.NotAfter
		c.NotAfter = &v
	}
	return &c
}

func copyResourceType(rt *resourcetype.ResourceType) *resourcetype.ResourceType {
	c := *rt
	if rt.Relations != nil {
		c.Relations = make([]resourcetype.RelationDef, len(rt.Relations))
		copy(c.Relations, rt.Relations)
	}
	if rt.Permissions != nil {
		c.Permissions = make([]resourcetype.PermissionDef, len(rt.Permissions))
		copy(c.Permissions, rt.Permissions)
	}
	return &c
}

func copyCheckLog(e *checklog.Entry) *checklog.Entry {
	c := *e
	if e.MatchedBy != nil {
		c.MatchedBy = make([]checklog.MatchRef, len(e.MatchedBy))
		copy(c.MatchedBy, e.MatchedBy)
	}
	if e.Obligations != nil {
		c.Obligations = make([]string, len(e.Obligations))
		copy(c.Obligations, e.Obligations)
	}
	return &c
}

// sortByCreatedAt orders items by (CreatedAt, ID) ascending, using key to
// pull the sort fields out of each item.
//
// Every List* method walks a Go map to build its result, and Go
// deliberately randomizes map iteration order, so two calls with the same
// filter could come back in a different row order. That's invisible to a
// caller who reads a whole result set in one call, but it breaks
// offset-based paging (dsl/paginate.go collectPages, and any caller doing
// its own Offset/Limit sweep): a row can be skipped or repeated across
// pages if it lands on either side of a page boundary differently call to
// call. Sorting by creation time, with ID as a tiebreak for rows created in
// the same instant, gives every List* call the same total order the SQL
// backends already provide via ORDER BY created_at.
func sortByCreatedAt[T any](items []*T, key func(*T) (time.Time, string)) {
	sort.Slice(items, func(i, j int) bool {
		ti, idi := key(items[i])
		tj, idj := key(items[j])
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return idi < idj
	})
}

// capTuples puts a relation fanout in (CreatedAt, ID) order and then
// truncates it to the caller's limit.
//
// The obvious optimisation here is to stop walking as soon as the result
// hits the cap, and that is what this used to do. It is wrong against a Go
// map: the SQL backends stop early on rows an index already handed over in
// created_at order, whereas a map hands them over shuffled, so breaking
// early samples an arbitrary subset rather than truncating a defined one.
// Two calls with identical arguments could return different tuples. Paying
// for the full walk buys the caller the same rows every backend returns.
func capTuples(result []*relation.Tuple, limit int) []*relation.Tuple {
	sortByCreatedAt(result, func(t *relation.Tuple) (time.Time, string) { return t.CreatedAt, t.ID.String() })
	if n := fanoutLimit(limit); len(result) > n {
		result = result[:n]
	}
	return result
}

// sortActivePolicies matches the order the SQL backends evaluate policies
// in: priority first, then creation time, then ID. Priority alone leaves
// ties unordered, which meant two calls could disagree about which of two
// equal-priority policies the engine saw first.
func sortActivePolicies(result []*policy.Policy) {
	sort.Slice(result, func(i, j int) bool {
		if result[i].Priority != result[j].Priority {
			return result[i].Priority < result[j].Priority
		}
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID.String() < result[j].ID.String()
	})
}

// Pagination helpers for each entity type.
type pagOpts struct{ limit, offset int }

func paginationOpts(f *role.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPagination[T any](items []*T, p pagOpts) []*T {
	if p.offset > 0 && p.offset < len(items) {
		items = items[p.offset:]
	} else if p.offset >= len(items) {
		return nil
	}
	if limit := fanoutLimit(p.limit); limit < len(items) {
		items = items[:limit]
	}
	return items
}

func paginationOptsPerm(f *permission.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationPerm(items []*permission.Permission, p pagOpts) []*permission.Permission {
	return applyPagination(items, p)
}

func paginationOptsAssign(f *assignment.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationAssign(items []*assignment.Assignment, p pagOpts) []*assignment.Assignment {
	return applyPagination(items, p)
}

func paginationOptsRel(f *relation.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationRel(items []*relation.Tuple, p pagOpts) []*relation.Tuple {
	return applyPagination(items, p)
}

func paginationOptsPol(f *policy.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationPol(items []*policy.Policy, p pagOpts) []*policy.Policy {
	return applyPagination(items, p)
}

func paginationOptsRT(f *resourcetype.ListFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationRT(items []*resourcetype.ResourceType, p pagOpts) []*resourcetype.ResourceType {
	return applyPagination(items, p)
}

func paginationOptsCL(f *checklog.QueryFilter) pagOpts {
	if f == nil {
		return pagOpts{}
	}
	return pagOpts{limit: f.Limit, offset: f.Offset}
}

func applyPaginationCL(items []*checklog.Entry, p pagOpts) []*checklog.Entry {
	return applyPagination(items, p)
}
