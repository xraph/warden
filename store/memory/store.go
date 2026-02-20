// Package memory provides an in-memory implementation of the Warden composite
// store. It is intended for testing and development.
package memory

import (
	"context"
	"fmt"
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

// Store is a thread-safe in-memory store for all Warden entities.
type Store struct {
	mu sync.RWMutex

	roles           map[string]*role.Role
	permissions     map[string]*permission.Permission
	rolePermissions map[string]map[string]struct{} // roleID -> set of permIDs
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID.String()] = copyRole(r)
	return nil
}

func (s *Store) GetRole(_ context.Context, roleID id.RoleID) (*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleID.String()]
	if !ok {
		return nil, fmt.Errorf("role %s: %w", roleID, errNotFound)
	}
	return copyRole(r), nil
}

func (s *Store) GetRoleBySlug(_ context.Context, tenantID, slug string) (*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.roles {
		if r.TenantID == tenantID && r.Slug == slug {
			return copyRole(r), nil
		}
	}
	return nil, fmt.Errorf("role slug %q: %w", slug, errNotFound)
}

func (s *Store) UpdateRole(_ context.Context, r *role.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[r.ID.String()]; !ok {
		return fmt.Errorf("role %s: %w", r.ID, errNotFound)
	}
	s.roles[r.ID.String()] = copyRole(r)
	return nil
}

func (s *Store) DeleteRole(_ context.Context, roleID id.RoleID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, roleID.String())
	delete(s.rolePermissions, roleID.String())
	return nil
}

func (s *Store) ListRoles(_ context.Context, filter *role.ListFilter) ([]*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*role.Role, 0, len(s.roles))
	for _, r := range s.roles {
		if filter != nil {
			if filter.TenantID != "" && r.TenantID != filter.TenantID {
				continue
			}
			if filter.IsSystem != nil && r.IsSystem != *filter.IsSystem {
				continue
			}
			if filter.IsDefault != nil && r.IsDefault != *filter.IsDefault {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(r.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyRole(r))
	}
	return applyPagination(result, paginationOpts(filter)), nil
}

func (s *Store) CountRoles(ctx context.Context, filter *role.ListFilter) (int64, error) {
	list, err := s.ListRoles(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

func (s *Store) ListRolePermissions(_ context.Context, roleID id.RoleID) ([]id.PermissionID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	perms, ok := s.rolePermissions[roleID.String()]
	if !ok {
		return nil, nil
	}
	result := make([]id.PermissionID, 0, len(perms))
	for pid := range perms {
		parsed, err := id.ParsePermissionID(pid)
		if err == nil {
			result = append(result, parsed)
		}
	}
	return result, nil
}

func (s *Store) AttachPermission(_ context.Context, roleID id.RoleID, permID id.PermissionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rk := roleID.String()
	if s.rolePermissions[rk] == nil {
		s.rolePermissions[rk] = make(map[string]struct{})
	}
	s.rolePermissions[rk][permID.String()] = struct{}{}
	return nil
}

func (s *Store) DetachPermission(_ context.Context, roleID id.RoleID, permID id.PermissionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if perms, ok := s.rolePermissions[roleID.String()]; ok {
		delete(perms, permID.String())
	}
	return nil
}

func (s *Store) SetRolePermissions(_ context.Context, roleID id.RoleID, permIDs []id.PermissionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	perms := make(map[string]struct{}, len(permIDs))
	for _, pid := range permIDs {
		perms[pid.String()] = struct{}{}
	}
	s.rolePermissions[roleID.String()] = perms
	return nil
}

func (s *Store) ListChildRoles(_ context.Context, parentID id.RoleID) ([]*role.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*role.Role
	pid := parentID.String()
	for _, r := range s.roles {
		if r.ParentID != nil && r.ParentID.String() == pid {
			result = append(result, copyRole(r))
		}
	}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.permissions[p.ID.String()] = copyPermission(p)
	return nil
}

func (s *Store) GetPermission(_ context.Context, permID id.PermissionID) (*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.permissions[permID.String()]
	if !ok {
		return nil, fmt.Errorf("permission %s: %w", permID, errNotFound)
	}
	return copyPermission(p), nil
}

func (s *Store) GetPermissionByName(_ context.Context, tenantID, name string) (*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.permissions {
		if p.TenantID == tenantID && p.Name == name {
			return copyPermission(p), nil
		}
	}
	return nil, fmt.Errorf("permission %q: %w", name, errNotFound)
}

func (s *Store) UpdatePermission(_ context.Context, p *permission.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.permissions[p.ID.String()]; !ok {
		return fmt.Errorf("permission %s: %w", p.ID, errNotFound)
	}
	s.permissions[p.ID.String()] = copyPermission(p)
	return nil
}

func (s *Store) DeletePermission(_ context.Context, permID id.PermissionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.permissions, permID.String())
	// Remove from role-permission mappings.
	pk := permID.String()
	for _, perms := range s.rolePermissions {
		delete(perms, pk)
	}
	return nil
}

func (s *Store) ListPermissions(_ context.Context, filter *permission.ListFilter) ([]*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*permission.Permission, 0, len(s.permissions))
	for _, p := range s.permissions {
		if filter != nil {
			if filter.TenantID != "" && p.TenantID != filter.TenantID {
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
	return applyPaginationPerm(result, paginationOptsPerm(filter)), nil
}

func (s *Store) CountPermissions(ctx context.Context, filter *permission.ListFilter) (int64, error) {
	list, err := s.ListPermissions(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

func (s *Store) ListPermissionsByRole(_ context.Context, roleID id.RoleID) ([]*permission.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	perms, ok := s.rolePermissions[roleID.String()]
	if !ok {
		return nil, nil
	}
	var result []*permission.Permission
	for pid := range perms {
		if p, ok := s.permissions[pid]; ok {
			result = append(result, copyPermission(p))
		}
	}
	return result, nil
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
	// Gather permissions from those roles.
	seen := make(map[string]struct{})
	var result []*permission.Permission
	for rid := range roleIDs {
		if perms, ok := s.rolePermissions[rid]; ok {
			for pid := range perms {
				if _, dup := seen[pid]; dup {
					continue
				}
				seen[pid] = struct{}{}
				if p, ok := s.permissions[pid]; ok {
					result = append(result, copyPermission(p))
				}
			}
		}
	}
	return result, nil
}

func (s *Store) DeletePermissionsByTenant(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.permissions {
		if p.TenantID == tenantID {
			delete(s.permissions, k)
			for _, perms := range s.rolePermissions {
				delete(perms, k)
			}
		}
	}
	return nil
}

// ──────────────────────────────────────────────────
// Assignment Store
// ──────────────────────────────────────────────────

func (s *Store) CreateAssignment(_ context.Context, a *assignment.Assignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assignments[a.ID.String()] = copyAssignment(a)
	return nil
}

func (s *Store) GetAssignment(_ context.Context, assID id.AssignmentID) (*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assignments[assID.String()]
	if !ok {
		return nil, fmt.Errorf("assignment %s: %w", assID, errNotFound)
	}
	return copyAssignment(a), nil
}

func (s *Store) DeleteAssignment(_ context.Context, assID id.AssignmentID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assignments, assID.String())
	return nil
}

func (s *Store) ListAssignments(_ context.Context, filter *assignment.ListFilter) ([]*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*assignment.Assignment, 0, len(s.assignments))
	for _, a := range s.assignments {
		if filter != nil {
			if filter.TenantID != "" && a.TenantID != filter.TenantID {
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
		}
		result = append(result, copyAssignment(a))
	}
	return applyPaginationAssign(result, paginationOptsAssign(filter)), nil
}

func (s *Store) CountAssignments(ctx context.Context, filter *assignment.ListFilter) (int64, error) {
	list, err := s.ListAssignments(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

func (s *Store) ListRolesForSubject(_ context.Context, tenantID, subjectKind, subjectID string) ([]id.RoleID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []id.RoleID
	for _, a := range s.assignments {
		if a.TenantID == tenantID && a.SubjectKind == subjectKind && a.SubjectID == subjectID && a.ResourceType == "" {
			result = append(result, a.RoleID)
		}
	}
	return result, nil
}

func (s *Store) ListRolesForSubjectOnResource(_ context.Context, tenantID, subjectKind, subjectID, resourceType, resourceID string) ([]id.RoleID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []id.RoleID
	for _, a := range s.assignments {
		if a.TenantID == tenantID && a.SubjectKind == subjectKind && a.SubjectID == subjectID && a.ResourceType == resourceType && a.ResourceID == resourceID {
			result = append(result, a.RoleID)
		}
	}
	return result, nil
}

func (s *Store) ListSubjectsForRole(_ context.Context, roleID id.RoleID) ([]*assignment.Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rid := roleID.String()
	var result []*assignment.Assignment
	for _, a := range s.assignments {
		if a.RoleID.String() == rid {
			result = append(result, copyAssignment(a))
		}
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

func (s *Store) DeleteAssignmentsByRole(_ context.Context, roleID id.RoleID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rid := roleID.String()
	for k, a := range s.assignments {
		if a.RoleID.String() == rid {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relations[t.ID.String()] = copyTuple(t)
	return nil
}

func (s *Store) DeleteRelation(_ context.Context, relID id.RelationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.relations, relID.String())
	return nil
}

func (s *Store) DeleteRelationTuple(_ context.Context, tenantID, objectType, objectID, rel, subjectType, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.relations {
		if t.TenantID == tenantID && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel && t.SubjectType == subjectType && t.SubjectID == subjectID {
			delete(s.relations, k)
			return nil
		}
	}
	return nil
}

func (s *Store) ListRelations(_ context.Context, filter *relation.ListFilter) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*relation.Tuple, 0, len(s.relations))
	for _, t := range s.relations {
		if filter != nil {
			if filter.TenantID != "" && t.TenantID != filter.TenantID {
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
		}
		result = append(result, copyTuple(t))
	}
	return applyPaginationRel(result, paginationOptsRel(filter)), nil
}

func (s *Store) CountRelations(ctx context.Context, filter *relation.ListFilter) (int64, error) {
	list, err := s.ListRelations(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

func (s *Store) ListRelationSubjects(_ context.Context, tenantID, objectType, objectID, rel string) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*relation.Tuple
	for _, t := range s.relations {
		if t.TenantID == tenantID && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel {
			result = append(result, copyTuple(t))
		}
	}
	return result, nil
}

func (s *Store) ListRelationObjects(_ context.Context, tenantID, subjectType, subjectID, rel string) ([]*relation.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*relation.Tuple
	for _, t := range s.relations {
		if t.TenantID == tenantID && t.SubjectType == subjectType && t.SubjectID == subjectID && t.Relation == rel {
			result = append(result, copyTuple(t))
		}
	}
	return result, nil
}

func (s *Store) CheckDirectRelation(_ context.Context, tenantID, objectType, objectID, rel, subjectType, subjectID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.relations {
		if t.TenantID == tenantID && t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == rel && t.SubjectType == subjectType && t.SubjectID == subjectID {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID.String()] = copyPolicy(p)
	return nil
}

func (s *Store) GetPolicy(_ context.Context, polID id.PolicyID) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[polID.String()]
	if !ok {
		return nil, fmt.Errorf("policy %s: %w", polID, errNotFound)
	}
	return copyPolicy(p), nil
}

func (s *Store) GetPolicyByName(_ context.Context, tenantID, name string) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.policies {
		if p.TenantID == tenantID && p.Name == name {
			return copyPolicy(p), nil
		}
	}
	return nil, fmt.Errorf("policy %q: %w", name, errNotFound)
}

func (s *Store) UpdatePolicy(_ context.Context, p *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[p.ID.String()]; !ok {
		return fmt.Errorf("policy %s: %w", p.ID, errNotFound)
	}
	s.policies[p.ID.String()] = copyPolicy(p)
	return nil
}

func (s *Store) DeletePolicy(_ context.Context, polID id.PolicyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, polID.String())
	return nil
}

func (s *Store) ListPolicies(_ context.Context, filter *policy.ListFilter) ([]*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		if filter != nil {
			if filter.TenantID != "" && p.TenantID != filter.TenantID {
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
	return applyPaginationPol(result, paginationOptsPol(filter)), nil
}

func (s *Store) CountPolicies(ctx context.Context, filter *policy.ListFilter) (int64, error) {
	list, err := s.ListPolicies(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

func (s *Store) ListActivePolicies(_ context.Context, tenantID string) ([]*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*policy.Policy
	for _, p := range s.policies {
		if p.TenantID == tenantID && p.IsActive {
			result = append(result, copyPolicy(p))
		}
	}
	return result, nil
}

func (s *Store) SetPolicyVersion(_ context.Context, polID id.PolicyID, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[polID.String()]
	if !ok {
		return fmt.Errorf("policy %s: %w", polID, errNotFound)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resourceTypes[rt.ID.String()] = copyResourceType(rt)
	return nil
}

func (s *Store) GetResourceType(_ context.Context, rtID id.ResourceTypeID) (*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.resourceTypes[rtID.String()]
	if !ok {
		return nil, fmt.Errorf("resource type %s: %w", rtID, errNotFound)
	}
	return copyResourceType(rt), nil
}

func (s *Store) GetResourceTypeByName(_ context.Context, tenantID, name string) (*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rt := range s.resourceTypes {
		if rt.TenantID == tenantID && rt.Name == name {
			return copyResourceType(rt), nil
		}
	}
	return nil, fmt.Errorf("resource type %q: %w", name, errNotFound)
}

func (s *Store) UpdateResourceType(_ context.Context, rt *resourcetype.ResourceType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.resourceTypes[rt.ID.String()]; !ok {
		return fmt.Errorf("resource type %s: %w", rt.ID, errNotFound)
	}
	s.resourceTypes[rt.ID.String()] = copyResourceType(rt)
	return nil
}

func (s *Store) DeleteResourceType(_ context.Context, rtID id.ResourceTypeID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.resourceTypes, rtID.String())
	return nil
}

func (s *Store) ListResourceTypes(_ context.Context, filter *resourcetype.ListFilter) ([]*resourcetype.ResourceType, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*resourcetype.ResourceType, 0, len(s.resourceTypes))
	for _, rt := range s.resourceTypes {
		if filter != nil {
			if filter.TenantID != "" && rt.TenantID != filter.TenantID {
				continue
			}
			if filter.Search != "" && !strings.Contains(strings.ToLower(rt.Name), strings.ToLower(filter.Search)) {
				continue
			}
		}
		result = append(result, copyResourceType(rt))
	}
	return applyPaginationRT(result, paginationOptsRT(filter)), nil
}

func (s *Store) CountResourceTypes(ctx context.Context, filter *resourcetype.ListFilter) (int64, error) {
	list, err := s.ListResourceTypes(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkLogs[e.ID.String()] = copyCheckLog(e)
	return nil
}

func (s *Store) GetCheckLog(_ context.Context, logID id.CheckLogID) (*checklog.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.checkLogs[logID.String()]
	if !ok {
		return nil, fmt.Errorf("check log %s: %w", logID, errNotFound)
	}
	return copyCheckLog(e), nil
}

func (s *Store) ListCheckLogs(_ context.Context, filter *checklog.QueryFilter) ([]*checklog.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*checklog.Entry, 0, len(s.checkLogs))
	for _, e := range s.checkLogs {
		if filter != nil {
			if filter.TenantID != "" && e.TenantID != filter.TenantID {
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
			if filter.Decision != "" && e.Decision != filter.Decision {
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
	return applyPaginationCL(result, paginationOptsCL(filter)), nil
}

func (s *Store) CountCheckLogs(ctx context.Context, filter *checklog.QueryFilter) (int64, error) {
	list, err := s.ListCheckLogs(ctx, filter)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
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

var errNotFound = fmt.Errorf("not found")

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
	return &c
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
	if p.limit > 0 && p.limit < len(items) {
		items = items[:p.limit]
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
