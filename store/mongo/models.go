package mongo

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// nonNilMap returns m unchanged unless it is nil, in which case it returns
// a non-nil empty map. MongoDB's generated $jsonSchema validator types a Go
// map field as strictly "object" (see buildFieldSchema in
// grove/drivers/mongodriver: only pointer-kind fields get the "or null"
// treatment). grove's insert path writes every field into the document
// regardless of Go zero value (it does not honor `omitempty`), so a nil map
// serializes to BSON null and the validator rejects it with "type did not
// match". Every *ToModel below normalizes its map/slice fields through this
// (and nonNilSlice) so a caller who never set Metadata still gets a valid,
// insertable document: an empty object/array instead of null.
func nonNilMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}

// nonNilSlice is nonNilMap's counterpart for slice fields typed "array" by
// the same generated validator.
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ──────────────────────────────────────────────────
// Role model
// ──────────────────────────────────────────────────

type roleModel struct {
	grove.BaseModel `grove:"table:warden_roles"`
	ID              string         `grove:"id,pk"           bson:"_id"`
	TenantID        string         `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string         `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string         `grove:"app_id"          bson:"app_id"`
	Name            string         `grove:"name"            bson:"name"`
	Description     string         `grove:"description"     bson:"description"`
	Slug            string         `grove:"slug"            bson:"slug"`
	IsSystem        bool           `grove:"is_system"       bson:"is_system"`
	IsDefault       bool           `grove:"is_default"      bson:"is_default"`
	ParentSlug      *string        `grove:"parent_slug"     bson:"parent_slug,omitempty"`
	MaxMembers      int            `grove:"max_members"     bson:"max_members"`
	Metadata        map[string]any `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedBy       string         `grove:"created_by"      bson:"created_by"`
	UpdatedBy       string         `grove:"updated_by"      bson:"updated_by"`
	CreatedAt       time.Time      `grove:"created_at"      bson:"created_at"`
	UpdatedAt       time.Time      `grove:"updated_at"      bson:"updated_at"`
}

func roleToModel(r *role.Role) *roleModel {
	m := &roleModel{
		ID:            r.ID.String(),
		TenantID:      r.TenantID,
		NamespacePath: r.NamespacePath,
		AppID:         r.AppID,
		Name:          r.Name,
		Description:   r.Description,
		Slug:          r.Slug,
		IsSystem:      r.IsSystem,
		IsDefault:     r.IsDefault,
		MaxMembers:    r.MaxMembers,
		Metadata:      nonNilMap(r.Metadata),
		CreatedBy:     r.CreatedBy,
		UpdatedBy:     r.UpdatedBy,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
	if r.ParentSlug != "" {
		s := r.ParentSlug
		m.ParentSlug = &s
	}
	return m
}

func roleFromModel(m *roleModel) *role.Role {
	rid, _ := id.ParseRoleID(m.ID) //nolint:errcheck // stored IDs are always valid
	r := &role.Role{
		ID:            rid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		Name:          m.Name,
		Description:   m.Description,
		Slug:          m.Slug,
		IsSystem:      m.IsSystem,
		IsDefault:     m.IsDefault,
		MaxMembers:    m.MaxMembers,
		Metadata:      m.Metadata,
		CreatedBy:     m.CreatedBy,
		UpdatedBy:     m.UpdatedBy,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
	if m.ParentSlug != nil {
		r.ParentSlug = *m.ParentSlug
	}
	return r
}

// ──────────────────────────────────────────────────
// Permission model
// ──────────────────────────────────────────────────

type permissionModel struct {
	grove.BaseModel `grove:"table:warden_permissions"`
	ID              string         `grove:"id,pk"           bson:"_id"`
	TenantID        string         `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string         `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string         `grove:"app_id"          bson:"app_id"`
	Name            string         `grove:"name"            bson:"name"`
	Description     string         `grove:"description"     bson:"description"`
	Resource        string         `grove:"resource"        bson:"resource"`
	Action          string         `grove:"action"          bson:"action"`
	IsSystem        bool           `grove:"is_system"       bson:"is_system"`
	Metadata        map[string]any `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedBy       string         `grove:"created_by"      bson:"created_by"`
	UpdatedBy       string         `grove:"updated_by"      bson:"updated_by"`
	CreatedAt       time.Time      `grove:"created_at"      bson:"created_at"`
	UpdatedAt       time.Time      `grove:"updated_at"      bson:"updated_at"`
}

func permissionToModel(p *permission.Permission) *permissionModel {
	return &permissionModel{
		ID:            p.ID.String(),
		TenantID:      p.TenantID,
		NamespacePath: p.NamespacePath,
		AppID:         p.AppID,
		Name:          p.Name,
		Description:   p.Description,
		Resource:      p.Resource,
		Action:        p.Action,
		IsSystem:      p.IsSystem,
		Metadata:      nonNilMap(p.Metadata),
		CreatedBy:     p.CreatedBy,
		UpdatedBy:     p.UpdatedBy,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

func permissionFromModel(m *permissionModel) *permission.Permission {
	pid, _ := id.ParsePermissionID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &permission.Permission{
		ID:            pid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		Name:          m.Name,
		Description:   m.Description,
		Resource:      m.Resource,
		Action:        m.Action,
		IsSystem:      m.IsSystem,
		Metadata:      m.Metadata,
		CreatedBy:     m.CreatedBy,
		UpdatedBy:     m.UpdatedBy,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Role-Permission junction model
// ──────────────────────────────────────────────────

// rolePermissionModel's uniqueness comes from the compound index on
// (role_id, perm_namespace_path, perm_name) created in migrations.go, not
// from a `pk`-tagged field: none of the three map to Mongo's actual `_id`
// (only a field whose grove Column is literally "id" does), so marking them
// `pk` bought nothing except grove's structToMapInsert treating each one as
// an independent auto-generated key and skipping it from the insert
// whenever its own value happens to be the Go zero value. perm_namespace_path
// is legitimately "" for the tenant root namespace, so that skip silently
// dropped the field from the document, which the collection's generated
// $jsonSchema then rejected as missing a required property. Plain (non-pk)
// grove tags avoid the skip; Mongo still auto-generates its own _id.
type rolePermissionModel struct {
	grove.BaseModel   `grove:"table:warden_role_permissions"`
	RoleID            string `grove:"role_id"             bson:"role_id"`
	PermNamespacePath string `grove:"perm_namespace_path" bson:"perm_namespace_path"`
	PermName          string `grove:"perm_name"           bson:"perm_name"`
}

// ──────────────────────────────────────────────────
// Assignment model
// ──────────────────────────────────────────────────

type assignmentModel struct {
	grove.BaseModel `grove:"table:warden_assignments"`
	ID              string         `grove:"id,pk"           bson:"_id"`
	TenantID        string         `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string         `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string         `grove:"app_id"          bson:"app_id"`
	RoleID          string         `grove:"role_id"         bson:"role_id"`
	SubjectKind     string         `grove:"subject_kind"    bson:"subject_kind"`
	SubjectID       string         `grove:"subject_id"      bson:"subject_id"`
	ResourceType    string         `grove:"resource_type"   bson:"resource_type"`
	ResourceID      string         `grove:"resource_id"     bson:"resource_id"`
	ExpiresAt       *time.Time     `grove:"expires_at"      bson:"expires_at,omitempty"`
	GrantedBy       string         `grove:"granted_by"      bson:"granted_by"`
	Metadata        map[string]any `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedAt       time.Time      `grove:"created_at"      bson:"created_at"`
}

func assignmentToModel(a *assignment.Assignment) *assignmentModel {
	return &assignmentModel{
		ID:            a.ID.String(),
		TenantID:      a.TenantID,
		NamespacePath: a.NamespacePath,
		AppID:         a.AppID,
		RoleID:        a.RoleID.String(),
		SubjectKind:   a.SubjectKind,
		SubjectID:     a.SubjectID,
		ResourceType:  a.ResourceType,
		ResourceID:    a.ResourceID,
		ExpiresAt:     a.ExpiresAt,
		GrantedBy:     a.GrantedBy,
		Metadata:      nonNilMap(a.Metadata),
		CreatedAt:     a.CreatedAt,
	}
}

func assignmentFromModel(m *assignmentModel) *assignment.Assignment {
	aid, _ := id.ParseAssignmentID(m.ID) //nolint:errcheck // stored IDs are always valid
	rid, _ := id.ParseRoleID(m.RoleID)   //nolint:errcheck // stored IDs are always valid
	return &assignment.Assignment{
		ID:            aid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		RoleID:        rid,
		SubjectKind:   m.SubjectKind,
		SubjectID:     m.SubjectID,
		ResourceType:  m.ResourceType,
		ResourceID:    m.ResourceID,
		ExpiresAt:     m.ExpiresAt,
		GrantedBy:     m.GrantedBy,
		Metadata:      m.Metadata,
		CreatedAt:     m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Relation (tuple) model
// ──────────────────────────────────────────────────

type relationModel struct {
	grove.BaseModel `grove:"table:warden_relations"`
	ID              string         `grove:"id,pk"              bson:"_id"`
	TenantID        string         `grove:"tenant_id"          bson:"tenant_id"`
	NamespacePath   string         `grove:"namespace_path"     bson:"namespace_path"`
	AppID           string         `grove:"app_id"             bson:"app_id"`
	ObjectType      string         `grove:"object_type"        bson:"object_type"`
	ObjectID        string         `grove:"object_id"          bson:"object_id"`
	Relation        string         `grove:"relation"           bson:"relation"`
	SubjectType     string         `grove:"subject_type"       bson:"subject_type"`
	SubjectID       string         `grove:"subject_id"         bson:"subject_id"`
	SubjectRelation string         `grove:"subject_relation"   bson:"subject_relation"`
	Metadata        map[string]any `grove:"metadata"           bson:"metadata,omitempty"`
	CreatedBy       string         `grove:"created_by"         bson:"created_by"`
	CreatedAt       time.Time      `grove:"created_at"         bson:"created_at"`
}

func relationToModel(t *relation.Tuple) *relationModel {
	return &relationModel{
		ID:              t.ID.String(),
		TenantID:        t.TenantID,
		NamespacePath:   t.NamespacePath,
		AppID:           t.AppID,
		ObjectType:      t.ObjectType,
		ObjectID:        t.ObjectID,
		Relation:        t.Relation,
		SubjectType:     t.SubjectType,
		SubjectID:       t.SubjectID,
		SubjectRelation: t.SubjectRelation,
		Metadata:        nonNilMap(t.Metadata),
		CreatedBy:       t.CreatedBy,
		CreatedAt:       t.CreatedAt,
	}
}

func relationFromModel(m *relationModel) *relation.Tuple {
	rid, _ := id.ParseRelationID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &relation.Tuple{
		ID:              rid,
		TenantID:        m.TenantID,
		NamespacePath:   m.NamespacePath,
		AppID:           m.AppID,
		ObjectType:      m.ObjectType,
		ObjectID:        m.ObjectID,
		Relation:        m.Relation,
		SubjectType:     m.SubjectType,
		SubjectID:       m.SubjectID,
		SubjectRelation: m.SubjectRelation,
		Metadata:        m.Metadata,
		CreatedBy:       m.CreatedBy,
		CreatedAt:       m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Policy model (ABAC)
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:warden_policies"`
	ID              string                `grove:"id,pk"           bson:"_id"`
	TenantID        string                `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string                `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string                `grove:"app_id"          bson:"app_id"`
	Name            string                `grove:"name"            bson:"name"`
	Description     string                `grove:"description"     bson:"description"`
	Effect          string                `grove:"effect"          bson:"effect"`
	Priority        int                   `grove:"priority"        bson:"priority"`
	IsActive        bool                  `grove:"is_active"       bson:"is_active"`
	NotBefore       *time.Time            `grove:"not_before"      bson:"not_before,omitempty"`
	NotAfter        *time.Time            `grove:"not_after"       bson:"not_after,omitempty"`
	Obligations     []string              `grove:"obligations"     bson:"obligations"`
	Version         int                   `grove:"version"         bson:"version"`
	Subjects        []policy.SubjectMatch `grove:"subjects"        bson:"subjects"`
	Actions         []string              `grove:"actions"         bson:"actions"`
	Resources       []string              `grove:"resources"       bson:"resources"`
	Conditions      []policy.Condition    `grove:"conditions"      bson:"conditions,omitempty"`
	Metadata        map[string]any        `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedBy       string                `grove:"created_by"      bson:"created_by"`
	UpdatedBy       string                `grove:"updated_by"      bson:"updated_by"`
	CreatedAt       time.Time             `grove:"created_at"      bson:"created_at"`
	UpdatedAt       time.Time             `grove:"updated_at"      bson:"updated_at"`
}

func policyToModel(p *policy.Policy) *policyModel {
	return &policyModel{
		ID:            p.ID.String(),
		TenantID:      p.TenantID,
		NamespacePath: p.NamespacePath,
		AppID:         p.AppID,
		Name:          p.Name,
		Description:   p.Description,
		Effect:        string(p.Effect),
		Priority:      p.Priority,
		IsActive:      p.IsActive,
		NotBefore:     p.NotBefore,
		NotAfter:      p.NotAfter,
		Obligations:   nonNilSlice(p.Obligations),
		Version:       p.Version,
		Subjects:      nonNilSlice(p.Subjects),
		Actions:       nonNilSlice(p.Actions),
		Resources:     nonNilSlice(p.Resources),
		Conditions:    nonNilSlice(p.Conditions),
		Metadata:      nonNilMap(p.Metadata),
		CreatedBy:     p.CreatedBy,
		UpdatedBy:     p.UpdatedBy,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
	}
}

func policyFromModel(m *policyModel) *policy.Policy {
	pid, _ := id.ParsePolicyID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &policy.Policy{
		ID:            pid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		Name:          m.Name,
		Description:   m.Description,
		Effect:        policy.Effect(m.Effect),
		Priority:      m.Priority,
		IsActive:      m.IsActive,
		NotBefore:     m.NotBefore,
		NotAfter:      m.NotAfter,
		Obligations:   m.Obligations,
		Version:       m.Version,
		Subjects:      m.Subjects,
		Actions:       m.Actions,
		Resources:     m.Resources,
		Conditions:    m.Conditions,
		Metadata:      m.Metadata,
		CreatedBy:     m.CreatedBy,
		UpdatedBy:     m.UpdatedBy,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Resource type model (ReBAC schema)
// ──────────────────────────────────────────────────

type resourceTypeModel struct {
	grove.BaseModel `grove:"table:warden_resource_types"`
	ID              string                       `grove:"id,pk"           bson:"_id"`
	TenantID        string                       `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string                       `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string                       `grove:"app_id"          bson:"app_id"`
	Name            string                       `grove:"name"            bson:"name"`
	Description     string                       `grove:"description"     bson:"description"`
	Relations       []resourcetype.RelationDef   `grove:"relations"       bson:"relations"`
	Permissions     []resourcetype.PermissionDef `grove:"permissions"     bson:"permissions"`
	Metadata        map[string]any               `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedBy       string                       `grove:"created_by"      bson:"created_by"`
	UpdatedBy       string                       `grove:"updated_by"      bson:"updated_by"`
	CreatedAt       time.Time                    `grove:"created_at"      bson:"created_at"`
	UpdatedAt       time.Time                    `grove:"updated_at"      bson:"updated_at"`
}

func resourceTypeToModel(rt *resourcetype.ResourceType) *resourceTypeModel {
	return &resourceTypeModel{
		ID:            rt.ID.String(),
		TenantID:      rt.TenantID,
		NamespacePath: rt.NamespacePath,
		AppID:         rt.AppID,
		Name:          rt.Name,
		Description:   rt.Description,
		Relations:     nonNilSlice(rt.Relations),
		Permissions:   nonNilSlice(rt.Permissions),
		Metadata:      nonNilMap(rt.Metadata),
		CreatedBy:     rt.CreatedBy,
		UpdatedBy:     rt.UpdatedBy,
		CreatedAt:     rt.CreatedAt,
		UpdatedAt:     rt.UpdatedAt,
	}
}

func resourceTypeFromModel(m *resourceTypeModel) *resourcetype.ResourceType {
	rtid, _ := id.ParseResourceTypeID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &resourcetype.ResourceType{
		ID:            rtid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		Name:          m.Name,
		Description:   m.Description,
		Relations:     m.Relations,
		Permissions:   m.Permissions,
		Metadata:      m.Metadata,
		CreatedBy:     m.CreatedBy,
		UpdatedBy:     m.UpdatedBy,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Check log model
// ──────────────────────────────────────────────────

type checkLogModel struct {
	grove.BaseModel `grove:"table:warden_check_logs"`
	ID              string              `grove:"id,pk"           bson:"_id"`
	TenantID        string              `grove:"tenant_id"       bson:"tenant_id"`
	NamespacePath   string              `grove:"namespace_path"  bson:"namespace_path"`
	AppID           string              `grove:"app_id"          bson:"app_id"`
	SubjectKind     string              `grove:"subject_kind"    bson:"subject_kind"`
	SubjectID       string              `grove:"subject_id"      bson:"subject_id"`
	Action          string              `grove:"action"          bson:"action"`
	ResourceType    string              `grove:"resource_type"   bson:"resource_type"`
	ResourceID      string              `grove:"resource_id"     bson:"resource_id"`
	Decision        string              `grove:"decision"        bson:"decision"`
	Reason          string              `grove:"reason"          bson:"reason"`
	MatchedBy       []checklog.MatchRef `grove:"matched_by"      bson:"matched_by"`
	Obligations     []string            `grove:"obligations"     bson:"obligations"`
	EvalTimeNs      int64               `grove:"eval_time_ns"    bson:"eval_time_ns"`
	RequestIP       string              `grove:"request_ip"      bson:"request_ip"`
	RequestID       string              `grove:"request_id"      bson:"request_id"`
	TraceID         string              `grove:"trace_id"        bson:"trace_id"`
	Cached          bool                `grove:"cached"          bson:"cached"`
	Error           string              `grove:"error"           bson:"error"`
	Metadata        map[string]any      `grove:"metadata"        bson:"metadata,omitempty"`
	CreatedAt       time.Time           `grove:"created_at"      bson:"created_at"`
}

func checkLogToModel(e *checklog.Entry) *checkLogModel {
	return &checkLogModel{
		ID:            e.ID.String(),
		TenantID:      e.TenantID,
		NamespacePath: e.NamespacePath,
		AppID:         e.AppID,
		SubjectKind:   e.SubjectKind,
		SubjectID:     e.SubjectID,
		Action:        e.Action,
		ResourceType:  e.ResourceType,
		ResourceID:    e.ResourceID,
		Decision:      e.Decision,
		Reason:        e.Reason,
		MatchedBy:     nonNilSlice(e.MatchedBy),
		Obligations:   nonNilSlice(e.Obligations),
		EvalTimeNs:    e.EvalTimeNs,
		RequestIP:     e.RequestIP,
		RequestID:     e.RequestID,
		TraceID:       e.TraceID,
		Cached:        e.Cached,
		Error:         e.Error,
		Metadata:      nonNilMap(e.Metadata),
		CreatedAt:     e.CreatedAt,
	}
}

func checkLogFromModel(m *checkLogModel) *checklog.Entry {
	clid, _ := id.ParseCheckLogID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &checklog.Entry{
		ID:            clid,
		TenantID:      m.TenantID,
		NamespacePath: m.NamespacePath,
		AppID:         m.AppID,
		SubjectKind:   m.SubjectKind,
		SubjectID:     m.SubjectID,
		Action:        m.Action,
		ResourceType:  m.ResourceType,
		ResourceID:    m.ResourceID,
		Decision:      m.Decision,
		Reason:        m.Reason,
		MatchedBy:     m.MatchedBy,
		Obligations:   m.Obligations,
		EvalTimeNs:    m.EvalTimeNs,
		RequestIP:     m.RequestIP,
		RequestID:     m.RequestID,
		TraceID:       m.TraceID,
		Cached:        m.Cached,
		Error:         m.Error,
		Metadata:      m.Metadata,
		CreatedAt:     m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Update documents
// ──────────────────────────────────────────────────
//
// Each builds the $set document for an update. Mongo has no column list to
// restrict, so the fields an update may write are spelled out here. _id and
// tenant_id are absent by design: the filter already matches on both, so
// writing them could only ever be a no-op or a tenant move, and a tenant move
// is not something this API offers. created_at is absent for the same reason
// the memory store preserves it.

func roleUpdateDoc(m *roleModel) bson.M {
	return bson.M{
		"namespace_path": m.NamespacePath,
		"app_id":         m.AppID,
		"name":           m.Name,
		"description":    m.Description,
		"slug":           m.Slug,
		"is_system":      m.IsSystem,
		"is_default":     m.IsDefault,
		"parent_slug":    m.ParentSlug,
		"max_members":    m.MaxMembers,
		"metadata":       m.Metadata,
		"updated_by":     m.UpdatedBy,
		"updated_at":     m.UpdatedAt,
	}
}

func permissionUpdateDoc(m *permissionModel) bson.M {
	return bson.M{
		"namespace_path": m.NamespacePath,
		"app_id":         m.AppID,
		"name":           m.Name,
		"description":    m.Description,
		"resource":       m.Resource,
		"action":         m.Action,
		"is_system":      m.IsSystem,
		"metadata":       m.Metadata,
		"updated_by":     m.UpdatedBy,
		"updated_at":     m.UpdatedAt,
	}
}

func policyUpdateDoc(m *policyModel) bson.M {
	return bson.M{
		"namespace_path": m.NamespacePath,
		"app_id":         m.AppID,
		"name":           m.Name,
		"description":    m.Description,
		"effect":         m.Effect,
		"priority":       m.Priority,
		"is_active":      m.IsActive,
		"not_before":     m.NotBefore,
		"not_after":      m.NotAfter,
		"obligations":    m.Obligations,
		"version":        m.Version,
		"subjects":       m.Subjects,
		"actions":        m.Actions,
		"resources":      m.Resources,
		"conditions":     m.Conditions,
		"metadata":       m.Metadata,
		"updated_by":     m.UpdatedBy,
		"updated_at":     m.UpdatedAt,
	}
}

func resourceTypeUpdateDoc(m *resourceTypeModel) bson.M {
	return bson.M{
		"namespace_path": m.NamespacePath,
		"app_id":         m.AppID,
		"name":           m.Name,
		"description":    m.Description,
		"relations":      m.Relations,
		"permissions":    m.Permissions,
		"metadata":       m.Metadata,
		"updated_by":     m.UpdatedBy,
		"updated_at":     m.UpdatedAt,
	}
}
