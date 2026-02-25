package postgres

import (
	"time"

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

// ──────────────────────────────────────────────────
// Role model
// ──────────────────────────────────────────────────

type roleModel struct {
	grove.BaseModel `grove:"table:warden_roles"`
	ID              string         `grove:"id,pk"`
	TenantID        string         `grove:"tenant_id,notnull"`
	AppID           string         `grove:"app_id,notnull"`
	Name            string         `grove:"name,notnull"`
	Description     string         `grove:"description"`
	Slug            string         `grove:"slug,notnull"`
	IsSystem        bool           `grove:"is_system,notnull"`
	IsDefault       bool           `grove:"is_default,notnull"`
	ParentID        *string        `grove:"parent_id"`
	MaxMembers      int            `grove:"max_members,notnull"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
	UpdatedAt       time.Time      `grove:"updated_at,notnull"`
}

func roleToModel(r *role.Role) *roleModel {
	m := &roleModel{
		ID:          r.ID.String(),
		TenantID:    r.TenantID,
		AppID:       r.AppID,
		Name:        r.Name,
		Description: r.Description,
		Slug:        r.Slug,
		IsSystem:    r.IsSystem,
		IsDefault:   r.IsDefault,
		MaxMembers:  r.MaxMembers,
		Metadata:    r.Metadata,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
	if r.ParentID != nil {
		s := r.ParentID.String()
		m.ParentID = &s
	}
	return m
}

func roleFromModel(m *roleModel) *role.Role {
	rid, _ := id.ParseRoleID(m.ID) //nolint:errcheck // stored IDs are always valid
	r := &role.Role{
		ID:          rid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Slug:        m.Slug,
		IsSystem:    m.IsSystem,
		IsDefault:   m.IsDefault,
		MaxMembers:  m.MaxMembers,
		Metadata:    m.Metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
	if m.ParentID != nil {
		pid, err := id.ParseRoleID(*m.ParentID)
		if err == nil {
			r.ParentID = &pid
		}
	}
	return r
}

// ──────────────────────────────────────────────────
// Permission model
// ──────────────────────────────────────────────────

type permissionModel struct {
	grove.BaseModel `grove:"table:warden_permissions"`
	ID              string         `grove:"id,pk"`
	TenantID        string         `grove:"tenant_id,notnull"`
	AppID           string         `grove:"app_id,notnull"`
	Name            string         `grove:"name,notnull"`
	Description     string         `grove:"description"`
	Resource        string         `grove:"resource,notnull"`
	Action          string         `grove:"action,notnull"`
	IsSystem        bool           `grove:"is_system,notnull"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
	UpdatedAt       time.Time      `grove:"updated_at,notnull"`
}

func permissionToModel(p *permission.Permission) *permissionModel {
	return &permissionModel{
		ID:          p.ID.String(),
		TenantID:    p.TenantID,
		AppID:       p.AppID,
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
		IsSystem:    p.IsSystem,
		Metadata:    p.Metadata,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

func permissionFromModel(m *permissionModel) *permission.Permission {
	pid, _ := id.ParsePermissionID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &permission.Permission{
		ID:          pid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Resource:    m.Resource,
		Action:      m.Action,
		IsSystem:    m.IsSystem,
		Metadata:    m.Metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Role-Permission junction model
// ──────────────────────────────────────────────────

type rolePermissionModel struct {
	grove.BaseModel `grove:"table:warden_role_permissions"`
	RoleID          string `grove:"role_id,pk"`
	PermissionID    string `grove:"permission_id,pk"`
}

// ──────────────────────────────────────────────────
// Assignment model
// ──────────────────────────────────────────────────

type assignmentModel struct {
	grove.BaseModel `grove:"table:warden_assignments"`
	ID              string         `grove:"id,pk"`
	TenantID        string         `grove:"tenant_id,notnull"`
	AppID           string         `grove:"app_id,notnull"`
	RoleID          string         `grove:"role_id,notnull"`
	SubjectKind     string         `grove:"subject_kind,notnull"`
	SubjectID       string         `grove:"subject_id,notnull"`
	ResourceType    string         `grove:"resource_type"`
	ResourceID      string         `grove:"resource_id"`
	ExpiresAt       *time.Time     `grove:"expires_at"`
	GrantedBy       string         `grove:"granted_by"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
}

func assignmentToModel(a *assignment.Assignment) *assignmentModel {
	return &assignmentModel{
		ID:           a.ID.String(),
		TenantID:     a.TenantID,
		AppID:        a.AppID,
		RoleID:       a.RoleID.String(),
		SubjectKind:  a.SubjectKind,
		SubjectID:    a.SubjectID,
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		ExpiresAt:    a.ExpiresAt,
		GrantedBy:    a.GrantedBy,
		Metadata:     a.Metadata,
		CreatedAt:    a.CreatedAt,
	}
}

func assignmentFromModel(m *assignmentModel) *assignment.Assignment {
	aid, _ := id.ParseAssignmentID(m.ID) //nolint:errcheck // stored IDs are always valid
	rid, _ := id.ParseRoleID(m.RoleID)   //nolint:errcheck // stored IDs are always valid
	return &assignment.Assignment{
		ID:           aid,
		TenantID:     m.TenantID,
		AppID:        m.AppID,
		RoleID:       rid,
		SubjectKind:  m.SubjectKind,
		SubjectID:    m.SubjectID,
		ResourceType: m.ResourceType,
		ResourceID:   m.ResourceID,
		ExpiresAt:    m.ExpiresAt,
		GrantedBy:    m.GrantedBy,
		Metadata:     m.Metadata,
		CreatedAt:    m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Relation (tuple) model
// ──────────────────────────────────────────────────

type relationModel struct {
	grove.BaseModel `grove:"table:warden_relations"`
	ID              string         `grove:"id,pk"`
	TenantID        string         `grove:"tenant_id,notnull"`
	AppID           string         `grove:"app_id,notnull"`
	ObjectType      string         `grove:"object_type,notnull"`
	ObjectID        string         `grove:"object_id,notnull"`
	Relation        string         `grove:"relation,notnull"`
	SubjectType     string         `grove:"subject_type,notnull"`
	SubjectID       string         `grove:"subject_id,notnull"`
	SubjectRelation string         `grove:"subject_relation"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
}

func relationToModel(t *relation.Tuple) *relationModel {
	return &relationModel{
		ID:              t.ID.String(),
		TenantID:        t.TenantID,
		AppID:           t.AppID,
		ObjectType:      t.ObjectType,
		ObjectID:        t.ObjectID,
		Relation:        t.Relation,
		SubjectType:     t.SubjectType,
		SubjectID:       t.SubjectID,
		SubjectRelation: t.SubjectRelation,
		Metadata:        t.Metadata,
		CreatedAt:       t.CreatedAt,
	}
}

func relationFromModel(m *relationModel) *relation.Tuple {
	rid, _ := id.ParseRelationID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &relation.Tuple{
		ID:              rid,
		TenantID:        m.TenantID,
		AppID:           m.AppID,
		ObjectType:      m.ObjectType,
		ObjectID:        m.ObjectID,
		Relation:        m.Relation,
		SubjectType:     m.SubjectType,
		SubjectID:       m.SubjectID,
		SubjectRelation: m.SubjectRelation,
		Metadata:        m.Metadata,
		CreatedAt:       m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Policy model (ABAC)
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:warden_policies"`
	ID              string                `grove:"id,pk"`
	TenantID        string                `grove:"tenant_id,notnull"`
	AppID           string                `grove:"app_id,notnull"`
	Name            string                `grove:"name,notnull"`
	Description     string                `grove:"description"`
	Effect          string                `grove:"effect,notnull"`
	Priority        int                   `grove:"priority,notnull"`
	IsActive        bool                  `grove:"is_active,notnull"`
	Version         int                   `grove:"version,notnull"`
	Subjects        []policy.SubjectMatch `grove:"subjects,type:jsonb"`
	Actions         []string              `grove:"actions,type:jsonb"`
	Resources       []string              `grove:"resources,type:jsonb"`
	Conditions      []policy.Condition    `grove:"conditions,type:jsonb"`
	Metadata        map[string]any        `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time             `grove:"created_at,notnull"`
	UpdatedAt       time.Time             `grove:"updated_at,notnull"`
}

func policyToModel(p *policy.Policy) *policyModel {
	return &policyModel{
		ID:          p.ID.String(),
		TenantID:    p.TenantID,
		AppID:       p.AppID,
		Name:        p.Name,
		Description: p.Description,
		Effect:      string(p.Effect),
		Priority:    p.Priority,
		IsActive:    p.IsActive,
		Version:     p.Version,
		Subjects:    p.Subjects,
		Actions:     p.Actions,
		Resources:   p.Resources,
		Conditions:  p.Conditions,
		Metadata:    p.Metadata,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

func policyFromModel(m *policyModel) *policy.Policy {
	pid, _ := id.ParsePolicyID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &policy.Policy{
		ID:          pid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Effect:      policy.Effect(m.Effect),
		Priority:    m.Priority,
		IsActive:    m.IsActive,
		Version:     m.Version,
		Subjects:    m.Subjects,
		Actions:     m.Actions,
		Resources:   m.Resources,
		Conditions:  m.Conditions,
		Metadata:    m.Metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Resource type model (ReBAC schema)
// ──────────────────────────────────────────────────

type resourceTypeModel struct {
	grove.BaseModel `grove:"table:warden_resource_types"`
	ID              string                       `grove:"id,pk"`
	TenantID        string                       `grove:"tenant_id,notnull"`
	AppID           string                       `grove:"app_id,notnull"`
	Name            string                       `grove:"name,notnull"`
	Description     string                       `grove:"description"`
	Relations       []resourcetype.RelationDef   `grove:"relations,type:jsonb"`
	Permissions     []resourcetype.PermissionDef `grove:"permissions,type:jsonb"`
	Metadata        map[string]any               `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time                    `grove:"created_at,notnull"`
	UpdatedAt       time.Time                    `grove:"updated_at,notnull"`
}

func resourceTypeToModel(rt *resourcetype.ResourceType) *resourceTypeModel {
	return &resourceTypeModel{
		ID:          rt.ID.String(),
		TenantID:    rt.TenantID,
		AppID:       rt.AppID,
		Name:        rt.Name,
		Description: rt.Description,
		Relations:   rt.Relations,
		Permissions: rt.Permissions,
		Metadata:    rt.Metadata,
		CreatedAt:   rt.CreatedAt,
		UpdatedAt:   rt.UpdatedAt,
	}
}

func resourceTypeFromModel(m *resourceTypeModel) *resourcetype.ResourceType {
	rtid, _ := id.ParseResourceTypeID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &resourcetype.ResourceType{
		ID:          rtid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Relations:   m.Relations,
		Permissions: m.Permissions,
		Metadata:    m.Metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// Check log model
// ──────────────────────────────────────────────────

type checkLogModel struct {
	grove.BaseModel `grove:"table:warden_check_logs"`
	ID              string         `grove:"id,pk"`
	TenantID        string         `grove:"tenant_id,notnull"`
	AppID           string         `grove:"app_id,notnull"`
	SubjectKind     string         `grove:"subject_kind,notnull"`
	SubjectID       string         `grove:"subject_id,notnull"`
	Action          string         `grove:"action,notnull"`
	ResourceType    string         `grove:"resource_type,notnull"`
	ResourceID      string         `grove:"resource_id,notnull"`
	Decision        string         `grove:"decision,notnull"`
	Reason          string         `grove:"reason"`
	EvalTimeNs      int64          `grove:"eval_time_ns,notnull"`
	RequestIP       string         `grove:"request_ip"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	CreatedAt       time.Time      `grove:"created_at,notnull"`
}

func checkLogToModel(e *checklog.Entry) *checkLogModel {
	return &checkLogModel{
		ID:           e.ID.String(),
		TenantID:     e.TenantID,
		AppID:        e.AppID,
		SubjectKind:  e.SubjectKind,
		SubjectID:    e.SubjectID,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Decision:     e.Decision,
		Reason:       e.Reason,
		EvalTimeNs:   e.EvalTimeNs,
		RequestIP:    e.RequestIP,
		Metadata:     e.Metadata,
		CreatedAt:    e.CreatedAt,
	}
}

func checkLogFromModel(m *checkLogModel) *checklog.Entry {
	clid, _ := id.ParseCheckLogID(m.ID) //nolint:errcheck // stored IDs are always valid
	return &checklog.Entry{
		ID:           clid,
		TenantID:     m.TenantID,
		AppID:        m.AppID,
		SubjectKind:  m.SubjectKind,
		SubjectID:    m.SubjectID,
		Action:       m.Action,
		ResourceType: m.ResourceType,
		ResourceID:   m.ResourceID,
		Decision:     m.Decision,
		Reason:       m.Reason,
		EvalTimeNs:   m.EvalTimeNs,
		RequestIP:    m.RequestIP,
		Metadata:     m.Metadata,
		CreatedAt:    m.CreatedAt,
	}
}
