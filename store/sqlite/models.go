package sqlite

import (
	"encoding/json"
	"fmt"
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
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	Slug            string    `grove:"slug,notnull"`
	IsSystem        bool      `grove:"is_system,notnull"`
	IsDefault       bool      `grove:"is_default,notnull"`
	ParentID        *string   `grove:"parent_id"`
	MaxMembers      int       `grove:"max_members,notnull"`
	Metadata        string    `grove:"metadata"` // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func roleToModel(r *role.Role) (*roleModel, error) {
	metadata, err := json.Marshal(r.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal role metadata: %w", err)
	}
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
		Metadata:    string(metadata),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
	if r.ParentID != nil {
		s := r.ParentID.String()
		m.ParentID = &s
	}
	return m, nil
}

func roleFromModel(m *roleModel) (*role.Role, error) {
	rid, _ := id.ParseRoleID(m.ID) //nolint:errcheck // stored IDs are always valid
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal role metadata: %w", err)
		}
	}
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
		Metadata:    metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
	if m.ParentID != nil {
		pid, err := id.ParseRoleID(*m.ParentID)
		if err == nil {
			r.ParentID = &pid
		}
	}
	return r, nil
}

// ──────────────────────────────────────────────────
// Permission model
// ──────────────────────────────────────────────────

type permissionModel struct {
	grove.BaseModel `grove:"table:warden_permissions"`
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	Resource        string    `grove:"resource,notnull"`
	Action          string    `grove:"action,notnull"`
	IsSystem        bool      `grove:"is_system,notnull"`
	Metadata        string    `grove:"metadata"` // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func permissionToModel(p *permission.Permission) (*permissionModel, error) {
	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal permission metadata: %w", err)
	}
	return &permissionModel{
		ID:          p.ID.String(),
		TenantID:    p.TenantID,
		AppID:       p.AppID,
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
		IsSystem:    p.IsSystem,
		Metadata:    string(metadata),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}, nil
}

func permissionFromModel(m *permissionModel) (*permission.Permission, error) {
	pid, _ := id.ParsePermissionID(m.ID) //nolint:errcheck // stored IDs are always valid
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal permission metadata: %w", err)
		}
	}
	return &permission.Permission{
		ID:          pid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Resource:    m.Resource,
		Action:      m.Action,
		IsSystem:    m.IsSystem,
		Metadata:    metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
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
	ID              string     `grove:"id,pk"`
	TenantID        string     `grove:"tenant_id,notnull"`
	AppID           string     `grove:"app_id,notnull"`
	RoleID          string     `grove:"role_id,notnull"`
	SubjectKind     string     `grove:"subject_kind,notnull"`
	SubjectID       string     `grove:"subject_id,notnull"`
	ResourceType    string     `grove:"resource_type"`
	ResourceID      string     `grove:"resource_id"`
	ExpiresAt       *time.Time `grove:"expires_at"`
	GrantedBy       string     `grove:"granted_by"`
	Metadata        string     `grove:"metadata"` // JSON text
	CreatedAt       time.Time  `grove:"created_at,notnull"`
}

func assignmentToModel(a *assignment.Assignment) (*assignmentModel, error) {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal assignment metadata: %w", err)
	}
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
		Metadata:     string(metadata),
		CreatedAt:    a.CreatedAt,
	}, nil
}

func assignmentFromModel(m *assignmentModel) (*assignment.Assignment, error) {
	aid, _ := id.ParseAssignmentID(m.ID) //nolint:errcheck // stored IDs are always valid
	rid, _ := id.ParseRoleID(m.RoleID)   //nolint:errcheck // stored IDs are always valid
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal assignment metadata: %w", err)
		}
	}
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
		Metadata:     metadata,
		CreatedAt:    m.CreatedAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Relation (tuple) model
// ──────────────────────────────────────────────────

type relationModel struct {
	grove.BaseModel `grove:"table:warden_relations"`
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	ObjectType      string    `grove:"object_type,notnull"`
	ObjectID        string    `grove:"object_id,notnull"`
	Relation        string    `grove:"relation,notnull"`
	SubjectType     string    `grove:"subject_type,notnull"`
	SubjectID       string    `grove:"subject_id,notnull"`
	SubjectRelation string    `grove:"subject_relation"`
	Metadata        string    `grove:"metadata"` // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

func relationToModel(t *relation.Tuple) (*relationModel, error) {
	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal relation metadata: %w", err)
	}
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
		Metadata:        string(metadata),
		CreatedAt:       t.CreatedAt,
	}, nil
}

func relationFromModel(m *relationModel) (*relation.Tuple, error) {
	rid, _ := id.ParseRelationID(m.ID) //nolint:errcheck // stored IDs are always valid
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal relation metadata: %w", err)
		}
	}
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
		Metadata:        metadata,
		CreatedAt:       m.CreatedAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Policy model (ABAC)
// ──────────────────────────────────────────────────

type policyModel struct {
	grove.BaseModel `grove:"table:warden_policies"`
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	Effect          string    `grove:"effect,notnull"`
	Priority        int       `grove:"priority,notnull"`
	IsActive        bool      `grove:"is_active,notnull"`
	Version         int       `grove:"version,notnull"`
	Subjects        string    `grove:"subjects"`   // JSON text
	Actions         string    `grove:"actions"`    // JSON text
	Resources       string    `grove:"resources"`  // JSON text
	Conditions      string    `grove:"conditions"` // JSON text
	Metadata        string    `grove:"metadata"`   // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func policyToModel(p *policy.Policy) (*policyModel, error) {
	subjects, err := json.Marshal(p.Subjects)
	if err != nil {
		return nil, fmt.Errorf("marshal policy subjects: %w", err)
	}
	actions, err := json.Marshal(p.Actions)
	if err != nil {
		return nil, fmt.Errorf("marshal policy actions: %w", err)
	}
	resources, err := json.Marshal(p.Resources)
	if err != nil {
		return nil, fmt.Errorf("marshal policy resources: %w", err)
	}
	conditions, err := json.Marshal(p.Conditions)
	if err != nil {
		return nil, fmt.Errorf("marshal policy conditions: %w", err)
	}
	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal policy metadata: %w", err)
	}
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
		Subjects:    string(subjects),
		Actions:     string(actions),
		Resources:   string(resources),
		Conditions:  string(conditions),
		Metadata:    string(metadata),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}, nil
}

func policyFromModel(m *policyModel) (*policy.Policy, error) {
	pid, _ := id.ParsePolicyID(m.ID) //nolint:errcheck // stored IDs are always valid

	var subjects []policy.SubjectMatch
	if m.Subjects != "" {
		if err := json.Unmarshal([]byte(m.Subjects), &subjects); err != nil {
			return nil, fmt.Errorf("unmarshal policy subjects: %w", err)
		}
	}
	var actions []string
	if m.Actions != "" {
		if err := json.Unmarshal([]byte(m.Actions), &actions); err != nil {
			return nil, fmt.Errorf("unmarshal policy actions: %w", err)
		}
	}
	var resources []string
	if m.Resources != "" {
		if err := json.Unmarshal([]byte(m.Resources), &resources); err != nil {
			return nil, fmt.Errorf("unmarshal policy resources: %w", err)
		}
	}
	var conditions []policy.Condition
	if m.Conditions != "" {
		if err := json.Unmarshal([]byte(m.Conditions), &conditions); err != nil {
			return nil, fmt.Errorf("unmarshal policy conditions: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal policy metadata: %w", err)
		}
	}
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
		Subjects:    subjects,
		Actions:     actions,
		Resources:   resources,
		Conditions:  conditions,
		Metadata:    metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Resource type model (ReBAC schema)
// ──────────────────────────────────────────────────

type resourceTypeModel struct {
	grove.BaseModel `grove:"table:warden_resource_types"`
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Name            string    `grove:"name,notnull"`
	Description     string    `grove:"description"`
	Relations       string    `grove:"relations"`   // JSON text
	Permissions     string    `grove:"permissions"` // JSON text
	Metadata        string    `grove:"metadata"`    // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func resourceTypeToModel(rt *resourcetype.ResourceType) (*resourceTypeModel, error) {
	relations, err := json.Marshal(rt.Relations)
	if err != nil {
		return nil, fmt.Errorf("marshal resource type relations: %w", err)
	}
	permissions, err := json.Marshal(rt.Permissions)
	if err != nil {
		return nil, fmt.Errorf("marshal resource type permissions: %w", err)
	}
	metadata, err := json.Marshal(rt.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal resource type metadata: %w", err)
	}
	return &resourceTypeModel{
		ID:          rt.ID.String(),
		TenantID:    rt.TenantID,
		AppID:       rt.AppID,
		Name:        rt.Name,
		Description: rt.Description,
		Relations:   string(relations),
		Permissions: string(permissions),
		Metadata:    string(metadata),
		CreatedAt:   rt.CreatedAt,
		UpdatedAt:   rt.UpdatedAt,
	}, nil
}

func resourceTypeFromModel(m *resourceTypeModel) (*resourcetype.ResourceType, error) {
	rtid, _ := id.ParseResourceTypeID(m.ID) //nolint:errcheck // stored IDs are always valid

	var relations []resourcetype.RelationDef
	if m.Relations != "" {
		if err := json.Unmarshal([]byte(m.Relations), &relations); err != nil {
			return nil, fmt.Errorf("unmarshal resource type relations: %w", err)
		}
	}
	var permissions []resourcetype.PermissionDef
	if m.Permissions != "" {
		if err := json.Unmarshal([]byte(m.Permissions), &permissions); err != nil {
			return nil, fmt.Errorf("unmarshal resource type permissions: %w", err)
		}
	}
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal resource type metadata: %w", err)
		}
	}
	return &resourcetype.ResourceType{
		ID:          rtid,
		TenantID:    m.TenantID,
		AppID:       m.AppID,
		Name:        m.Name,
		Description: m.Description,
		Relations:   relations,
		Permissions: permissions,
		Metadata:    metadata,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}, nil
}

// ──────────────────────────────────────────────────
// Check log model
// ──────────────────────────────────────────────────

type checkLogModel struct {
	grove.BaseModel `grove:"table:warden_check_logs"`
	ID              string    `grove:"id,pk"`
	TenantID        string    `grove:"tenant_id,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	SubjectKind     string    `grove:"subject_kind,notnull"`
	SubjectID       string    `grove:"subject_id,notnull"`
	Action          string    `grove:"action,notnull"`
	ResourceType    string    `grove:"resource_type,notnull"`
	ResourceID      string    `grove:"resource_id,notnull"`
	Decision        string    `grove:"decision,notnull"`
	Reason          string    `grove:"reason"`
	EvalTimeNs      int64     `grove:"eval_time_ns,notnull"`
	RequestIP       string    `grove:"request_ip"`
	Metadata        string    `grove:"metadata"` // JSON text
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

func checkLogToModel(e *checklog.Entry) (*checkLogModel, error) {
	metadata, err := json.Marshal(e.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal check log metadata: %w", err)
	}
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
		Metadata:     string(metadata),
		CreatedAt:    e.CreatedAt,
	}, nil
}

func checkLogFromModel(m *checkLogModel) (*checklog.Entry, error) {
	clid, _ := id.ParseCheckLogID(m.ID) //nolint:errcheck // stored IDs are always valid
	var metadata map[string]any
	if m.Metadata != "" {
		if err := json.Unmarshal([]byte(m.Metadata), &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal check log metadata: %w", err)
		}
	}
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
		Metadata:     metadata,
		CreatedAt:    m.CreatedAt,
	}, nil
}
