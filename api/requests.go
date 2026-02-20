package api

import (
	"github.com/xraph/warden/policy"
)

// ──────────────────────────────────────────────────
// Check requests
// ──────────────────────────────────────────────────

// CheckRequest is the request body for an authorization check.
type CheckRequest struct {
	SubjectKind  string         `json:"subject_kind" description:"Subject type (user, api_key, service, service_acct)"`
	SubjectID    string         `json:"subject_id" description:"Subject identifier"`
	Action       string         `json:"action" description:"Action name"`
	ResourceType string         `json:"resource_type" description:"Resource type"`
	ResourceID   string         `json:"resource_id" description:"Resource identifier"`
	Context      map[string]any `json:"context,omitempty" description:"Additional context attributes"`
}

// BatchCheckRequest contains multiple checks.
type BatchCheckRequest struct {
	Checks []CheckRequest `json:"checks" description:"List of authorization checks"`
}

// ──────────────────────────────────────────────────
// Role requests
// ──────────────────────────────────────────────────

// CreateRoleRequest is the body for creating a role.
type CreateRoleRequest struct {
	Name        string         `json:"name" description:"Role name"`
	Slug        string         `json:"slug" description:"URL-safe slug"`
	Description string         `json:"description,omitempty" description:"Human-readable description"`
	ParentID    string         `json:"parent_id,omitempty" description:"Parent role ID for inheritance"`
	MaxMembers  int            `json:"max_members,omitempty" description:"Maximum members (0 = unlimited)"`
	IsSystem    bool           `json:"is_system,omitempty" description:"System role flag"`
	IsDefault   bool           `json:"is_default,omitempty" description:"Default role flag"`
	Metadata    map[string]any `json:"metadata,omitempty" description:"Custom metadata"`
}

// UpdateRoleRequest is the body for updating a role.
type UpdateRoleRequest struct {
	Name        string         `json:"name,omitempty" description:"Role name"`
	Description string         `json:"description,omitempty" description:"Human-readable description"`
	MaxMembers  *int           `json:"max_members,omitempty" description:"Maximum members"`
	IsDefault   *bool          `json:"is_default,omitempty" description:"Default role flag"`
	Metadata    map[string]any `json:"metadata,omitempty" description:"Custom metadata"`
}

// GetRoleRequest is the path parameter for getting a role.
type GetRoleRequest struct {
	RoleID string `path:"roleId" description:"Role ID"`
}

// ListRolesRequest holds query parameters for listing roles.
type ListRolesRequest struct {
	Search string `query:"search" description:"Search by name"`
	Limit  int    `query:"limit" description:"Maximum results (default: 50)"`
	Offset int    `query:"offset" description:"Results to skip"`
}

// AttachPermissionRequest is the body for attaching a permission to a role.
type AttachPermissionRequest struct {
	PermissionID string `json:"permission_id" description:"Permission ID to attach"`
}

// ──────────────────────────────────────────────────
// Permission requests
// ──────────────────────────────────────────────────

// CreatePermissionRequest is the body for creating a permission.
type CreatePermissionRequest struct {
	Name        string         `json:"name" description:"Permission name (e.g. document:read)"`
	Resource    string         `json:"resource" description:"Resource type"`
	Action      string         `json:"action" description:"Action name"`
	Description string         `json:"description,omitempty" description:"Human-readable description"`
	IsSystem    bool           `json:"is_system,omitempty" description:"System permission flag"`
	Metadata    map[string]any `json:"metadata,omitempty" description:"Custom metadata"`
}

// GetPermissionRequest is the path parameter for getting a permission.
type GetPermissionRequest struct {
	PermissionID string `path:"permissionId" description:"Permission ID"`
}

// ListPermissionsRequest holds query parameters.
type ListPermissionsRequest struct {
	Resource string `query:"resource" description:"Filter by resource type"`
	Action   string `query:"action" description:"Filter by action"`
	Search   string `query:"search" description:"Search by name"`
	Limit    int    `query:"limit" description:"Maximum results"`
	Offset   int    `query:"offset" description:"Results to skip"`
}

// ──────────────────────────────────────────────────
// Assignment requests
// ──────────────────────────────────────────────────

// AssignRoleRequest is the body for assigning a role to a subject.
type AssignRoleRequest struct {
	RoleID       string `json:"role_id" description:"Role ID to assign"`
	SubjectKind  string `json:"subject_kind" description:"Subject type"`
	SubjectID    string `json:"subject_id" description:"Subject identifier"`
	ResourceType string `json:"resource_type,omitempty" description:"Scope to resource type"`
	ResourceID   string `json:"resource_id,omitempty" description:"Scope to resource ID"`
	ExpiresAt    string `json:"expires_at,omitempty" description:"Expiration time (RFC3339)"`
}

// GetAssignmentRequest is the path parameter for getting an assignment.
type GetAssignmentRequest struct {
	AssignmentID string `path:"assignmentId" description:"Assignment ID"`
}

// ListAssignmentsRequest holds query parameters.
type ListAssignmentsRequest struct {
	SubjectKind string `query:"subject_kind" description:"Filter by subject type"`
	SubjectID   string `query:"subject_id" description:"Filter by subject ID"`
	RoleID      string `query:"role_id" description:"Filter by role ID"`
	Limit       int    `query:"limit" description:"Maximum results"`
	Offset      int    `query:"offset" description:"Results to skip"`
}

// ListSubjectRolesRequest gets roles for a subject.
type ListSubjectRolesRequest struct {
	SubjectKind string `path:"subjectKind" description:"Subject type"`
	SubjectID   string `path:"subjectId" description:"Subject ID"`
}

// ──────────────────────────────────────────────────
// Relation requests
// ──────────────────────────────────────────────────

// WriteRelationRequest is the body for writing a relation tuple.
type WriteRelationRequest struct {
	ObjectType      string `json:"object_type" description:"Object resource type"`
	ObjectID        string `json:"object_id" description:"Object identifier"`
	Relation        string `json:"relation" description:"Relation name"`
	SubjectType     string `json:"subject_type" description:"Subject resource type"`
	SubjectID       string `json:"subject_id" description:"Subject identifier"`
	SubjectRelation string `json:"subject_relation,omitempty" description:"Subject relation (for nested relations)"`
}

// DeleteRelationRequest is the body for deleting a relation tuple.
type DeleteRelationRequest struct {
	ObjectType  string `json:"object_type" description:"Object resource type"`
	ObjectID    string `json:"object_id" description:"Object identifier"`
	Relation    string `json:"relation" description:"Relation name"`
	SubjectType string `json:"subject_type" description:"Subject resource type"`
	SubjectID   string `json:"subject_id" description:"Subject identifier"`
}

// ListRelationsRequest holds query parameters.
type ListRelationsRequest struct {
	ObjectType  string `query:"object_type" description:"Filter by object type"`
	ObjectID    string `query:"object_id" description:"Filter by object ID"`
	Relation    string `query:"relation" description:"Filter by relation"`
	SubjectType string `query:"subject_type" description:"Filter by subject type"`
	SubjectID   string `query:"subject_id" description:"Filter by subject ID"`
	Limit       int    `query:"limit" description:"Maximum results"`
	Offset      int    `query:"offset" description:"Results to skip"`
}

// ──────────────────────────────────────────────────
// Policy requests
// ──────────────────────────────────────────────────

// CreatePolicyRequest is the body for creating an ABAC policy.
type CreatePolicyRequest struct {
	Name        string                `json:"name" description:"Policy name"`
	Description string                `json:"description,omitempty" description:"Human-readable description"`
	Effect      string                `json:"effect" description:"Policy effect (allow or deny)"`
	Priority    int                   `json:"priority,omitempty" description:"Policy priority"`
	IsActive    bool                  `json:"is_active" description:"Whether the policy is active"`
	Subjects    []policy.SubjectMatch `json:"subjects,omitempty" description:"Subject matchers"`
	Actions     []string              `json:"actions,omitempty" description:"Action patterns"`
	Resources   []string              `json:"resources,omitempty" description:"Resource patterns"`
	Conditions  []ConditionInput      `json:"conditions,omitempty" description:"Policy conditions"`
	Metadata    map[string]any        `json:"metadata,omitempty" description:"Custom metadata"`
}

// ConditionInput is the input format for a policy condition.
type ConditionInput struct {
	Field    string `json:"field" description:"Dot-separated field path (e.g. context.ip)"`
	Operator string `json:"operator" description:"Comparison operator"`
	Value    any    `json:"value" description:"Expected value"`
}

// UpdatePolicyRequest is the body for updating a policy.
type UpdatePolicyRequest struct {
	Name        string                `json:"name,omitempty" description:"Policy name"`
	Description string                `json:"description,omitempty" description:"Description"`
	Effect      string                `json:"effect,omitempty" description:"Policy effect"`
	Priority    *int                  `json:"priority,omitempty" description:"Priority"`
	IsActive    *bool                 `json:"is_active,omitempty" description:"Active flag"`
	Subjects    []policy.SubjectMatch `json:"subjects,omitempty" description:"Subject matchers"`
	Actions     []string              `json:"actions,omitempty" description:"Action patterns"`
	Resources   []string              `json:"resources,omitempty" description:"Resource patterns"`
	Conditions  []ConditionInput      `json:"conditions,omitempty" description:"Conditions"`
	Metadata    map[string]any        `json:"metadata,omitempty" description:"Metadata"`
}

// GetPolicyRequest is the path parameter for getting a policy.
type GetPolicyRequest struct {
	PolicyID string `path:"policyId" description:"Policy ID"`
}

// ListPoliciesRequest holds query parameters.
type ListPoliciesRequest struct {
	Effect string `query:"effect" description:"Filter by effect (allow/deny)"`
	Active string `query:"active" description:"Filter by active status (true/false)"`
	Search string `query:"search" description:"Search by name"`
	Limit  int    `query:"limit" description:"Maximum results"`
	Offset int    `query:"offset" description:"Results to skip"`
}

// ──────────────────────────────────────────────────
// Resource type requests
// ──────────────────────────────────────────────────

// CreateResourceTypeRequest is the body for creating a resource type.
type CreateResourceTypeRequest struct {
	Name        string               `json:"name" description:"Resource type name"`
	Description string               `json:"description,omitempty" description:"Description"`
	Relations   []RelationDefInput   `json:"relations,omitempty" description:"Relation definitions"`
	Permissions []PermissionDefInput `json:"permissions,omitempty" description:"Permission definitions"`
	Metadata    map[string]any       `json:"metadata,omitempty" description:"Custom metadata"`
}

// RelationDefInput is the input for a relation definition.
type RelationDefInput struct {
	Name            string   `json:"name" description:"Relation name"`
	AllowedSubjects []string `json:"allowed_subjects" description:"Allowed subject types"`
}

// PermissionDefInput is the input for a permission definition.
type PermissionDefInput struct {
	Name       string `json:"name" description:"Permission name"`
	Expression string `json:"expression" description:"Permission expression"`
}

// GetResourceTypeRequest is the path parameter.
type GetResourceTypeRequest struct {
	ResourceTypeID string `path:"resourceTypeId" description:"Resource type ID"`
}

// ListResourceTypesRequest holds query parameters.
type ListResourceTypesRequest struct {
	Search string `query:"search" description:"Search by name"`
	Limit  int    `query:"limit" description:"Maximum results"`
	Offset int    `query:"offset" description:"Results to skip"`
}

// ──────────────────────────────────────────────────
// Check log requests
// ──────────────────────────────────────────────────

// ListCheckLogsRequest holds query parameters for querying check logs.
type ListCheckLogsRequest struct {
	SubjectKind  string `query:"subject_kind" description:"Filter by subject type"`
	SubjectID    string `query:"subject_id" description:"Filter by subject ID"`
	Action       string `query:"action" description:"Filter by action"`
	ResourceType string `query:"resource_type" description:"Filter by resource type"`
	Decision     string `query:"decision" description:"Filter by decision"`
	After        string `query:"after" description:"After timestamp (RFC3339)"`
	Before       string `query:"before" description:"Before timestamp (RFC3339)"`
	Limit        int    `query:"limit" description:"Maximum results"`
	Offset       int    `query:"offset" description:"Results to skip"`
}
