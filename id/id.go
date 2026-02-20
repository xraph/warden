// Package id provides TypeID-based identity types for all Warden entities.
//
// Every entity in Warden gets a type-prefixed, K-sortable, UUIDv7-based
// identifier. IDs are compile-time safe — you cannot pass a RoleID where a
// PolicyID is expected.
//
// Examples:
//
//	wrol_01h2xcejqtf2nbrexx3vqjhp41
//	wpol_01h2xcejqtf2nbrexx3vqjhp41
//	wrel_01h455vb4pex5vsknk084sn02q
package id

import "go.jetify.com/typeid"

// ──────────────────────────────────────────────────
// Prefix types — each entity has its own prefix
// ──────────────────────────────────────────────────

// RolePrefix is the TypeID prefix for roles.
type RolePrefix struct{}

// Prefix returns "wrol".
func (RolePrefix) Prefix() string { return "wrol" }

// PermissionPrefix is the TypeID prefix for permissions.
type PermissionPrefix struct{}

// Prefix returns "wprm".
func (PermissionPrefix) Prefix() string { return "wprm" }

// AssignmentPrefix is the TypeID prefix for role assignments.
type AssignmentPrefix struct{}

// Prefix returns "wasn".
func (AssignmentPrefix) Prefix() string { return "wasn" }

// PolicyPrefix is the TypeID prefix for ABAC policies.
type PolicyPrefix struct{}

// Prefix returns "wpol".
func (PolicyPrefix) Prefix() string { return "wpol" }

// RelationPrefix is the TypeID prefix for relation tuples.
type RelationPrefix struct{}

// Prefix returns "wrel".
func (RelationPrefix) Prefix() string { return "wrel" }

// CheckLogPrefix is the TypeID prefix for check audit log entries.
type CheckLogPrefix struct{}

// Prefix returns "wclg".
func (CheckLogPrefix) Prefix() string { return "wclg" }

// ResourceTypePrefix is the TypeID prefix for resource type definitions.
type ResourceTypePrefix struct{}

// Prefix returns "wrtp".
func (ResourceTypePrefix) Prefix() string { return "wrtp" }

// ConditionPrefix is the TypeID prefix for policy conditions.
type ConditionPrefix struct{}

// Prefix returns "wcnd".
func (ConditionPrefix) Prefix() string { return "wcnd" }

// ──────────────────────────────────────────────────
// Typed ID aliases — compile-time safe
// ──────────────────────────────────────────────────

// RoleID is a type-safe identifier for roles (prefix: "wrol").
type RoleID = typeid.TypeID[RolePrefix]

// PermissionID is a type-safe identifier for permissions (prefix: "wprm").
type PermissionID = typeid.TypeID[PermissionPrefix]

// AssignmentID is a type-safe identifier for role assignments (prefix: "wasn").
type AssignmentID = typeid.TypeID[AssignmentPrefix]

// PolicyID is a type-safe identifier for ABAC policies (prefix: "wpol").
type PolicyID = typeid.TypeID[PolicyPrefix]

// RelationID is a type-safe identifier for relation tuples (prefix: "wrel").
type RelationID = typeid.TypeID[RelationPrefix]

// CheckLogID is a type-safe identifier for check log entries (prefix: "wclg").
type CheckLogID = typeid.TypeID[CheckLogPrefix]

// ResourceTypeID is a type-safe identifier for resource type definitions (prefix: "wrtp").
type ResourceTypeID = typeid.TypeID[ResourceTypePrefix]

// ConditionID is a type-safe identifier for policy conditions (prefix: "wcnd").
type ConditionID = typeid.TypeID[ConditionPrefix]

// AnyID is a TypeID that accepts any valid prefix. Use for cases where
// the prefix is dynamic or unknown at compile time.
type AnyID = typeid.AnyID

// ──────────────────────────────────────────────────
// Constructors
// ──────────────────────────────────────────────────

// NewRoleID returns a new random RoleID.
func NewRoleID() RoleID { return must(typeid.New[RoleID]()) }

// NewPermissionID returns a new random PermissionID.
func NewPermissionID() PermissionID { return must(typeid.New[PermissionID]()) }

// NewAssignmentID returns a new random AssignmentID.
func NewAssignmentID() AssignmentID { return must(typeid.New[AssignmentID]()) }

// NewPolicyID returns a new random PolicyID.
func NewPolicyID() PolicyID { return must(typeid.New[PolicyID]()) }

// NewRelationID returns a new random RelationID.
func NewRelationID() RelationID { return must(typeid.New[RelationID]()) }

// NewCheckLogID returns a new random CheckLogID.
func NewCheckLogID() CheckLogID { return must(typeid.New[CheckLogID]()) }

// NewResourceTypeID returns a new random ResourceTypeID.
func NewResourceTypeID() ResourceTypeID { return must(typeid.New[ResourceTypeID]()) }

// NewConditionID returns a new random ConditionID.
func NewConditionID() ConditionID { return must(typeid.New[ConditionID]()) }

// ──────────────────────────────────────────────────
// Parsing (type-safe: ParseRoleID("wpol_01h...") fails)
// ──────────────────────────────────────────────────

// ParseRoleID parses a string into a RoleID. Returns an error if the prefix
// is not "wrol" or the suffix is invalid.
func ParseRoleID(s string) (RoleID, error) { return typeid.Parse[RoleID](s) }

// ParsePermissionID parses a string into a PermissionID.
func ParsePermissionID(s string) (PermissionID, error) { return typeid.Parse[PermissionID](s) }

// ParseAssignmentID parses a string into an AssignmentID.
func ParseAssignmentID(s string) (AssignmentID, error) { return typeid.Parse[AssignmentID](s) }

// ParsePolicyID parses a string into a PolicyID.
func ParsePolicyID(s string) (PolicyID, error) { return typeid.Parse[PolicyID](s) }

// ParseRelationID parses a string into a RelationID.
func ParseRelationID(s string) (RelationID, error) { return typeid.Parse[RelationID](s) }

// ParseCheckLogID parses a string into a CheckLogID.
func ParseCheckLogID(s string) (CheckLogID, error) { return typeid.Parse[CheckLogID](s) }

// ParseResourceTypeID parses a string into a ResourceTypeID.
func ParseResourceTypeID(s string) (ResourceTypeID, error) { return typeid.Parse[ResourceTypeID](s) }

// ParseConditionID parses a string into a ConditionID.
func ParseConditionID(s string) (ConditionID, error) { return typeid.Parse[ConditionID](s) }

// ParseAny parses a string into an AnyID, accepting any valid prefix.
func ParseAny(s string) (AnyID, error) { return typeid.FromString(s) }

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
