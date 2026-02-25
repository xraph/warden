// Package id defines TypeID-based identity types for all Warden entities.
//
// Every entity in Warden uses a single ID struct with a prefix that identifies
// the entity type. IDs are K-sortable (UUIDv7-based), globally unique,
// and URL-safe in the format "prefix_suffix".
package id

import (
	"database/sql/driver"
	"fmt"

	"go.jetify.com/typeid/v2"
)

// Prefix identifies the entity type encoded in a TypeID.
type Prefix string

// Prefix constants for all Warden entity types.
const (
	PrefixRole         Prefix = "role"
	PrefixPermission   Prefix = "perm"
	PrefixAssignment   Prefix = "asgn"
	PrefixPolicy       Prefix = "wpol"
	PrefixRelation     Prefix = "rel"
	PrefixCheckLog     Prefix = "chklog"
	PrefixResourceType Prefix = "rtype"
	PrefixCondition    Prefix = "cond"
)

// ID is the primary identifier type for all Warden entities.
// It wraps a TypeID providing a prefix-qualified, globally unique,
// sortable, URL-safe identifier in the format "prefix_suffix".
//
//nolint:recvcheck // Value receivers for read-only methods, pointer receivers for UnmarshalText/Scan.
type ID struct {
	inner typeid.TypeID
	valid bool
}

// Nil is the zero-value ID.
var Nil ID

// New generates a new globally unique ID with the given prefix.
// It panics if prefix is not a valid TypeID prefix (programming error).
func New(prefix Prefix) ID {
	tid, err := typeid.Generate(string(prefix))
	if err != nil {
		panic(fmt.Sprintf("id: invalid prefix %q: %v", prefix, err))
	}

	return ID{inner: tid, valid: true}
}

// Parse parses a TypeID string (e.g., "role_01h2xcejqtf2nbrexx3vqjhp41")
// into an ID. Returns an error if the string is not valid.
func Parse(s string) (ID, error) {
	if s == "" {
		return Nil, fmt.Errorf("id: parse %q: empty string", s)
	}

	tid, err := typeid.Parse(s)
	if err != nil {
		return Nil, fmt.Errorf("id: parse %q: %w", s, err)
	}

	return ID{inner: tid, valid: true}, nil
}

// ParseWithPrefix parses a TypeID string and validates that its prefix
// matches the expected value.
func ParseWithPrefix(s string, expected Prefix) (ID, error) {
	parsed, err := Parse(s)
	if err != nil {
		return Nil, err
	}

	if parsed.Prefix() != expected {
		return Nil, fmt.Errorf("id: expected prefix %q, got %q", expected, parsed.Prefix())
	}

	return parsed, nil
}

// MustParse is like Parse but panics on error. Use for hardcoded ID values.
func MustParse(s string) ID {
	parsed, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("id: must parse %q: %v", s, err))
	}

	return parsed
}

// MustParseWithPrefix is like ParseWithPrefix but panics on error.
func MustParseWithPrefix(s string, expected Prefix) ID {
	parsed, err := ParseWithPrefix(s, expected)
	if err != nil {
		panic(fmt.Sprintf("id: must parse with prefix %q: %v", expected, err))
	}

	return parsed
}

// ──────────────────────────────────────────────────
// Type aliases for backward compatibility
// ──────────────────────────────────────────────────

// RoleID is a type-safe identifier for roles (prefix: "role").
type RoleID = ID

// PermissionID is a type-safe identifier for permissions (prefix: "perm").
type PermissionID = ID

// AssignmentID is a type-safe identifier for role assignments (prefix: "asgn").
type AssignmentID = ID

// PolicyID is a type-safe identifier for ABAC policies (prefix: "wpol").
type PolicyID = ID

// RelationID is a type-safe identifier for relation tuples (prefix: "rel").
type RelationID = ID

// CheckLogID is a type-safe identifier for check log entries (prefix: "chklog").
type CheckLogID = ID

// ResourceTypeID is a type-safe identifier for resource type definitions (prefix: "rtype").
type ResourceTypeID = ID

// ConditionID is a type-safe identifier for policy conditions (prefix: "cond").
type ConditionID = ID

// AnyID is a type alias that accepts any valid prefix.
type AnyID = ID

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

// NewRoleID generates a new unique role ID.
func NewRoleID() ID { return New(PrefixRole) }

// NewPermissionID generates a new unique permission ID.
func NewPermissionID() ID { return New(PrefixPermission) }

// NewAssignmentID generates a new unique assignment ID.
func NewAssignmentID() ID { return New(PrefixAssignment) }

// NewPolicyID generates a new unique policy ID.
func NewPolicyID() ID { return New(PrefixPolicy) }

// NewRelationID generates a new unique relation ID.
func NewRelationID() ID { return New(PrefixRelation) }

// NewCheckLogID generates a new unique check log ID.
func NewCheckLogID() ID { return New(PrefixCheckLog) }

// NewResourceTypeID generates a new unique resource type ID.
func NewResourceTypeID() ID { return New(PrefixResourceType) }

// NewConditionID generates a new unique condition ID.
func NewConditionID() ID { return New(PrefixCondition) }

// ──────────────────────────────────────────────────
// Convenience parsers
// ──────────────────────────────────────────────────

// ParseRoleID parses a string and validates the "role" prefix.
func ParseRoleID(s string) (ID, error) { return ParseWithPrefix(s, PrefixRole) }

// ParsePermissionID parses a string and validates the "perm" prefix.
func ParsePermissionID(s string) (ID, error) { return ParseWithPrefix(s, PrefixPermission) }

// ParseAssignmentID parses a string and validates the "asgn" prefix.
func ParseAssignmentID(s string) (ID, error) { return ParseWithPrefix(s, PrefixAssignment) }

// ParsePolicyID parses a string and validates the "wpol" prefix.
func ParsePolicyID(s string) (ID, error) { return ParseWithPrefix(s, PrefixPolicy) }

// ParseRelationID parses a string and validates the "rel" prefix.
func ParseRelationID(s string) (ID, error) { return ParseWithPrefix(s, PrefixRelation) }

// ParseCheckLogID parses a string and validates the "chklog" prefix.
func ParseCheckLogID(s string) (ID, error) { return ParseWithPrefix(s, PrefixCheckLog) }

// ParseResourceTypeID parses a string and validates the "rtype" prefix.
func ParseResourceTypeID(s string) (ID, error) { return ParseWithPrefix(s, PrefixResourceType) }

// ParseConditionID parses a string and validates the "cond" prefix.
func ParseConditionID(s string) (ID, error) { return ParseWithPrefix(s, PrefixCondition) }

// ParseAny parses a string into an ID without type checking the prefix.
func ParseAny(s string) (ID, error) { return Parse(s) }

// ──────────────────────────────────────────────────
// ID methods
// ──────────────────────────────────────────────────

// String returns the full TypeID string representation (prefix_suffix).
// Returns an empty string for the Nil ID.
func (i ID) String() string {
	if !i.valid {
		return ""
	}

	return i.inner.String()
}

// Prefix returns the prefix component of this ID.
func (i ID) Prefix() Prefix {
	if !i.valid {
		return ""
	}

	return Prefix(i.inner.Prefix())
}

// IsNil reports whether this ID is the zero value.
func (i ID) IsNil() bool {
	return !i.valid
}

// MarshalText implements encoding.TextMarshaler.
func (i ID) MarshalText() ([]byte, error) {
	if !i.valid {
		return []byte{}, nil
	}

	return []byte(i.inner.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (i *ID) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		*i = Nil

		return nil
	}

	parsed, err := Parse(string(data))
	if err != nil {
		return err
	}

	*i = parsed

	return nil
}

// Value implements driver.Valuer for database storage.
// Returns nil for the Nil ID so that optional foreign key columns store NULL.
func (i ID) Value() (driver.Value, error) {
	if !i.valid {
		return nil, nil //nolint:nilnil // nil is the canonical NULL for driver.Valuer
	}

	return i.inner.String(), nil
}

// Scan implements sql.Scanner for database retrieval.
func (i *ID) Scan(src any) error {
	if src == nil {
		*i = Nil

		return nil
	}

	switch v := src.(type) {
	case string:
		if v == "" {
			*i = Nil

			return nil
		}

		return i.UnmarshalText([]byte(v))
	case []byte:
		if len(v) == 0 {
			*i = Nil

			return nil
		}

		return i.UnmarshalText(v)
	default:
		return fmt.Errorf("id: cannot scan %T into ID", src)
	}
}
