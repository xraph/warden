package id_test

import (
	"strings"
	"testing"

	"github.com/xraph/warden/id"
)

func TestNewAndParse(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		newFn   func() string
		parseFn func(string) (any, error)
	}{
		{"RoleID", "wrol", func() string { return id.NewRoleID().String() }, func(s string) (any, error) { return id.ParseRoleID(s) }},
		{"PermissionID", "wprm", func() string { return id.NewPermissionID().String() }, func(s string) (any, error) { return id.ParsePermissionID(s) }},
		{"AssignmentID", "wasn", func() string { return id.NewAssignmentID().String() }, func(s string) (any, error) { return id.ParseAssignmentID(s) }},
		{"PolicyID", "wpol", func() string { return id.NewPolicyID().String() }, func(s string) (any, error) { return id.ParsePolicyID(s) }},
		{"RelationID", "wrel", func() string { return id.NewRelationID().String() }, func(s string) (any, error) { return id.ParseRelationID(s) }},
		{"CheckLogID", "wclg", func() string { return id.NewCheckLogID().String() }, func(s string) (any, error) { return id.ParseCheckLogID(s) }},
		{"ResourceTypeID", "wrtp", func() string { return id.NewResourceTypeID().String() }, func(s string) (any, error) { return id.ParseResourceTypeID(s) }},
		{"ConditionID", "wcnd", func() string { return id.NewConditionID().String() }, func(s string) (any, error) { return id.ParseConditionID(s) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.newFn()

			if !strings.HasPrefix(s, tt.prefix+"_") {
				t.Errorf("expected prefix %q, got %q", tt.prefix, s)
			}

			v, err := tt.parseFn(s)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if v == nil {
				t.Fatal("parsed value is nil")
			}
		})
	}
}

func TestParseWrongPrefix(t *testing.T) {
	roleID := id.NewRoleID().String()

	_, err := id.ParsePolicyID(roleID)
	if err == nil {
		t.Fatal("expected error parsing role ID as policy ID")
	}
}

func TestParseAny(t *testing.T) {
	roleID := id.NewRoleID().String()

	anyID, err := id.ParseAny(roleID)
	if err != nil {
		t.Fatalf("ParseAny failed: %v", err)
	}
	if anyID.String() != roleID {
		t.Errorf("round-trip mismatch: got %q, want %q", anyID.String(), roleID)
	}
}

func TestUniqueness(t *testing.T) {
	a := id.NewRoleID().String()
	b := id.NewRoleID().String()
	if a == b {
		t.Error("two generated IDs should not be equal")
	}
}
