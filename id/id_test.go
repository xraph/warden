package id_test

import (
	"strings"
	"testing"

	"github.com/xraph/warden/id"
)

func TestConstructors(t *testing.T) {
	tests := []struct {
		name   string
		newFn  func() id.ID
		prefix string
	}{
		{"RoleID", id.NewRoleID, "role_"},
		{"PermissionID", id.NewPermissionID, "perm_"},
		{"AssignmentID", id.NewAssignmentID, "asgn_"},
		{"PolicyID", id.NewPolicyID, "wpol_"},
		{"RelationID", id.NewRelationID, "rel_"},
		{"CheckLogID", id.NewCheckLogID, "chklog_"},
		{"ResourceTypeID", id.NewResourceTypeID, "rtype_"},
		{"ConditionID", id.NewConditionID, "cond_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.newFn().String()
			if !strings.HasPrefix(got, tt.prefix) {
				t.Errorf("expected prefix %q, got %q", tt.prefix, got)
			}
		})
	}
}

func TestNew(t *testing.T) {
	i := id.New(id.PrefixRole)
	if i.IsNil() {
		t.Fatal("expected non-nil ID")
	}
	if i.Prefix() != id.PrefixRole {
		t.Errorf("expected prefix %q, got %q", id.PrefixRole, i.Prefix())
	}
}

func TestParseRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		newFn   func() id.ID
		parseFn func(string) (id.ID, error)
	}{
		{"RoleID", id.NewRoleID, id.ParseRoleID},
		{"PermissionID", id.NewPermissionID, id.ParsePermissionID},
		{"AssignmentID", id.NewAssignmentID, id.ParseAssignmentID},
		{"PolicyID", id.NewPolicyID, id.ParsePolicyID},
		{"RelationID", id.NewRelationID, id.ParseRelationID},
		{"CheckLogID", id.NewCheckLogID, id.ParseCheckLogID},
		{"ResourceTypeID", id.NewResourceTypeID, id.ParseResourceTypeID},
		{"ConditionID", id.NewConditionID, id.ParseConditionID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.newFn()
			parsed, err := tt.parseFn(original.String())
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if parsed.String() != original.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), original.String())
			}
		})
	}
}

func TestCrossTypeRejection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		parseFn func(string) (id.ID, error)
	}{
		{"ParseRoleID rejects perm_", id.NewPermissionID().String(), id.ParseRoleID},
		{"ParsePermissionID rejects asgn_", id.NewAssignmentID().String(), id.ParsePermissionID},
		{"ParseAssignmentID rejects wpol_", id.NewPolicyID().String(), id.ParseAssignmentID},
		{"ParsePolicyID rejects rel_", id.NewRelationID().String(), id.ParsePolicyID},
		{"ParseRelationID rejects chklog_", id.NewCheckLogID().String(), id.ParseRelationID},
		{"ParseCheckLogID rejects rtype_", id.NewResourceTypeID().String(), id.ParseCheckLogID},
		{"ParseResourceTypeID rejects cond_", id.NewConditionID().String(), id.ParseResourceTypeID},
		{"ParseConditionID rejects role_", id.NewRoleID().String(), id.ParseConditionID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.parseFn(tt.input)
			if err == nil {
				t.Errorf("expected error for cross-type parse of %q, got nil", tt.input)
			}
		})
	}
}

func TestParseAny(t *testing.T) {
	ids := []id.ID{
		id.NewRoleID(),
		id.NewPermissionID(),
		id.NewAssignmentID(),
		id.NewPolicyID(),
		id.NewRelationID(),
		id.NewCheckLogID(),
		id.NewResourceTypeID(),
		id.NewConditionID(),
	}

	for _, i := range ids {
		t.Run(i.String(), func(t *testing.T) {
			parsed, err := id.ParseAny(i.String())
			if err != nil {
				t.Fatalf("ParseAny(%q) failed: %v", i.String(), err)
			}
			if parsed.String() != i.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), i.String())
			}
		})
	}
}

func TestParseWithPrefix(t *testing.T) {
	i := id.NewRoleID()
	parsed, err := id.ParseWithPrefix(i.String(), id.PrefixRole)
	if err != nil {
		t.Fatalf("ParseWithPrefix failed: %v", err)
	}
	if parsed.String() != i.String() {
		t.Errorf("mismatch: %q != %q", parsed.String(), i.String())
	}

	_, err = id.ParseWithPrefix(i.String(), id.PrefixPermission)
	if err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := id.Parse("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestNilID(t *testing.T) {
	var i id.ID
	if !i.IsNil() {
		t.Error("zero-value ID should be nil")
	}
	if i.String() != "" {
		t.Errorf("expected empty string, got %q", i.String())
	}
	if i.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", i.Prefix())
	}
}

func TestMarshalUnmarshalText(t *testing.T) {
	original := id.NewRoleID()
	data, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText failed: %v", err)
	}

	var restored id.ID
	if unmarshalErr := restored.UnmarshalText(data); unmarshalErr != nil {
		t.Fatalf("UnmarshalText failed: %v", unmarshalErr)
	}
	if restored.String() != original.String() {
		t.Errorf("mismatch: %q != %q", restored.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	data, err = nilID.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(nil) failed: %v", err)
	}
	var restored2 id.ID
	if err := restored2.UnmarshalText(data); err != nil {
		t.Fatalf("UnmarshalText(nil) failed: %v", err)
	}
	if !restored2.IsNil() {
		t.Error("expected nil after round-trip of nil ID")
	}
}

func TestValueScan(t *testing.T) {
	original := id.NewPolicyID()
	val, err := original.Value()
	if err != nil {
		t.Fatalf("Value failed: %v", err)
	}

	var scanned id.ID
	if scanErr := scanned.Scan(val); scanErr != nil {
		t.Fatalf("Scan failed: %v", scanErr)
	}
	if scanned.String() != original.String() {
		t.Errorf("mismatch: %q != %q", scanned.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	val, err = nilID.Value()
	if err != nil {
		t.Fatalf("Value(nil) failed: %v", err)
	}
	if val != nil {
		t.Errorf("expected nil value for nil ID, got %v", val)
	}

	var scanned2 id.ID
	if err := scanned2.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) failed: %v", err)
	}
	if !scanned2.IsNil() {
		t.Error("expected nil after scan of nil")
	}
}

func TestUniqueness(t *testing.T) {
	a := id.NewRoleID()
	b := id.NewRoleID()
	if a.String() == b.String() {
		t.Errorf("two consecutive NewRoleID() calls returned the same ID: %q", a.String())
	}
}
