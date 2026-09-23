package contract

import (
	"errors"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func TestGuardSystemRoleRefusesASystemRole(t *testing.T) {
	// Nothing below the contract layer enforces this. A repository-wide
	// grep finds zero places that return ErrSystemRoleImmutable: no store
	// guards IsSystem on update or delete, and neither does the HTTP API.
	// If this guard is absent the dashboard will rename and delete system
	// roles without complaint.
	err := guardSystemRole(&role.Role{IsSystem: true, Name: "System"})
	if err == nil {
		t.Fatal("want a refusal for a system role")
	}
	if !errors.Is(err, warden.ErrSystemRoleImmutable) {
		t.Errorf("want ErrSystemRoleImmutable in the chain, got %v", err)
	}
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
		t.Errorf("want CodePermissionDenied on the wire, got %v", err)
	}
}

func TestGuardSystemRoleAllowsAnOrdinaryRole(t *testing.T) {
	if err := guardSystemRole(&role.Role{IsSystem: false}); err != nil {
		t.Errorf("an ordinary role must pass, got %v", err)
	}
}

func TestGuardSystemPermissionRefusesASystemPermission(t *testing.T) {
	err := guardSystemPermission(&permission.Permission{IsSystem: true, Name: "document:read"})
	if err == nil {
		t.Fatal("want a refusal for a system permission")
	}
	if !errors.Is(err, warden.ErrSystemPermissionImmutable) {
		t.Errorf("want ErrSystemPermissionImmutable in the chain, got %v", err)
	}
}

func TestGuardSystemPermissionAllowsAnOrdinaryPermission(t *testing.T) {
	if err := guardSystemPermission(&permission.Permission{IsSystem: false}); err != nil {
		t.Errorf("an ordinary permission must pass, got %v", err)
	}
}

func TestGuardsNameTheEntityInTheirMessage(t *testing.T) {
	// The operator needs to know WHICH row refused, because these appear
	// in a list where several rows look alike.
	err := guardSystemRole(&role.Role{IsSystem: true, Name: "Platform admin"})
	var ce *dashcontract.Error
	if !errors.As(err, &ce) {
		t.Fatalf("want a contract error, got %v", err)
	}
	if !containsText(ce.Message, "Platform admin") {
		t.Errorf("message %q does not name the role", ce.Message)
	}
}

func containsText(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
