package permission

import (
	"fmt"

	"github.com/xraph/warden/wardenerr"
)

// SystemPermissionError refuses a write that would change or delete a
// system permission. It wraps wardenerr.ErrSystemPermissionImmutable
// (warden.ErrSystemPermissionImmutable).
type SystemPermissionError struct {
	Name string
}

func (e *SystemPermissionError) Error() string {
	return fmt.Sprintf("%q is a system permission and cannot be changed or deleted", e.Name)
}

func (e *SystemPermissionError) Unwrap() error { return wardenerr.ErrSystemPermissionImmutable }

// CheckWritable refuses, with a *SystemPermissionError, an update or delete
// of a system permission. The REST API and the dashboard contract both call
// it before they write one. The dashboard's schema.plan and schema.apply
// refuse the same writes through dsl.ApplyOptions.ProtectSystem; `warden
// apply` and DeclarativeOnStart leave that off on purpose, since they are
// operator tooling, and can change or delete one. No store checks
// IsSystem, so code that writes through the store directly checks nothing.
// A nil permission passes.
func CheckWritable(p *Permission) error {
	if p == nil || !p.IsSystem {
		return nil
	}
	return &SystemPermissionError{Name: p.Name}
}
