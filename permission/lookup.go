package permission

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/warden/wardenerr"
)

// RefNotFoundError refuses a grant of a permission that does not exist. It
// wraps wardenerr.ErrPermissionNotFound, so the REST API answers it with
// 404 and the dashboard with NOT_FOUND.
type RefNotFoundError struct {
	Name string
}

func (e *RefNotFoundError) Error() string {
	return fmt.Sprintf("no permission named %s in that namespace", e.Name)
}

func (e *RefNotFoundError) Unwrap() error { return wardenerr.ErrPermissionNotFound }

// NameGetter is the one store read LookupRef needs.
type NameGetter interface {
	GetPermissionByName(ctx context.Context, tenantID, namespacePath, name string) (*Permission, error)
}

// LookupRef returns the permission ref names in tenantID, or a
// *RefNotFoundError when there is none. The REST API and the dashboard
// contract both call it before they attach a grant: a store records a
// grant for a name that is not there, and the role then appears to grant
// something and grants nothing, because the evaluator resolves grants by
// joining against the permissions. A store failure is returned as is.
func LookupRef(ctx context.Context, s NameGetter, tenantID string, ref Ref) (*Permission, error) {
	p, err := s.GetPermissionByName(ctx, tenantID, ref.NamespacePath, ref.Name)
	if err != nil {
		if errors.Is(err, wardenerr.ErrNotFound) {
			return nil, &RefNotFoundError{Name: ref.Name}
		}
		return nil, err
	}
	if p == nil {
		return nil, &RefNotFoundError{Name: ref.Name}
	}
	return p, nil
}
