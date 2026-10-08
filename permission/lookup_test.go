package permission

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/warden/wardenerr"
)

type names struct {
	held map[Ref]*Permission
	fail error
}

func (n names) GetPermissionByName(_ context.Context, _, ns, name string) (*Permission, error) {
	if n.fail != nil {
		return nil, n.fail
	}
	if p, ok := n.held[Ref{NamespacePath: ns, Name: name}]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("permission %q: %w", name, wardenerr.ErrPermissionNotFound)
}

func TestLookupRef(t *testing.T) {
	ctx := context.Background()
	docRead := &Permission{Name: "doc:read"}
	s := names{held: map[Ref]*Permission{{Name: "doc:read"}: docRead}}

	if got, err := LookupRef(ctx, s, "t1", Ref{Name: "doc:read"}); err != nil || got != docRead {
		t.Fatalf("existing: got %v, %v", got, err)
	}
	for _, ref := range []Ref{{Name: "ghost:read"}, {NamespacePath: "eng", Name: "doc:read"}} {
		_, err := LookupRef(ctx, s, "t1", ref)
		var nf *RefNotFoundError
		if !errors.As(err, &nf) || !errors.Is(err, wardenerr.ErrPermissionNotFound) {
			t.Errorf("%+v: err = %v, want a *RefNotFoundError wrapping ErrPermissionNotFound", ref, err)
			continue
		}
		if want := "no permission named " + ref.Name + " in that namespace"; err.Error() != want {
			t.Errorf("%+v: message = %q, want %q", ref, err.Error(), want)
		}
	}

	boom := errors.New("store down")
	_, err := LookupRef(ctx, names{fail: boom}, "t1", Ref{Name: "doc:read"})
	var nf *RefNotFoundError
	if !errors.Is(err, boom) || errors.As(err, &nf) {
		t.Errorf("store failure: err = %v, want the failure itself, not a not-found", err)
	}
}
