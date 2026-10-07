package role

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/warden/wardenerr"
)

// slugs is a SlugGetter over slug -> parent slug. A slug it does not hold
// is ErrRoleNotFound; fail, when set, is returned for every read.
type slugs struct {
	parents map[string]string
	fail    error
	reads   int
}

func (s *slugs) GetRoleBySlug(_ context.Context, _, _, slug string) (*Role, error) {
	s.reads++
	if s.fail != nil {
		return nil, s.fail
	}
	parent, ok := s.parents[slug]
	if !ok {
		return nil, fmt.Errorf("role slug %q: %w", slug, wardenerr.ErrRoleNotFound)
	}
	return &Role{Slug: slug, ParentSlug: parent}, nil
}

func TestCheckParent(t *testing.T) {
	// viewer <- editor <- owner, plus a loop x -> y -> x already stored, and
	// orphan whose parent ghost does not exist.
	stored := map[string]string{
		"viewer": "", "editor": "viewer", "owner": "editor",
		"x": "y", "y": "x",
		"orphan": "ghost",
	}
	var cycle *CycleError
	var missing *ParentNotFoundError
	cases := []struct {
		name   string
		slug   string
		parent string
		want   any // nil, &cycle or &missing
	}{
		{"no parent", "viewer", "", nil},
		{"an unrelated parent", "owner", "viewer", nil},
		{"itself", "viewer", "viewer", &cycle},
		{"a direct child", "viewer", "editor", &cycle},
		{"a grandchild", "viewer", "owner", &cycle},
		{"a missing parent", "viewer", "ghost", &missing},
		{"a parent whose own parent is missing", "viewer", "orphan", nil},
		{"a parent inside a loop that does not reach this role", "viewer", "x", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &slugs{parents: stored}
			err := CheckParent(context.Background(), s, "t1", &Role{Slug: tc.slug}, tc.parent)
			switch target := tc.want.(type) {
			case nil:
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			case **CycleError:
				if !errors.As(err, target) || !errors.Is(err, wardenerr.ErrCyclicRoleInheritance) {
					t.Fatalf("err = %v, want a *CycleError wrapping ErrCyclicRoleInheritance", err)
				}
			case **ParentNotFoundError:
				if !errors.As(err, target) || errors.Is(err, wardenerr.ErrNotFound) {
					t.Fatalf("err = %v, want a *ParentNotFoundError that is not a not-found", err)
				}
			}
			if tc.parent == "" && s.reads != 0 {
				t.Errorf("no parent read the store %d times, want 0", s.reads)
			}
		})
	}
}

func TestCheckParent_StoreFailurePassesThrough(t *testing.T) {
	boom := errors.New("store down")
	err := CheckParent(context.Background(), &slugs{fail: boom}, "t1", &Role{Slug: "a"}, "b")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store's error", err)
	}
}

func TestCheckWritable(t *testing.T) {
	if err := CheckWritable(&Role{Name: "Editor"}); err != nil {
		t.Fatalf("ordinary role: err = %v, want nil", err)
	}
	if err := CheckWritable(nil); err != nil {
		t.Fatalf("nil role: err = %v, want nil", err)
	}
	err := CheckWritable(&Role{Name: "Admin", Slug: "admin", IsSystem: true})
	if !errors.Is(err, wardenerr.ErrSystemRoleImmutable) {
		t.Fatalf("err = %v, want ErrSystemRoleImmutable", err)
	}
	if want := `"Admin" is a system role and cannot be changed or deleted`; err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
}
