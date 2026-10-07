package role

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/warden/wardenerr"
)

// No store checks IsSystem or the parent graph on a write. The two checks
// below are what the REST API and the dashboard contract both call before
// they write a role, so the two cannot refuse different things. A DSL apply
// holds the same rules its own way: dsl.Resolve rejects a parent cycle in
// the source, and dsl.ApplyOptions.ProtectSystem refuses a change to a
// system role. Code that writes through the store directly checks nothing.

// SystemRoleError refuses a write that would change or delete a system
// role. It wraps wardenerr.ErrSystemRoleImmutable (warden.ErrSystemRoleImmutable).
type SystemRoleError struct {
	Name string
}

func (e *SystemRoleError) Error() string {
	return fmt.Sprintf("%q is a system role and cannot be changed or deleted", e.Name)
}

func (e *SystemRoleError) Unwrap() error { return wardenerr.ErrSystemRoleImmutable }

// CheckWritable refuses, with a *SystemRoleError, any write to a system
// role: an update of any field, a delete, or a change to its grants.
// Assigning a system role to a subject is a membership change, not a write
// to the role, and does not call this. A nil role passes.
func CheckWritable(r *Role) error {
	if r == nil || !r.IsSystem {
		return nil
	}
	return &SystemRoleError{Name: r.Name}
}

// CycleError refuses a parent that would make a role its own ancestor,
// either directly (the role names itself) or through a chain of parents
// that leads back to it. It wraps wardenerr.ErrCyclicRoleInheritance
// (warden.ErrCyclicRoleInheritance).
type CycleError struct {
	Slug   string
	Parent string
}

func (e *CycleError) Error() string {
	if e.Slug == e.Parent {
		return "a role cannot be its own parent"
	}
	return "that parent would create a cycle in role inheritance"
}

func (e *CycleError) Unwrap() error { return wardenerr.ErrCyclicRoleInheritance }

// ParentNotFoundError refuses a parent slug that names no role in the
// child's tenant and namespace. The engine resolves a parent only there, so
// a role stored with such a parent would inherit nothing from it.
//
// It deliberately does not wrap ErrRoleNotFound: the role being written was
// found, and the request is what names a missing parent, so it is bad
// input rather than a missing entity.
type ParentNotFoundError struct {
	Parent string
}

func (e *ParentNotFoundError) Error() string {
	return "no role with slug " + e.Parent + " in this namespace"
}

// SlugGetter is the one store read CheckParent needs.
type SlugGetter interface {
	GetRoleBySlug(ctx context.Context, tenantID, namespacePath, slug string) (*Role, error)
}

// CheckParent refuses setting parentSlug as the parent of r, in tenant
// tenantID and r's namespace. An empty parentSlug (no parent) always
// passes and reads nothing.
//
// It returns a *ParentNotFoundError when no role in r's namespace has that
// slug, and a *CycleError when the parent is r itself or one of r's
// descendants. It walks up from the parent through ParentSlug; reaching r
// means the engine's inheritance walk would loop. A missing role further up
// the chain ends the walk, since a chain through a role that does not
// exist cannot lead back to r. The walk stops at the first slug it has
// already seen, so a cycle already in the data cannot hang it. A store
// failure is returned as is.
func CheckParent(ctx context.Context, s SlugGetter, tenantID string, r *Role, parentSlug string) error {
	if parentSlug == "" {
		return nil
	}
	if parentSlug == r.Slug {
		return &CycleError{Slug: r.Slug, Parent: parentSlug}
	}
	seen := map[string]struct{}{r.Slug: {}}
	for slug := parentSlug; slug != ""; {
		if slug == r.Slug {
			return &CycleError{Slug: r.Slug, Parent: parentSlug}
		}
		if _, again := seen[slug]; again {
			// A loop above r that does not pass through r: the data
			// already holds a cycle, and this parent does not add one.
			return nil
		}
		seen[slug] = struct{}{}
		next, err := s.GetRoleBySlug(ctx, tenantID, r.NamespacePath, slug)
		if err != nil {
			if !errors.Is(err, wardenerr.ErrNotFound) {
				return err
			}
			if slug == parentSlug {
				return &ParentNotFoundError{Parent: parentSlug}
			}
			return nil
		}
		slug = next.ParentSlug
	}
	return nil
}
