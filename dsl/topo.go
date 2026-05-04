package dsl

import "fmt"

// topoSortRoles sorts roles so that every role appears after its parent
// (when the parent is also in the slice). Cycles produce an error.
//
// The applier uses this to insert roles in dependency order so the FK
// constraint on parent_slug isn't violated mid-transaction even when the
// underlying store doesn't support DEFERRABLE constraints.
func topoSortRoles(roles []*RoleDecl) ([]*RoleDecl, error) {
	// Index by (namespace_path, slug) for parent lookup.
	byKey := make(map[string]*RoleDecl, len(roles))
	for _, r := range roles {
		byKey[r.NamespacePath+"\x00"+r.Slug] = r
	}

	const (
		unvisited = 0
		inStack   = 1
		visited   = 2
	)
	state := make(map[*RoleDecl]int, len(roles))
	out := make([]*RoleDecl, 0, len(roles))

	var visit func(*RoleDecl) error
	visit = func(r *RoleDecl) error {
		switch state[r] {
		case visited:
			return nil
		case inStack:
			return fmt.Errorf("role parent cycle detected at %s", r.Slug)
		}
		state[r] = inStack
		// Resolve parent in the same scope as the resolver does, but we only
		// use it if the parent is one of the roles we're sorting (i.e. it
		// will be created by this apply). Parents that already exist in the
		// store don't need ordering.
		if r.Parent != "" {
			if parent, ok := lookupParentInSet(r, byKey); ok {
				if err := visit(parent); err != nil {
					return err
				}
			}
		}
		state[r] = visited
		out = append(out, r)
		return nil
	}

	for _, r := range roles {
		if err := visit(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// lookupParentInSet returns the RoleDecl matching the role's Parent
// reference, only if it's in the given set (i.e. being applied alongside).
func lookupParentInSet(r *RoleDecl, byKey map[string]*RoleDecl) (*RoleDecl, bool) {
	parent := r.Parent
	if len(parent) > 0 && parent[0] == '/' {
		// Absolute path.
		rest := parent[1:]
		var ns, slug string
		if i := lastIndex(rest, '/'); i < 0 {
			ns = ""
			slug = rest
		} else {
			ns = rest[:i]
			slug = rest[i+1:]
		}
		p, ok := byKey[ns+"\x00"+slug]
		return p, ok
	}
	// Local search with ancestor walk.
	ns := r.NamespacePath
	for {
		if p, ok := byKey[ns+"\x00"+parent]; ok {
			return p, true
		}
		if ns == "" {
			return nil, false
		}
		if i := lastIndex(ns, '/'); i < 0 {
			ns = ""
		} else {
			ns = ns[:i]
		}
	}
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
