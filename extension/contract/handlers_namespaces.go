// handlers_namespaces.go: the derived namespace list.
//
// There is no namespace entity in warden. No table, no CRUD, no create. A
// namespace exists only as a string on rows, so this scans the entity tables
// for distinct values. The tenant root ("") is always present, because it is
// a real place where things live and the filter needs it as an option
// distinct from "all namespaces".
package contract

import (
	"context"
	"sort"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// NamespacesResponse is the namespaces.list reply. Paths are sorted, with
// the tenant root first because the empty string sorts first anyway and the
// filter renders it at the top.
type NamespacesResponse struct {
	Namespaces []string `json:"namespaces"`
}

// namespaceScanLimit caps how many rows of each kind are scanned for
// distinct namespace values. A tenant with more entities than this in one
// namespace still reports that namespace; a tenant whose namespaces are all
// beyond the cap is pathological and would need a store-level DISTINCT,
// which no backend exposes today.
const namespaceScanLimit = 1000

func namespacesListHandler(deps Deps) func(context.Context, struct{}, dashcontract.Principal) (NamespacesResponse, error) {
	return func(ctx context.Context, _ struct{}, p dashcontract.Principal) (NamespacesResponse, error) {
		if err := requireEngine(deps); err != nil {
			return NamespacesResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return NamespacesResponse{}, err
		}
		s := deps.Engine.Store()
		seen := map[string]struct{}{"": {}}

		roles, err := s.ListRoles(ctx, &role.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, r := range roles {
			seen[r.NamespacePath] = struct{}{}
		}

		perms, err := s.ListPermissions(ctx, &permission.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, pm := range perms {
			seen[pm.NamespacePath] = struct{}{}
		}

		pols, err := s.ListPolicies(ctx, &policy.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, pl := range pols {
			seen[pl.NamespacePath] = struct{}{}
		}

		rts, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, rt := range rts {
			seen[rt.NamespacePath] = struct{}{}
		}

		asgs, err := s.ListAssignments(ctx, &assignment.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, a := range asgs {
			seen[a.NamespacePath] = struct{}{}
		}

		tuples, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: tenantID, Limit: namespaceScanLimit})
		if err != nil {
			return NamespacesResponse{}, mapWardenError(err)
		}
		for _, tp := range tuples {
			seen[tp.NamespacePath] = struct{}{}
		}

		out := make([]string, 0, len(seen))
		for ns := range seen {
			out = append(out, ns)
		}
		sort.Strings(out)
		return NamespacesResponse{Namespaces: out}, nil
	}
}
