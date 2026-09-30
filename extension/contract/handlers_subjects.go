// handlers_subjects.go: what one subject can do at a namespace, and why.
package contract

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// subjectListCap is how many assignments and relations the view returns.
// The store is asked for one more, so a full page proves there is more
// rather than guessing from a total.
const subjectListCap = 200

// subjectRecentChecks is how many check log rows the view returns.
const subjectRecentChecks = 10

// SubjectDetailInput names one subject at one namespace.
//
// SubjectKind is not validated: the check log and the stores accept any
// string, and a subject of a kind no assignment names is a legitimate
// question with an empty answer.
type SubjectDetailInput struct {
	SubjectKind   string `json:"subjectKind"`
	SubjectID     string `json:"subjectId"`
	NamespacePath string `json:"namespacePath"` // "" is the root; always explicit
}

// SubjectPermission is one grant of a role.
type SubjectPermission struct {
	Name     string `json:"name"` // resource:action as stored, wildcards included
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// SubjectRole is one resolved role.
type SubjectRole struct {
	ID            string `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	NamespacePath string `json:"namespacePath"`
	// Via is "assigned" or "inherited".
	Via string `json:"via"`
	// InheritedBy lists the slugs of the resolved roles whose ParentSlug
	// names this role in its namespace. Empty for an assigned role that no
	// other resolved role inherits.
	InheritedBy []string            `json:"inheritedBy"`
	Permissions []SubjectPermission `json:"permissions"`
}

// SubjectAssignment is one assignment row of the subject.
type SubjectAssignment struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	RoleID        string `json:"roleId"`
	RoleSlug      string `json:"roleSlug"`
	ResourceType  string `json:"resourceType,omitempty"`
	ResourceID    string `json:"resourceId,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	Expired       bool   `json:"expired"`
	// ExpiringSoon is true for a live assignment whose ExpiresAt falls within
	// the horizon assignments.expiring uses. That feed also lists lapsed
	// rows; this flag does not, because Expired already says so.
	ExpiringSoon bool `json:"expiringSoon"`
}

// SubjectRelation is one tuple naming the subject.
type SubjectRelation struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	ObjectType    string `json:"objectType"`
	ObjectID      string `json:"objectId"`
	Relation      string `json:"relation"`
}

// SubjectPolicy is one policy in effect that selects the subject.
type SubjectPolicy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Effect        string `json:"effect"`
	Priority      int    `json:"priority"`
	NamespacePath string `json:"namespacePath"`
	// SelectedBy says how the policy's subject matchers select this subject:
	// "everyone" (no subject matchers, or an empty matcher), "kind", "id" or
	// "role:<slug>" (the first agreeing matcher's most specific field).
	SelectedBy string `json:"selectedBy"`
}

// SubjectDetailResponse is the subjects.detail reply.
type SubjectDetailResponse struct {
	Roles                []SubjectRole       `json:"roles"`
	Assignments          []SubjectAssignment `json:"assignments"`
	AssignmentsTruncated bool                `json:"assignmentsTruncated"`
	Relations            []SubjectRelation   `json:"relations"`
	RelationsTruncated   bool                `json:"relationsTruncated"`
	Policies             []SubjectPolicy     `json:"policies"`
	RecentChecks         []CheckLogSummary   `json:"recentChecks"`
}

// subjectScanPage is how many rows the empty-kind scan asks the store for at
// a time.
const subjectScanPage = 200

// collectForKind returns up to want rows for one subject kind.
//
// A store's filter treats an empty SubjectKind or SubjectType as "any kind",
// but the engine matches "" exactly (SubjectRoles, CheckDirectRelation). So
// for a non-empty kind the filter is exact and one fetch of want rows is
// enough. For "" the filter would also return user:alice, api_key:alice and
// every other kind, so this pages through the store with an offset and keeps
// only rows whose kind is exactly "", until it has want of them or the store
// runs out. That keeps the callers' truncated flags true to the data.
func collectForKind[T any](kind string, want int, kindOf func(T) string, fetch func(offset, limit int) ([]T, error)) ([]T, error) {
	if kind != "" {
		return fetch(0, want)
	}
	out := make([]T, 0, want)
	for offset := 0; len(out) < want; offset += subjectScanPage {
		page, err := fetch(offset, subjectScanPage)
		if err != nil {
			return nil, err
		}
		for _, row := range page {
			if kindOf(row) == "" {
				out = append(out, row)
				if len(out) == want {
					break
				}
			}
		}
		if len(page) < subjectScanPage {
			break
		}
	}
	return out, nil
}

// namespaceField refuses a malformed namespace and names the field, which
// validateNamespace's own message does not.
func namespaceField(path string) error {
	err := validateNamespace(path)
	if err == nil {
		return nil
	}
	var ce *dashcontract.Error
	if errors.As(err, &ce) {
		return badRequest("namespacePath: " + ce.Message)
	}
	return err
}

// subjectPolicySelection reports how pol's matchers select the subject: the
// first matcher that agrees, in list order, reported by its most specific
// field. It mirrors warden.PolicySelectsSubject, which decides whether the
// policy selects at all.
func subjectPolicySelection(pol *policy.Policy, kind, subjectID string, roleSlugs []string) string {
	for _, sm := range pol.Subjects {
		if sm.Kind != "" && sm.Kind != kind {
			continue
		}
		if sm.ID != "" && sm.ID != subjectID {
			continue
		}
		if sm.Role != "" && !containsString(roleSlugs, sm.Role) {
			continue
		}
		switch {
		case sm.Role != "":
			return "role:" + sm.Role
		case sm.ID != "":
			return "id"
		case sm.Kind != "":
			return "kind"
		}
		return "everyone"
	}
	return "everyone"
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func subjectsDetailHandler(deps Deps) func(context.Context, SubjectDetailInput, dashcontract.Principal) (SubjectDetailResponse, error) {
	return func(ctx context.Context, in SubjectDetailInput, p dashcontract.Principal) (SubjectDetailResponse, error) {
		if err := requireEngine(deps); err != nil {
			return SubjectDetailResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return SubjectDetailResponse{}, err
		}
		if in.SubjectID == "" {
			return SubjectDetailResponse{}, badRequest("subjectId is required: name the subject to look up")
		}
		if err := namespaceField(in.NamespacePath); err != nil {
			return SubjectDetailResponse{}, err
		}

		eng := deps.Engine
		s := eng.Store()
		now := time.Now()

		direct, all, err := eng.SubjectRoles(ctx, warden.SubjectKind(in.SubjectKind), in.SubjectID,
			warden.WithCallTenantID(tenantID), warden.WithCallNamespacePath(in.NamespacePath))
		if err != nil {
			return SubjectDetailResponse{}, mapWardenError(err)
		}
		roles, slugs, err := subjectRoles(ctx, deps, tenantID, direct, all)
		if err != nil {
			return SubjectDetailResponse{}, err
		}
		out := SubjectDetailResponse{
			Roles:        roles,
			Assignments:  make([]SubjectAssignment, 0),
			Relations:    make([]SubjectRelation, 0),
			Policies:     make([]SubjectPolicy, 0),
			RecentChecks: make([]CheckLogSummary, 0),
		}

		// Assignments cover every namespace, not the one asked about: the
		// roles above are what resolves here, and this is where each came
		// from and what else the subject holds.
		rows, err := collectForKind(in.SubjectKind, subjectListCap+1,
			func(a *assignment.Assignment) string { return a.SubjectKind },
			func(offset, limit int) ([]*assignment.Assignment, error) {
				return s.ListAssignments(ctx, &assignment.ListFilter{
					TenantID:    tenantID,
					SubjectKind: in.SubjectKind,
					SubjectID:   in.SubjectID,
					Limit:       limit,
					Offset:      offset,
				})
			})
		if err != nil {
			return SubjectDetailResponse{}, mapWardenError(err)
		}
		if len(rows) > subjectListCap {
			rows, out.AssignmentsTruncated = rows[:subjectListCap], true
		}
		byID, err := rolesByIDFor(ctx, deps, tenantID, rows)
		if err != nil {
			return SubjectDetailResponse{}, err
		}
		horizon := now.Add(defaultExpiringWindowHours * time.Hour)
		for _, a := range rows {
			sa := SubjectAssignment{
				ID:            a.ID.String(),
				NamespacePath: a.NamespacePath,
				RoleID:        a.RoleID.String(),
				ResourceType:  a.ResourceType,
				ResourceID:    a.ResourceID,
				Expired:       !isLive(a, now),
			}
			if r := byID[a.RoleID]; r != nil {
				sa.RoleSlug = r.Slug
			}
			if a.ExpiresAt != nil {
				sa.ExpiresAt = a.ExpiresAt.UTC().Format(time.RFC3339)
				sa.ExpiringSoon = !sa.Expired && !a.ExpiresAt.After(horizon)
			}
			out.Assignments = append(out.Assignments, sa)
		}

		tuples, err := collectForKind(in.SubjectKind, subjectListCap+1,
			func(tp *relation.Tuple) string { return tp.SubjectType },
			func(offset, limit int) ([]*relation.Tuple, error) {
				return s.ListRelations(ctx, &relation.ListFilter{
					TenantID:    tenantID,
					SubjectType: in.SubjectKind,
					SubjectID:   in.SubjectID,
					Limit:       limit,
					Offset:      offset,
				})
			})
		if err != nil {
			return SubjectDetailResponse{}, mapWardenError(err)
		}
		if len(tuples) > subjectListCap {
			tuples, out.RelationsTruncated = tuples[:subjectListCap], true
		}
		for _, tp := range tuples {
			out.Relations = append(out.Relations, SubjectRelation{
				ID:            tp.ID.String(),
				NamespacePath: tp.NamespacePath,
				ObjectType:    tp.ObjectType,
				ObjectID:      tp.ObjectID,
				Relation:      tp.Relation,
			})
		}

		// A policy is a candidate when it is stored at this namespace or an
		// ancestor, in effect right now, and its matchers select a subject
		// holding these roles. Selecting is not applying: its actions,
		// resources and conditions still decide each check.
		candidates, err := s.ListActivePolicies(ctx, tenantID, warden.AncestorNamespaces(in.NamespacePath))
		if err != nil {
			return SubjectDetailResponse{}, mapWardenError(err)
		}
		for _, pol := range candidates {
			if !pol.EffectiveAt(now) {
				continue
			}
			if !warden.PolicySelectsSubject(pol, warden.SubjectKind(in.SubjectKind), in.SubjectID, slugs) {
				continue
			}
			out.Policies = append(out.Policies, SubjectPolicy{
				ID:            pol.ID.String(),
				Name:          pol.Name,
				Effect:        string(pol.Effect),
				Priority:      pol.Priority,
				NamespacePath: pol.NamespacePath,
				SelectedBy:    subjectPolicySelection(pol, in.SubjectKind, in.SubjectID, slugs),
			})
		}

		entries, err := collectForKind(in.SubjectKind, subjectRecentChecks,
			func(e *checklog.Entry) string { return e.SubjectKind },
			func(offset, limit int) ([]*checklog.Entry, error) {
				return s.ListCheckLogs(ctx, &checklog.QueryFilter{
					TenantID:    tenantID,
					SubjectKind: in.SubjectKind,
					SubjectID:   in.SubjectID,
					Limit:       limit,
					Offset:      offset,
				})
			})
		if err != nil {
			return SubjectDetailResponse{}, mapWardenError(err)
		}
		for _, e := range entries {
			out.RecentChecks = append(out.RecentChecks, projectCheckLog(e))
		}
		return out, nil
	}
}

// subjectRoles projects the resolved roles. all is already deduplicated;
// direct is a set exactly as the store gave it (a role assigned at two
// ancestor namespaces can repeat), so it only decides each role's Via.
func subjectRoles(ctx context.Context, deps Deps, tenantID string, direct, all []*role.Role) ([]SubjectRole, []string, error) {
	assigned := make(map[id.RoleID]struct{}, len(direct))
	for _, r := range direct {
		assigned[r.ID] = struct{}{}
	}
	ids := make([]id.RoleID, 0, len(all))
	slugs := make([]string, 0, len(all))
	for _, r := range all {
		ids = append(ids, r.ID)
		slugs = append(slugs, r.Slug)
	}
	grants := map[id.RoleID][]*permission.Permission{}
	if len(ids) > 0 {
		var err error
		grants, err = deps.Engine.Store().ListRolePermissionsForRoles(ctx, tenantID, ids)
		if err != nil {
			return nil, nil, mapWardenError(err)
		}
	}
	out := make([]SubjectRole, 0, len(all))
	for _, r := range all {
		via := "inherited"
		if _, ok := assigned[r.ID]; ok {
			via = "assigned"
		}
		by := []string{}
		for _, child := range all {
			if child.ParentSlug == r.Slug && child.NamespacePath == r.NamespacePath {
				by = append(by, child.Slug)
			}
		}
		sort.Strings(by)
		perms := make([]SubjectPermission, 0, len(grants[r.ID]))
		for _, g := range grants[r.ID] {
			if g == nil {
				continue
			}
			perms = append(perms, SubjectPermission{Name: g.Name, Resource: g.Resource, Action: g.Action})
		}
		sort.Slice(perms, func(i, j int) bool { return perms[i].Name < perms[j].Name })
		out = append(out, SubjectRole{
			ID:            r.ID.String(),
			Slug:          r.Slug,
			Name:          r.Name,
			NamespacePath: r.NamespacePath,
			Via:           via,
			InheritedBy:   by,
			Permissions:   perms,
		})
	}
	return out, slugs, nil
}
