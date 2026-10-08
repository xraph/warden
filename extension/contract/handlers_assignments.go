// handlers_assignments.go: the assignment surface.
//
// Assignments are create-and-delete only, because assignment.Store exposes
// no update. So there is no patch input here and no edit form on the page:
// changing who holds a role means deleting one binding and making another.
//
// The one thing this file cares about more than the rest is expiry. The
// engine's resolution path filters expired assignments, so an expired row
// grants nothing. The LISTING path does not filter them, so they are
// visible. A page that showed them without saying so would be reporting
// access that does not exist, which is why every projected row carries
// Expired.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/role"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// defaultExpiringWindowHours is the horizon assignments.expiring uses when
// the caller names none. Not zero: a zero window would return nothing and an
// empty page would look like nothing is lapsing.
const defaultExpiringWindowHours = 7 * 24

// AssignmentSummary is one row of the assignments list.
//
// RoleSlug is denormalised deliberately. A row that named only a role id
// would be unreadable, and resolving it per row in the page would be a
// request per row.
//
// Expired is computed rather than stored, because the store has no such
// column: it is ExpiresAt compared against now, using the same test the
// engine applies when it resolves roles.
type AssignmentSummary struct {
	ID            string `json:"id"`
	NamespacePath string `json:"namespacePath"`
	RoleID        string `json:"roleId"`
	RoleSlug      string `json:"roleSlug"`
	RoleName      string `json:"roleName"`
	SubjectKind   string `json:"subjectKind"`
	SubjectID     string `json:"subjectId"`
	ResourceType  string `json:"resourceType,omitempty"`
	ResourceID    string `json:"resourceId,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	Expired       bool   `json:"expired"`
	GrantedBy     string `json:"grantedBy,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// AssignmentsListInput filters the assignments list.
type AssignmentsListInput struct {
	PageRequest
	NamespacePath *string `json:"namespacePath,omitempty"`
	RoleID        string  `json:"roleId,omitempty"`
	SubjectKind   string  `json:"subjectKind,omitempty"`
	SubjectID     string  `json:"subjectId,omitempty"`
	ResourceType  string  `json:"resourceType,omitempty"`
	ResourceID    string  `json:"resourceId,omitempty"`
}

// AssignmentsListResponse is the paged reply.
type AssignmentsListResponse struct {
	PageMeta
	Items []AssignmentSummary `json:"items"`
}

// AssignmentCreateInput binds a subject to a role.
//
// ExpiresAt is an RFC3339 string rather than a time, because that is what
// the wire carries and parsing it here lets a malformed value be a
// BAD_REQUEST naming the field instead of a JSON decode failure naming
// nothing.
type AssignmentCreateInput struct {
	RoleID        string `json:"roleId"`
	SubjectKind   string `json:"subjectKind"`
	SubjectID     string `json:"subjectId"`
	NamespacePath string `json:"namespacePath,omitempty"`
	ResourceType  string `json:"resourceType,omitempty"`
	ResourceID    string `json:"resourceId,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
}

// AssignmentDeleteInput names the binding to remove.
type AssignmentDeleteInput struct {
	ID string `json:"id"`
}

// ExpiringInput asks what lapses within a horizon.
type ExpiringInput struct {
	WithinHours int `json:"withinHours,omitempty"`
	Limit       int `json:"limit,omitempty"`
}

// ExpiringResponse is the reply. Not paged: this is a "what needs attention"
// feed with a caller-set limit, not a browsable collection, so it carries no
// PageMeta. Compare overview.recentChecks in the spine plan.
type ExpiringResponse struct {
	Items []AssignmentSummary `json:"items"`
}

// validSubjectKinds is warden's closed set. A kind outside it stores an
// assignment no check will ever match, because the engine compares
// req.Subject.Kind verbatim against the stored string.
var validSubjectKinds = map[string]struct{}{
	"user":         {},
	"api_key":      {},
	"service":      {},
	"service_acct": {},
}

// validateResourceScope refuses an assignment that names half a resource.
//
// The engine reads the two fields as one key, and each half on its own
// grants something other than what it looks like:
//
//   - An id without a type is a GLOBAL grant. ListRolesForSubject keeps
//     every row whose ResourceType is empty, whatever its ResourceID, so the
//     id is ignored and the subject holds the role for every resource.
//   - A type without an id matches only a check whose resource id is the
//     empty string, because ListRolesForSubjectOnResource compares both
//     fields exactly. It looks scoped to a type and matches almost nothing.
//
// So the rule is both or neither.
func validateResourceScope(resourceType, resourceID string) error {
	switch {
	case resourceID != "" && resourceType == "":
		return badRequest("resourceId needs a resourceType: warden ignores an id without a type, " +
			"so this assignment would apply to every resource, not one. Give both, or neither")
	case resourceType != "" && resourceID == "":
		return badRequest("resourceType needs a resourceId: without one this assignment would match " +
			"only checks on a resource whose id is empty. Give both, or neither")
	}
	return nil
}

func parseAssignmentID(raw string) (id.AssignmentID, error) {
	aid, err := id.ParseAssignmentID(raw)
	if err != nil {
		return id.Nil, badRequest("not an assignment id: " + raw)
	}
	return aid, nil
}

func projectAssignment(a *assignment.Assignment, r *role.Role, now time.Time) AssignmentSummary {
	out := AssignmentSummary{
		ID:            a.ID.String(),
		NamespacePath: a.NamespacePath,
		RoleID:        a.RoleID.String(),
		SubjectKind:   a.SubjectKind,
		SubjectID:     a.SubjectID,
		ResourceType:  a.ResourceType,
		ResourceID:    a.ResourceID,
		Expired:       !isLive(a, now),
		GrantedBy:     a.GrantedBy,
		CreatedAt:     a.CreatedAt.UTC().Format(time.RFC3339),
	}
	if a.ExpiresAt != nil {
		out.ExpiresAt = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if r != nil {
		out.RoleSlug = r.Slug
		out.RoleName = r.Name
	}
	return out
}

// rolesByIDFor resolves the roles a page of assignments references, in one
// round trip rather than one per row.
func rolesByIDFor(ctx context.Context, deps Deps, tenantID string, rows []*assignment.Assignment) (map[id.RoleID]*role.Role, error) {
	seen := map[id.RoleID]struct{}{}
	ids := make([]id.RoleID, 0, len(rows))
	for _, a := range rows {
		if _, dup := seen[a.RoleID]; dup {
			continue
		}
		seen[a.RoleID] = struct{}{}
		ids = append(ids, a.RoleID)
	}
	if len(ids) == 0 {
		return map[id.RoleID]*role.Role{}, nil
	}
	found, err := deps.Engine.Store().GetRoles(ctx, tenantID, ids)
	if err != nil {
		return nil, mapWardenError(err)
	}
	byID := make(map[id.RoleID]*role.Role, len(found))
	for _, r := range found {
		byID[r.ID] = r
	}
	return byID, nil
}

func assignmentsListHandler(deps Deps) func(context.Context, AssignmentsListInput, dashcontract.Principal) (AssignmentsListResponse, error) {
	return func(ctx context.Context, in AssignmentsListInput, p dashcontract.Principal) (AssignmentsListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AssignmentsListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AssignmentsListResponse{}, err
		}
		limit, offset := in.Clamp()
		filter := &assignment.ListFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			SubjectKind:   in.SubjectKind,
			SubjectID:     in.SubjectID,
			ResourceType:  in.ResourceType,
			ResourceID:    in.ResourceID,
			Limit:         limit,
			Offset:        offset,
		}
		if in.RoleID != "" {
			rid, err := parseRoleID(in.RoleID)
			if err != nil {
				return AssignmentsListResponse{}, err
			}
			filter.RoleID = &rid
		}
		s := deps.Engine.Store()
		rows, err := s.ListAssignments(ctx, filter)
		if err != nil {
			return AssignmentsListResponse{}, mapWardenError(err)
		}
		total, err := s.CountAssignments(ctx, filter)
		if err != nil {
			return AssignmentsListResponse{}, mapWardenError(err)
		}
		byID, err := rolesByIDFor(ctx, deps, tenantID, rows)
		if err != nil {
			return AssignmentsListResponse{}, err
		}
		now := time.Now()
		out := AssignmentsListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]AssignmentSummary, 0, len(rows)),
		}
		for _, a := range rows {
			out.Items = append(out.Items, projectAssignment(a, byID[a.RoleID], now))
		}
		return out, nil
	}
}

func assignmentsCreateHandler(deps Deps) func(context.Context, AssignmentCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in AssignmentCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		if in.SubjectID == "" {
			return AckResponse{}, badRequest("an assignment needs a subject id")
		}
		if _, ok := validSubjectKinds[in.SubjectKind]; !ok {
			return AckResponse{}, badRequest(
				"subjectKind must be one of user, api_key, service, service_acct, got " + in.SubjectKind)
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		if err := validateResourceScope(in.ResourceType, in.ResourceID); err != nil {
			return AckResponse{}, err
		}
		rid, err := parseRoleID(in.RoleID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		r, err := s.GetRole(ctx, tenantID, rid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// NOTE: no guardSystemRole here, and that is deliberate.
		// extension/bootstrap.go creates a system role and assigns a
		// subject to it, so refusing assignments to system roles would
		// break first-run bootstrap from the dashboard. Assigning is a
		// membership change, not an edit of the role.
		now := time.Now()
		ctx = withActor(ctx, p)
		a := &assignment.Assignment{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			RoleID:        rid,
			SubjectKind:   in.SubjectKind,
			SubjectID:     in.SubjectID,
			ResourceType:  in.ResourceType,
			ResourceID:    in.ResourceID,
			GrantedBy:     actorFor(p).ID,
		}
		if in.ExpiresAt != "" {
			when, parseErr := time.Parse(time.RFC3339, in.ExpiresAt)
			if parseErr != nil {
				return AckResponse{}, badRequest("expiresAt must be an RFC3339 instant, got " + in.ExpiresAt)
			}
			if !when.After(now) {
				return AckResponse{}, badRequest("expiresAt is already in the past, so this assignment would grant nothing")
			}
			a.ExpiresAt = &when
		}
		// The cap goes LAST, after every input check, so a malformed request
		// against a full role reports what is actually wrong with it rather
		// than the cap. A subject who already holds the role is never
		// refused by the cap, so a duplicate binding reaches the store and
		// reports the duplicate.
		if err := guardMemberCap(ctx, s, tenantID, r, in.SubjectKind, in.SubjectID, now); err != nil {
			return AckResponse{}, err
		}
		if err := s.CreateAssignment(ctx, a); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// Same emissions as the REST handler (api/assignment_handler.go). The
		// audit event is what the cache invalidator listens to, so skipping
		// it would leave a stale DENY for the new holder until the cache
		// entry aged out.
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRoleAssigned(ctx, a)
		}
		emitAudit(ctx, deps, p, "assignment.created", tenantID, a.ID.String(), a, nil)
		return AckResponse{ID: a.ID.String()}, nil
	}
}

func assignmentsDeleteHandler(deps Deps) func(context.Context, AssignmentDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in AssignmentDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		aid, err := parseAssignmentID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		// Read first, so deleting another tenant's assignment is NOT_FOUND
		// rather than a silent no-op.
		before, err := s.GetAssignment(ctx, tenantID, aid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := s.DeleteAssignment(ctx, tenantID, aid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// The audit event is load-bearing here: the cache invalidator flushes
		// the tenant on it, and without the flush a revoked subject keeps an
		// ALLOW until the cached decision expires.
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitRoleUnassigned(ctx, before)
		}
		emitAudit(ctx, deps, p, "assignment.deleted", tenantID, aid.String(), nil, before)
		return AckResponse{}, nil
	}
}

func assignmentsExpiringHandler(deps Deps) func(context.Context, ExpiringInput, dashcontract.Principal) (ExpiringResponse, error) {
	return func(ctx context.Context, in ExpiringInput, p dashcontract.Principal) (ExpiringResponse, error) {
		if err := requireEngine(deps); err != nil {
			return ExpiringResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return ExpiringResponse{}, err
		}
		hours := in.WithinHours
		if hours <= 0 {
			hours = defaultExpiringWindowHours
		}
		// Clamp like PageRequest.Clamp, do not fall back to the default. The
		// store sorts ascending by expiry and includes rows that lapsed long
		// ago, so a small page can be filled entirely by old lapsed grants and
		// push every upcoming expiry off it. An oversized request gets the
		// most the contract allows, not less than it would have got at the cap.
		limit := in.Limit
		if limit <= 0 {
			limit = defaultPageLimit
		}
		if limit > maxPageLimit {
			limit = maxPageLimit
		}
		now := time.Now()
		before := now.Add(time.Duration(hours) * time.Hour)
		rows, err := deps.Engine.Store().ListExpiringAssignments(ctx, tenantID, before, limit)
		if err != nil {
			return ExpiringResponse{}, mapWardenError(err)
		}
		byID, err := rolesByIDFor(ctx, deps, tenantID, rows)
		if err != nil {
			return ExpiringResponse{}, err
		}
		out := ExpiringResponse{Items: make([]AssignmentSummary, 0, len(rows))}
		for _, a := range rows {
			out.Items = append(out.Items, projectAssignment(a, byID[a.RoleID], now))
		}
		return out, nil
	}
}
