package api

import (
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
)

// scopeFromForgeContext extracts appID and tenantID from a forge.Context
// using the warden scope resolution chain.
func scopeFromForgeContext(ctx forge.Context) (appID, tenantID string) {
	return warden.ScopeFromContext(ctx.Context())
}

// mapError maps domain errors to Forge HTTP errors.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return forge.NotFound(err.Error())
	}
	var capErr *assignment.CapBelowMembersError
	if errors.As(err, &capErr) {
		return forge.NewHTTPError(http.StatusConflict, capErr.Error())
	}
	var fullErr *assignment.RoleFullError
	if errors.As(err, &fullErr) {
		return forge.NewHTTPError(http.StatusConflict, fullErr.Error())
	}
	// A conditional write found the record at another version than the one
	// the handler read: another write landed in between, and nothing was
	// written here.
	if errors.Is(err, warden.ErrStaleWrite) {
		return forge.NewHTTPError(http.StatusConflict, staleWriteMessage(err))
	}
	// A permission delete while roles still grant it: the refusal names
	// them. The dashboard returns CONFLICT with the same text.
	var granted *role.PermissionGrantedError
	if errors.As(err, &granted) {
		return forge.NewHTTPError(http.StatusConflict, granted.Error())
	}
	// Every duplicate (role, permission, policy, resource type, assignment,
	// relation tuple) wraps ErrAlreadyExists and nothing else does. The
	// message is the store's, which names the entity and its scope.
	if errors.Is(err, warden.ErrAlreadyExists) {
		return forge.NewHTTPError(http.StatusConflict, err.Error())
	}
	// A system role or permission cannot be changed by any request, so
	// this is 403 rather than 400: the caller cannot fix it by changing
	// what it sent. The dashboard returns PERMISSION_DENIED for the same
	// refusal, with the same message.
	if errors.Is(err, warden.ErrSystemRoleImmutable) || errors.Is(err, warden.ErrSystemPermissionImmutable) {
		return forge.Forbidden(err.Error())
	}
	// A parent that would make a role its own ancestor, or one that does
	// not exist in the role's namespace: the caller can pick another.
	// Nothing on REST raises ErrMaxMembersExceeded today (a full role is
	// assignment.RoleFullError, 409 above); the branch stays as a defence
	// should a store or plugin start returning it.
	var missingParent *role.ParentNotFoundError
	if errors.Is(err, warden.ErrCyclicRoleInheritance) || errors.As(err, &missingParent) ||
		errors.Is(err, warden.ErrMaxMembersExceeded) {
		return forge.BadRequest(err.Error())
	}
	// A tuple its resource type does not declare: the caller can fix the
	// request, and the refusal names the tuple, the resource type and what
	// it allows.
	var undeclared *resourcetype.UndeclaredTupleError
	if errors.As(err, &undeclared) {
		return forge.BadRequest(undeclared.Error())
	}
	// Nothing on REST raises ErrInvalidCondition today: only the evaluator
	// returns it, and the evaluator handles it itself (a deny policy still
	// applies, an allow policy is skipped). The branch stays as a defence.
	if errors.Is(err, warden.ErrInvalidCondition) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrAccessDenied) {
		return forge.Forbidden(err.Error())
	}
	return err
}

// staleWriteMessage names no writer: the change may have come from another
// REST call, the dashboard or a DSL apply.
func staleWriteMessage(err error) string {
	if errors.Is(err, warden.ErrPolicyVersionConflict) {
		return "the policy changed after this request read it, so nothing was written; read it again and retry"
	}
	return "the record changed after this request read it, so nothing was written; read it again and retry"
}

func isNotFound(err error) bool {
	return errors.Is(err, warden.ErrRoleNotFound) ||
		errors.Is(err, warden.ErrPermissionNotFound) ||
		errors.Is(err, warden.ErrAssignmentNotFound) ||
		errors.Is(err, warden.ErrPolicyNotFound) ||
		errors.Is(err, warden.ErrRelationNotFound) ||
		errors.Is(err, warden.ErrResourceTypeNotFound) ||
		isGrantNotHeld(err)
}

// isGrantNotHeld reports a detach of a grant the role does not hold, which
// the dashboard answers with NOT_FOUND.
func isGrantNotHeld(err error) bool {
	var notHeld *role.GrantNotHeldError
	return errors.As(err, &notHeld)
}

func defaultLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

// tenantReasonPattern matches the "in tenant "<id>"" fragment the engine
// appends to some deny reasons (see engine.go's DecisionDenyNoRoles path).
// sanitizeReason strips it before a Reason string goes out over HTTP so a
// caller without read access to the tenant catalog can't fingerprint
// tenant IDs from check responses.
var tenantReasonPattern = regexp.MustCompile(`\s*in tenant "[^"]*"`)

// sanitizeReason strips tenant-identifying fragments from a CheckResult
// reason string before it's returned to an HTTP caller.
func sanitizeReason(reason string) string {
	return strings.TrimSpace(tenantReasonPattern.ReplaceAllString(reason, ""))
}

// validSubjectKinds are the only subject kinds an actor-binding write
// (role assignment) may name. Relation tuples are intentionally excluded:
// their subject_type is a Zanzibar-style resource type (e.g. "group",
// "folder"), not a warden.SubjectKind, so constraining it here would
// break ordinary ReBAC usage.
var validSubjectKinds = map[string]struct{}{
	string(warden.SubjectUser):        {},
	string(warden.SubjectAPIKey):      {},
	string(warden.SubjectService):     {},
	string(warden.SubjectServiceAcct): {},
}

// validSubjectKind reports whether kind is one of the four subject kinds
// the engine recognizes.
func validSubjectKind(kind string) bool {
	_, ok := validSubjectKinds[kind]
	return ok
}

// requestIP extracts the caller's IP from the first hop of
// X-Forwarded-For, falling back to the connection's remote address.
func requestIP(ctx forge.Context) string {
	if xff := ctx.Header("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	req := ctx.Request()
	if req == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}
