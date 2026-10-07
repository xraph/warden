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
	if errors.Is(err, warden.ErrSystemRoleImmutable) || errors.Is(err, warden.ErrSystemPermissionImmutable) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrDuplicateAssignment) || errors.Is(err, warden.ErrDuplicateRelation) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, warden.ErrCyclicRoleInheritance) || errors.Is(err, warden.ErrMaxMembersExceeded) {
		return forge.BadRequest(err.Error())
	}
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
		errors.Is(err, warden.ErrResourceTypeNotFound)
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
