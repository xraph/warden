package permission

import (
	"fmt"
	"strings"
)

// ActionColonError refuses a permission action that contains ':'.
//
// The engine checks a role's grant by joining the permission's resource and
// action with ':' into one string, and compares that with the request's
// resource and action joined the same way. An action with a ':' would make
// (warden, role:manage) and (warden:role, manage) the same grant. A resource
// may contain ':' (warden:role); only the action may not.
type ActionColonError struct {
	Action string
}

func (e *ActionColonError) Error() string {
	return fmt.Sprintf("action %q contains ':': the engine joins resource and action with ':', so an action may not contain one", e.Action)
}

// CheckAction refuses an action that contains ':' with an
// *ActionColonError. Every write path that creates a permission, or sets a
// new action on one, calls it before writing. Stores do not: a permission
// already stored with ':' in its action still loads, checks and deletes.
func CheckAction(action string) error {
	if strings.Contains(action, ":") {
		return &ActionColonError{Action: action}
	}
	return nil
}
