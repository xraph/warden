package dsl

import (
	"fmt"
	"strings"
)

// Identifier conventions.
//
// A name is valid in source when the store and the dashboard contract
// would accept it, so that anything a tenant holds can be exported and
// applied back. The contract's create validation asks only that a name is
// not empty (a role slug, a resource type name, a policy name after
// trimming), and that a permission has a resource and an action. Names a
// bare identifier cannot spell (a keyword, a leading digit, a space, a
// colon such as `warden:role`, a glob such as `*`) are written as string
// literals; Format quotes them.
//
// Namespace paths keep their own rule (warden.ValidateNamespacePath), which
// the contract applies too.

// validSlug reports whether s can be a role slug.
func validSlug(s string) bool { return s != "" }

// validPolicyName reports whether s can be a policy name. The contract
// trims a policy name before it checks and stores it, so a name that is
// only whitespace is empty.
func validPolicyName(s string) bool { return strings.TrimSpace(s) != "" }

// validResourceTypeName reports whether s can be a resource type name.
func validResourceTypeName(s string) bool { return s != "" }

// validPermission reports whether a permission names a resource and an
// action. The name itself is free text: the contract derives it as
// `<resource>:<action>`, and the store keys on it, so `warden:role:read`
// (resource `warden:role`) and `warden:*` are both valid.
func validPermission(p *PermissionDecl) bool {
	return p.Name != "" && p.Resource != "" && p.Action != ""
}

// formatf is a thin wrapper used by resolver/checker error messages.
func formatf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
