package dsl

import (
	"fmt"
	"regexp"
)

// Identifier convention regexes (per spec B.6 in WARDEN-DESIGN).

// slugRegex matches a kebab-case role slug or policy name: starts with a
// lowercase letter, then up to 62 chars of [a-z0-9-].
var slugRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// permNameRegex matches a permission name as `<resource>:<action>` where
// action may include `*` for globbing.
var permNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z0-9_*-]+$`)

// rtNameRegex matches a resource type name: snake_case, starts with a letter.
var rtNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// formatf is a thin wrapper used by resolver/checker error messages.
func formatf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
