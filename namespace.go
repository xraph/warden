package warden

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxNamespaceDepth is the default cap on namespace nesting. Practical
// organizations don't go deeper than this; the cap keeps walking-cost
// predictable. Configurable via Config.MaxNamespaceDepth.
const MaxNamespaceDepth = 8

// namespaceSegmentRegex matches a single namespace segment: lowercase,
// kebab-allowed, must start with a letter, max 63 chars.
var namespaceSegmentRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// reservedNamespaceSegments cannot appear in user-supplied namespace paths.
// These are reserved for warden's own use.
var reservedNamespaceSegments = map[string]struct{}{
	"system": {},
	"admin":  {},
}

// ValidateNamespacePath checks that a path is well-formed.
// Empty string (the tenant root) is always valid. Otherwise the path is
// "/"-separated, each segment matches namespaceSegmentRegex, no reserved
// segment appears, and depth ≤ maxDepth (or MaxNamespaceDepth if 0).
func ValidateNamespacePath(path string, maxDepth int) error {
	if path == "" {
		return nil
	}
	if maxDepth <= 0 {
		maxDepth = MaxNamespaceDepth
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return fmt.Errorf("warden: namespace path %q must not start or end with /", path)
	}
	if strings.Contains(path, "//") {
		return fmt.Errorf("warden: namespace path %q must not contain empty segments", path)
	}
	segments := strings.Split(path, "/")
	if len(segments) > maxDepth {
		return fmt.Errorf("warden: namespace path %q exceeds max depth %d (got %d)", path, maxDepth, len(segments))
	}
	for _, seg := range segments {
		if !namespaceSegmentRegex.MatchString(seg) {
			return fmt.Errorf("warden: namespace segment %q is not valid (must match %s)", seg, namespaceSegmentRegex.String())
		}
		if _, reserved := reservedNamespaceSegments[seg]; reserved {
			return fmt.Errorf("warden: namespace segment %q is reserved", seg)
		}
	}
	return nil
}

// AncestorNamespaces returns the path itself and every ancestor up to the
// tenant root, ordered from most-specific to most-general. The tenant root
// (empty string) is always the last element.
//
// Examples:
//
//	AncestorNamespaces("")                   → [""]
//	AncestorNamespaces("eng")                → ["eng", ""]
//	AncestorNamespaces("eng/platform")       → ["eng/platform", "eng", ""]
//	AncestorNamespaces("eng/platform/sre")   → ["eng/platform/sre", "eng/platform", "eng", ""]
//
// Used by the engine to resolve roles, permissions, policies, and resource
// types across the namespace ancestor chain (cascading scope inheritance).
func AncestorNamespaces(path string) []string {
	if path == "" {
		return []string{""}
	}
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments)+1)
	for i := len(segments); i > 0; i-- {
		out = append(out, strings.Join(segments[:i], "/"))
	}
	out = append(out, "")
	return out
}

// IsAncestorOrSelf reports whether ancestor is path itself or a strict
// ancestor of path. Both must be valid namespace paths (or empty string).
func IsAncestorOrSelf(ancestor, path string) bool {
	if ancestor == "" {
		return true
	}
	if ancestor == path {
		return true
	}
	return strings.HasPrefix(path, ancestor+"/")
}

// JoinNamespace concatenates two namespace paths with a "/" separator,
// dropping empties on either side. Used by the DSL parser to build absolute
// paths from nested namespace blocks.
func JoinNamespace(parent, child string) string {
	switch {
	case parent == "" && child == "":
		return ""
	case parent == "":
		return child
	case child == "":
		return parent
	default:
		return parent + "/" + child
	}
}
