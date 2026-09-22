package warden

import "strings"

// matchGlob checks if a pattern matches a value with simple glob support.
//
// A trailing '*' is only treated as a wildcard when it stands for an
// entire colon- or dot-separated segment ("document:*", "doc.*") or when
// the pattern has no separator at all ("prefix*"). A pattern like
// "document:1*" is NOT a prefix match against "document:1999" — the
// segment after the colon is "1*", not "*", so no wildcard expansion
// happens and the pattern simply fails to match. This keeps an
// administrator from accidentally writing a policy resource/action glob
// that silently matches far more than intended.
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// Full wildcards: "*:*" and "*.*" match everything (any resource:action).
	if pattern == "*:*" || pattern == "*.*" {
		return true
	}
	if pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasSuffix(pattern, "*") {
		// A bare trailing '*' that is not the whole of a ':'/'.' segment
		// only wildcards when the pattern has no segment separator at all.
		if strings.ContainsAny(pattern, ":.") {
			return false
		}
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return false
}

// matchPermission checks if a permission name matches a required permission.
// Permission format: "resource:action" (e.g., "document:read").
// Supports wildcards: "document:*" matches "document:read".
func matchPermission(permName, required string) bool {
	if permName == required {
		return true
	}
	return matchGlob(permName, required)
}
