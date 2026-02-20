package warden

import "strings"

// matchGlob checks if a pattern matches a value with simple glob support.
// Supports trailing '*' (e.g., "document:*" matches "document:read").
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
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
