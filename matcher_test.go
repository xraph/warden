package warden

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// Bare wildcard.
		{"bare wildcard matches anything", "*", "settings:manage", true},
		{"bare wildcard matches empty", "*", "", true},

		// Full wildcards: *:* and *.*
		{"*:* matches resource:action", "*:*", "settings:manage", true},
		{"*:* matches any resource:action", "*:*", "document:read", true},
		{"*.* matches resource.action", "*.*", "settings.manage", true},
		{"*.* matches any resource.action", "*.*", "document.read", true},

		// Colon-separated resource wildcard: "resource:*"
		{"resource:* matches same resource", "document:*", "document:read", true},
		{"resource:* matches different action", "document:*", "document:write", true},
		{"resource:* rejects different resource", "document:*", "settings:read", false},

		// Dot-separated resource wildcard: "resource.*"
		{"resource.* matches same resource", "doc.*", "doc.read", true},
		{"resource.* rejects different resource", "doc.*", "settings.read", false},

		// Trailing wildcard.
		{"trailing * matches prefix", "prefix*", "prefixsuffix", true},
		{"trailing * rejects non-prefix", "prefix*", "other", false},

		// Exact match.
		{"exact match", "settings:manage", "settings:manage", true},
		{"exact mismatch", "settings:manage", "settings:read", false},

		// No match.
		{"no pattern match", "document:read", "settings:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		name     string
		permName string
		required string
		want     bool
	}{
		{"exact match", "settings:manage", "settings:manage", true},
		{"wildcard via matchGlob", "*:*", "settings:manage", true},
		{"resource wildcard via matchGlob", "settings:*", "settings:manage", true},
		{"mismatch", "document:read", "settings:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPermission(tt.permName, tt.required)
			if got != tt.want {
				t.Errorf("matchPermission(%q, %q) = %v, want %v", tt.permName, tt.required, got, tt.want)
			}
		})
	}
}
