package warden

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidateNamespacePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		max     int
		wantErr bool
		errSub  string
	}{
		{"empty is root", "", 8, false, ""},
		{"single segment", "engineering", 8, false, ""},
		{"two segments", "engineering/platform", 8, false, ""},
		{"deep but legal", "a/b/c/d/e/f/g/h", 8, false, ""},
		{"over depth", "a/b/c/d/e/f/g/h/i", 8, true, "exceeds max depth"},
		{"depth uses default 8 when 0", "a/b/c/d/e/f/g/h", 0, false, ""},
		{"leading slash forbidden", "/eng", 8, true, "must not start"},
		{"trailing slash forbidden", "eng/", 8, true, "must not start or end"},
		{"empty segment forbidden", "eng//platform", 8, true, "empty segments"},
		{"uppercase forbidden", "Eng", 8, true, "is not valid"},
		{"underscore forbidden", "eng_team", 8, true, "is not valid"},
		{"starts with digit forbidden", "1eng", 8, true, "is not valid"},
		{"hyphen ok", "platform-eng", 8, false, ""},
		{"system reserved", "engineering/system", 8, true, "is reserved"},
		{"admin reserved at root", "admin", 8, true, "is reserved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNamespacePath(tt.path, tt.max)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateNamespacePath(%q, %d) err=%v, wantErr=%v", tt.path, tt.max, err, tt.wantErr)
			}
			if tt.wantErr && tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.errSub)
			}
		})
	}
}

func TestAncestorNamespaces(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"", []string{""}},
		{"eng", []string{"eng", ""}},
		{"eng/platform", []string{"eng/platform", "eng", ""}},
		{"eng/platform/sre", []string{"eng/platform/sre", "eng/platform", "eng", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := AncestorNamespaces(tt.path)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("AncestorNamespaces(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsAncestorOrSelf(t *testing.T) {
	tests := []struct {
		ancestor string
		path     string
		want     bool
	}{
		{"", "", true},
		{"", "eng", true},
		{"eng", "eng", true},
		{"eng", "eng/platform", true},
		{"eng", "eng/platform/sre", true},
		{"eng", "billing", false},
		{"eng/platform", "eng", false},
		{"eng/plat", "eng/platform", false}, // prefix string but not ancestor segment
	}
	for _, tt := range tests {
		t.Run(tt.ancestor+"|"+tt.path, func(t *testing.T) {
			if got := IsAncestorOrSelf(tt.ancestor, tt.path); got != tt.want {
				t.Fatalf("IsAncestorOrSelf(%q, %q) = %v, want %v", tt.ancestor, tt.path, got, tt.want)
			}
		})
	}
}

func TestJoinNamespace(t *testing.T) {
	tests := []struct {
		parent string
		child  string
		want   string
	}{
		{"", "", ""},
		{"eng", "", "eng"},
		{"", "platform", "platform"},
		{"eng", "platform", "eng/platform"},
		{"eng/team", "alpha", "eng/team/alpha"},
	}
	for _, tt := range tests {
		t.Run(tt.parent+"+"+tt.child, func(t *testing.T) {
			if got := JoinNamespace(tt.parent, tt.child); got != tt.want {
				t.Fatalf("JoinNamespace(%q, %q) = %q, want %q", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}
