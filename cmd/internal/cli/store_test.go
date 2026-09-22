package cli

import (
	"strings"
	"testing"
)

// TestRedactDSN checks that a DSN's password never survives into the
// redacted form, since redactDSN is what stands between a postgres
// connection string and stderr, CI logs, and pasted bug reports.
func TestRedactDSN(t *testing.T) {
	tests := []struct {
		name       string
		dsn        string
		wantSecret string // must NOT appear in the output
	}{
		{
			name:       "postgres DSN with password",
			dsn:        "postgres://admin:s3cr3t-pw@localhost:5432/warden_admin?sslmode=disable",
			wantSecret: "s3cr3t-pw",
		},
		{
			name:       "postgresql scheme with password",
			dsn:        "postgresql://svc:hunter2@db.internal:5432/warden",
			wantSecret: "hunter2",
		},
		{
			name:       "sqlite DSN has no credentials to leak",
			dsn:        "sqlite:/var/lib/warden/warden.db",
			wantSecret: "",
		},
		{
			name:       "memory DSN has no credentials to leak",
			dsn:        "memory:",
			wantSecret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactDSN(tt.dsn)
			if tt.wantSecret != "" && strings.Contains(got, tt.wantSecret) {
				t.Errorf("redactDSN(%q) = %q, leaked secret %q", tt.dsn, got, tt.wantSecret)
			}
		})
	}
}

// TestRedactDSN_Unparseable checks that a DSN that fails url.Parse still
// comes back as a fixed placeholder rather than echoed verbatim. We can't
// prove an unparseable string has no password hiding in it, so the safe
// default is to withhold it entirely.
func TestRedactDSN_Unparseable(t *testing.T) {
	// A raw control character makes url.Parse fail.
	dsn := "postgres://user:pass@host/db\x7f"
	got := redactDSN(dsn)
	if got != "<redacted DSN>" {
		t.Errorf("redactDSN(unparseable) = %q, want the fixed placeholder", got)
	}
}
