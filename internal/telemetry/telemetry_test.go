package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/xraph/warden/wardenerr"
)

func TestErrorType(t *testing.T) {
	opErr := &net.OpError{Op: "dial", Err: errors.New("connection refused to alice@example.com")}
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"sentinel":         {wardenerr.ErrTenantRequired, "warden.ErrTenantRequired"},
		"wrapped family":   {fmt.Errorf("get: %w", wardenerr.ErrRoleNotFound), "warden.ErrNotFound"},
		"deadline":         {fmt.Errorf("query: %w", context.DeadlineExceeded), "context.DeadlineExceeded"},
		"innermost type":   {fmt.Errorf("warden rbac: %w", fmt.Errorf("list roles: %w", opErr)), "*errors.errorString"},
		"unwrapped struct": {opErr, "*errors.errorString"},
		"plain":            {errors.New("boom"), "*errors.errorString"},
		"no unwrap":        {&net.DNSError{Err: "no such host", Name: "db.internal"}, "*net.DNSError"},
	} {
		if got := ErrorType(tc.err); got != tc.want {
			t.Errorf("%s: ErrorType = %q, want %q", name, got, tc.want)
		}
	}
}
