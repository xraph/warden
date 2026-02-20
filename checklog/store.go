package checklog

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
)

// Store defines persistence operations for check audit logs.
type Store interface {
	// CreateCheckLog persists a new check log entry.
	CreateCheckLog(ctx context.Context, e *Entry) error

	// GetCheckLog retrieves a check log entry by ID.
	GetCheckLog(ctx context.Context, logID id.CheckLogID) (*Entry, error)

	// ListCheckLogs returns check log entries matching the filter.
	ListCheckLogs(ctx context.Context, filter *QueryFilter) ([]*Entry, error)

	// CountCheckLogs returns the number of entries matching the filter.
	CountCheckLogs(ctx context.Context, filter *QueryFilter) (int64, error)

	// PurgeCheckLogs removes check log entries older than the given time.
	PurgeCheckLogs(ctx context.Context, before time.Time) (int64, error)

	// DeleteCheckLogsByTenant removes all check logs for a tenant.
	DeleteCheckLogsByTenant(ctx context.Context, tenantID string) error
}
