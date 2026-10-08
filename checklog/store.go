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

	// GetCheckLog retrieves a check log entry by ID within a tenant. Returns
	// ErrCheckLogNotFound when the entry is not in the tenant.
	GetCheckLog(ctx context.Context, tenantID string, logID id.CheckLogID) (*Entry, error)

	// ListCheckLogs returns check log entries matching the filter.
	ListCheckLogs(ctx context.Context, filter *QueryFilter) ([]*Entry, error)

	// CountCheckLogs returns the number of entries matching the filter.
	CountCheckLogs(ctx context.Context, filter *QueryFilter) (int64, error)

	// PurgeCheckLogs removes check log entries older than the given time, in
	// every tenant.
	PurgeCheckLogs(ctx context.Context, before time.Time) (int64, error)

	// PurgeCheckLogsForTenant removes one tenant's check log entries older
	// than the given time and reports how many rows it removed. No other
	// tenant's entries are touched. An empty tenantID returns
	// wardenerr.ErrTenantRequired and deletes nothing; it never means every
	// tenant.
	PurgeCheckLogsForTenant(ctx context.Context, tenantID string, before time.Time) (int64, error)

	// DeleteCheckLogsBySubject removes a tenant's check logs for one subject
	// and reports how many rows it removed. Used to service erasure requests.
	DeleteCheckLogsBySubject(ctx context.Context, tenantID, subjectKind, subjectID string) (int64, error)

	// DeleteCheckLogsByTenant removes all check logs for a tenant.
	DeleteCheckLogsByTenant(ctx context.Context, tenantID string) error
}
