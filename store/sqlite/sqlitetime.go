package sqlite

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// sqliteTime is a model-layer wrapper around time.Time that knows how to
// round-trip through SQLite's TEXT-typed timestamp columns.
//
// The underlying driver (modernc.org/sqlite or similar) returns TEXT
// columns as strings, so a plain time.Time field would fail with
// "unsupported Scan, storing driver.Value type string into type *time.Time"
// during result mapping. This wrapper accepts both string and time.Time
// inputs on Scan, and emits RFC3339 on insert/update via Value.
type sqliteTime time.Time

// Common formats SQLite produces. RFC3339 covers values written by grove's
// SqliteDialect.AppendTime; the others handle DEFAULT (datetime('now'))
// columns and legacy data.
var sqliteTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// Scan implements sql.Scanner.
func (t *sqliteTime) Scan(src any) error {
	if src == nil {
		*t = sqliteTime(time.Time{})
		return nil
	}
	switch v := src.(type) {
	case time.Time:
		*t = sqliteTime(v)
		return nil
	case string:
		return t.scanString(v)
	case []byte:
		return t.scanString(string(v))
	default:
		return fmt.Errorf("sqlite: cannot scan %T into time.Time", src)
	}
}

func (t *sqliteTime) scanString(s string) error {
	if s == "" {
		*t = sqliteTime(time.Time{})
		return nil
	}
	for _, layout := range sqliteTimeLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			*t = sqliteTime(parsed)
			return nil
		}
	}
	return fmt.Errorf("sqlite: cannot parse %q as time (tried %d layouts)", s, len(sqliteTimeLayouts))
}

// Value implements driver.Valuer. We always emit RFC3339 with nanosecond
// precision so reads round-trip cleanly through scanString above.
func (t sqliteTime) Value() (driver.Value, error) {
	zero := time.Time{}
	gt := time.Time(t)
	if gt.Equal(zero) {
		// Empty time.Time → SQLite NULL.
		return nil, nil
	}
	return gt.UTC().Format(time.RFC3339Nano), nil
}

// Time returns the underlying time.Time for caller convenience.
func (t sqliteTime) Time() time.Time { return time.Time(t) }
