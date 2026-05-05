package postgres

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// isUniqueViolation reports whether err is a postgres unique_violation
// (SQLSTATE 23505). Used by the Create* methods to map index/constraint
// violations to the typed warden duplicate sentinels.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// jsonbSlice is a generic JSONB-backed slice for PostgreSQL. It implements
// database/sql/driver.Valuer and sql.Scanner for transparent serialization
// to/from PostgreSQL jsonb columns.
type jsonbSlice[T any] []T

// Value marshals the slice to JSON for storage.
func (s jsonbSlice[T]) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	b, err := json.Marshal([]T(s))
	if err != nil {
		return nil, fmt.Errorf("postgres: jsonbSlice.Value: %w", err)
	}
	return b, nil
}

// Scan unmarshals JSON data from the database into the slice. Accepts []byte
// or string source values.
func (s *jsonbSlice[T]) Scan(src any) error {
	if src == nil {
		*s = nil
		return nil
	}

	var data []byte
	switch v := src.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("postgres: jsonbSlice.Scan: unsupported type %T", src)
	}

	var result []T
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("postgres: jsonbSlice.Scan: %w", err)
	}
	*s = jsonbSlice[T](result)
	return nil
}
