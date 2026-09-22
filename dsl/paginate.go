package dsl

import "errors"

// The Postgres and SQLite backends cap a List* query at 1000 rows when the
// caller leaves ListFilter.Limit at zero. The DSL exporter and applier both
// need the whole tenant, not the first page, so they page explicitly through
// the helper below instead of relying on whatever a backend does with an
// unset limit.

// listPageSize is the Limit each page request carries. It sits below the SQL
// backends' 1000-row default so a page is always a deliberate request rather
// than a backend fallback.
const listPageSize = 500

// maxCollectedRows bounds a single accumulation. A tenant this large is
// beyond what a whole-tenant export or prune can hold in memory, and a
// backend that ignores Offset would otherwise loop forever.
const maxCollectedRows = 200_000

// errListTooLarge is returned when an accumulation exceeds maxCollectedRows.
var errListTooLarge = errors.New("warden dsl: result set too large to collect; narrow the namespace filter")

// collectPages calls fetch with an increasing offset until a page comes back
// shorter than the page size, accumulating every row.
//
// Paging by offset assumes each page is ordered consistently. The SQL
// backends order by created_at, so rows sharing a timestamp can in principle
// shift between pages; callers that need exactness should prefer a narrower
// filter over a whole-tenant scan.
func collectPages[T any](fetch func(limit, offset int) ([]T, error)) ([]T, error) {
	var all []T
	for offset := 0; ; offset += listPageSize {
		page, err := fetch(listPageSize, offset)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < listPageSize {
			return all, nil
		}
		if len(all) >= maxCollectedRows {
			return nil, errListTooLarge
		}
	}
}
