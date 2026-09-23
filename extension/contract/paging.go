// paging.go: the one paging shape every list intent in this contract uses.
//
// Warden's stores all expose ListX(filter) plus CountX(filter) with Limit
// and Offset, and none of them offers a cursor. So this contract pages by
// offset everywhere, and there is no second convention to translate
// between.
package contract

// defaultPageLimit is what a request with no limit gets.
//
// It is not zero for a reason that is easy to miss: every store ListFilter
// treats Limit 0 as "no limit", so passing an unset limit straight through
// would load the whole table and call it a page.
const defaultPageLimit = 25

// maxPageLimit caps what one request can ask for, so a client cannot turn a
// paged list back into a full table scan by asking for a million rows.
const maxPageLimit = 200

// PageRequest is embedded in every list intent's input.
type PageRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// Clamp returns a limit and offset safe to hand to a store filter. An unset
// or non-positive limit becomes the default, an oversized one is capped, and
// a negative offset becomes zero rather than reaching SQL as OFFSET -1.
func (p PageRequest) Clamp() (limit, offset int) {
	limit = p.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	offset = p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// PageMeta is embedded in every list intent's response, beside its items.
//
// Total is the count matching the filter rather than the number of rows
// returned, which is what a pager needs to know how many pages exist. Limit
// and Offset are echoed back as clamped, so a client that asked for a
// million rows can see what it actually got.
type PageMeta struct {
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// newPageMeta pairs a count with the clamped request that produced it.
func newPageMeta(total int64, limit, offset int) PageMeta {
	return PageMeta{Total: total, Limit: limit, Offset: offset}
}
