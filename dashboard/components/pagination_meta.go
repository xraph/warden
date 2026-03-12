package components

// PaginationMeta holds pagination metadata for list pages.
type PaginationMeta struct {
	Total       int64
	Limit       int
	Offset      int
	CurrentPage int
	TotalPages  int
}

// NewPaginationMeta creates pagination metadata from total count, limit, and offset.
func NewPaginationMeta(total int64, limit, offset int) PaginationMeta {
	if limit <= 0 {
		limit = 20
	}
	totalPages := int(total) / limit
	if int(total)%limit != 0 {
		totalPages++
	}
	if totalPages == 0 {
		totalPages = 1
	}
	currentPage := (offset / limit) + 1
	return PaginationMeta{
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		CurrentPage: currentPage,
		TotalPages:  totalPages,
	}
}
