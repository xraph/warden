package contract

import "testing"

func TestPageRequestClampDefaultsAnUnsetLimit(t *testing.T) {
	// A list intent called with no limit must not return the whole table.
	// Every store ListFilter treats Limit 0 as "no limit", so an unset
	// limit here would page nothing and load everything.
	limit, offset := PageRequest{}.Clamp()
	if limit != defaultPageLimit {
		t.Errorf("limit = %d, want the default %d", limit, defaultPageLimit)
	}
	if offset != 0 {
		t.Errorf("offset = %d, want 0", offset)
	}
}

func TestPageRequestClampCapsAnOversizedLimit(t *testing.T) {
	limit, _ := PageRequest{Limit: 100000}.Clamp()
	if limit != maxPageLimit {
		t.Errorf("limit = %d, want the cap %d", limit, maxPageLimit)
	}
}

func TestPageRequestClampRejectsANegativeOffset(t *testing.T) {
	// A negative offset reaches SQL as OFFSET -1, which errors on some
	// backends and is ignored on others. Neither is a page of results.
	_, offset := PageRequest{Offset: -5}.Clamp()
	if offset != 0 {
		t.Errorf("offset = %d, want 0", offset)
	}
}

func TestPageRequestClampKeepsAValidRequest(t *testing.T) {
	limit, offset := PageRequest{Limit: 25, Offset: 50}.Clamp()
	if limit != 25 || offset != 50 {
		t.Errorf("clamp altered a valid request: limit %d offset %d", limit, offset)
	}
}
