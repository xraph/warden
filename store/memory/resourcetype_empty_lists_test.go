package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

func TestMemory_ResourceTypeEmptyListsContract(t *testing.T) {
	contract.RunResourceTypeEmptyListsContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
