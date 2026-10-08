package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

func TestMemory_PolicyVersionContract(t *testing.T) {
	contract.RunPolicyVersionContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
