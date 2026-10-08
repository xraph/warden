package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

func TestMemory_PolicyRenameUniquenessContract(t *testing.T) {
	contract.RunPolicyRenameUniquenessContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
