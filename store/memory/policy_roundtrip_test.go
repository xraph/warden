package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

func TestMemory_PolicyRoundTripContract(t *testing.T) {
	contract.RunPolicyRoundTripContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
