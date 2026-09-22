package memory

import (
	"testing"

	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMemory_LikeEscapeContract runs the shared LIKE-escaping contract
// against the in-memory store. The in-memory Search filter uses
// strings.Contains, which is literal by construction, so this mainly
// guards against a future switch to a pattern-matching implementation
// that reintroduces the bug the SQL backends have to escape around.
func TestMemory_LikeEscapeContract(t *testing.T) {
	contract.RunLikeEscapeContract(t, func(_ *testing.T) (store.Store, func()) {
		return New(), func() {}
	})
}
