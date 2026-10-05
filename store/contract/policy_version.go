// policy_version.go: UpdatePolicyIfVersion writes only over the version the
// caller read, as one atomic step.
//
// Two editors who opened the same policy at version N both save with
// expected N. Exactly one of them may win; the other must get
// ErrPolicyVersionConflict and leave the stored policy exactly as the winner
// wrote it. A missing id or a foreign tenant is ErrPolicyNotFound, never a
// conflict, so a caller can tell "someone else changed it" from "it is not
// there".
package contract

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/wardenerr"
)

const versionTenant = "ver-tenant"

func versionedPolicy() *policy.Policy {
	return &policy.Policy{
		TenantID:      versionTenant,
		NamespacePath: "eng",
		Name:          "versioned",
		Description:   "as created",
		Effect:        policy.EffectAllow,
		Priority:      10,
		IsActive:      true,
		Version:       1,
		Actions:       []string{"document:read"},
		Resources:     []string{"document:*"},
	}
}

// edited is a copy of p carrying a new description and the version an
// update writes (the read version plus one).
func edited(p *policy.Policy, description string) *policy.Policy {
	c := *p
	c.Description = description
	c.Version = p.Version + 1
	return &c
}

// requireUnchanged fails unless got is the stored policy want was read as:
// every field, including both timestamps.
func requireUnchanged(t *testing.T, path string, want, got *policy.Policy) {
	t.Helper()
	if w, g := canonical(t, want), canonical(t, got); !reflect.DeepEqual(w, g) {
		t.Errorf("%s: stored policy changed\n want %#v\n  got %#v", path, w, g)
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("%s: UpdatedAt moved from %v to %v", path, want.UpdatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("%s: CreatedAt moved from %v to %v", path, want.CreatedAt, got.CreatedAt)
	}
}

// RunPolicyVersionContract proves UpdatePolicyIfVersion writes on a matching
// version, refuses a stale one without writing, tells not-found from stale,
// and lets exactly one of several racing writers win.
func RunPolicyVersionContract(t *testing.T, mk MakeStore) {
	setup := func(t *testing.T) (s policy.Store, created *policy.Policy, cleanup func()) {
		t.Helper()
		st, cleanup := mk(t)
		p := versionedPolicy()
		if err := st.CreatePolicy(context.Background(), p); err != nil {
			cleanup()
			t.Fatalf("CreatePolicy: %v", err)
		}
		got, err := st.GetPolicy(context.Background(), versionTenant, p.ID)
		if err != nil {
			cleanup()
			t.Fatalf("GetPolicy: %v", err)
		}
		if got.Version != 1 {
			cleanup()
			t.Fatalf("created policy is at version %d, want 1", got.Version)
		}
		return st, got, cleanup
	}

	t.Run("writes when the version matches", func(t *testing.T) {
		s, read, cleanup := setup(t)
		defer cleanup()
		ctx := context.Background()

		if err := s.UpdatePolicyIfVersion(ctx, edited(read, "edited once"), 1); err != nil {
			t.Fatalf("UpdatePolicyIfVersion: %v", err)
		}
		got, err := s.GetPolicy(ctx, versionTenant, read.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if got.Description != "edited once" || got.Version != 2 {
			t.Fatalf("read back description %q version %d, want %q version 2", got.Description, got.Version, "edited once")
		}
	})

	t.Run("refuses a stale version and writes nothing", func(t *testing.T) {
		s, read, cleanup := setup(t)
		defer cleanup()
		ctx := context.Background()

		if err := s.UpdatePolicyIfVersion(ctx, edited(read, "first editor"), 1); err != nil {
			t.Fatalf("first UpdatePolicyIfVersion: %v", err)
		}
		before, err := s.GetPolicy(ctx, versionTenant, read.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if before.Version != 2 {
			t.Fatalf("after the first write the version is %d, want 2", before.Version)
		}

		// The second editor still holds version 1.
		stale := edited(read, "second editor")
		staleUpdatedAt := stale.UpdatedAt
		err = s.UpdatePolicyIfVersion(ctx, stale, 1)
		if !errors.Is(err, wardenerr.ErrPolicyVersionConflict) {
			t.Fatalf("stale write: got %v, want ErrPolicyVersionConflict", err)
		}
		if !errors.Is(err, wardenerr.ErrStaleWrite) {
			t.Fatalf("stale write: %v does not match ErrStaleWrite", err)
		}
		if errors.Is(err, wardenerr.ErrNotFound) {
			t.Fatalf("stale write: %v also matches ErrNotFound", err)
		}
		if !stale.UpdatedAt.Equal(staleUpdatedAt) {
			t.Errorf("a refused write moved the caller's UpdatedAt from %v to %v", staleUpdatedAt, stale.UpdatedAt)
		}

		after, err := s.GetPolicy(ctx, versionTenant, read.ID)
		if err != nil {
			t.Fatalf("GetPolicy after refusal: %v", err)
		}
		requireUnchanged(t, "after a stale write", before, after)
	})

	t.Run("missing id is not found", func(t *testing.T) {
		s, read, cleanup := setup(t)
		defer cleanup()
		ctx := context.Background()

		ghost := edited(read, "ghost")
		ghost.ID = id.NewPolicyID()
		err := s.UpdatePolicyIfVersion(ctx, ghost, 1)
		if !errors.Is(err, wardenerr.ErrPolicyNotFound) {
			t.Fatalf("missing id: got %v, want ErrPolicyNotFound", err)
		}
		if errors.Is(err, wardenerr.ErrStaleWrite) {
			t.Fatalf("missing id: %v also matches ErrStaleWrite", err)
		}
		if _, err := s.GetPolicy(ctx, versionTenant, ghost.ID); !errors.Is(err, wardenerr.ErrPolicyNotFound) {
			t.Fatalf("missing id: a refused write created the policy (GetPolicy err %v)", err)
		}
	})

	t.Run("foreign tenant is not found", func(t *testing.T) {
		s, read, cleanup := setup(t)
		defer cleanup()
		ctx := context.Background()

		// The right id and the right version: only the tenant is wrong, so a
		// store that ignored the tenant would write.
		foreign := edited(read, "from another tenant")
		foreign.TenantID = "other-tenant"
		err := s.UpdatePolicyIfVersion(ctx, foreign, read.Version)
		if !errors.Is(err, wardenerr.ErrPolicyNotFound) {
			t.Fatalf("foreign tenant: got %v, want ErrPolicyNotFound", err)
		}
		if errors.Is(err, wardenerr.ErrStaleWrite) {
			t.Fatalf("foreign tenant: %v also matches ErrStaleWrite", err)
		}
		after, err := s.GetPolicy(ctx, versionTenant, read.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		requireUnchanged(t, "after a foreign-tenant write", read, after)
	})

	t.Run("one winner among racing writers", func(t *testing.T) {
		s, read, cleanup := setup(t)
		defer cleanup()
		ctx := context.Background()

		const writers = 8
		errs := make([]error, writers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				p := edited(read, fmt.Sprintf("writer %d", i))
				<-start
				errs[i] = s.UpdatePolicyIfVersion(ctx, p, read.Version)
			}(i)
		}
		close(start)
		wg.Wait()

		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if winner >= 0 {
					t.Errorf("writers %d and %d both won", winner, i)
				}
				winner = i
			case errors.Is(err, wardenerr.ErrPolicyVersionConflict):
			default:
				t.Errorf("writer %d: got %v, want nil or ErrPolicyVersionConflict", i, err)
			}
		}
		if winner < 0 {
			t.Fatalf("no writer won: %v", errs)
		}

		got, err := s.GetPolicy(ctx, versionTenant, read.ID)
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if want := fmt.Sprintf("writer %d", winner); got.Description != want {
			t.Fatalf("stored description %q, want the winner's %q", got.Description, want)
		}
		if got.Version != read.Version+1 {
			t.Fatalf("stored version %d, want %d", got.Version, read.Version+1)
		}
	})
}
