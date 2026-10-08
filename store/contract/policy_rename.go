// policy_rename.go: renaming a policy onto a name another policy holds in the
// same tenant and namespace is a duplicate, whichever update call carries the
// rename.
//
// Create refuses a taken (tenant, namespace, name) with ErrDuplicatePolicy.
// Update and UpdatePolicyIfVersion must refuse it the same way and write
// nothing, on every backend. A policy keeping its own name, or taking a name
// another namespace holds, is not a duplicate.
package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/wardenerr"
)

// RunPolicyRenameUniquenessContract proves both update calls refuse a rename
// onto a taken name with ErrDuplicatePolicy, leave the stored policy as it
// was, and accept the renames that are not duplicates.
func RunPolicyRenameUniquenessContract(t *testing.T, mk MakeStore) {
	named := func(ns, name string) *policy.Policy {
		p := versionedPolicy()
		p.NamespacePath = ns
		p.Name = name
		return p
	}

	// each update call under test: how it writes p over a policy read at
	// version read.Version.
	calls := []struct {
		name  string
		write func(ctx context.Context, s policy.Store, p *policy.Policy, readVersion int) error
	}{
		{"UpdatePolicy", func(ctx context.Context, s policy.Store, p *policy.Policy, _ int) error {
			return s.UpdatePolicy(ctx, p)
		}},
		{"UpdatePolicyIfVersion", func(ctx context.Context, s policy.Store, p *policy.Policy, readVersion int) error {
			return s.UpdatePolicyIfVersion(ctx, p, readVersion)
		}},
	}

	for _, call := range calls {
		t.Run(call.name, func(t *testing.T) {
			setup := func(t *testing.T) (s policy.Store, a, b *policy.Policy, cleanup func()) {
				t.Helper()
				st, cleanup := mk(t)
				ctx := context.Background()
				pa, pb := named("eng", "alpha"), named("eng", "beta")
				for _, p := range []*policy.Policy{pa, pb} {
					if err := st.CreatePolicy(ctx, p); err != nil {
						cleanup()
						t.Fatalf("CreatePolicy %q: %v", p.Name, err)
					}
				}
				ga, err := st.GetPolicy(ctx, versionTenant, pa.ID)
				if err != nil {
					cleanup()
					t.Fatalf("GetPolicy: %v", err)
				}
				gb, err := st.GetPolicy(ctx, versionTenant, pb.ID)
				if err != nil {
					cleanup()
					t.Fatalf("GetPolicy: %v", err)
				}
				return st, ga, gb, cleanup
			}

			t.Run("rename onto a taken name is a duplicate and writes nothing", func(t *testing.T) {
				s, a, b, cleanup := setup(t)
				defer cleanup()
				ctx := context.Background()

				attempt := edited(b, "renamed")
				attempt.Name = a.Name
				err := call.write(ctx, s, attempt, b.Version)
				if !errors.Is(err, wardenerr.ErrDuplicatePolicy) {
					t.Fatalf("rename onto a taken name: want ErrDuplicatePolicy, got %v", err)
				}
				if !errors.Is(err, wardenerr.ErrAlreadyExists) {
					t.Errorf("refusal does not wrap ErrAlreadyExists: %v", err)
				}
				gotB, err := s.GetPolicy(ctx, versionTenant, b.ID)
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				requireUnchanged(t, "renamed policy", b, gotB)
				gotA, err := s.GetPolicy(ctx, versionTenant, a.ID)
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				requireUnchanged(t, "policy that holds the name", a, gotA)
			})

			t.Run("keeping its own name is fine", func(t *testing.T) {
				s, _, b, cleanup := setup(t)
				defer cleanup()
				ctx := context.Background()

				if err := call.write(ctx, s, edited(b, "same name, new description"), b.Version); err != nil {
					t.Fatalf("update keeping the name: %v", err)
				}
				got, err := s.GetPolicy(ctx, versionTenant, b.ID)
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				if got.Description != "same name, new description" || got.Name != b.Name {
					t.Errorf("stored policy = name %q, description %q", got.Name, got.Description)
				}
			})

			t.Run("the same name in another namespace is fine", func(t *testing.T) {
				s, a, b, cleanup := setup(t)
				defer cleanup()
				ctx := context.Background()

				moved := edited(b, "moved")
				moved.NamespacePath = "ops"
				moved.Name = a.Name
				if err := call.write(ctx, s, moved, b.Version); err != nil {
					t.Fatalf("rename onto a name another namespace holds: %v", err)
				}
				got, err := s.GetPolicy(ctx, versionTenant, b.ID)
				if err != nil {
					t.Fatalf("GetPolicy: %v", err)
				}
				if got.NamespacePath != "ops" || got.Name != a.Name {
					t.Errorf("stored policy = ns %q name %q, want ns ops name %q", got.NamespacePath, got.Name, a.Name)
				}
			})

			t.Run("a free name is fine", func(t *testing.T) {
				s, _, b, cleanup := setup(t)
				defer cleanup()
				ctx := context.Background()

				renamed := edited(b, "renamed")
				renamed.Name = "gamma"
				if err := call.write(ctx, s, renamed, b.Version); err != nil {
					t.Fatalf("rename to a free name: %v", err)
				}
			})
		})
	}
}
