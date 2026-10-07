// relation_get.go: a relation tuple can be read back by its ID within its
// own tenant, and only there.
//
// The dashboard deletes a tuple by ID. Its audit event has to carry the
// tuple that went away, not just the ID, so the handler reads the row first.
// That read is also the tenant check: another tenant's ID must come back as
// ErrRelationNotFound, exactly as a missing one does, so the caller learns
// nothing about rows outside its tenant.
package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/wardenerr"
)

// RunRelationGetContract proves GetRelation returns every field of the
// stored tuple, and returns ErrRelationNotFound both for an ID that was
// never stored and for an ID that belongs to another tenant.
func RunRelationGetContract(t *testing.T, mk MakeStore) {
	t.Run("returns the stored tuple", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		want := &relation.Tuple{
			TenantID:        "relget-t1",
			NamespacePath:   "eng",
			AppID:           "app-1",
			ObjectType:      "document",
			ObjectID:        "readme",
			Relation:        "viewer",
			SubjectType:     "group",
			SubjectID:       "engineering",
			SubjectRelation: "member",
			Metadata:        map[string]any{"source": "contract"},
			CreatedBy:       "tester",
		}
		createRelation(t, s, want)

		got, err := s.GetRelation(ctx, "relget-t1", want.ID)
		if err != nil {
			t.Fatalf("GetRelation: %v", err)
		}
		if got.ID != want.ID {
			t.Errorf("ID = %s, want %s", got.ID, want.ID)
		}
		for _, f := range []struct{ name, got, want string }{
			{"TenantID", got.TenantID, want.TenantID},
			{"NamespacePath", got.NamespacePath, want.NamespacePath},
			{"AppID", got.AppID, want.AppID},
			{"ObjectType", got.ObjectType, want.ObjectType},
			{"ObjectID", got.ObjectID, want.ObjectID},
			{"Relation", got.Relation, want.Relation},
			{"SubjectType", got.SubjectType, want.SubjectType},
			{"SubjectID", got.SubjectID, want.SubjectID},
			{"SubjectRelation", got.SubjectRelation, want.SubjectRelation},
			{"CreatedBy", got.CreatedBy, want.CreatedBy},
		} {
			if f.got != f.want {
				t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
			}
		}
		if got.Metadata["source"] != "contract" {
			t.Errorf("Metadata = %#v, want source=contract", got.Metadata)
		}
		if got.CreatedAt.IsZero() {
			t.Error("CreatedAt is zero")
		}
	})

	t.Run("a missing id is not found", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()

		got, err := s.GetRelation(context.Background(), "relget-t1", id.NewRelationID())
		if !errors.Is(err, wardenerr.ErrRelationNotFound) {
			t.Errorf("GetRelation of a missing id: tuple=%+v err=%v, want ErrRelationNotFound", got, err)
		}
	})

	t.Run("another tenant's id is not found", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()

		theirs := &relation.Tuple{
			TenantID: "relget-t2", ObjectType: "document", ObjectID: "theirs",
			Relation: "viewer", SubjectType: "user", SubjectID: "bob",
		}
		createRelation(t, s, theirs)

		got, err := s.GetRelation(ctx, "relget-t1", theirs.ID)
		if !errors.Is(err, wardenerr.ErrRelationNotFound) {
			t.Errorf("GetRelation of another tenant's id: tuple=%+v err=%v, want ErrRelationNotFound", got, err)
		}
		// The owner still reads it, so the miss above is the tenant check
		// and not a lost write.
		if _, err := s.GetRelation(ctx, "relget-t2", theirs.ID); err != nil {
			t.Errorf("GetRelation by the owning tenant: %v", err)
		}
	})
}
