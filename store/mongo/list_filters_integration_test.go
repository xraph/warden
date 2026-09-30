//go:build integration

package mongo

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/contract"
)

// TestMongo_ListFiltersContract runs the shared namespace/list-filter
// contract against a real MongoDB instance. Mongo had no runner for this
// contract, which is how it kept two divergences the other backends had
// already fixed: no default cap on an unlimited List* call, and a sort on
// created_at with no tiebreaker to make it a total order.
func TestMongo_ListFiltersContract(t *testing.T) {
	contract.RunListFiltersContract(t, func(t *testing.T) (store.Store, func()) {
		return setupMongo(t)
	})
}

func TestMongoCheckLogWithoutCachedFieldCountsAsNotCached(t *testing.T) {
	s, cleanup := setupMongoStore(t)
	defer cleanup()
	ctx := context.Background()

	e := &checklog.Entry{
		ID: id.NewCheckLogID(), TenantID: "t1",
		SubjectKind: "user", SubjectID: "alice", Action: "read",
		ResourceType: "doc", ResourceID: "old", Decision: "allow",
	}
	if err := s.CreateCheckLog(ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Make it look like a row written before the field existed.
	res, err := s.mdb.Collection(colCheckLogs).UpdateOne(ctx,
		bson.M{"_id": e.ID.String()}, bson.M{"$unset": bson.M{"cached": ""}})
	if err != nil || res.ModifiedCount != 1 {
		t.Fatalf("unset cached: modified=%v err=%v", res, err)
	}

	no, yes := false, true
	got, err := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", Cached: &no})
	if err != nil || len(got) != 1 {
		t.Fatalf("Cached=false: want the old row, got %d (err %v)", len(got), err)
	}
	if n, err := s.CountCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", Cached: &no}); err != nil || n != 1 {
		t.Fatalf("Cached=false count: want 1, got %d (err %v)", n, err)
	}
	if got, _ := s.ListCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1", Cached: &yes}); len(got) != 0 {
		t.Fatalf("Cached=true: want no rows, got %d", len(got))
	}
}
