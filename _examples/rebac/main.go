// Example: Zanzibar-style ReBAC with transitive relations.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store/memory"
)

func main() {
	ctx := warden.WithTenant(context.Background(), "app", "t1")
	s := memory.New()

	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		log.Fatal(err)
	}

	// Direct relation: Alice is a viewer of doc-1.
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID: id.NewRelationID(), TenantID: "t1",
		ObjectType: "document", ObjectID: "doc-1", Relation: "read",
		SubjectType: "user", SubjectID: "alice",
	})

	// Transitive relation via folder:
	//   document:doc-2#read -> folder:engineering#read (subject set)
	//   folder:engineering#read -> user:bob
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID: id.NewRelationID(), TenantID: "t1",
		ObjectType: "document", ObjectID: "doc-2", Relation: "read",
		SubjectType: "folder", SubjectID: "engineering", SubjectRelation: "read",
	})
	_ = s.CreateRelation(ctx, &relation.Tuple{
		ID: id.NewRelationID(), TenantID: "t1",
		ObjectType: "folder", ObjectID: "engineering", Relation: "read",
		SubjectType: "user", SubjectID: "bob",
	})

	// Alice can read doc-1 (direct relation).
	check(eng, ctx, "alice", "read", "document", "doc-1")
	// Alice cannot read doc-2 (no relation).
	check(eng, ctx, "alice", "read", "document", "doc-2")
	// Bob can read doc-2 (via folder:engineering).
	check(eng, ctx, "bob", "read", "document", "doc-2")
}

func check(eng *warden.Engine, ctx context.Context, userID, action, resType, resID string) {
	result, err := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: userID},
		Action:   warden.Action{Name: action},
		Resource: warden.Resource{Type: resType, ID: resID},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s %s %s:%s → %v (%s)\n", userID, action, resType, resID, result.Allowed, result.Decision)
}
