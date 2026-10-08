package warden

import (
	"context"
	"testing"

	log "github.com/xraph/go-utils/log"
)

func TestActorFromContext_Explicit(t *testing.T) {
	ctx := WithActor(context.Background(), Actor{Kind: "service", ID: "svc-1", Via: "cli"})
	a, ok := ActorFromContext(ctx)
	if !ok {
		t.Fatal("expected actor to be found")
	}
	if a.Kind != "service" || a.ID != "svc-1" || a.Via != "cli" {
		t.Fatalf("unexpected actor: %+v", a)
	}
}

func TestActorFromContext_FallsBackToUserID(t *testing.T) {
	ctx := log.WithUserID(context.Background(), "u1")
	a, ok := ActorFromContext(ctx)
	if !ok {
		t.Fatal("expected actor to be found via log.UserIDFromContext")
	}
	if a.Kind != "user" || a.ID != "u1" || a.Via != "forge" {
		t.Fatalf("unexpected actor: %+v", a)
	}
}

func TestActorFromContext_ExplicitTakesPriority(t *testing.T) {
	ctx := log.WithUserID(context.Background(), "u1")
	ctx = WithActor(ctx, Actor{Kind: "system", ID: "warden", Via: "system"})
	a, ok := ActorFromContext(ctx)
	if !ok {
		t.Fatal("expected actor to be found")
	}
	if a.Kind != "system" || a.ID != "warden" {
		t.Fatalf("expected explicit actor to win, got %+v", a)
	}
}

func TestActorFromContext_NotFound(t *testing.T) {
	_, ok := ActorFromContext(context.Background())
	if ok {
		t.Fatal("expected no actor found in bare context")
	}
}

func TestSystemActor(t *testing.T) {
	if SystemActor.Kind != "system" || SystemActor.ID != "warden" {
		t.Fatalf("unexpected SystemActor: %+v", SystemActor)
	}
}
