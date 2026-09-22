package dsl

import (
	"context"
	"testing"

	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"
)

func TestInvalidatorPlugin_IgnoresUnrelatedActions(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	expr1, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")

	p := NewInvalidatorPlugin(ev)
	if err := p.(plugin.Audit).OnAudit(context.Background(), plugin.Event{
		Action:   "role.created",
		TenantID: "t1",
	}); err != nil {
		t.Fatal(err)
	}

	expr2, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	if expr1 != expr2 {
		t.Fatal("an unrelated audit action must not invalidate the expression cache")
	}
}

func TestInvalidatorPlugin_InvalidatesByEntityName(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	expr1, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")

	p := NewInvalidatorPlugin(ev)
	rt := &resourcetype.ResourceType{TenantID: "t1", Name: "doc"}
	if err := p.(plugin.Audit).OnAudit(context.Background(), plugin.Event{
		Action:   "resourcetype.updated",
		TenantID: "t1",
		Entity:   rt,
	}); err != nil {
		t.Fatal(err)
	}

	expr2, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	if expr1 == expr2 {
		t.Fatal("expected a fresh AST after a resourcetype.updated audit event")
	}
}

func TestInvalidatorPlugin_FallsBackToTenantFlushOnDelete(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	exprDoc1, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	exprFolder1, _ := ev.CompileAndCache("t1", "", "folder", "read", "viewer")

	p := NewInvalidatorPlugin(ev)
	// A delete event carries no typed Entity, only an EntityID — the
	// plugin can't know which resource type's Name to target, so it must
	// fall back to flushing the whole tenant.
	if err := p.(plugin.Audit).OnAudit(context.Background(), plugin.Event{
		Action:   "resourcetype.deleted",
		TenantID: "t1",
		EntityID: "rt_123",
	}); err != nil {
		t.Fatal(err)
	}

	exprDoc2, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	exprFolder2, _ := ev.CompileAndCache("t1", "", "folder", "read", "viewer")
	if exprDoc1 == exprDoc2 {
		t.Fatal("expected doc's cached AST to be invalidated by the tenant-wide fallback")
	}
	if exprFolder1 == exprFolder2 {
		t.Fatal("expected folder's cached AST to be invalidated by the tenant-wide fallback")
	}
}

func TestInvalidatorPlugin_ScopedToTenant(t *testing.T) {
	s := memory.New()
	ev := NewEvaluator(s)
	exprT1, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	exprT2, _ := ev.CompileAndCache("t2", "", "doc", "read", "viewer")

	p := NewInvalidatorPlugin(ev)
	rt := &resourcetype.ResourceType{TenantID: "t1", Name: "doc"}
	if err := p.(plugin.Audit).OnAudit(context.Background(), plugin.Event{
		Action:   "resourcetype.updated",
		TenantID: "t1",
		Entity:   rt,
	}); err != nil {
		t.Fatal(err)
	}

	exprT1After, _ := ev.CompileAndCache("t1", "", "doc", "read", "viewer")
	exprT2After, _ := ev.CompileAndCache("t2", "", "doc", "read", "viewer")
	if exprT1 == exprT1After {
		t.Fatal("expected t1's cached AST to be invalidated")
	}
	if exprT2 != exprT2After {
		t.Fatal("t2's cached AST must be unaffected by a t1 audit event")
	}
}

func TestInvalidatorPlugin_Name(t *testing.T) {
	p := NewInvalidatorPlugin(NewEvaluator(memory.New()))
	if p.Name() == "" {
		t.Fatal("expected non-empty plugin name")
	}
}
