package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"
)

func seedRESTDocumentType(t *testing.T, s *memory.Store, ns string) {
	t.Helper()
	err := s.CreateResourceType(context.Background(), &resourcetype.ResourceType{
		TenantID: testTenant, NamespacePath: ns, Name: "document",
		Relations: []resourcetype.RelationDef{
			{Name: "owner", AllowedSubjects: []string{"user"}},
			{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
		},
	})
	if err != nil {
		t.Fatalf("seed resource type: %v", err)
	}
}

func TestRelations_RESTWriteObeysTheGoverningResourceType(t *testing.T) {
	// REST writes every tuple at the tenant root, so the root's declaration
	// governs and a namespace's never does.
	h, s, _ := newRelationAuditAPI(t)
	seedRESTDocumentType(t, s, "")
	ctx := context.Background()
	err := s.CreateResourceType(ctx, &resourcetype.ResourceType{
		TenantID: testTenant, NamespacePath: "eng", Name: "folder",
		Relations: []resourcetype.RelationDef{{Name: "parent", AllowedSubjects: []string{"folder"}}},
	})
	if err != nil {
		t.Fatalf("seed folder type: %v", err)
	}

	write := func(body map[string]any) (int, string) {
		rec := do(h, request(http.MethodPost, "/v1/relations", "alice", testTenant, body))
		return rec.Code, rec.Body.String()
	}

	written := []struct {
		name string
		body map[string]any
	}{
		{"undeclared object type", map[string]any{"object_type": "team", "object_id": "t", "relation": "anything", "subject_type": "x", "subject_id": "y"}},
		{"declared relation, allowed subject", map[string]any{"object_type": "document", "object_id": "d1", "relation": "viewer", "subject_type": "user", "subject_id": "alice"}},
		{"allowed subject set", map[string]any{"object_type": "document", "object_id": "d1", "relation": "viewer", "subject_type": "group", "subject_id": "eng", "subject_relation": "member"}},
		{"a namespace's declaration does not govern the root", map[string]any{"object_type": "folder", "object_id": "f", "relation": "owner", "subject_type": "user", "subject_id": "alice"}},
	}
	for _, c := range written {
		if code, body := write(c.body); code != http.StatusCreated {
			t.Errorf("%s: status = %d, want 201; body=%s", c.name, code, body)
		}
	}

	refused := []struct {
		name string
		body map[string]any
		msg  string
	}{
		{
			"undeclared relation",
			map[string]any{"object_type": "document", "object_id": "d1", "relation": "editor", "subject_type": "user", "subject_id": "alice"},
			`tuple document:d1#editor@user:alice in the tenant root is refused: resource type \"document\" in the tenant root declares no relation \"editor\" (its relations are \"owner\", \"viewer\")`,
		},
		{
			"disallowed subject",
			map[string]any{"object_type": "document", "object_id": "d1", "relation": "viewer", "subject_type": "group", "subject_id": "eng"},
			`tuple document:d1#viewer@group:eng in the tenant root is refused: relation \"viewer\" of resource type \"document\" in the tenant root allows subjects \"user\", \"group#member\", not \"group\"`,
		},
	}
	for _, c := range refused {
		code, body := write(c.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", c.name, code, body)
			continue
		}
		if !strings.Contains(body, c.msg) {
			t.Errorf("%s: body = %s\nwant it to carry %s", c.name, body, c.msg)
		}
	}

	rows, err := s.ListRelations(ctx, &relation.ListFilter{TenantID: testTenant})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != len(written) {
		t.Errorf("stored %d tuples, want %d: a refused tuple was written", len(rows), len(written))
	}
}
