package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xraph/warden/permission"
)

// The engine checks a grant by joining resource and action with ':', so
// REST refuses an action with a ':' as 400 and writes nothing. A resource
// keeps its colons, and '*' stays a valid action.
func TestPermissions_RESTCreateRefusesAColonInTheAction(t *testing.T) {
	h, s, _ := newRelationAuditAPI(t)

	for _, body := range []map[string]any{
		{"name": "warden:role:manage", "resource": "warden", "action": "role:manage"},
		{"name": "doc::", "resource": "doc", "action": ":"},
	} {
		rec := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("create %v: status = %d, want 400; body=%s", body, rec.Code, rec.Body.String())
		}
		var got struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode %s: %v", rec.Body.String(), err)
		}
		want := `action "` + body["action"].(string) + `" contains ':': the engine joins resource and action with ':', so an action may not contain one`
		if got.Error != want {
			t.Errorf("create %v message\n got: %s\nwant: %s", body, got.Error, want)
		}
	}
	all, err := s.ListPermissions(context.Background(), &permission.ListFilter{TenantID: testTenant})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("a refused create wrote %d permissions", len(all))
	}

	for _, body := range []map[string]any{
		{"name": "warden:role:manage", "resource": "warden:role", "action": "manage"},
		{"name": "warden:role:*", "resource": "warden:role", "action": "*"},
	} {
		rec := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, body))
		if rec.Code != http.StatusCreated {
			t.Errorf("create %v: status = %d, want 201; body=%s", body, rec.Code, rec.Body.String())
		}
	}
}

// A permission stored before the rule keeps working through REST: it reads
// and deletes.
func TestPermissions_RESTAStoredColonActionStillLoadsAndDeletes(t *testing.T) {
	h, s, _ := newRelationAuditAPI(t)
	pm := &permission.Permission{TenantID: testTenant, Name: "warden:role:manage", Resource: "warden", Action: "role:manage"}
	if err := s.CreatePermission(context.Background(), pm); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := do(h, request(http.MethodGet, "/v1/permissions/"+pm.ID.String(), "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var got permission.Permission
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Action != "role:manage" {
		t.Errorf("action = %q, want role:manage", got.Action)
	}

	rec = do(h, request(http.MethodDelete, "/v1/permissions/"+pm.ID.String(), "alice", testTenant, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetPermission(context.Background(), testTenant, pm.ID); err == nil {
		t.Fatal("the stored permission is still there after delete")
	}
}
