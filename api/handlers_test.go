package api

import (
	"net/http"
	"testing"

	"github.com/xraph/warden/id"
)

// Every subtest below runs against a fresh newTestAPI (allow-all
// authorizer, real requireIdentity/requireScope middleware, real
// handlers, real memory store), covering M13's four cases per route:
// unauthenticated -> 401, malformed body -> 400 with field codes,
// foreign-tenant ID -> 404, and one happy path.

// ─────────────────────────────────────────────────────────────────────────
// Roles
// ─────────────────────────────────────────────────────────────────────────

func TestRoles_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/roles?search=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRoles_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	decodeJSON(t, rec, &body)
	if body["error"] == nil {
		t.Fatalf("expected a field-level error message, got %v", body)
	}
}

func TestRoles_HappyPath_CreateGetUpdateDelete(t *testing.T) {
	h := newTestAPI(t)

	create := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		IsSystem bool   `json:"is_system"`
	}
	decodeJSON(t, create, &created)
	if created.ID == "" {
		t.Fatalf("create: no id in response: %s", create.Body.String())
	}
	if created.IsSystem {
		t.Fatalf("create: is_system was true, but CreateRoleRequest no longer accepts it (L2)")
	}

	get := do(h, request(http.MethodGet, "/v1/roles/"+created.ID, "alice", testTenant, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%s", get.Code, get.Body.String())
	}

	update := do(h, request(http.MethodPut, "/v1/roles/"+created.ID, "alice", testTenant, map[string]any{
		"name": "Senior Editor",
	}))
	if update.Code != http.StatusOK {
		t.Fatalf("update: status = %d, want 200; body=%s", update.Code, update.Body.String())
	}
	var updated struct {
		Name      string `json:"name"`
		UpdatedBy string `json:"updated_by"`
	}
	decodeJSON(t, update, &updated)
	if updated.Name != "Senior Editor" {
		t.Fatalf("update: name = %q, want %q", updated.Name, "Senior Editor")
	}
	if updated.UpdatedBy != "alice" {
		t.Fatalf("update: updated_by = %q, want %q (H4 actor capture)", updated.UpdatedBy, "alice")
	}

	del := do(h, request(http.MethodDelete, "/v1/roles/"+created.ID, "alice", testTenant, nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", del.Code, del.Body.String())
	}
}

func TestRoles_ForeignTenant404(t *testing.T) {
	h := newTestAPI(t)

	create := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)

	get := do(h, request(http.MethodGet, "/v1/roles/"+created.ID, "alice", otherTenant, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: status = %d, want 404; body=%s", get.Code, get.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Permissions
// ─────────────────────────────────────────────────────────────────────────

func TestPermissions_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/permissions?search=&resource=&action=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPermissions_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPermissions_HappyPath_CreateGetDelete(t *testing.T) {
	h := newTestAPI(t)

	create := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, map[string]any{
		"name": "document:read", "resource": "document", "action": "read",
	}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		IsSystem bool   `json:"is_system"`
	}
	decodeJSON(t, create, &created)
	if created.IsSystem {
		t.Fatalf("create: is_system was true, but CreatePermissionRequest no longer accepts it (L2)")
	}

	get := do(h, request(http.MethodGet, "/v1/permissions/"+created.ID, "alice", testTenant, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%s", get.Code, get.Body.String())
	}

	del := do(h, request(http.MethodDelete, "/v1/permissions/"+created.ID, "alice", testTenant, nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", del.Code, del.Body.String())
	}
}

func TestPermissions_ForeignTenant404(t *testing.T) {
	h := newTestAPI(t)
	create := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, map[string]any{
		"name": "document:read", "resource": "document", "action": "read",
	}))
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)

	get := do(h, request(http.MethodGet, "/v1/permissions/"+created.ID, "alice", otherTenant, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: status = %d, want 404; body=%s", get.Code, get.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Assignments
// ─────────────────────────────────────────────────────────────────────────

func TestAssignments_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/assignments?limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAssignments_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAssignments_InvalidSubjectKind422 checks the M4 subject_kind enum
// guard. It expects 422, not 400: this check is an explicit
// forge.NewValidationErrors ENUM code (business-rule validation on an
// otherwise well-formed field), and forge.ValidationErrors.StatusCode()
// always reports 422, distinct from forge's own pre-handler "field is
// required" schema binding (which reports 400 and is what the other
// *_MalformedBody400 tests in this file exercise).
func TestAssignments_InvalidSubjectKind422(t *testing.T) {
	h := newTestAPI(t)
	roleCreate := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var role struct {
		ID string `json:"id"`
	}
	decodeJSON(t, roleCreate, &role)

	rec := do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{
		"role_id": role.ID, "subject_kind": "admin_override", "subject_id": "u1",
	}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for an out-of-enum subject_kind; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAssignments_HappyPath_AssignListUnassign(t *testing.T) {
	h := newTestAPI(t)
	roleCreate := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var role struct {
		ID string `json:"id"`
	}
	decodeJSON(t, roleCreate, &role)

	assign := do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{
		"role_id": role.ID, "subject_kind": "user", "subject_id": "bob",
	}))
	if assign.Code != http.StatusCreated {
		t.Fatalf("assign: status = %d, want 201; body=%s", assign.Code, assign.Body.String())
	}
	var ass struct {
		ID        string `json:"id"`
		GrantedBy string `json:"granted_by"`
	}
	decodeJSON(t, assign, &ass)
	if ass.GrantedBy != "alice" {
		t.Fatalf("assign: granted_by = %q, want %q (H4 actor capture)", ass.GrantedBy, "alice")
	}

	list := do(h, request(http.MethodGet, "/v1/assignments?limit=10&offset=0", "alice", testTenant, nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200; body=%s", list.Code, list.Body.String())
	}

	unassign := do(h, request(http.MethodDelete, "/v1/assignments/"+ass.ID, "alice", testTenant, nil))
	if unassign.Code != http.StatusNoContent {
		t.Fatalf("unassign: status = %d, want 204; body=%s", unassign.Code, unassign.Body.String())
	}
}

func TestAssignments_ForeignTenant404(t *testing.T) {
	h := newTestAPI(t)
	roleCreate := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var role struct {
		ID string `json:"id"`
	}
	decodeJSON(t, roleCreate, &role)
	assign := do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{
		"role_id": role.ID, "subject_kind": "user", "subject_id": "bob",
	}))
	var ass struct {
		ID string `json:"id"`
	}
	decodeJSON(t, assign, &ass)

	unassign := do(h, request(http.MethodDelete, "/v1/assignments/"+ass.ID, "alice", otherTenant, nil))
	if unassign.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant unassign: status = %d, want 404; body=%s", unassign.Code, unassign.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Relations
// ─────────────────────────────────────────────────────────────────────────

func TestRelations_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/relations?limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRelations_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/relations", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRelations_HappyPath_WriteListDelete(t *testing.T) {
	h := newTestAPI(t)

	write := do(h, request(http.MethodPost, "/v1/relations", "alice", testTenant, map[string]any{
		"object_type": "document", "object_id": "doc1", "relation": "viewer",
		"subject_type": "user", "subject_id": "bob",
	}))
	if write.Code != http.StatusCreated {
		t.Fatalf("write: status = %d, want 201; body=%s", write.Code, write.Body.String())
	}
	var tuple struct {
		CreatedBy string `json:"created_by"`
	}
	decodeJSON(t, write, &tuple)
	if tuple.CreatedBy != "alice" {
		t.Fatalf("write: created_by = %q, want %q (H4 actor capture)", tuple.CreatedBy, "alice")
	}

	list := do(h, request(http.MethodGet, "/v1/relations?limit=10&offset=0", "alice", testTenant, nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200; body=%s", list.Code, list.Body.String())
	}

	del := do(h, request(http.MethodPost, "/v1/relations/delete", "alice", testTenant, map[string]any{
		"object_type": "document", "object_id": "doc1", "relation": "viewer",
		"subject_type": "user", "subject_id": "bob",
	}))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", del.Code, del.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Policies
// ─────────────────────────────────────────────────────────────────────────

func TestPolicies_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/policies?search=&effect=&active=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestPolicies_InvalidEffect422 is Policies' malformed-body case: an
// out-of-enum effect is a forge.NewValidationErrors ENUM code, which
// forge always reports as 422 (see TestAssignments_InvalidSubjectKind422).
func TestPolicies_InvalidEffect422(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
		"name": "p1", "effect": "not-a-real-effect",
	}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicies_HappyPath_CreateGetUpdateDelete(t *testing.T) {
	h := newTestAPI(t)

	create := do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
		"name": "allow-read", "effect": "allow", "is_active": true,
	}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID        string `json:"id"`
		CreatedBy string `json:"created_by"`
	}
	decodeJSON(t, create, &created)
	if created.CreatedBy != "alice" {
		t.Fatalf("create: created_by = %q, want %q (H4 actor capture)", created.CreatedBy, "alice")
	}

	get := do(h, request(http.MethodGet, "/v1/policies/"+created.ID, "alice", testTenant, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%s", get.Code, get.Body.String())
	}

	update := do(h, request(http.MethodPut, "/v1/policies/"+created.ID, "alice", testTenant, map[string]any{
		"description": "updated",
	}))
	if update.Code != http.StatusOK {
		t.Fatalf("update: status = %d, want 200; body=%s", update.Code, update.Body.String())
	}
	var updated struct {
		UpdatedBy string `json:"updated_by"`
	}
	decodeJSON(t, update, &updated)
	if updated.UpdatedBy != "alice" {
		t.Fatalf("update: updated_by = %q, want %q (H4 actor capture)", updated.UpdatedBy, "alice")
	}

	del := do(h, request(http.MethodDelete, "/v1/policies/"+created.ID, "alice", testTenant, nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", del.Code, del.Body.String())
	}
}

func TestPolicies_ForeignTenant404(t *testing.T) {
	h := newTestAPI(t)
	create := do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
		"name": "allow-read", "effect": "allow", "is_active": true,
	}))
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)

	get := do(h, request(http.MethodGet, "/v1/policies/"+created.ID, "alice", otherTenant, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: status = %d, want 404; body=%s", get.Code, get.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Resource types
// ─────────────────────────────────────────────────────────────────────────

func TestResourceTypes_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/resource-types?search=&limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestResourceTypes_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/resource-types", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestResourceTypes_HappyPath_CreateGetDelete(t *testing.T) {
	h := newTestAPI(t)

	create := do(h, request(http.MethodPost, "/v1/resource-types", "alice", testTenant, map[string]any{
		"name": "document",
	}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body=%s", create.Code, create.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)

	get := do(h, request(http.MethodGet, "/v1/resource-types/"+created.ID, "alice", testTenant, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body=%s", get.Code, get.Body.String())
	}

	del := do(h, request(http.MethodDelete, "/v1/resource-types/"+created.ID, "alice", testTenant, nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", del.Code, del.Body.String())
	}
}

func TestResourceTypes_ForeignTenant404(t *testing.T) {
	h := newTestAPI(t)
	create := do(h, request(http.MethodPost, "/v1/resource-types", "alice", testTenant, map[string]any{
		"name": "document",
	}))
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, create, &created)

	get := do(h, request(http.MethodGet, "/v1/resource-types/"+created.ID, "alice", otherTenant, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: status = %d, want 404; body=%s", get.Code, get.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Check logs
// ─────────────────────────────────────────────────────────────────────────

func TestCheckLogs_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/check-logs?limit=10&offset=0", "", testTenant, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheckLogs_MalformedQuery400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/check-logs?limit=10&offset=0&after=not-a-timestamp", "alice", testTenant, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheckLogs_HappyPath_List(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodGet, "/v1/check-logs?limit=10&offset=0", "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Check (authz)
// ─────────────────────────────────────────────────────────────────────────

func TestCheck_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/authz/check", "", testTenant, map[string]any{
		"subject_id": "u1", "action": "read", "resource_type": "document",
	}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheck_MalformedBody400(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/authz/check", "alice", testTenant, map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheck_NoTenantIDField(t *testing.T) {
	// H2: api.CheckRequest must not accept tenant_id at all.
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/authz/check", "alice", testTenant, map[string]any{
		"subject_id": "u1", "action": "read", "resource_type": "document", "tenant_id": otherTenant,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (tenant_id must be silently ignored as an unknown field, not error); body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheck_HappyPath(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/authz/check", "alice", testTenant, map[string]any{
		"subject_id": "u1", "action": "read", "resource_type": "document",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var result struct {
		Allowed bool `json:"allowed"`
	}
	decodeJSON(t, rec, &result)
	if result.Allowed {
		t.Fatalf("expected denial against an empty role/permission catalog, got allowed=true")
	}
}

func TestCheck_BatchOverLimit422(t *testing.T) {
	h := newTestAPI(t)
	checks := make([]map[string]any, 0, 5)
	for i := 0; i < 5; i++ {
		checks = append(checks, map[string]any{"subject_id": "u1", "action": "read", "resource_type": "document"})
	}
	rec := do(h, request(http.MethodPost, "/v1/authz/batch-check", "alice", testTenant, map[string]any{"checks": checks}))
	if rec.Code != http.StatusOK {
		t.Fatalf("under-limit batch: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// AuthZEN
// ─────────────────────────────────────────────────────────────────────────

func TestAuthzen_Unauthenticated401(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluation", "", testTenant, map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1"},
		"action":   map[string]any{"name": "read"},
		"resource": map[string]any{"type": "document", "id": "d1"},
	}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAuthzen_EmptyEvaluationsBatch422 is AuthZEN's malformed-body case:
// an empty evaluations array is a forge.NewValidationErrors MIN_ITEMS
// code, which forge always reports as 422 (see
// TestAssignments_InvalidSubjectKind422).
func TestAuthzen_EmptyEvaluationsBatch422(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluations", "alice", testTenant, map[string]any{
		"evaluations": []any{},
	}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthzen_HappyPath(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluation", "alice", testTenant, map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1"},
		"action":   map[string]any{"name": "read"},
		"resource": map[string]any{"type": "document", "id": "d1"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthzen_MismatchedContextTenant403(t *testing.T) {
	// H2: AuthZEN ignores tenant_id/namespace_path in context unless it
	// equals the caller's own scope, otherwise 403. A caller can never
	// use the context field to reach into another tenant's catalog.
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluation", "alice", testTenant, map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1"},
		"action":   map[string]any{"name": "read"},
		"resource": map[string]any{"type": "document", "id": "d1"},
		"context":  map[string]any{"tenant_id": otherTenant},
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a mismatched context tenant_id; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthzen_MatchingContextTenantAllowed(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluation", "alice", testTenant, map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1"},
		"action":   map[string]any{"name": "read"},
		"resource": map[string]any{"type": "document", "id": "d1"},
		"context":  map[string]any{"tenant_id": testTenant},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when context tenant_id matches scope; body=%s", rec.Code, rec.Body.String())
	}
}

// sanity: id-parsing helper used in negative-path assertions elsewhere
// stays exercised so a change to id package formatting is caught here too.
func TestRoles_UnknownIDNotFound(t *testing.T) {
	h := newTestAPI(t)
	unknown := id.NewRoleID().String()
	rec := do(h, request(http.MethodGet, "/v1/roles/"+unknown, "alice", testTenant, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Remaining list/attach/detach/enforce coverage
// ─────────────────────────────────────────────────────────────────────────

func TestRoles_AttachDetachPermission(t *testing.T) {
	h := newTestAPI(t)

	roleCreate := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var role struct {
		ID string `json:"id"`
	}
	decodeJSON(t, roleCreate, &role)

	permCreate := do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, map[string]any{
		"name": "document:read", "resource": "document", "action": "read",
	}))
	var perm struct {
		ID string `json:"id"`
	}
	decodeJSON(t, permCreate, &perm)

	attach := do(h, request(http.MethodPost, "/v1/roles/"+role.ID+"/permissions", "alice", testTenant, map[string]any{
		"permission_id": perm.ID,
	}))
	if attach.Code != http.StatusNoContent {
		t.Fatalf("attach: status = %d, want 204; body=%s", attach.Code, attach.Body.String())
	}

	detach := do(h, request(http.MethodDelete, "/v1/roles/"+role.ID+"/permissions/"+perm.ID, "alice", testTenant, nil))
	if detach.Code != http.StatusNoContent {
		t.Fatalf("detach: status = %d, want 204; body=%s", detach.Code, detach.Body.String())
	}

	// Name-form attach/detach (Phase A.5 natural-key path).
	attachByName := do(h, request(http.MethodPost, "/v1/roles/"+role.ID+"/permissions", "alice", testTenant, map[string]any{
		"permission_name": "document:read",
	}))
	if attachByName.Code != http.StatusNoContent {
		t.Fatalf("attach by name: status = %d, want 204; body=%s", attachByName.Code, attachByName.Body.String())
	}
	detachByName := do(h, request(http.MethodDelete, "/v1/roles/"+role.ID+"/permissions/"+perm.ID+"?permission_name=document:read", "alice", testTenant, nil))
	if detachByName.Code != http.StatusNoContent {
		t.Fatalf("detach by name: status = %d, want 204; body=%s", detachByName.Code, detachByName.Body.String())
	}
}

func TestAssignments_ListSubjectRoles(t *testing.T) {
	h := newTestAPI(t)
	roleCreate := do(h, request(http.MethodPost, "/v1/roles", "alice", testTenant, map[string]any{
		"name": "Editor", "slug": "editor",
	}))
	var role struct {
		ID string `json:"id"`
	}
	decodeJSON(t, roleCreate, &role)
	do(h, request(http.MethodPost, "/v1/assignments", "alice", testTenant, map[string]any{
		"role_id": role.ID, "subject_kind": "user", "subject_id": "bob",
	}))

	rec := do(h, request(http.MethodGet, "/v1/subjects/user/bob/roles", "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPermissions_List(t *testing.T) {
	h := newTestAPI(t)
	do(h, request(http.MethodPost, "/v1/permissions", "alice", testTenant, map[string]any{
		"name": "document:read", "resource": "document", "action": "read",
	}))
	rec := do(h, request(http.MethodGet, "/v1/permissions?search=&resource=&action=&limit=10&offset=0", "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicies_List(t *testing.T) {
	h := newTestAPI(t)
	do(h, request(http.MethodPost, "/v1/policies", "alice", testTenant, map[string]any{
		"name": "allow-read", "effect": "allow", "is_active": true,
	}))
	rec := do(h, request(http.MethodGet, "/v1/policies?search=&effect=allow&active=true&limit=10&offset=0", "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestResourceTypes_List(t *testing.T) {
	h := newTestAPI(t)
	do(h, request(http.MethodPost, "/v1/resource-types", "alice", testTenant, map[string]any{
		"name": "document",
	}))
	rec := do(h, request(http.MethodGet, "/v1/resource-types?search=&limit=10&offset=0", "alice", testTenant, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCheck_Enforce(t *testing.T) {
	h := newTestAPI(t)

	deny := do(h, request(http.MethodPost, "/v1/authz/enforce", "alice", testTenant, map[string]any{
		"subject_id": "u1", "action": "read", "resource_type": "document",
	}))
	if deny.Code != http.StatusForbidden {
		t.Fatalf("enforce deny: status = %d, want 403; body=%s", deny.Code, deny.Body.String())
	}
}

func TestAuthzen_BatchHappyPath(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/access/v1/evaluations", "alice", testTenant, map[string]any{
		"subject": map[string]any{"type": "user", "id": "u1"},
		"evaluations": []map[string]any{
			{"action": map[string]any{"name": "read"}, "resource": map[string]any{"type": "document", "id": "d1"}},
			{"action": map[string]any{"name": "write"}, "resource": map[string]any{"type": "document", "id": "d2"}},
		},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Evaluations []map[string]any `json:"evaluations"`
	}
	decodeJSON(t, rec, &resp)
	if len(resp.Evaluations) != 2 {
		t.Fatalf("expected 2 evaluation results, got %d: %+v", len(resp.Evaluations), resp.Evaluations)
	}
}

func TestRelations_MissingFields422(t *testing.T) {
	h := newTestAPI(t)
	rec := do(h, request(http.MethodPost, "/v1/relations", "alice", testTenant, map[string]any{
		"object_type": "document",
	}))
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 400 or 422; body=%s", rec.Code, rec.Body.String())
	}
}
