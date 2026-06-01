package api

import (
	"testing"

	"github.com/xraph/warden"
)

func TestAuthzenToCheckRequest_MapsFieldsAndAttributes(t *testing.T) {
	req := &AuthZenEvaluationRequest{
		Subject: AuthZenSubject{
			Type:       "user",
			ID:         "alice",
			Properties: map[string]any{"dept": "eng"},
		},
		Action: AuthZenAction{Name: "read"},
		Resource: AuthZenResource{
			Type:       "document",
			ID:         "doc_1",
			Properties: map[string]any{"owner": "bob"},
		},
		Context: map[string]any{"tenant_id": "t-1", "ip": "10.0.0.1"},
	}

	cr := authzenToCheckRequest(req)

	if cr.Subject.Kind != warden.SubjectUser || cr.Subject.ID != "alice" {
		t.Fatalf("subject mapped wrong: %+v", cr.Subject)
	}
	if cr.Subject.Attributes["dept"] != "eng" {
		t.Fatalf("subject attributes not forwarded: %+v", cr.Subject.Attributes)
	}
	if cr.Action.Name != "read" {
		t.Fatalf("action mapped wrong: %+v", cr.Action)
	}
	if cr.Resource.Type != "document" || cr.Resource.ID != "doc_1" {
		t.Fatalf("resource mapped wrong: %+v", cr.Resource)
	}
	if cr.Resource.Attributes["owner"] != "bob" {
		t.Fatalf("resource attributes not forwarded: %+v", cr.Resource.Attributes)
	}
	if cr.TenantID != "t-1" {
		t.Fatalf("tenant_id not derived from context: %q", cr.TenantID)
	}
}

func TestToSubjectKind_DefaultsToUser(t *testing.T) {
	cases := map[string]warden.SubjectKind{
		"user":          warden.SubjectUser,
		"api_key":       warden.SubjectAPIKey,
		"service":       warden.SubjectService,
		"service_acct":  warden.SubjectServiceAcct,
		"something_new": warden.SubjectUser,
		"":              warden.SubjectUser,
	}
	for in, want := range cases {
		if got := toSubjectKind(in); got != want {
			t.Errorf("toSubjectKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthzenToResponse_SurfacesDecisionAndReason(t *testing.T) {
	allow := authzenToResponse(&warden.CheckResult{
		Allowed:  true,
		Decision: warden.DecisionAllow,
	})
	if !allow.Decision {
		t.Fatal("expected decision true for allowed result")
	}
	if allow.Context["decision"] != string(warden.DecisionAllow) {
		t.Fatalf("decision code not surfaced: %+v", allow.Context)
	}

	deny := authzenToResponse(&warden.CheckResult{
		Allowed:     false,
		Decision:    warden.DecisionDenyExplicit,
		Reason:      "explicit deny policy",
		Obligations: []string{"audit-log"},
	})
	if deny.Decision {
		t.Fatal("expected decision false for denied result")
	}
	if deny.Context["reason"] != "explicit deny policy" {
		t.Fatalf("reason not surfaced: %+v", deny.Context)
	}
	if obs, ok := deny.Context["obligations"].([]string); !ok || len(obs) != 1 {
		t.Fatalf("obligations not surfaced: %+v", deny.Context)
	}
}

func TestResolveAuthZenDefaults_InheritsAndMergesContext(t *testing.T) {
	req := &AuthZenEvaluationsRequest{
		Subject: &AuthZenSubject{Type: "user", ID: "alice"},
		Action:  &AuthZenAction{Name: "read"},
		Context: map[string]any{"tenant_id": "t-1"},
	}
	item := AuthZenEvaluationRequest{
		Resource: AuthZenResource{Type: "document", ID: "doc_9"},
		Context:  map[string]any{"ip": "10.0.0.2"},
	}

	got := resolveAuthZenDefaults(req, item)

	if got.Subject.ID != "alice" || got.Action.Name != "read" {
		t.Fatalf("defaults not inherited: %+v", got)
	}
	if got.Resource.ID != "doc_9" {
		t.Fatalf("item resource overwritten: %+v", got.Resource)
	}
	if got.Context["tenant_id"] != "t-1" || got.Context["ip"] != "10.0.0.2" {
		t.Fatalf("context not merged: %+v", got.Context)
	}
}
