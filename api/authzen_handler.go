package api

import (
	"net/http"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// AuthZEN Authorization API 1.0 information model.
//
// This adapts Warden's engine to the OpenID AuthZEN Authorization API so any
// AuthZEN-compatible Policy Enforcement Point (e.g. the Octopus gateway) can
// obtain decisions over a vendor-neutral contract. Unlike the flat /v1/authz
// DTO, this path forwards subject/resource properties to the engine as
// attributes (enabling ABAC) and surfaces reasons/obligations via the response
// context.

// AuthZenSubject is the AuthZEN subject (the actor requesting access).
type AuthZenSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZenAction is the AuthZEN action (what the subject wants to do).
type AuthZenAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZenResource is the AuthZEN resource (the target of the request).
type AuthZenResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZenEvaluationRequest is a single AuthZEN access-evaluation request.
type AuthZenEvaluationRequest struct {
	Subject  AuthZenSubject  `json:"subject"`
	Action   AuthZenAction   `json:"action"`
	Resource AuthZenResource `json:"resource"`
	Context  map[string]any  `json:"context,omitempty"`
}

// AuthZenEvaluationResponse is an AuthZEN decision. Additional Warden detail
// (decision code, reason, matched rules, obligations) is exposed via Context.
type AuthZenEvaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthZenEvaluationsRequest is the boxcarred ("evaluations") batch form. The
// top-level subject/action/resource/context act as defaults for items that
// omit them.
type AuthZenEvaluationsRequest struct {
	Subject     *AuthZenSubject            `json:"subject,omitempty"`
	Action      *AuthZenAction             `json:"action,omitempty"`
	Resource    *AuthZenResource           `json:"resource,omitempty"`
	Context     map[string]any             `json:"context,omitempty"`
	Evaluations []AuthZenEvaluationRequest `json:"evaluations"`
}

// AuthZenEvaluationsResponse is the batch decision list.
type AuthZenEvaluationsResponse struct {
	Evaluations []AuthZenEvaluationResponse `json:"evaluations"`
}

func (a *API) registerAuthZenRoutes(router forge.Router) error {
	g := router.Group("/access/v1", forge.WithGroupTags("authorization", "authzen"))

	if err := g.POST("/evaluation", a.authzenEvaluation,
		forge.WithSummary("AuthZEN access evaluation"),
		forge.WithDescription("OpenID AuthZEN Authorization API 1.0 single access evaluation."),
		forge.WithOperationID("authzenEvaluation"),
		forge.WithRequestSchema(AuthZenEvaluationRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Decision", AuthZenEvaluationResponse{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.POST("/evaluations", a.authzenEvaluations,
		forge.WithSummary("AuthZEN batch access evaluations"),
		forge.WithDescription("OpenID AuthZEN Authorization API 1.0 boxcarred evaluations."),
		forge.WithOperationID("authzenEvaluations"),
		forge.WithRequestSchema(AuthZenEvaluationsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Decisions", AuthZenEvaluationsResponse{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) authzenEvaluation(ctx forge.Context, req *AuthZenEvaluationRequest) (*AuthZenEvaluationResponse, error) {
	result, err := a.eng.Check(ctx.Context(), authzenToCheckRequest(req))
	if err != nil {
		return nil, mapError(err)
	}
	resp := authzenToResponse(result)
	return resp, ctx.JSON(http.StatusOK, resp)
}

func (a *API) authzenEvaluations(ctx forge.Context, req *AuthZenEvaluationsRequest) (*AuthZenEvaluationsResponse, error) {
	if len(req.Evaluations) == 0 {
		verr := forge.NewValidationErrors()
		verr.AddWithCode("evaluations", "evaluations cannot be empty", "MIN_ITEMS", nil)
		return nil, verr
	}

	out := make([]AuthZenEvaluationResponse, len(req.Evaluations))
	for i := range req.Evaluations {
		item := resolveAuthZenDefaults(req, req.Evaluations[i])
		result, err := a.eng.Check(ctx.Context(), authzenToCheckRequest(&item))
		if err != nil {
			return nil, mapError(err)
		}
		out[i] = *authzenToResponse(result)
	}

	resp := &AuthZenEvaluationsResponse{Evaluations: out}
	return resp, ctx.JSON(http.StatusOK, resp)
}

// resolveAuthZenDefaults fills a batch item's omitted subject/action/resource
// from the request-level defaults and overlays the default context.
func resolveAuthZenDefaults(req *AuthZenEvaluationsRequest, item AuthZenEvaluationRequest) AuthZenEvaluationRequest {
	if item.Subject.Type == "" && item.Subject.ID == "" && req.Subject != nil {
		item.Subject = *req.Subject
	}
	if item.Action.Name == "" && req.Action != nil {
		item.Action = *req.Action
	}
	if item.Resource.Type == "" && item.Resource.ID == "" && req.Resource != nil {
		item.Resource = *req.Resource
	}
	if len(req.Context) > 0 {
		merged := make(map[string]any, len(req.Context)+len(item.Context))
		for k, v := range req.Context {
			merged[k] = v
		}
		for k, v := range item.Context {
			merged[k] = v
		}
		item.Context = merged
	}
	return item
}

func authzenToCheckRequest(r *AuthZenEvaluationRequest) *warden.CheckRequest {
	cr := &warden.CheckRequest{
		Subject: warden.Subject{
			Kind:       toSubjectKind(r.Subject.Type),
			ID:         r.Subject.ID,
			Attributes: r.Subject.Properties,
		},
		Action: warden.Action{Name: r.Action.Name},
		Resource: warden.Resource{
			Type:       r.Resource.Type,
			ID:         r.Resource.ID,
			Attributes: r.Resource.Properties,
		},
		Context: r.Context,
	}
	// AuthZEN has no standard tenant field; honor conventional context keys so
	// multi-tenant callers can scope the decision.
	if r.Context != nil {
		if t, ok := r.Context["tenant_id"].(string); ok {
			cr.TenantID = t
		}
		if n, ok := r.Context["namespace_path"].(string); ok {
			cr.NamespacePath = n
		}
	}
	return cr
}

// toSubjectKind maps an AuthZEN subject type to a Warden SubjectKind, defaulting
// unknown types to a user subject.
func toSubjectKind(t string) warden.SubjectKind {
	switch warden.SubjectKind(t) {
	case warden.SubjectUser, warden.SubjectAPIKey, warden.SubjectService, warden.SubjectServiceAcct:
		return warden.SubjectKind(t)
	default:
		return warden.SubjectUser
	}
}

func authzenToResponse(r *warden.CheckResult) *AuthZenEvaluationResponse {
	rctx := map[string]any{
		"decision":     string(r.Decision),
		"eval_time_ns": r.EvalTimeNs,
	}
	if r.Reason != "" {
		rctx["reason"] = r.Reason
	}
	if len(r.Obligations) > 0 {
		rctx["obligations"] = r.Obligations
	}
	if len(r.MatchedBy) > 0 {
		matched := make([]map[string]string, 0, len(r.MatchedBy))
		for _, m := range r.MatchedBy {
			matched = append(matched, map[string]string{
				"source":  m.Source,
				"rule_id": m.RuleID,
				"detail":  m.Detail,
			})
		}
		rctx["matched_by"] = matched
	}
	return &AuthZenEvaluationResponse{Decision: r.Allowed, Context: rctx}
}
