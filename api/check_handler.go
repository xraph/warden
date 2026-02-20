package api

import (
	"net/http"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

func (a *API) registerCheckRoutes(router forge.Router) error {
	g := router.Group("/v1/authz", forge.WithGroupTags("authorization"))

	if err := g.POST("/check", a.check,
		forge.WithSummary("Authorization check"),
		forge.WithDescription("Evaluates whether the subject can perform the action on the resource."),
		forge.WithOperationID("authzCheck"),
		forge.WithRequestSchema(CheckRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Check result", CheckResponse{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.POST("/enforce", a.enforce,
		forge.WithSummary("Enforce authorization"),
		forge.WithDescription("Returns 200 if allowed, 403 if denied."),
		forge.WithOperationID("authzEnforce"),
		forge.WithRequestSchema(CheckRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Allowed", CheckResponse{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.POST("/batch-check", a.batchCheck,
		forge.WithSummary("Batch authorization check"),
		forge.WithDescription("Evaluates multiple authorization checks in one request."),
		forge.WithOperationID("authzBatchCheck"),
		forge.WithRequestSchema(BatchCheckRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Batch results", BatchCheckResponse{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) check(ctx forge.Context, req *CheckRequest) (*CheckResponse, error) {
	if req.SubjectID == "" || req.Action == "" || req.ResourceType == "" {
		return nil, forge.BadRequest("subject_id, action, and resource_type are required")
	}

	result, err := a.eng.Check(ctx.Context(), toCheckRequest(req))
	if err != nil {
		return nil, mapError(err)
	}

	resp := toCheckResponse(result)
	return resp, ctx.JSON(http.StatusOK, resp)
}

func (a *API) enforce(ctx forge.Context, req *CheckRequest) (*CheckResponse, error) {
	if req.SubjectID == "" || req.Action == "" || req.ResourceType == "" {
		return nil, forge.BadRequest("subject_id, action, and resource_type are required")
	}

	result, err := a.eng.Check(ctx.Context(), toCheckRequest(req))
	if err != nil {
		return nil, mapError(err)
	}

	resp := toCheckResponse(result)
	if !result.Allowed {
		return resp, ctx.JSON(http.StatusForbidden, resp)
	}
	return resp, ctx.JSON(http.StatusOK, resp)
}

func (a *API) batchCheck(ctx forge.Context, req *BatchCheckRequest) (*BatchCheckResponse, error) {
	if len(req.Checks) == 0 {
		return nil, forge.BadRequest("checks cannot be empty")
	}

	results := make([]CheckResponse, len(req.Checks))
	for i, c := range req.Checks {
		result, err := a.eng.Check(ctx.Context(), toCheckRequest(&c))
		if err != nil {
			return nil, mapError(err)
		}
		results[i] = *toCheckResponse(result)
	}

	resp := &BatchCheckResponse{Results: results}
	return resp, ctx.JSON(http.StatusOK, resp)
}

func toCheckRequest(r *CheckRequest) *warden.CheckRequest {
	return &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectKind(r.SubjectKind), ID: r.SubjectID},
		Action:   warden.Action{Name: r.Action},
		Resource: warden.Resource{Type: r.ResourceType, ID: r.ResourceID},
		Context:  r.Context,
	}
}

func toCheckResponse(r *warden.CheckResult) *CheckResponse {
	resp := &CheckResponse{
		Allowed:    r.Allowed,
		Decision:   string(r.Decision),
		Reason:     r.Reason,
		EvalTimeNs: r.EvalTimeNs,
	}
	for _, m := range r.MatchedBy {
		resp.MatchedBy = append(resp.MatchedBy, MatchInfo{
			Source: m.Source,
			RuleID: m.RuleID,
			Detail: m.Detail,
		})
	}
	return resp
}
