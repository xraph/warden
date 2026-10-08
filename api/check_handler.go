package api

import (
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	"golang.org/x/sync/errgroup"

	"github.com/xraph/warden"
)

// maxCheckBodyBytes caps the request body accepted on the check routes,
// independent of the app-wide default, so a caller can't force the
// server to buffer an arbitrarily large batch-check payload.
const maxCheckBodyBytes = 256 << 10

// defaultMaxBatchChecks is used when the engine's Config.MaxBatchChecks
// is unset (zero), matching warden.DefaultConfig().
const defaultMaxBatchChecks = 100

// batchParallelism bounds how many checks in a batch run concurrently.
const batchParallelism = 8

func (a *API) registerCheckRoutes(router forge.Router) error {
	g := router.Group("/v1/authz", forge.WithGroupTags("authorization"))

	authz := a.authorize("check", "warden:authz")

	if err := g.POST("/check", a.check,
		forge.WithSummary("Authorization check"),
		forge.WithDescription("Evaluates whether the subject can perform the action on the resource."),
		forge.WithOperationID("authzCheck"),
		forge.WithRequestSchema(CheckRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Check result", CheckResponse{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(authz),
		forge.WithMaxBodySize(maxCheckBodyBytes),
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
		forge.WithMiddleware(authz),
		forge.WithMaxBodySize(maxCheckBodyBytes),
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
		forge.WithMiddleware(authz),
		forge.WithMaxBodySize(maxCheckBodyBytes),
	)
}

func (a *API) check(ctx forge.Context, req *CheckRequest) (*CheckResponse, error) {
	if err := validateCheckRequest(req); err != nil {
		return nil, err
	}

	result, err := a.eng.Check(ctx.Context(), toCheckRequest(req))
	if err != nil {
		return nil, mapError(err)
	}

	// No explicit ctx.JSON: Forge auto-serializes a non-nil return value
	// at 200, which is exactly what a plain "allowed or not" check
	// response needs.
	resp := toCheckResponse(result)
	return resp, nil
}

func (a *API) enforce(ctx forge.Context, req *CheckRequest) (*CheckResponse, error) {
	if err := validateCheckRequest(req); err != nil {
		return nil, err
	}

	result, err := a.eng.Check(ctx.Context(), toCheckRequest(req))
	if err != nil {
		return nil, mapError(err)
	}

	resp := toCheckResponse(result)
	if !result.Allowed {
		// A non-200 status needs an explicit write; return nil so Forge's
		// auto-serializer (always 200) doesn't also write the body.
		return nil, ctx.JSON(http.StatusForbidden, resp)
	}
	return resp, nil
}

func (a *API) maxBatchChecks() int {
	if n := a.eng.Config().MaxBatchChecks; n > 0 {
		return n
	}
	return defaultMaxBatchChecks
}

func (a *API) batchCheck(ctx forge.Context, req *BatchCheckRequest) (*BatchCheckResponse, error) {
	if len(req.Checks) == 0 {
		verr := forge.NewValidationErrors()
		verr.AddWithCode("checks", "checks cannot be empty", "MIN_ITEMS", nil)
		return nil, verr
	}
	if maxBatch := a.maxBatchChecks(); len(req.Checks) > maxBatch {
		return nil, forge.NewHTTPError(http.StatusUnprocessableEntity,
			fmt.Sprintf("checks exceeds the maximum batch size of %d", maxBatch))
	}

	results := make([]CheckResponse, len(req.Checks))
	g, gctx := errgroup.WithContext(ctx.Context())
	g.SetLimit(batchParallelism)

	for i := range req.Checks {
		i, c := i, req.Checks[i]
		if err := validateCheckRequestAt(&c, fmt.Sprintf("checks[%d]", i)); err != nil {
			results[i] = CheckResponse{Error: err.Error()}
			continue
		}
		g.Go(func() error {
			result, err := a.eng.Check(gctx, toCheckRequest(&c))
			if err != nil {
				results[i] = CheckResponse{Error: err.Error()}
				return nil
			}
			results[i] = *toCheckResponse(result)
			return nil
		})
	}
	_ = g.Wait() //nolint:errcheck // per-item errors are captured in results; nothing to propagate

	return &BatchCheckResponse{Results: results}, nil
}

func validateCheckRequest(req *CheckRequest) error {
	return validateCheckRequestAt(req, "")
}

func validateCheckRequestAt(req *CheckRequest, prefix string) error {
	verr := forge.NewValidationErrors()
	fieldName := func(name string) string {
		if prefix != "" {
			return prefix + "." + name
		}
		return name
	}
	if req.SubjectID == "" {
		verr.AddWithCode(fieldName("subject_id"), "subject_id is required", "REQUIRED", nil)
	}
	if req.SubjectKind != "" && !validSubjectKind(req.SubjectKind) {
		verr.AddWithCode(fieldName("subject_kind"), "subject_kind must be one of user, api_key, service, service_acct", "ENUM", req.SubjectKind)
	}
	if req.Action == "" {
		verr.AddWithCode(fieldName("action"), "action is required", "REQUIRED", nil)
	}
	if req.ResourceType == "" {
		verr.AddWithCode(fieldName("resource_type"), "resource_type is required", "REQUIRED", nil)
	}
	if verr.HasErrors() {
		return verr
	}
	return nil
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
		Reason:     sanitizeReason(r.Reason),
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
