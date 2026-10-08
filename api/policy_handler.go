package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
	"github.com/xraph/warden/policy"
)

func (a *API) registerPolicyRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("policies"))

	manage := a.authorize("manage", "warden:policy")
	read := a.authorize("read", "warden:policy")

	if err := g.POST("/policies", a.createPolicy,
		forge.WithSummary("Create policy"),
		forge.WithDescription("Creates a new ABAC policy."),
		forge.WithOperationID("wardenCreatePolicy"),
		forge.WithRequestSchema(CreatePolicyRequest{}),
		forge.WithCreatedResponse(&policy.Policy{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.GET("/policies/:policyId", a.getPolicy,
		forge.WithSummary("Get policy"),
		forge.WithOperationID("wardenGetPolicy"),
		forge.WithRequestSchema(GetPolicyRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Policy details", &policy.Policy{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	); err != nil {
		return err
	}

	if err := g.PUT("/policies/:policyId", a.updatePolicy,
		forge.WithSummary("Update policy"),
		forge.WithOperationID("wardenUpdatePolicy"),
		forge.WithRequestSchema(UpdatePolicyRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Updated policy", &policy.Policy{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.DELETE("/policies/:policyId", a.deletePolicy,
		forge.WithSummary("Delete policy"),
		forge.WithOperationID("wardenDeletePolicy"),
		forge.WithRequestSchema(GetPolicyRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	return g.GET("/policies", a.listPolicies,
		forge.WithSummary("List policies"),
		forge.WithOperationID("wardenListPolicies"),
		forge.WithRequestSchema(ListPoliciesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Policy list", []*policy.Policy{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	)
}

func (a *API) createPolicy(ctx forge.Context, req *CreatePolicyRequest) (*policy.Policy, error) {
	{
		verr := forge.NewValidationErrors()
		if req.Name == "" {
			verr.AddWithCode("name", "name is required", "REQUIRED", nil)
		}
		if req.Effect != string(policy.EffectAllow) && req.Effect != string(policy.EffectDeny) {
			verr.AddWithCode("effect", "effect must be 'allow' or 'deny'", "ENUM", req.Effect)
		}
		addConditionErrors(verr, req.Conditions)
		if verr.HasErrors() {
			return nil, verr
		}
	}

	appID, tenantID := scopeFromForgeContext(ctx)
	actor, _ := warden.ActorFromContext(ctx.Context())
	now := time.Now()
	p := &policy.Policy{
		ID:          id.NewPolicyID(),
		TenantID:    tenantID,
		AppID:       appID,
		Name:        req.Name,
		Description: req.Description,
		Effect:      policy.Effect(req.Effect),
		Priority:    req.Priority,
		IsActive:    req.IsActive,
		NotBefore:   req.NotBefore,
		NotAfter:    req.NotAfter,
		Obligations: req.Obligations,
		Version:     1,
		Subjects:    req.Subjects,
		Actions:     req.Actions,
		Resources:   req.Resources,
		Metadata:    req.Metadata,
		CreatedBy:   actor.ID,
		UpdatedBy:   actor.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	for _, c := range req.Conditions {
		p.Conditions = append(p.Conditions, policy.Condition{
			ID:       id.NewConditionID(),
			Field:    c.Field,
			Operator: policy.Operator(c.Operator),
			Value:    c.Value,
		})
	}

	if err := a.eng.Store().CreatePolicy(ctx.Context(), p); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPolicyCreated(ctx.Context(), p)
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: now, Action: "policy.created",
			TenantID: tenantID, EntityID: p.ID.String(), Entity: p,
		})
	}

	return nil, ctx.JSON(http.StatusCreated, p)
}

func (a *API) getPolicy(ctx forge.Context, _ *GetPolicyRequest) (*policy.Policy, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)

	p, err := a.eng.Store().GetPolicy(ctx.Context(), tenantID, polID)
	if err != nil {
		return nil, mapError(err)
	}

	return p, nil
}

func (a *API) updatePolicy(ctx forge.Context, req *UpdatePolicyRequest) (*policy.Policy, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	// Only conditions the request sends are checked, so a policy stored
	// with a bad condition can still have its other fields edited.
	if req.Conditions != nil {
		verr := forge.NewValidationErrors()
		addConditionErrors(verr, req.Conditions)
		if verr.HasErrors() {
			return nil, verr
		}
	}

	_, tenantID := scopeFromForgeContext(ctx)

	before, err := a.eng.Store().GetPolicy(ctx.Context(), tenantID, polID)
	if err != nil {
		return nil, mapError(err)
	}
	p := *before

	if req.Name != "" {
		p.Name = req.Name
	}
	if req.Description != "" {
		p.Description = req.Description
	}
	if req.Effect != "" {
		p.Effect = policy.Effect(req.Effect)
	}
	if req.Priority != nil {
		p.Priority = *req.Priority
	}
	if req.IsActive != nil {
		p.IsActive = *req.IsActive
	}
	if req.NotBefore != nil {
		p.NotBefore = req.NotBefore
	}
	if req.NotAfter != nil {
		p.NotAfter = req.NotAfter
	}
	if req.Obligations != nil {
		p.Obligations = req.Obligations
	}
	if req.Subjects != nil {
		p.Subjects = req.Subjects
	}
	if req.Actions != nil {
		p.Actions = req.Actions
	}
	if req.Resources != nil {
		p.Resources = req.Resources
	}
	if req.Conditions != nil {
		p.Conditions = nil
		for _, c := range req.Conditions {
			p.Conditions = append(p.Conditions, policy.Condition{
				ID:       id.NewConditionID(),
				Field:    c.Field,
				Operator: policy.Operator(c.Operator),
				Value:    c.Value,
			})
		}
	}
	if req.Metadata != nil {
		p.Metadata = req.Metadata
	}
	actor, _ := warden.ActorFromContext(ctx.Context())
	p.UpdatedBy = actor.ID
	p.Version = before.Version + 1
	p.UpdatedAt = time.Now()

	// Conditional on the version read above, so a write that lands in
	// between (another update, a dashboard edit, a DSL apply) is answered
	// 409 instead of being silently undone by this one.
	if err := a.eng.Store().UpdatePolicyIfVersion(ctx.Context(), &p, before.Version); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPolicyUpdated(ctx.Context(), &p)
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: p.UpdatedAt, Action: "policy.updated",
			TenantID: tenantID, EntityID: p.ID.String(), Entity: &p, Before: before,
		})
	}

	return &p, nil
}

func (a *API) deletePolicy(ctx forge.Context, _ *GetPolicyRequest) (*struct{}, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)
	before, getErr := a.eng.Store().GetPolicy(ctx.Context(), tenantID, polID)

	if err := a.eng.Store().DeletePolicy(ctx.Context(), tenantID, polID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPolicyDeleted(ctx.Context(), polID)
		actor, _ := warden.ActorFromContext(ctx.Context())
		ev := plugin.Event{
			Actor: actor, At: time.Now(), Action: "policy.deleted",
			TenantID: tenantID, EntityID: polID.String(),
		}
		if getErr == nil {
			ev.Before = before
		}
		a.eng.Plugins().EmitAudit(ctx.Context(), ev)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listPolicies(ctx forge.Context, req *ListPoliciesRequest) (*PolicyListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &policy.ListFilter{
		TenantID: tenantID,
		Search:   req.Search,
		Limit:    defaultLimit(req.Limit),
		Offset:   req.Offset,
	}

	if req.Effect != "" {
		filter.Effect = policy.Effect(req.Effect)
	}
	switch req.Active {
	case "true":
		t := true
		filter.IsActive = &t
	case "false":
		f := false
		filter.IsActive = &f
	}

	policies, err := a.eng.Store().ListPolicies(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return &PolicyListResponse{Body: policies}, nil
}

// addConditionErrors records every condition policy.ValidateCondition
// refuses, keyed conditions[i]. An unknown operator, a field the evaluator
// does not read, an in or not_in value that is not a list, or a regex, CIDR
// or time that does not parse would all store fine and then fail every
// check.
func addConditionErrors(verr *forge.ValidationErrors, conds []ConditionInput) {
	for i, c := range conds {
		err := policy.ValidateCondition(policy.Condition{Field: c.Field, Operator: policy.Operator(c.Operator), Value: c.Value})
		if err != nil {
			verr.AddWithCode(fmt.Sprintf("conditions[%d]", i), strings.TrimPrefix(err.Error(), "policy: "), "INVALID_FORMAT", c.Value)
		}
	}
}
