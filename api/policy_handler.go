package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"
)

func (a *API) registerPolicyRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("policies"))

	if err := g.POST("/policies", a.createPolicy,
		forge.WithSummary("Create policy"),
		forge.WithDescription("Creates a new ABAC policy."),
		forge.WithOperationID("createPolicy"),
		forge.WithRequestSchema(CreatePolicyRequest{}),
		forge.WithCreatedResponse(&policy.Policy{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.GET("/policies/:policyId", a.getPolicy,
		forge.WithSummary("Get policy"),
		forge.WithOperationID("getPolicy"),
		forge.WithResponseSchema(http.StatusOK, "Policy details", &policy.Policy{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.PUT("/policies/:policyId", a.updatePolicy,
		forge.WithSummary("Update policy"),
		forge.WithOperationID("updatePolicy"),
		forge.WithRequestSchema(UpdatePolicyRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Updated policy", &policy.Policy{}),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	if err := g.DELETE("/policies/:policyId", a.deletePolicy,
		forge.WithSummary("Delete policy"),
		forge.WithOperationID("deletePolicy"),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	); err != nil {
		return err
	}

	return g.GET("/policies", a.listPolicies,
		forge.WithSummary("List policies"),
		forge.WithOperationID("listPolicies"),
		forge.WithRequestSchema(ListPoliciesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Policy list", []*policy.Policy{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) createPolicy(ctx forge.Context, req *CreatePolicyRequest) (*policy.Policy, error) {
	if req.Name == "" {
		return nil, forge.BadRequest("name is required")
	}
	if req.Effect != string(policy.EffectAllow) && req.Effect != string(policy.EffectDeny) {
		return nil, forge.BadRequest("effect must be 'allow' or 'deny'")
	}

	now := time.Now()
	p := &policy.Policy{
		ID:          id.NewPolicyID(),
		Name:        req.Name,
		Description: req.Description,
		Effect:      policy.Effect(req.Effect),
		Priority:    req.Priority,
		IsActive:    req.IsActive,
		Version:     1,
		Subjects:    req.Subjects,
		Actions:     req.Actions,
		Resources:   req.Resources,
		Metadata:    req.Metadata,
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
	}

	return p, ctx.JSON(http.StatusCreated, p)
}

func (a *API) getPolicy(ctx forge.Context, _ *GetPolicyRequest) (*policy.Policy, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	p, err := a.eng.Store().GetPolicy(ctx.Context(), polID)
	if err != nil {
		return nil, mapError(err)
	}

	return p, ctx.JSON(http.StatusOK, p)
}

func (a *API) updatePolicy(ctx forge.Context, req *UpdatePolicyRequest) (*policy.Policy, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	p, err := a.eng.Store().GetPolicy(ctx.Context(), polID)
	if err != nil {
		return nil, mapError(err)
	}

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
	p.Version++
	p.UpdatedAt = time.Now()

	if err := a.eng.Store().UpdatePolicy(ctx.Context(), p); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPolicyUpdated(ctx.Context(), p)
	}

	return p, ctx.JSON(http.StatusOK, p)
}

func (a *API) deletePolicy(ctx forge.Context, _ *GetPolicyRequest) (*struct{}, error) {
	polID, err := id.ParsePolicyID(ctx.Param("policyId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	if err := a.eng.Store().DeletePolicy(ctx.Context(), polID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitPolicyDeleted(ctx.Context(), polID)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listPolicies(ctx forge.Context, req *ListPoliciesRequest) ([]*policy.Policy, error) {
	filter := &policy.ListFilter{
		Search: req.Search,
		Limit:  defaultLimit(req.Limit),
		Offset: req.Offset,
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

	return policies, ctx.JSON(http.StatusOK, policies)
}
