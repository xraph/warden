// handlers_policies.go: the read side of the policy surface.
//
// A policy row carries two kinds of fact. The stored fields say what was
// written. analysePolicy says what the policy will do, and the two disagree
// more often than they should: an allow whose condition throws looks exactly
// like a working allow, and a deny with a broken condition applies to every
// check. So the state, failsClosed, neverApplies and matchesEverything flags
// on every row come from the analysis, computed at read time, never stored
// and never guessed by a page.
package contract

import (
	"context"
	"time"

	"github.com/xraph/warden/id"
	"github.com/xraph/warden/policy"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// PolicySummary is one row of the policies list.
//
// State, FailsClosed, NeverApplies and MatchesEverything are computed by
// analysePolicy, because the stored fields do not say them and a page that
// guessed would guess wrong: an allow whose condition throws looks exactly
// like a working allow.
type PolicySummary struct {
	ID                string `json:"id"`
	NamespacePath     string `json:"namespacePath"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	Effect            string `json:"effect"`
	Priority          int    `json:"priority"`
	IsActive          bool   `json:"isActive"`
	State             string `json:"state"`
	FailsClosed       bool   `json:"failsClosed"`
	NeverApplies      bool   `json:"neverApplies"`
	MatchesEverything bool   `json:"matchesEverything"`
	Version           int    `json:"version"`
	UpdatedAt         string `json:"updatedAt"`
}

// PolicyConditionView is a stored condition plus what it will do.
type PolicyConditionView struct {
	PolicyCondition
	Problem string `json:"problem,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyDetail is one policy, everything the rule block renders.
type PolicyDetail struct {
	PolicySummary
	Subjects              []PolicySubject       `json:"subjects"`
	Actions               []string              `json:"actions"`
	Resources             []string              `json:"resources"`
	Conditions            []PolicyConditionView `json:"conditions"`
	Obligations           []string              `json:"obligations"`
	NotBefore             string                `json:"notBefore,omitempty"`
	NotAfter              string                `json:"notAfter,omitempty"`
	SubjectsUnrestricted  bool                  `json:"subjectsUnrestricted"`
	ActionsUnrestricted   bool                  `json:"actionsUnrestricted"`
	ResourcesUnrestricted bool                  `json:"resourcesUnrestricted"`
	HasRoleMatcher        bool                  `json:"hasRoleMatcher"`
	// DecidingCondition is the index of the condition that makes the
	// policy fail closed or never apply. Absent when neither.
	DecidingCondition *int   `json:"decidingCondition,omitempty"`
	CreatedBy         string `json:"createdBy,omitempty"`
	UpdatedBy         string `json:"updatedBy,omitempty"`
	CreatedAt         string `json:"createdAt"`
}

// PoliciesListInput filters the policy list. NamespacePath is a pointer for
// the same reason it is on every other list: nil means every namespace and
// "" means the root namespace only.
type PoliciesListInput struct {
	PageRequest
	NamespacePath *string `json:"namespacePath,omitempty"`
	Effect        string  `json:"effect,omitempty"`
	IsActive      *bool   `json:"isActive,omitempty"`
	Search        string  `json:"search,omitempty"`
}

// PoliciesListResponse is the paged reply.
type PoliciesListResponse struct {
	PageMeta
	Items []PolicySummary `json:"items"`
}

// PolicyDetailInput names the policy to read, by id.
type PolicyDetailInput struct {
	ID string `json:"id"`
}

func parsePolicyID(raw string) (id.PolicyID, error) {
	pid, err := id.ParsePolicyID(raw)
	if err != nil {
		return id.Nil, badRequest("not a policy id: " + raw)
	}
	return pid, nil
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func rfc3339Ptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return rfc3339(*t)
}

// projectPolicySummary is the list row, analysed as of now.
func projectPolicySummary(p *policy.Policy, now time.Time) PolicySummary {
	return summaryOf(p, analysePolicy(p, now))
}

// summaryOf builds the row from an analysis already in hand, so the detail
// projection, which needs the whole analysis anyway, does not run it twice.
func summaryOf(p *policy.Policy, a policyAnalysis) PolicySummary {
	return PolicySummary{
		ID:                p.ID.String(),
		NamespacePath:     p.NamespacePath,
		Name:              p.Name,
		Description:       p.Description,
		Effect:            string(p.Effect),
		Priority:          p.Priority,
		IsActive:          p.IsActive,
		State:             a.State,
		FailsClosed:       a.FailsClosed,
		NeverApplies:      a.NeverApplies,
		MatchesEverything: a.MatchesEverything,
		Version:           p.Version,
		UpdatedAt:         rfc3339(p.UpdatedAt),
	}
}

// projectPolicyDetail builds the full view, analysed as of now. Every slice
// is non-nil so the JSON carries [] and a page never has to guard against
// null.
func projectPolicyDetail(p *policy.Policy, now time.Time) PolicyDetail {
	a := analysePolicy(p, now)
	d := PolicyDetail{
		PolicySummary:         summaryOf(p, a),
		Subjects:              make([]PolicySubject, 0, len(p.Subjects)),
		Actions:               append([]string{}, p.Actions...),
		Resources:             append([]string{}, p.Resources...),
		Conditions:            make([]PolicyConditionView, 0, len(p.Conditions)),
		Obligations:           append([]string{}, p.Obligations...),
		NotBefore:             rfc3339Ptr(p.NotBefore),
		NotAfter:              rfc3339Ptr(p.NotAfter),
		SubjectsUnrestricted:  a.SubjectsUnrestricted,
		ActionsUnrestricted:   a.ActionsUnrestricted,
		ResourcesUnrestricted: a.ResourcesUnrestricted,
		HasRoleMatcher:        a.HasRoleMatcher,
		CreatedBy:             p.CreatedBy,
		UpdatedBy:             p.UpdatedBy,
		CreatedAt:             rfc3339(p.CreatedAt),
	}
	for _, s := range p.Subjects {
		d.Subjects = append(d.Subjects, PolicySubject{Kind: s.Kind, ID: s.ID, Role: s.Role})
	}
	for i, c := range p.Conditions {
		v := PolicyConditionView{
			PolicyCondition: PolicyCondition{
				ID:       c.ID.String(),
				Field:    c.Field,
				Operator: string(c.Operator),
				Value:    c.Value,
			},
		}
		// analysePolicy sizes Problems and Reasons to Conditions, so the
		// index is always in range; the guard is for a future change to it.
		if i < len(a.Problems) {
			v.Problem = string(a.Problems[i])
		}
		if i < len(a.Reasons) {
			v.Reason = string(a.Reasons[i])
		}
		d.Conditions = append(d.Conditions, v)
	}
	if a.DecidingCondition >= 0 {
		idx := a.DecidingCondition
		d.DecidingCondition = &idx
	}
	return d
}

func policiesListHandler(deps Deps) func(context.Context, PoliciesListInput, dashcontract.Principal) (PoliciesListResponse, error) {
	return func(ctx context.Context, in PoliciesListInput, p dashcontract.Principal) (PoliciesListResponse, error) {
		if err := requireEngine(deps); err != nil {
			return PoliciesListResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PoliciesListResponse{}, err
		}
		limit, offset := in.Clamp()
		// One filter for the page and the count, so total always honours
		// whatever the page was filtered by.
		filter := &policy.ListFilter{
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Effect:        policy.Effect(in.Effect),
			IsActive:      in.IsActive,
			Search:        in.Search,
			Limit:         limit,
			Offset:        offset,
		}
		s := deps.Engine.Store()
		rows, err := s.ListPolicies(ctx, filter)
		if err != nil {
			return PoliciesListResponse{}, mapWardenError(err)
		}
		total, err := s.CountPolicies(ctx, filter)
		if err != nil {
			return PoliciesListResponse{}, mapWardenError(err)
		}
		now := time.Now()
		out := PoliciesListResponse{
			PageMeta: newPageMeta(total, limit, offset),
			Items:    make([]PolicySummary, 0, len(rows)),
		}
		for _, pol := range rows {
			out.Items = append(out.Items, projectPolicySummary(pol, now))
		}
		return out, nil
	}
}

func policiesDetailHandler(deps Deps) func(context.Context, PolicyDetailInput, dashcontract.Principal) (PolicyDetail, error) {
	return func(ctx context.Context, in PolicyDetailInput, p dashcontract.Principal) (PolicyDetail, error) {
		if err := requireEngine(deps); err != nil {
			return PolicyDetail{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return PolicyDetail{}, err
		}
		pid, err := parsePolicyID(in.ID)
		if err != nil {
			return PolicyDetail{}, err
		}
		pol, err := deps.Engine.Store().GetPolicy(ctx, tenantID, pid)
		if err != nil {
			return PolicyDetail{}, mapWardenError(err)
		}
		return projectPolicyDetail(pol, time.Now()), nil
	}
}
