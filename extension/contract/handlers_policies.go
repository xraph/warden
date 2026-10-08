// handlers_policies.go: the policy surface, reads and writes.
//
// A policy row carries two kinds of fact. The stored fields say what was
// written. analysePolicy says what the policy will do, and the two disagree
// more often than they should: an allow whose condition throws looks exactly
// like a working allow, and a deny with a broken condition applies to every
// check. So the state, failsClosed, neverApplies and matchesEverything flags
// on every row come from the analysis, computed at read time, never stored
// and never guessed by a page.
//
// The writes hold two rules the REST API does not. Every write is validated
// by collectPolicyIssues, so the dashboard cannot store a condition that
// cannot behave the way it reads. And a create is always stored inactive: a
// new policy with no matchers matches every check in its namespace and
// below, so storing it active would make an empty allow grant everything.
// Activation is an explicit policies.setActive.
package contract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/warden"
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

// rfc3339Ptr formats a window bound at full precision. A stored bound can
// carry a fraction of a second (the policy writes here parse one, and a Go
// caller can set any time), and a projection cut to the second would show a
// different instant from the one EffectiveAt compares. A whole-second bound
// has no fraction to print, so it reads as it always has.
func rfc3339Ptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
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

// PolicyCreateInput creates a policy. It is always stored INACTIVE: a new
// policy with no matchers matches every check in its namespace and below,
// so storing it active would make an empty allow grant everything, or an
// empty deny lock everyone out, the moment it is saved. Activation is an
// explicit policies.setActive. The REST create honours isActive; this
// contract deliberately does not.
type PolicyCreateInput struct {
	PolicyDraft
	NamespacePath string `json:"namespacePath,omitempty"`
}

// PolicyUpdateInput patches a policy. Namespace is not patchable. An empty
// string on NotBefore or NotAfter clears that bound.
//
// ExpectedVersion is the version the caller loaded. When it is present and
// older than the stored version, the update is refused as stale and nothing
// is written, so an editor cannot save over a change it never saw. A version
// above the stored one, or a negative one, was never stored, so it is refused
// as bad input. Absent, the update is still guarded against a write that lands
// between this handler's own read and write, but not against anything older.
type PolicyUpdateInput struct {
	ID              string             `json:"id"`
	ExpectedVersion *int               `json:"expectedVersion,omitempty"`
	Name            *string            `json:"name,omitempty"`
	Description     *string            `json:"description,omitempty"`
	Effect          *string            `json:"effect,omitempty"`
	Priority        *int               `json:"priority,omitempty"`
	NotBefore       *string            `json:"notBefore,omitempty"`
	NotAfter        *string            `json:"notAfter,omitempty"`
	Subjects        *[]PolicySubject   `json:"subjects,omitempty"`
	Actions         *[]string          `json:"actions,omitempty"`
	Resources       *[]string          `json:"resources,omitempty"`
	Conditions      *[]PolicyCondition `json:"conditions,omitempty"`
	Obligations     *[]string          `json:"obligations,omitempty"`
}

// PolicySetActiveInput turns a policy on or off and changes nothing else.
type PolicySetActiveInput struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}

// PolicyDeleteInput names the policy to remove.
type PolicyDeleteInput struct {
	ID string `json:"id"`
}

// parseWindow turns the two wire bounds into stored times. An empty string
// is no bound. The strings were already accepted by windowIssue, so an error
// here means a caller skipped validation.
func parseWindow(notBefore, notAfter string) (nb, na *time.Time, err error) {
	parse := func(raw string) (*time.Time, error) {
		if raw == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, badRequest("not an RFC3339 time: " + raw)
		}
		t = t.UTC()
		return &t, nil
	}
	if nb, err = parse(notBefore); err != nil {
		return nil, nil, err
	}
	if na, err = parse(notAfter); err != nil {
		return nil, nil, err
	}
	return nb, na, nil
}

func policiesCreateHandler(deps Deps) func(context.Context, PolicyCreateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PolicyCreateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return AckResponse{}, err
		}
		if err := issuesError(collectPolicyIssues(in.PolicyDraft, allParts)); err != nil {
			return AckResponse{}, err
		}
		nb, na, err := parseWindow(in.NotBefore, in.NotAfter)
		if err != nil {
			return AckResponse{}, err
		}
		ctx = withActor(ctx, p)
		actor := actorFor(p)
		now := time.Now().UTC()
		pol := &policy.Policy{
			ID:            id.NewPolicyID(),
			TenantID:      tenantID,
			NamespacePath: in.NamespacePath,
			Name:          strings.TrimSpace(in.Name),
			Description:   in.Description,
			Effect:        policy.Effect(in.Effect),
			Priority:      in.Priority,
			// Always inactive, see PolicyCreateInput.
			IsActive:    false,
			NotBefore:   nb,
			NotAfter:    na,
			Obligations: trimmedList(in.Obligations),
			Version:     1,
			Subjects:    toPolicySubjects(in.Subjects),
			Actions:     trimmedList(in.Actions),
			Resources:   trimmedList(in.Resources),
			Conditions:  toPolicyConditions(in.Conditions, nil),
			CreatedBy:   actor.ID,
			UpdatedBy:   actor.ID,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := deps.Engine.Store().CreatePolicy(ctx, pol); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// Same emissions as the REST handler (api/policy_handler.go). Only
		// after the store accepted the write: a refused write emits nothing.
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPolicyCreated(ctx, pol)
		}
		emitAudit(ctx, deps, p, "policy.created", tenantID, pol.ID.String(), pol, nil)
		return AckResponse{ID: pol.ID.String()}, nil
	}
}

// draftAndParts describes a patch as the draft collectPolicyIssues judges:
// each present field, and the parts that are present. The window is not one
// of them: it is judged by mergedWindow on exact times, because a string
// round trip through rfc3339 drops sub-seconds.
func draftAndParts(in PolicyUpdateInput) (PolicyDraft, draftParts) {
	var d PolicyDraft
	var parts draftParts
	if in.Name != nil {
		d.Name, parts.name = *in.Name, true
	}
	if in.Effect != nil {
		d.Effect, parts.effect = *in.Effect, true
	}
	if in.Subjects != nil {
		d.Subjects, parts.subjects = *in.Subjects, true
	}
	if in.Actions != nil {
		d.Actions, parts.actions = *in.Actions, true
	}
	if in.Resources != nil {
		d.Resources, parts.resources = *in.Resources, true
	}
	if in.Conditions != nil {
		d.Conditions, parts.conditions = *in.Conditions, true
	}
	if in.Obligations != nil {
		d.Obligations, parts.obligations = *in.Obligations, true
	}
	return d, parts
}

// mergedWindow is the window after the patch, as exact times. A bound the
// patch does not name is the stored *time.Time itself, never a formatted
// copy, so an unrelated update cannot truncate it. An empty string clears a
// bound. The message is why the pair cannot be saved, or "".
func mergedWindow(before *policy.Policy, in PolicyUpdateInput) (nb, na *time.Time, msg string) {
	nb, na = before.NotBefore, before.NotAfter
	bound := func(raw *string, cur *time.Time, notATime string) (*time.Time, string) {
		if raw == nil {
			return cur, ""
		}
		if *raw == "" {
			return nil, ""
		}
		t, err := time.Parse(time.RFC3339, *raw)
		if err != nil {
			return cur, notATime
		}
		t = t.UTC()
		return &t, ""
	}
	if nb, msg = bound(in.NotBefore, nb, windowStartNotATime); msg != "" {
		return nb, na, msg
	}
	if na, msg = bound(in.NotAfter, na, windowEndNotATime); msg != "" {
		return nb, na, msg
	}
	return nb, na, windowOrderIssue(nb, na)
}

func policiesUpdateHandler(deps Deps) func(context.Context, PolicyUpdateInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PolicyUpdateInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		pid, err := parsePolicyID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		before, err := s.GetPolicy(ctx, tenantID, pid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		// Checked before validation: an edit made from a stale copy is
		// refused as stale even when it is also invalid, because fixing the
		// input would not make it saveable.
		if err := checkExpectedVersion(before, in.ExpectedVersion); err != nil {
			return AckResponse{}, err
		}
		// Only what the patch changes is validated, so a policy stored
		// with a bad condition before this validation existed can still
		// have its description edited.
		merged, parts := draftAndParts(in)
		issues := collectPolicyIssues(merged, parts)
		// The window is a part if either bound is patched, and is judged as
		// the merged pair, so a new start after the stored end is refused.
		windowPatched := in.NotBefore != nil || in.NotAfter != nil
		nb, na, windowMsg := mergedWindow(before, in)
		if windowPatched && windowMsg != "" {
			issues.Fields["window"] = windowMsg
		}
		if err := issuesError(issues); err != nil {
			return AckResponse{}, err
		}

		// The store persists the whole struct, so this is read, patch
		// the present fields on a copy, write. The copy is shallow and every
		// patched slice is replaced rather than edited, so before stays the
		// stored policy the audit event reports.
		pol := *before
		if in.Name != nil {
			pol.Name = strings.TrimSpace(*in.Name)
		}
		if in.Description != nil {
			pol.Description = *in.Description
		}
		if in.Effect != nil {
			pol.Effect = policy.Effect(*in.Effect)
		}
		if in.Priority != nil {
			pol.Priority = *in.Priority
		}
		if windowPatched {
			pol.NotBefore, pol.NotAfter = nb, na
		}
		if in.Subjects != nil {
			pol.Subjects = toPolicySubjects(*in.Subjects)
		}
		if in.Actions != nil {
			pol.Actions = trimmedList(*in.Actions)
		}
		if in.Resources != nil {
			pol.Resources = trimmedList(*in.Resources)
		}
		if in.Conditions != nil {
			pol.Conditions = toPolicyConditions(*in.Conditions, before.Conditions)
		}
		if in.Obligations != nil {
			pol.Obligations = trimmedList(*in.Obligations)
		}

		// A rename onto a name already in this namespace. The guard is what
		// excludes renaming a policy to its own name. Every store refuses
		// the rename itself with ErrDuplicatePolicy; asking first gives the
		// page the refusal before the versioned write, and a rename that
		// races past this read is still refused by the store.
		if in.Name != nil && pol.Name != before.Name {
			_, err := s.GetPolicyByName(ctx, tenantID, before.NamespacePath, pol.Name)
			switch {
			case err == nil:
				return AckResponse{}, mapWardenError(fmt.Errorf("policy %q in ns %q: %w", pol.Name, before.NamespacePath, warden.ErrDuplicatePolicy))
			case !errors.Is(err, warden.ErrPolicyNotFound):
				return AckResponse{}, mapWardenError(err)
			}
		}

		ctx = withActor(ctx, p)
		return writePolicy(ctx, deps, p, tenantID, before, &pol)
	}
}

// checkExpectedVersion refuses an update whose caller loaded a version other
// than the stored one. Versions only grow, so an expected version below the
// stored one means the policy changed after the caller read it. One above
// it was never stored, so it is bad input rather than a stale copy, and so
// is a negative one. Equality is tested first: a policy written straight
// through a store without a version sits at 0, and its editor sends 0.
func checkExpectedVersion(before *policy.Policy, expected *int) error {
	if expected == nil {
		return nil
	}
	if *expected == before.Version {
		return nil
	}
	if *expected < 0 {
		return badRequest(fmt.Sprintf("expectedVersion %d is not a version: versions are never negative", *expected))
	}
	if *expected > before.Version {
		return badRequest(fmt.Sprintf("expectedVersion %d is ahead of the stored version %d", *expected, before.Version))
	}
	return mapWardenError(fmt.Errorf("policy %s, expected version %d, stored version %d: %w",
		before.ID, *expected, before.Version, warden.ErrPolicyVersionConflict))
}

// writePolicy stamps and stores a patched copy and emits what the REST
// update emits. Both policies.update and policies.setActive end here: REST
// has no separate activate action, and an audit consumer keys on REST's
// vocabulary, so both are "policy.updated".
//
// The write is conditional on the version read as before. Anything that
// lands between that read and this write (another save, a toggle, a REST
// update, a DSL apply) moves the version, and the store then refuses this
// write rather than letting it silently undo the other one.
func writePolicy(ctx context.Context, deps Deps, p dashcontract.Principal, tenantID string, before, pol *policy.Policy) (AckResponse, error) {
	pol.UpdatedBy = actorFor(p).ID
	pol.Version = before.Version + 1
	pol.UpdatedAt = time.Now().UTC()
	if err := deps.Engine.Store().UpdatePolicyIfVersion(ctx, pol, before.Version); err != nil {
		return AckResponse{}, mapWardenError(err)
	}
	if pl := deps.Engine.Plugins(); pl != nil {
		pl.EmitPolicyUpdated(ctx, pol)
	}
	emitAudit(ctx, deps, p, "policy.updated", tenantID, pol.ID.String(), pol, before)
	return AckResponse{}, nil
}

func policiesSetActiveHandler(deps Deps) func(context.Context, PolicySetActiveInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PolicySetActiveInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		pid, err := parsePolicyID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		before, err := deps.Engine.Store().GetPolicy(ctx, tenantID, pid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		pol := *before
		pol.IsActive = in.Active
		ctx = withActor(ctx, p)
		return writePolicy(ctx, deps, p, tenantID, before, &pol)
	}
}

func policiesDeleteHandler(deps Deps) func(context.Context, PolicyDeleteInput, dashcontract.Principal) (AckResponse, error) {
	return func(ctx context.Context, in PolicyDeleteInput, p dashcontract.Principal) (AckResponse, error) {
		if err := requireEngine(deps); err != nil {
			return AckResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return AckResponse{}, err
		}
		pid, err := parsePolicyID(in.ID)
		if err != nil {
			return AckResponse{}, err
		}
		s := deps.Engine.Store()
		// Read first: it makes another tenant's policy NOT_FOUND and gives
		// the audit event the row that is about to disappear.
		before, err := s.GetPolicy(ctx, tenantID, pid)
		if err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		ctx = withActor(ctx, p)
		if err := s.DeletePolicy(ctx, tenantID, pid); err != nil {
			return AckResponse{}, mapWardenError(err)
		}
		if pl := deps.Engine.Plugins(); pl != nil {
			pl.EmitPolicyDeleted(ctx, pid)
		}
		emitAudit(ctx, deps, p, "policy.deleted", tenantID, pid.String(), nil, before)
		return AckResponse{}, nil
	}
}
