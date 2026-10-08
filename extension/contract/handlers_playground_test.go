package contract

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedReader lets user:alice read document in tenant.
func seedReader(t *testing.T, s *memory.Store, tenant string) *role.Role {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{TenantID: tenant, Name: "Reader", Slug: "reader"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	perm := &permission.Permission{TenantID: tenant, Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, tenant, r.ID, permission.Ref{Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		TenantID: tenant, RoleID: r.ID, SubjectKind: "user", SubjectID: "alice",
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	return r
}

func aliceReads() PlaygroundExplainInput {
	return PlaygroundExplainInput{
		SubjectKind:  "user",
		SubjectID:    "alice",
		Action:       "read",
		ResourceType: "document",
		ResourceID:   "doc1",
	}
}

func runExplain(t *testing.T, deps Deps, in PlaygroundExplainInput) PlaygroundExplainResponse {
	t.Helper()
	got, err := playgroundExplainHandler(deps)(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("playground.explain: %v", err)
	}
	return got
}

func laneByModel(t *testing.T, r PlaygroundExplainResponse, model string) PlaygroundLane {
	t.Helper()
	for _, l := range r.Lanes {
		if l.Model == model {
			return l
		}
	}
	t.Fatalf("no %s lane in %+v", model, r.Lanes)
	return PlaygroundLane{}
}

func TestPlaygroundExplainRefusesBadInput(t *testing.T) {
	deps := Deps{Engine: engineOver(t, memory.New())}
	cases := []struct {
		name string
		mut  func(*PlaygroundExplainInput)
		want string
	}{
		{"empty subject id", func(in *PlaygroundExplainInput) { in.SubjectID = "" }, "subjectId is required"},
		{"empty action", func(in *PlaygroundExplainInput) { in.Action = "" }, "action is required"},
		{"empty resource type", func(in *PlaygroundExplainInput) { in.ResourceType = "" }, "resourceType is required"},
		{"invalid namespace", func(in *PlaygroundExplainInput) { in.NamespacePath = "a//b" }, "empty segments"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			in := aliceReads()
			tc.mut(&in)
			_, err := playgroundExplainHandler(deps)(context.Background(), in, principalFor("t1"))
			var ce *dashcontract.Error
			if !errors.As(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
				t.Fatalf("want a BAD_REQUEST refusal, got %v", err)
			}
			if !strings.Contains(ce.Message, tc.want) {
				t.Errorf("message = %q, want it to contain %q", ce.Message, tc.want)
			}
		})
	}
}

// Warden logs checks under kinds outside the four assignments accept: the
// REST API passes "" through and Go callers pass anything. The engine
// evaluates whatever kind it is given, so a logged check must replay here.
func TestPlaygroundExplainEvaluatesAnySubjectKind(t *testing.T) {
	deps := Deps{Engine: engineOver(t, memory.New())}
	for _, kind := range []string{"", "robot"} {
		kind := kind
		t.Run("kind "+strconv.Quote(kind), func(t *testing.T) {
			in := aliceReads()
			in.SubjectKind = kind
			got := runExplain(t, deps, in)
			if got.Allowed {
				t.Fatalf("allowed with no grants: %+v", got)
			}
			rbac := laneByModel(t, got, "rbac")
			if rbac.State != string(warden.LaneNoMatch) {
				t.Errorf("rbac state = %q, want noMatch", rbac.State)
			}
			if rbac.Decision != string(warden.DecisionDenyNoRoles) {
				t.Errorf("rbac decision = %q, want %q", rbac.Decision, warden.DecisionDenyNoRoles)
			}
			wantReason := `subject ` + kind + `:alice has no assigned roles in tenant "t1"`
			if rbac.Reason != wantReason {
				t.Errorf("rbac reason = %q, want %q", rbac.Reason, wantReason)
			}
		})
	}
}

func TestPlaygroundExplainNamespaceRefusalComesFromValidateNamespace(t *testing.T) {
	deps := Deps{Engine: engineOver(t, memory.New())}
	in := aliceReads()
	in.NamespacePath = "a//b"
	_, err := playgroundExplainHandler(deps)(context.Background(), in, principalFor("t1"))
	want := validateNamespace("a//b")
	if err == nil || want == nil || err.Error() != want.Error() {
		t.Fatalf("err = %v, want validateNamespace's %v", err, want)
	}
}

func TestPlaygroundExplainInputHasNoTenantField(t *testing.T) {
	raw, err := json.Marshal(PlaygroundExplainInput{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range m {
		if strings.Contains(strings.ToLower(k), "tenant") {
			t.Errorf("input carries %q: the tenant must come from the principal, never the request", k)
		}
	}
}

func TestPlaygroundExplainIsScopedToTheCallersTenant(t *testing.T) {
	s := memory.New()
	seedReader(t, s, "t2") // only t2 grants alice
	deps := Deps{Engine: engineOver(t, s)}

	got := runExplain(t, deps, aliceReads())
	if got.Allowed {
		t.Fatalf("t1's principal was allowed on a grant only t2 holds: %+v", got)
	}
	if l := laneByModel(t, got, "rbac"); l.State != string(warden.LaneNoMatch) {
		t.Errorf("rbac state = %q, want noMatch", l.State)
	}

	// The same grant in t1 does allow, so the noMatch above is the tenant
	// scope and not a broken seed.
	seedReader(t, s, "t1")
	got = runExplain(t, deps, aliceReads())
	if !got.Allowed {
		t.Fatalf("t1 grant did not allow: %+v", got)
	}
}

func TestPlaygroundExplainRefusesWithoutATenant(t *testing.T) {
	deps := Deps{Engine: engineOver(t, memory.New())}
	_, err := playgroundExplainHandler(deps)(context.Background(), aliceReads(), signedInNoTenant())
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
		t.Fatalf("want PERMISSION_DENIED, got %v", err)
	}
}

func TestPlaygroundExplainProjectsAnRBACAllow(t *testing.T) {
	s := memory.New()
	reader := seedReader(t, s, "t1")
	got := runExplain(t, Deps{Engine: engineOver(t, s)}, aliceReads())

	if !got.Allowed || got.Decision != string(warden.DecisionAllow) {
		t.Fatalf("decision = %q allowed = %v, want allow", got.Decision, got.Allowed)
	}
	if len(got.Lanes) != 3 {
		t.Fatalf("got %d lanes, want 3", len(got.Lanes))
	}
	for i, model := range []string{"rbac", "rebac", "abac"} {
		if got.Lanes[i].Model != model {
			t.Errorf("lane %d model = %q, want %q", i, got.Lanes[i].Model, model)
		}
	}
	rbac, rebac, abac := got.Lanes[0], got.Lanes[1], got.Lanes[2]
	if rbac.State != "allow" || rbac.Decision != "allow" {
		t.Errorf("rbac = %+v, want allow", rbac)
	}
	wantMatch := []CheckLogMatch{{Source: "rbac", RuleID: reader.ID.String(), Detail: "role grants document:read"}}
	if !reflect.DeepEqual(rbac.MatchedBy, wantMatch) {
		t.Errorf("rbac matchedBy = %+v, want %+v", rbac.MatchedBy, wantMatch)
	}
	if rebac.State != "skipped" || rebac.Decision != "" {
		t.Errorf("rebac = %+v, want skipped with no decision", rebac)
	}
	if abac.State != "noMatch" || abac.Decision != "" || abac.Reason != "" {
		t.Errorf("abac = %+v, want noMatch with an empty decision and reason", abac)
	}
	for _, l := range []PlaygroundLane{rebac, abac} {
		if l.MatchedBy == nil || len(l.MatchedBy) != 0 {
			t.Errorf("%s matchedBy = %#v, want an empty, non-nil slice", l.Model, l.MatchedBy)
		}
	}
	if !reflect.DeepEqual(got.MatchedBy, wantMatch) {
		t.Errorf("top-level matchedBy = %+v, want %+v", got.MatchedBy, wantMatch)
	}
	if got.Obligations == nil || len(got.Obligations) != 0 {
		t.Errorf("obligations = %#v, want an empty, non-nil slice", got.Obligations)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "null") {
		t.Errorf("response carries a null: %s", raw)
	}
}

func TestPlaygroundExplainProjectsAnExplicitDenyOverAnRBACAllow(t *testing.T) {
	s := memory.New()
	seedReader(t, s, "t1")
	deny := seedPolicy(t, s, "", "no-reads", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Actions = []string{"read"}
		p.Obligations = []string{"notify-security"}
	})
	got := runExplain(t, Deps{Engine: engineOver(t, s)}, aliceReads())

	if got.Allowed || got.Decision != string(warden.DecisionDenyExplicit) {
		t.Fatalf("decision = %q allowed = %v, want deny_explicit", got.Decision, got.Allowed)
	}
	rbac, abac := laneByModel(t, got, "rbac"), laneByModel(t, got, "abac")
	if rbac.State != "allow" {
		t.Errorf("rbac state = %q, want allow: the deny came from a later model", rbac.State)
	}
	if abac.State != "deny" || abac.Decision != string(warden.DecisionDenyExplicit) {
		t.Fatalf("abac = %+v, want deny with deny_explicit", abac)
	}
	if len(abac.MatchedBy) != 1 || abac.MatchedBy[0].Source != "abac" || abac.MatchedBy[0].RuleID != deny.ID.String() {
		t.Errorf("abac matchedBy = %+v, want the deny policy %s", abac.MatchedBy, deny.ID)
	}
	if !reflect.DeepEqual(got.Obligations, []string{"notify-security"}) {
		t.Errorf("obligations = %v, want [notify-security]", got.Obligations)
	}
	if len(got.MatchedBy) == 0 || got.MatchedBy[0].RuleID != deny.ID.String() {
		t.Errorf("top-level matchedBy = %+v, want the deny policy first", got.MatchedBy)
	}
}

func TestPlaygroundExplainRunsAtTheNamespaceItIsGiven(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "eng", "eng-freeze", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Actions = []string{"read"}
	})
	deps := Deps{Engine: engineOver(t, s)}

	in := aliceReads()
	in.NamespacePath = "eng/platform"
	if got := runExplain(t, deps, in); laneByModel(t, got, "abac").State != "deny" {
		t.Errorf("a policy at eng did not deny a check at eng/platform: %+v", got)
	}

	in.NamespacePath = ""
	if got := runExplain(t, deps, in); laneByModel(t, got, "abac").State == "deny" {
		t.Errorf("a policy at eng denied a check at the tenant root: %+v", got)
	}
}

func TestPlaygroundExplainPassesSubjectAttributesToTheEngine(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "", "mfa-off", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Actions = []string{"read"}
		p.Conditions = []policy.Condition{{Field: "subject.mfa", Operator: policy.OpEquals, Value: false}}
	})
	deps := Deps{Engine: engineOver(t, s)}

	in := aliceReads()
	in.SubjectAttributes = map[string]any{"mfa": false}
	if got := runExplain(t, deps, in); laneByModel(t, got, "abac").State != "deny" {
		t.Errorf("subject.mfa=false did not reach the engine: %+v", got)
	}

	if got := runExplain(t, deps, aliceReads()); laneByModel(t, got, "abac").State == "deny" {
		t.Errorf("the policy denied a subject with no mfa attribute: %+v", got)
	}
}

func TestPlaygroundExplainPassesResourceAttributesToTheEngine(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "", "locked", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Actions = []string{"read"}
		p.Conditions = []policy.Condition{{Field: "resource.locked", Operator: policy.OpEquals, Value: true}}
	})
	deps := Deps{Engine: engineOver(t, s)}

	in := aliceReads()
	in.ResourceAttributes = map[string]any{"locked": true}
	if got := runExplain(t, deps, in); laneByModel(t, got, "abac").State != "deny" {
		t.Errorf("resource.locked=true did not reach the engine: %+v", got)
	}
	if got := runExplain(t, deps, aliceReads()); laneByModel(t, got, "abac").State == "deny" {
		t.Errorf("the policy denied a resource with no locked attribute: %+v", got)
	}
}

func TestPlaygroundExplainPassesContextToTheEngine(t *testing.T) {
	s := memory.New()
	seedPolicy(t, s, "", "bad-ip", func(p *policy.Policy) {
		p.Effect = policy.EffectDeny
		p.Actions = []string{"read"}
		p.Conditions = []policy.Condition{{Field: "context.ip", Operator: policy.OpEquals, Value: "10.0.0.9"}}
	})
	deps := Deps{Engine: engineOver(t, s)}

	in := aliceReads()
	in.Context = map[string]any{"ip": "10.0.0.9"}
	if got := runExplain(t, deps, in); laneByModel(t, got, "abac").State != "deny" {
		t.Errorf("context.ip did not reach the engine: %+v", got)
	}
	if got := runExplain(t, deps, aliceReads()); laneByModel(t, got, "abac").State == "deny" {
		t.Errorf("the policy denied a check with no ip in its context: %+v", got)
	}
}

func TestPlaygroundExplainWritesNoCheckLog(t *testing.T) {
	ctx := context.Background()
	count := func(s *memory.Store) int64 {
		n, err := s.CountCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1"})
		if err != nil {
			t.Fatalf("count check logs: %v", err)
		}
		return n
	}

	s := memory.New()
	seedReader(t, s, "t1")
	eng := engineOver(t, s)
	runExplain(t, Deps{Engine: eng}, aliceReads())
	// Stopping flushes the writer, so a row that was queued has landed.
	if err := eng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := count(s); n != 0 {
		t.Fatalf("explain left %d check log rows, want 0", n)
	}

	// The same request through Check does log, so the zero above is not a
	// writer that never writes.
	cs := memory.New()
	seedReader(t, cs, "t1")
	ceng := engineOver(t, cs)
	if _, err := ceng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document", ID: "doc1"},
		TenantID: "t1",
	}); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := ceng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := count(cs); n != 1 {
		t.Fatalf("Check left %d check log rows, want 1", n)
	}
}

// failingPermsStore fails the read RBAC makes after it has resolved roles.
type failingPermsStore struct{ *memory.Store }

func (failingPermsStore) ListRolePermissionsForRoles(context.Context, string, []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	return nil, errors.New("role permissions unavailable")
}

func TestPlaygroundExplainReportsAFailedModel(t *testing.T) {
	s := memory.New()
	seedReader(t, s, "t1")
	eng, err := warden.NewEngine(warden.WithStore(failingPermsStore{s}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })

	got := runExplain(t, Deps{Engine: eng}, aliceReads())
	if got.Decision != "error" || got.Allowed {
		t.Fatalf("decision = %q allowed = %v, want error and not allowed", got.Decision, got.Allowed)
	}
	if !strings.Contains(got.Error, "role permissions unavailable") {
		t.Errorf("error = %q, want the store's message", got.Error)
	}
	if got.MatchedBy == nil || len(got.MatchedBy) != 0 || got.Obligations == nil || len(got.Obligations) != 0 {
		t.Errorf("matchedBy = %#v obligations = %#v, want both empty and non-nil", got.MatchedBy, got.Obligations)
	}
	rbac := laneByModel(t, got, "rbac")
	if rbac.State != "error" || rbac.Error != "role permissions unavailable" {
		t.Errorf("rbac = %+v, want error with the store's own message", rbac)
	}
	for _, model := range []string{"rebac", "abac"} {
		if l := laneByModel(t, got, model); l.State != "notEvaluated" {
			t.Errorf("%s state = %q, want notEvaluated", model, l.State)
		}
	}
	if len(got.Lanes) != 3 {
		t.Errorf("got %d lanes, want 3", len(got.Lanes))
	}
}

// batchOf builds n copies of alice's read as batch items.
func batchOf(n int) []PlaygroundBatchItem {
	items := make([]PlaygroundBatchItem, n)
	for i := range items {
		items[i] = PlaygroundBatchItem{SubjectKind: "user", SubjectID: "alice", Action: "read", ResourceType: "document", ResourceID: "doc" + strconv.Itoa(i)}
	}
	return items
}

func runBatch(t *testing.T, deps Deps, in PlaygroundBatchInput) PlaygroundBatchResponse {
	t.Helper()
	got, err := playgroundBatchHandler(deps)(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("playground.batchCheck: %v", err)
	}
	return got
}

func batchEngine(t *testing.T, s *memory.Store, maxBatch int) *warden.Engine {
	t.Helper()
	cfg := warden.DefaultConfig()
	cfg.MaxBatchChecks = maxBatch
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithConfig(cfg))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	return eng
}

func TestPlaygroundBatchRefusesBadInput(t *testing.T) {
	deps := Deps{Engine: batchEngine(t, memory.New(), 3)}
	item := func(mut func(*PlaygroundBatchItem)) PlaygroundBatchItem {
		it := batchOf(1)[0]
		if mut != nil {
			mut(&it)
		}
		return it
	}
	cases := []struct {
		name string
		in   PlaygroundBatchInput
		want string
	}{
		{"no items", PlaygroundBatchInput{}, "items is required"},
		{"empty items", PlaygroundBatchInput{Items: []PlaygroundBatchItem{}}, "items is required"},
		{"over the configured cap", PlaygroundBatchInput{Items: batchOf(4)}, "a batch holds at most 3 checks"},
		{"empty subject id", PlaygroundBatchInput{Items: []PlaygroundBatchItem{item(nil), item(func(i *PlaygroundBatchItem) { i.SubjectID = "" })}}, "items[1].subjectId is required"},
		{"empty action", PlaygroundBatchInput{Items: []PlaygroundBatchItem{item(func(i *PlaygroundBatchItem) { i.Action = "" })}}, "items[0].action is required"},
		{"empty resource type", PlaygroundBatchInput{Items: []PlaygroundBatchItem{item(nil), item(nil), item(func(i *PlaygroundBatchItem) { i.ResourceType = "" })}}, "items[2].resourceType is required"},
		{"first offending item wins", PlaygroundBatchInput{Items: []PlaygroundBatchItem{
			item(nil),
			item(func(i *PlaygroundBatchItem) { i.Action = "" }),
			item(func(i *PlaygroundBatchItem) { i.SubjectID = "" }),
		}}, "items[1].action is required"},
		{"invalid namespace", PlaygroundBatchInput{NamespacePath: "a//b", Items: batchOf(1)}, "empty segments"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := playgroundBatchHandler(deps)(context.Background(), tc.in, principalFor("t1"))
			var ce *dashcontract.Error
			if !errors.As(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
				t.Fatalf("want a BAD_REQUEST refusal, got %v", err)
			}
			if !strings.Contains(ce.Message, tc.want) {
				t.Errorf("message = %q, want it to contain %q", ce.Message, tc.want)
			}
		})
	}
}

// MaxBatchChecks of 0 means the default cap, as Config documents.
func TestPlaygroundBatchCapOfZeroMeansTheDefaultOf100(t *testing.T) {
	deps := Deps{Engine: testEngine(t, warden.Config{})}
	if n := deps.Engine.Config().MaxBatchChecks; n != 0 {
		t.Fatalf("test engine MaxBatchChecks = %d, want 0", n)
	}
	got := runBatch(t, deps, PlaygroundBatchInput{Items: batchOf(100)})
	if len(got.Results) != 100 {
		t.Fatalf("100 items gave %d results", len(got.Results))
	}
	_, err := playgroundBatchHandler(deps)(context.Background(), PlaygroundBatchInput{Items: batchOf(101)}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Fatalf("want a BAD_REQUEST refusal, got %v", err)
	}
	if !strings.Contains(ce.Message, "a batch holds at most 100 checks") {
		t.Errorf("message = %q, want the default cap of 100", ce.Message)
	}
}

func TestPlaygroundBatchAcceptsExactlyTheConfiguredCap(t *testing.T) {
	deps := Deps{Engine: batchEngine(t, memory.New(), 3)}
	if got := runBatch(t, deps, PlaygroundBatchInput{Items: batchOf(3)}); len(got.Results) != 3 {
		t.Fatalf("3 items gave %d results", len(got.Results))
	}
}

func TestPlaygroundBatchResultsMatchADryRunCheckInOrder(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	seedReader(t, s, "t1")
	eng := batchEngine(t, s, 10)
	items := []PlaygroundBatchItem{
		{SubjectKind: "user", SubjectID: "alice", Action: "read", ResourceType: "document", ResourceID: "doc1"},
		{SubjectKind: "user", SubjectID: "bob", Action: "read", ResourceType: "document", ResourceID: "doc1"},
		{SubjectKind: "user", SubjectID: "alice", Action: "delete", ResourceType: "document"},
		{SubjectKind: "", SubjectID: "alice", Action: "read", ResourceType: "document", ResourceID: "doc1"},
		{SubjectKind: "robot", SubjectID: "alice", Action: "read", ResourceType: "document"},
	}
	got := runBatch(t, Deps{Engine: eng}, PlaygroundBatchInput{Items: items})
	if len(got.Results) != len(items) {
		t.Fatalf("%d items gave %d results", len(items), len(got.Results))
	}
	var allowed, denied int
	for i, it := range items {
		want, err := eng.Check(ctx, &warden.CheckRequest{
			Subject:  warden.Subject{Kind: warden.SubjectKind(it.SubjectKind), ID: it.SubjectID},
			Action:   warden.Action{Name: it.Action},
			Resource: warden.Resource{Type: it.ResourceType, ID: it.ResourceID},
		}, warden.WithCallTenantID("t1"), warden.WithCallNamespacePath(""), warden.WithCallDryRun())
		if err != nil {
			t.Fatalf("item %d dry-run check: %v", i, err)
		}
		wantRes := PlaygroundBatchResult{Decision: string(want.Decision), Allowed: want.Allowed, Reason: want.Reason}
		if got.Results[i] != wantRes {
			t.Errorf("results[%d] = %+v, want %+v", i, got.Results[i], wantRes)
		}
		if want.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	// A mix, so equality above is not two empty answers agreeing.
	if allowed == 0 || denied == 0 {
		t.Fatalf("fixture gave %d allowed and %d denied, want both", allowed, denied)
	}
}

func TestPlaygroundBatchRunsAtTheNamespaceItIsGiven(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	r := &role.Role{TenantID: "t1", NamespacePath: "eng", Name: "Reader", Slug: "reader"}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("create role: %v", err)
	}
	perm := &permission.Permission{TenantID: "t1", NamespacePath: "eng", Name: "document:read", Resource: "document", Action: "read"}
	if err := s.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := s.AttachPermission(ctx, "t1", r.ID, permission.Ref{NamespacePath: "eng", Name: "document:read"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		TenantID: "t1", NamespacePath: "eng", RoleID: r.ID, SubjectKind: "user", SubjectID: "alice",
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	deps := Deps{Engine: batchEngine(t, s, 10)}

	inEng := runBatch(t, deps, PlaygroundBatchInput{NamespacePath: "eng", Items: batchOf(1)})
	if !inEng.Results[0].Allowed {
		t.Fatalf("not allowed at eng: %+v", inEng.Results[0])
	}
	atRoot := runBatch(t, deps, PlaygroundBatchInput{Items: batchOf(1)})
	if atRoot.Results[0].Allowed {
		t.Fatalf("allowed at the root on a grant that lives at eng: %+v", atRoot.Results[0])
	}
}

// brokenRoleStore fails the permission read only for calls that include one
// role, so one item of a batch fails and the others do not.
type brokenRoleStore struct {
	*memory.Store
	broken id.RoleID
}

func (b brokenRoleStore) ListRolePermissionsForRoles(ctx context.Context, tenantID string, ids []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	for _, rid := range ids {
		if rid == b.broken {
			return nil, errors.New("role permissions unavailable")
		}
	}
	return b.Store.ListRolePermissionsForRoles(ctx, tenantID, ids)
}

func TestPlaygroundBatchOneFailedItemDoesNotStopTheRest(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	seedReader(t, s, "t1")
	broken := &role.Role{TenantID: "t1", Name: "Broken", Slug: "broken"}
	if err := s.CreateRole(ctx, broken); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.CreateAssignment(ctx, &assignment.Assignment{
		TenantID: "t1", RoleID: broken.ID, SubjectKind: "user", SubjectID: "carol",
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	cfg := warden.DefaultConfig()
	eng, err := warden.NewEngine(warden.WithStore(brokenRoleStore{Store: s, broken: broken.ID}), warden.WithConfig(cfg))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Stop(ctx) })

	carol := PlaygroundBatchItem{SubjectKind: "user", SubjectID: "carol", Action: "read", ResourceType: "document"}
	alice := batchOf(1)[0]
	got := runBatch(t, Deps{Engine: eng}, PlaygroundBatchInput{Items: []PlaygroundBatchItem{alice, carol, alice}})
	if len(got.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(got.Results))
	}

	_, wantErr := eng.Check(ctx, &warden.CheckRequest{
		Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "carol"},
		Action:   warden.Action{Name: "read"},
		Resource: warden.Resource{Type: "document"},
	}, warden.WithCallTenantID("t1"), warden.WithCallDryRun())
	if wantErr == nil {
		t.Fatal("the direct check for carol did not fail, so the fixture proves nothing")
	}
	if !strings.Contains(wantErr.Error(), "role permissions unavailable") {
		t.Fatalf("direct check error = %q, want the store's message", wantErr)
	}
	failed := got.Results[1]
	if failed.Decision != "error" || failed.Allowed || failed.Error != wantErr.Error() {
		t.Errorf("results[1] = %+v, want decision error, not allowed and Error %q", failed, wantErr.Error())
	}
	for _, i := range []int{0, 2} {
		r := got.Results[i]
		if !r.Allowed || r.Decision == "error" || r.Error != "" {
			t.Errorf("results[%d] = %+v, want alice allowed with no error", i, r)
		}
	}
}

// spyCache records every Set, so "no cache entry" is asserted on the write
// and not only on a lookup that a TTL could hide.
type spyCache struct {
	warden.Cache
	sets int
}

func (c *spyCache) Set(ctx context.Context, tenantID, namespacePath string, req *warden.CheckRequest, res *warden.CheckResult) {
	c.sets++
	c.Cache.Set(ctx, tenantID, namespacePath, req, res)
}

func TestPlaygroundBatchLeavesNoCheckLogAndNoCacheEntry(t *testing.T) {
	ctx := context.Background()
	newEngine := func(s *memory.Store) (*warden.Engine, *spyCache) {
		cache := &spyCache{Cache: warden.NewMemoryCache()}
		eng, err := warden.NewEngine(warden.WithStore(s), warden.WithCache(cache))
		if err != nil {
			t.Fatalf("new engine: %v", err)
		}
		return eng, cache
	}
	count := func(s *memory.Store) int64 {
		n, err := s.CountCheckLogs(ctx, &checklog.QueryFilter{TenantID: "t1"})
		if err != nil {
			t.Fatalf("count check logs: %v", err)
		}
		return n
	}
	items := []PlaygroundBatchItem{
		{SubjectKind: "user", SubjectID: "alice", Action: "read", ResourceType: "document", ResourceID: "doc1"},
		{SubjectKind: "user", SubjectID: "bob", Action: "read", ResourceType: "document", ResourceID: "doc1"},
	}
	req := func(it PlaygroundBatchItem) *warden.CheckRequest {
		return &warden.CheckRequest{
			Subject:  warden.Subject{Kind: warden.SubjectKind(it.SubjectKind), ID: it.SubjectID},
			Action:   warden.Action{Name: it.Action},
			Resource: warden.Resource{Type: it.ResourceType, ID: it.ResourceID},
		}
	}

	s := memory.New()
	seedReader(t, s, "t1")
	eng, cache := newEngine(s)
	got := runBatch(t, Deps{Engine: eng}, PlaygroundBatchInput{Items: items})
	if len(got.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(got.Results))
	}
	// Stopping flushes the writer, so a row that was queued has landed.
	if err := eng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := count(s); n != 0 {
		t.Fatalf("batch left %d check log rows, want 0", n)
	}
	if cache.sets != 0 {
		t.Fatalf("batch wrote %d cache entries, want 0", cache.sets)
	}
	for i, it := range items {
		if _, ok := cache.Get(ctx, "t1", "", req(it)); ok {
			t.Errorf("item %d is in the cache after the batch", i)
		}
	}

	// The same requests through Check do log and cache, so the zeros above
	// are not a writer and a cache that never write.
	cs := memory.New()
	seedReader(t, cs, "t1")
	ceng, ccache := newEngine(cs)
	for i, it := range items {
		r := req(it)
		r.TenantID = "t1"
		if _, err := ceng.Check(ctx, r); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	if err := ceng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := count(cs); n != 2 {
		t.Fatalf("Check left %d check log rows, want 2", n)
	}
	if ccache.sets != 2 {
		t.Fatalf("Check wrote %d cache entries, want 2", ccache.sets)
	}
}

func TestPlaygroundBatchIsScopedToTheCallersTenant(t *testing.T) {
	s := memory.New()
	seedReader(t, s, "t2") // only t2 grants alice
	deps := Deps{Engine: batchEngine(t, s, 10)}

	got := runBatch(t, deps, PlaygroundBatchInput{Items: batchOf(1)})
	if got.Results[0].Allowed {
		t.Fatalf("t1's principal was allowed on a grant only t2 holds: %+v", got.Results[0])
	}
	// The same grant in t1 does allow, so the deny above is the tenant
	// scope and not a broken seed.
	seedReader(t, s, "t1")
	got = runBatch(t, deps, PlaygroundBatchInput{Items: batchOf(1)})
	if !got.Results[0].Allowed {
		t.Fatalf("t1 grant did not allow: %+v", got.Results[0])
	}
}

func TestPlaygroundBatchInputHasNoTenantField(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(PlaygroundBatchInput{}), reflect.TypeOf(PlaygroundBatchItem{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if strings.Contains(strings.ToLower(f.Name), "tenant") || strings.Contains(strings.ToLower(f.Tag.Get("json")), "tenant") {
				t.Errorf("%s.%s reads as a tenant field: a request must never name its tenant", typ.Name(), f.Name)
			}
		}
	}
}

func TestPlaygroundBatchRefusesWithoutATenant(t *testing.T) {
	deps := Deps{Engine: engineOver(t, memory.New())}
	_, err := playgroundBatchHandler(deps)(context.Background(), PlaygroundBatchInput{Items: batchOf(1)}, signedInNoTenant())
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodePermissionDenied {
		t.Fatalf("want PERMISSION_DENIED, got %v", err)
	}
}

func TestPlaygroundBatchResponseSerializesResultsAsAnArray(t *testing.T) {
	b, err := json.Marshal(PlaygroundBatchResponse{Results: []PlaygroundBatchResult{{Decision: "allow", Allowed: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"results":[{"decision":"allow","allowed":true}]}`; got != want {
		t.Errorf("json = %s, want %s", got, want)
	}
}
