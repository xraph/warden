package warden

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
)

// failingPermsStore fails the one read RBAC makes after it has resolved
// roles, so the failure lands inside the RBAC model rather than before it.
type failingPermsStore struct{ *memory.Store }

func (failingPermsStore) ListRolePermissionsForRoles(context.Context, string, []id.RoleID) (map[id.RoleID][]*permission.Permission, error) {
	return nil, errors.New("role permissions unavailable")
}

// budgetWalker stops every walk as if MaxGraphVisited had been reached.
type budgetWalker struct{}

func (budgetWalker) Walk(context.Context, relation.Store, string, string, *CheckRequest) (bool, string, error) {
	return false, "", ErrGraphBudgetExceeded
}

// failingExprEval fails every resource-type permission expression.
type failingExprEval struct{}

func (failingExprEval) EvalPermission(context.Context, string, string, string, string, string, string, string) (bool, error) {
	return false, errors.New("expression exploded")
}

// recordingLogStore is a memory store whose check log writes land in a
// recordingCheckLogStore, so a test can see exactly what the writer sent.
type recordingLogStore struct {
	*memory.Store
	rec *recordingCheckLogStore
}

func (s recordingLogStore) CreateCheckLog(ctx context.Context, e *checklog.Entry) error {
	return s.rec.CreateCheckLog(ctx, e)
}

func newExplainEngine(t *testing.T, opts ...Option) *Engine {
	t.Helper()
	eng, err := NewEngine(opts...)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	return eng
}

func configWith(tweak func(*Config)) Config {
	cfg := DefaultConfig()
	tweak(&cfg)
	return cfg
}

func off() *bool { f := false; return &f }

// seedDenyAll adds an active deny policy for every action in tenant t1.
func seedDenyAll(t *testing.T, s *memory.Store) {
	t.Helper()
	if err := s.CreatePolicy(context.Background(), &policy.Policy{
		TenantID: "t1", Name: "deny-all",
		Effect: policy.EffectDeny, IsActive: true,
		Actions: []string{"*"},
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
}

func bobReads() *CheckRequest {
	req := readReq()
	req.Subject.ID = "bob"
	return req
}

func explain(t *testing.T, eng *Engine, req *CheckRequest, opts ...CallOption) *Explanation {
	t.Helper()
	ex, err := eng.Explain(context.Background(), req, opts...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if ex == nil {
		t.Fatal("explain returned a nil Explanation without an error")
	}
	return ex
}

func TestExplain_RBACAllowSkipsReBAC(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	eng := newExplainEngine(t, WithStore(s))

	ex := explain(t, eng, readReq())

	if ex.RBAC.State != LaneAllow {
		t.Fatalf("RBAC state = %q, want allow", ex.RBAC.State)
	}
	reader, err := s.GetRoleBySlug(context.Background(), "t1", "", "reader")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	want := []MatchInfo{{Source: "rbac", RuleID: reader.ID.String(), Detail: "role grants document:read"}}
	if ex.RBAC.Result == nil || !reflect.DeepEqual(ex.RBAC.Result.MatchedBy, want) {
		t.Fatalf("RBAC result = %+v, want MatchedBy %+v", ex.RBAC.Result, want)
	}
	if ex.ReBAC.State != LaneSkipped {
		t.Errorf("ReBAC state = %q, want skipped", ex.ReBAC.State)
	}
	if ex.ReBAC.Result != nil {
		t.Errorf("skipped ReBAC lane carries a result: %+v", ex.ReBAC.Result)
	}
	if ex.ABAC.State != LaneNoMatch {
		t.Errorf("ABAC state = %q, want noMatch", ex.ABAC.State)
	}
	if ex.ABAC.Result != nil {
		t.Errorf("ABAC with no policies carries a result: %+v", ex.ABAC.Result)
	}
	if ex.Result == nil || !ex.Result.Allowed {
		t.Errorf("merged result = %+v, want an allow", ex.Result)
	}
	if ex.Err != "" {
		t.Errorf("Err = %q, want empty", ex.Err)
	}
}

func TestExplain_EvaluateAllModelsRunsReBACAfterAnAllow(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	eng := newExplainEngine(t, WithStore(s), WithConfig(configWith(func(c *Config) { c.EvaluateAllModels = true })))

	ex := explain(t, eng, readReq())

	if ex.RBAC.State != LaneAllow {
		t.Errorf("RBAC state = %q, want allow", ex.RBAC.State)
	}
	if ex.ReBAC.State != LaneNoMatch {
		t.Fatalf("ReBAC state = %q, want noMatch", ex.ReBAC.State)
	}
	if ex.ReBAC.Result == nil || ex.ReBAC.Result.Decision != DecisionDenyRelation {
		t.Fatalf("ReBAC result = %+v, want decision %q", ex.ReBAC.Result, DecisionDenyRelation)
	}
}

func TestExplain_ExplicitDenyOverAnRBACAllow(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	seedDenyAll(t, s)
	eng := newExplainEngine(t, WithStore(s))

	ex := explain(t, eng, readReq())

	if ex.ABAC.State != LaneDeny {
		t.Fatalf("ABAC state = %q, want deny", ex.ABAC.State)
	}
	if ex.ABAC.Result == nil || ex.ABAC.Result.Decision != DecisionDenyExplicit {
		t.Fatalf("ABAC result = %+v, want decision %q", ex.ABAC.Result, DecisionDenyExplicit)
	}
	if ex.RBAC.State != LaneAllow {
		t.Errorf("RBAC state = %q, want allow", ex.RBAC.State)
	}
	if ex.Result == nil || ex.Result.Allowed || ex.Result.Decision != DecisionDenyExplicit {
		t.Errorf("merged result = %+v, want an explicit deny", ex.Result)
	}
}

func TestExplain_NoRolesIsAnRBACNoMatchWithItsReason(t *testing.T) {
	eng := newExplainEngine(t, WithStore(memory.New()))

	ex := explain(t, eng, bobReads())

	if ex.RBAC.State != LaneNoMatch {
		t.Fatalf("RBAC state = %q, want noMatch", ex.RBAC.State)
	}
	want := fmt.Sprintf("subject %s:%s has no assigned roles in tenant %q", SubjectUser, "bob", "t1")
	if ex.RBAC.Result == nil || ex.RBAC.Result.Reason != want {
		t.Fatalf("RBAC result = %+v, want reason %q", ex.RBAC.Result, want)
	}
	if ex.RBAC.Result.Decision != DecisionDenyNoRoles {
		t.Errorf("RBAC decision = %q, want %q", ex.RBAC.Result.Decision, DecisionDenyNoRoles)
	}
}

func TestExplain_DisabledReBAC(t *testing.T) {
	eng := newExplainEngine(t, WithStore(memory.New()), WithConfig(configWith(func(c *Config) { c.EnableReBAC = off() })))

	ex := explain(t, eng, bobReads())

	if ex.ReBAC.State != LaneDisabled {
		t.Fatalf("ReBAC state = %q, want disabled", ex.ReBAC.State)
	}
	if ex.ReBAC.Result != nil {
		t.Errorf("disabled ReBAC lane carries a result: %+v", ex.ReBAC.Result)
	}
}

func TestExplain_StoreFailureIsReportedOnItsLane(t *testing.T) {
	mem := memory.New()
	seedAllow(t, mem)
	eng := newExplainEngine(t, WithStore(failingPermsStore{mem}))

	ex := explain(t, eng, readReq())

	if ex.RBAC.State != LaneError {
		t.Fatalf("RBAC state = %q, want error", ex.RBAC.State)
	}
	if ex.RBAC.Err != "role permissions unavailable" {
		t.Errorf("RBAC Err = %q, want the store's message", ex.RBAC.Err)
	}
	if ex.ReBAC.State != LaneNotEvaluated {
		t.Errorf("ReBAC state = %q, want notEvaluated", ex.ReBAC.State)
	}
	if ex.ABAC.State != LaneNotEvaluated {
		t.Errorf("ABAC state = %q, want notEvaluated", ex.ABAC.State)
	}
	if ex.Result != nil {
		t.Errorf("Result = %+v, want nil after a failure", ex.Result)
	}

	_, checkErr := eng.Check(context.Background(), readReq())
	if checkErr == nil {
		t.Fatal("Check succeeded against a failing store")
	}
	if ex.Err != checkErr.Error() {
		t.Errorf("Err = %q, want Check's error %q", ex.Err, checkErr.Error())
	}
}

func TestExplain_TruncatedWalk(t *testing.T) {
	eng := newExplainEngine(t, WithStore(memory.New()), WithGraphWalker(budgetWalker{}))

	ex := explain(t, eng, bobReads())

	if ex.ReBAC.State != LaneNoMatch {
		t.Fatalf("ReBAC state = %q, want noMatch", ex.ReBAC.State)
	}
	if !ex.ReBAC.WalkTruncated {
		t.Error("ReBAC WalkTruncated = false, want true")
	}
}

func TestExplain_ExpressionErrorIsReported(t *testing.T) {
	eng := newExplainEngine(t, WithStore(memory.New()), WithExpressionEvaluator(failingExprEval{}))

	ex := explain(t, eng, bobReads())

	if ex.ReBAC.ExpressionErr != "expression exploded" {
		t.Fatalf("ReBAC ExpressionErr = %q, want the evaluator's message", ex.ReBAC.ExpressionErr)
	}
	if ex.ReBAC.State != LaneNoMatch {
		t.Errorf("ReBAC state = %q, want noMatch", ex.ReBAC.State)
	}
	if ex.ReBAC.WalkTruncated {
		t.Error("ReBAC WalkTruncated = true for a walk that finished")
	}
}

func TestExplain_IgnoresAWarmCache(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	eng := newExplainEngine(t, WithStore(s), WithCache(NewMemoryCache()))
	ctx := context.Background()

	warm, err := eng.Check(ctx, readReq())
	if err != nil || !warm.Allowed {
		t.Fatalf("warming check = %+v, %v; want an allow", warm, err)
	}
	if err := s.DeleteAssignmentsBySubject(ctx, "t1", "user", "alice"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// The cache still serves the stale allow, so the assertion below is
	// not passing because the cache was never warm.
	if stale, err := eng.Check(ctx, readReq()); err != nil || !stale.Allowed {
		t.Fatalf("cached check = %+v, %v; want the stale allow", stale, err)
	}

	ex := explain(t, eng, readReq())

	if ex.Result == nil || ex.Result.Allowed {
		t.Fatalf("Explain result = %+v, want the store's fresh deny", ex.Result)
	}
	if ex.RBAC.State != LaneNoMatch {
		t.Errorf("RBAC state = %q, want noMatch after the revoke", ex.RBAC.State)
	}
}

func TestExplain_WritesNoCheckLog(t *testing.T) {
	newStore := func() recordingLogStore {
		s := recordingLogStore{Store: memory.New(), rec: &recordingCheckLogStore{}}
		seedAllow(t, s.Store)
		return s
	}
	ctx := context.Background()

	s := newStore()
	eng, err := NewEngine(WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	explain(t, eng, readReq())
	if err := eng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := len(s.rec.snapshot()); got != 0 {
		t.Fatalf("Explain wrote %d check log entries, want 0", got)
	}

	// The same request through Check does log, so the zero above is not
	// the writer being broken.
	control := newStore()
	ceng, err := NewEngine(WithStore(control))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if _, err := ceng.Check(ctx, readReq()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := ceng.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := len(control.rec.snapshot()); got != 1 {
		t.Fatalf("Check wrote %d check log entries, want 1", got)
	}
}

func TestExplain_FiresNoPluginHooks(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	probe := &probePlugin{}
	eng := newExplainEngine(t, WithStore(s), WithPlugin(probe))

	explain(t, eng, readReq())
	if probe.beforeCheckCalled {
		t.Fatal("Explain fired OnBeforeCheck")
	}
	if probe.afterCheckCalled {
		t.Fatal("Explain fired OnAfterCheck")
	}

	if _, err := eng.Check(context.Background(), readReq()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !probe.beforeCheckCalled || !probe.afterCheckCalled {
		t.Fatal("Check did not fire both hooks, so the assertions above prove nothing")
	}
}

func TestExplain_LeavesNoCacheEntry(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	cache := NewMemoryCache()
	eng := newExplainEngine(t, WithStore(s), WithCache(cache))
	ctx := context.Background()

	explain(t, eng, readReq())
	if _, hit := cache.Get(ctx, "t1", "", readReq()); hit {
		t.Fatal("Explain wrote its result to the cache")
	}

	if _, err := eng.Check(ctx, readReq()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if _, hit := cache.Get(ctx, "t1", "", readReq()); !hit {
		t.Fatal("Check left no cache entry either, so the miss above proves nothing")
	}
}

// TestExplain_MatchesADryRunCheck: Explain's merged result is what Check
// returns for the same request, field for field, except the evaluation
// time.
func TestExplain_MatchesADryRunCheck(t *testing.T) {
	type tc struct {
		name     string
		seed     func(t *testing.T, s *memory.Store)
		store    func(s *memory.Store) store.Store
		engine   []Option
		req      *CheckRequest
		callOpts []CallOption
		// want is the decision Check reaches, or "" when Check errors. It
		// keeps a case from passing because both sides went wrong alike.
		want Decision
	}
	cases := []tc{
		{name: "rbac allow", seed: seedAllow, req: readReq(), want: DecisionAllow},
		{
			name: "evaluate all models", seed: seedAllow, req: readReq(), want: DecisionAllow,
			engine: []Option{WithConfig(configWith(func(c *Config) { c.EvaluateAllModels = true }))},
		},
		{
			name: "explicit deny over an allow", req: readReq(), want: DecisionDenyExplicit,
			seed: func(t *testing.T, s *memory.Store) { seedAllow(t, s); seedDenyAll(t, s) },
		},
		{name: "no roles", req: bobReads(), want: DecisionDenyNoRoles},
		{
			name: "rebac disabled", seed: seedAllow, req: bobReads(), want: DecisionDenyNoRoles,
			engine: []Option{WithConfig(configWith(func(c *Config) { c.EnableReBAC = off() }))},
		},
		{
			name: "rbac store failure", seed: seedAllow, req: readReq(),
			store: func(s *memory.Store) store.Store { return failingPermsStore{s} },
		},
		{name: "truncated walk", req: bobReads(), want: DecisionDenyNoRoles, engine: []Option{WithGraphWalker(budgetWalker{})}},
		{name: "expression error", req: bobReads(), want: DecisionDenyNoRoles, engine: []Option{WithExpressionEvaluator(failingExprEval{})}},
		{
			name: "no tenant with RequireTenant off", want: DecisionAllow,
			seed: func(t *testing.T, s *memory.Store) {
				t.Helper()
				if err := s.CreatePolicy(context.Background(), &policy.Policy{
					Name: "allow-read", Effect: policy.EffectAllow, IsActive: true, Actions: []string{"read"},
				}); err != nil {
					t.Fatalf("create policy: %v", err)
				}
			},
			req: func() *CheckRequest {
				r := readReq()
				r.TenantID = ""
				return r
			}(),
			engine: []Option{WithConfig(configWith(func(c *Config) { c.RequireTenant = off() }))},
		},
		{
			name: "policy at an ancestor namespace", want: DecisionAllow,
			seed: func(t *testing.T, s *memory.Store) {
				t.Helper()
				if err := s.CreatePolicy(context.Background(), &policy.Policy{
					TenantID: "t1", NamespacePath: "eng", Name: "eng-read",
					Effect: policy.EffectAllow, IsActive: true, Actions: []string{"read"},
				}); err != nil {
					t.Fatalf("create policy: %v", err)
				}
			},
			req: func() *CheckRequest {
				r := bobReads()
				r.TenantID = ""
				return r
			}(),
			callOpts: []CallOption{WithCallTenantID("t1"), WithCallNamespacePath("eng/platform")},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mem := memory.New()
			if c.seed != nil {
				c.seed(t, mem)
			}
			var st store.Store = mem
			if c.store != nil {
				st = c.store(mem)
			}
			eng := newExplainEngine(t, append([]Option{WithStore(st)}, c.engine...)...)
			ctx := context.Background()

			ex := explain(t, eng, c.req, c.callOpts...)
			want, checkErr := eng.Check(ctx, c.req, append(append([]CallOption{}, c.callOpts...), WithCallDryRun())...)

			if c.want == "" && checkErr == nil {
				t.Fatalf("Check succeeded with %+v, but this case expects an error", want)
			}
			if checkErr != nil {
				if c.want != "" {
					t.Fatalf("Check failed with %v, want decision %q", checkErr, c.want)
				}
				if ex.Err != checkErr.Error() {
					t.Fatalf("Explain Err = %q, want Check's error %q", ex.Err, checkErr.Error())
				}
				if ex.Result != nil {
					t.Fatalf("Explain Result = %+v alongside an error", ex.Result)
				}
				return
			}
			if ex.Err != "" {
				t.Fatalf("Explain Err = %q, but Check succeeded", ex.Err)
			}
			if ex.Result == nil {
				t.Fatal("Explain Result is nil, but Check succeeded")
			}
			if want.Decision != c.want {
				t.Fatalf("Check decided %q (%s), want %q", want.Decision, want.Reason, c.want)
			}
			got := *ex.Result
			exp := *want
			got.EvalTimeNs, exp.EvalTimeNs = 0, 0
			if !reflect.DeepEqual(got, exp) {
				t.Fatalf("Explain result differs from a dry run Check:\n got  %+v\n want %+v", got, exp)
			}
		})
	}
}

func TestExplain_RefusesWhatCheckRefuses(t *testing.T) {
	eng := newExplainEngine(t, WithStore(memory.New()))
	ctx := context.Background()

	cases := map[string]func(*CheckRequest){
		"empty subject id":    func(r *CheckRequest) { r.Subject.ID = "" },
		"empty action":        func(r *CheckRequest) { r.Action.Name = "" },
		"empty resource type": func(r *CheckRequest) { r.Resource.Type = "" },
		"missing tenant":      func(r *CheckRequest) { r.TenantID = "" },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			req := readReq()
			breakIt(req)

			ex, err := eng.Explain(ctx, req)
			_, checkErr := eng.Check(ctx, req, WithCallDryRun())
			if checkErr == nil {
				t.Fatal("Check accepted the request, so this case tests nothing")
			}
			if err == nil || err.Error() != checkErr.Error() {
				t.Fatalf("Explain err = %v, want Check's %v", err, checkErr)
			}
			if ex != nil {
				t.Fatalf("Explain returned %+v alongside its error, want nil", ex)
			}
		})
	}
}

// countingWalker counts walks and never finds a relation.
type countingWalker struct{ walks atomic.Int32 }

func (w *countingWalker) Walk(context.Context, relation.Store, string, string, *CheckRequest) (bool, string, error) {
	w.walks.Add(1)
	return false, "", nil
}

// TestCheck_SkipsTheGraphWalkAfterAnRBACAllow pins, on Check itself, the
// rule the skipped ReBAC lane reports: once RBAC allows, the graph walk
// runs only when EvaluateAllModels is on. The equivalence test cannot see
// this, because Check and Explain share runModels and the merged result
// is RBAC's allow either way.
func TestCheck_SkipsTheGraphWalkAfterAnRBACAllow(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(fmt.Sprintf("EvaluateAllModels=%v", all), func(t *testing.T) {
			s := memory.New()
			seedAllow(t, s)
			walker := &countingWalker{}
			eng := newExplainEngine(t, WithStore(s), WithGraphWalker(walker),
				WithConfig(configWith(func(c *Config) { c.EvaluateAllModels = all })))

			res, err := eng.Check(context.Background(), readReq())
			if err != nil || !res.Allowed {
				t.Fatalf("check = %+v, %v; want an allow", res, err)
			}
			want := int32(0)
			if all {
				want = 1
			}
			if got := walker.walks.Load(); got != want {
				t.Fatalf("graph walks = %d, want %d", got, want)
			}
		})
	}
}

// failingRelationStore fails ReBAC's first store read.
type failingRelationStore struct{ *memory.Store }

func (failingRelationStore) CheckDirectRelation(context.Context, string, []string, string, string, string, string, string) (bool, error) {
	return false, errors.New("relations unavailable")
}

// failingPolicyStore fails ABAC's policy read.
type failingPolicyStore struct{ *memory.Store }

func (failingPolicyStore) ListActivePolicies(context.Context, string, []string) ([]*policy.Policy, error) {
	return nil, errors.New("policies unavailable")
}

func TestExplain_ReBACStoreFailure(t *testing.T) {
	eng := newExplainEngine(t, WithStore(failingRelationStore{memory.New()}))

	ex := explain(t, eng, bobReads())

	if ex.RBAC.State != LaneNoMatch {
		t.Errorf("RBAC state = %q, want noMatch", ex.RBAC.State)
	}
	if ex.ReBAC.State != LaneError || ex.ReBAC.Err != "relations unavailable" {
		t.Errorf("ReBAC lane = %+v, want error with the store's message", ex.ReBAC)
	}
	if ex.ABAC.State != LaneNotEvaluated {
		t.Errorf("ABAC state = %q, want notEvaluated", ex.ABAC.State)
	}
	if ex.Result != nil || ex.Err == "" {
		t.Errorf("Result = %+v, Err = %q; want no result and an error", ex.Result, ex.Err)
	}
}

func TestExplain_ABACStoreFailureAfterAnRBACAllow(t *testing.T) {
	mem := memory.New()
	seedAllow(t, mem)
	eng := newExplainEngine(t, WithStore(failingPolicyStore{mem}))

	ex := explain(t, eng, readReq())

	if ex.RBAC.State != LaneAllow {
		t.Errorf("RBAC state = %q, want allow", ex.RBAC.State)
	}
	if ex.ReBAC.State != LaneSkipped {
		t.Errorf("ReBAC state = %q, want skipped: RBAC allowed, so Check never walked", ex.ReBAC.State)
	}
	if ex.ABAC.State != LaneError || ex.ABAC.Err != "policies unavailable" {
		t.Errorf("ABAC lane = %+v, want error with the store's message", ex.ABAC)
	}
	if ex.Result != nil || ex.Err == "" {
		t.Errorf("Result = %+v, Err = %q; want no result and an error", ex.Result, ex.Err)
	}
}

func TestExplain_ABACStoreFailureWithEvaluateAllModels(t *testing.T) {
	mem := memory.New()
	seedAllow(t, mem)
	eng := newExplainEngine(t, WithStore(failingPolicyStore{mem}),
		WithConfig(configWith(func(c *Config) { c.EvaluateAllModels = true })))

	ex := explain(t, eng, readReq())

	if ex.RBAC.State != LaneAllow {
		t.Errorf("RBAC state = %q, want allow", ex.RBAC.State)
	}
	if ex.ReBAC.State != LaneNoMatch || ex.ReBAC.Result == nil || ex.ReBAC.Result.Decision != DecisionDenyRelation {
		t.Errorf("ReBAC lane = %+v, want the noMatch it really reached", ex.ReBAC)
	}
	if ex.ABAC.State != LaneError || ex.ABAC.Err != "policies unavailable" {
		t.Errorf("ABAC lane = %+v, want error with the store's message", ex.ABAC)
	}
}
