package warden

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/store"
	"github.com/xraph/warden/store/memory"
)

// expandSeed is one tuple for the expansion tests. ns is its namespace path.
type expandSeed struct {
	objType, objID, rel    string
	subType, subID, subRel string
	ns                     string
}

// seedTuples writes tuples in tenant t1 with strictly increasing creation
// times, so the memory store returns each hop's tuples in seed order.
func seedTuples(t *testing.T, s *memory.Store, seeds []expandSeed) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, sd := range seeds {
		if err := s.CreateRelation(context.Background(), &relation.Tuple{
			TenantID: "t1", NamespacePath: sd.ns,
			ObjectType: sd.objType, ObjectID: sd.objID, Relation: sd.rel,
			SubjectType: sd.subType, SubjectID: sd.subID, SubjectRelation: sd.subRel,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("CreateRelation %d: %v", i, err)
		}
	}
}

// newExpandEngine builds an engine over s whose graph budget is the default
// adjusted by budget (nil keeps the default).
func newExpandEngine(t *testing.T, s store.Store, budget func(*Config), opts ...Option) *Engine {
	t.Helper()
	cfg := DefaultConfig()
	if budget != nil {
		budget(&cfg)
	}
	eng, err := NewEngine(append([]Option{WithStore(s), WithConfig(cfg)}, opts...)...)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// chainSeeds is document:1#viewer -> group:0#member -> ... -> group:n#member
// -> user:bob, one subject set per hop.
func chainSeeds(n int) []expandSeed {
	seeds := []expandSeed{{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "0", subRel: "member"}}
	for i := 0; i < n; i++ {
		seeds = append(seeds, expandSeed{objType: "group", objID: strconv.Itoa(i), rel: "member", subType: "group", subID: strconv.Itoa(i + 1), subRel: "member"})
	}
	return append(seeds, expandSeed{objType: "group", objID: strconv.Itoa(n), rel: "member", subType: "user", subID: "bob"})
}

func TestExpandRelation_TwoHopChainCompletes(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "eng", subRel: "member"},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "carol"},
		{objType: "group", objID: "eng", rel: "member", subType: "team", subID: "core", subRel: "member"},
		{objType: "group", objID: "eng", rel: "member", subType: "user", subID: "alice"},
		{objType: "team", objID: "core", rel: "member", subType: "user", subID: "bob"},
		{objType: "team", objID: "core", rel: "member", subType: "user", subID: "alice"},
	})
	eng := newExpandEngine(t, s, nil)

	x, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}

	wantNodes := []ExpandNode{
		{Type: "document", ID: "1", Relation: "viewer", Depth: 0},
		{Type: "group", ID: "eng", Relation: "member", Depth: 1},
		{Type: "user", ID: "carol", Relation: "", Depth: 1},
		{Type: "team", ID: "core", Relation: "member", Depth: 2},
		{Type: "user", ID: "alice", Relation: "", Depth: 2},
		{Type: "user", ID: "bob", Relation: "", Depth: 3},
	}
	if !reflect.DeepEqual(x.Nodes, wantNodes) {
		t.Fatalf("nodes:\n got %+v\nwant %+v", x.Nodes, wantNodes)
	}
	// alice is reached twice and recorded once: the second tuple is an edge
	// to the node she already has.
	wantEdges := []ExpandEdge{{From: 0, To: 1}, {From: 0, To: 2}, {From: 1, To: 3}, {From: 1, To: 4}, {From: 3, To: 5}, {From: 3, To: 4}}
	if !reflect.DeepEqual(x.Edges, wantEdges) {
		t.Fatalf("edges:\n got %+v\nwant %+v", x.Edges, wantEdges)
	}
	if want := []int{-1, 0, 0, 1, 1, 3}; !reflect.DeepEqual(x.Parent, want) {
		t.Fatalf("parent: got %v, want %v", x.Parent, want)
	}
	if x.Stop != ExpandComplete || x.Limit != 0 {
		t.Fatalf("stop: got %q limit %d, want complete 0", x.Stop, x.Limit)
	}
	if got, want := x.PathTo("user", "bob"), "document:1#viewer -> group:eng#member -> team:core#member -> user:bob"; got != want {
		t.Fatalf("PathTo(bob): got %q, want %q", got, want)
	}
	if got := x.PathTo("user", "nobody"); got != "" {
		t.Fatalf("PathTo(nobody): got %q, want empty", got)
	}
}

func TestExpandRelation_SingleSubjectIsNeverExpanded(t *testing.T) {
	// document:1#viewer@group:eng names the group itself, so group:eng's
	// own tuples are not part of the walk, as in
	// TestGraphWalker_PlainSubjectIsNotASubjectSet.
	s := memory.New()
	seedTuples(t, s, []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "eng"},
		{objType: "group", objID: "eng", rel: "viewer", subType: "user", subID: "bob"},
	})
	x, err := newExpandEngine(t, s, nil).ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	want := []ExpandNode{{Type: "document", ID: "1", Relation: "viewer"}, {Type: "group", ID: "eng", Depth: 1}}
	if !reflect.DeepEqual(x.Nodes, want) {
		t.Fatalf("nodes:\n got %+v\nwant %+v", x.Nodes, want)
	}
}

func TestExpandRelation_StopsAtDepth(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, chainSeeds(6))
	eng := newExpandEngine(t, s, func(c *Config) { c.MaxGraphDepth = 2 })

	x, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if x.Stop != ExpandDepth || x.Limit != 2 {
		t.Fatalf("stop: got %q limit %d, want depth 2", x.Stop, x.Limit)
	}
	// Depths 0..2 were walked; the depth 3 node was reached, not walked.
	if last := x.Nodes[len(x.Nodes)-1]; last.Depth != 3 || len(x.Nodes) != 4 {
		t.Fatalf("nodes: got %+v, want 4 ending at depth 3", x.Nodes)
	}
}

func TestExpandRelation_StopsAtVisited(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, chainSeeds(10))
	eng := newExpandEngine(t, s, func(c *Config) { c.MaxGraphDepth = 50; c.MaxGraphVisited = 3 })

	x, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if x.Stop != ExpandVisited || x.Limit != 3 {
		t.Fatalf("stop: got %q limit %d, want visited 3", x.Stop, x.Limit)
	}
}

func TestExpandRelation_StopsAtFanout(t *testing.T) {
	seedSubjects := func(n int) *memory.Store {
		s := memory.New()
		var seeds []expandSeed
		for i := 0; i < n; i++ {
			seeds = append(seeds, expandSeed{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "u" + strconv.Itoa(i)})
		}
		seedTuples(t, s, seeds)
		return s
	}
	budget := func(c *Config) { c.MaxGraphFanout = 3 }

	// Exactly MaxGraphFanout tuples in one hop stops the walk: the
	// walker's rule is len(tuples) >= maxFanout.
	x, err := newExpandEngine(t, seedSubjects(3), budget).ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if x.Stop != ExpandFanout || x.Limit != 3 {
		t.Fatalf("3 tuples: got %q limit %d, want fanout 3", x.Stop, x.Limit)
	}
	// The stopping hop's tuples were not walked, so none is drawn.
	if len(x.Edges) != 0 || len(x.Nodes) != 1 {
		t.Fatalf("3 tuples: got %d nodes %d edges, want the root alone", len(x.Nodes), len(x.Edges))
	}

	x, err = newExpandEngine(t, seedSubjects(2), budget).ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if x.Stop != ExpandComplete || len(x.Edges) != 2 {
		t.Fatalf("2 tuples: got %q with %d edges, want complete with 2", x.Stop, len(x.Edges))
	}
}

func TestExpandRelation_CascadesFromAncestorNamespaces(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "root", ns: ""},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "acme", ns: "acme"},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "eng", ns: "acme/eng"},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "ops", ns: "acme/ops"},
	})
	x, err := newExpandEngine(t, s, nil).ExpandRelation(context.Background(), "document", "1", "viewer",
		WithCallTenantID("t1"), WithCallNamespacePath("acme/eng"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range x.Edges {
		got[x.Nodes[e.To].ID] = e.NamespacePath
	}
	want := map[string]string{"root": "", "acme": "acme", "eng": "acme/eng"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects by namespace: got %v, want %v", got, want)
	}
}

func TestExpandRelation_Validates(t *testing.T) {
	eng := newExpandEngine(t, memory.New(), nil)
	ctx := context.Background()
	for _, tc := range []struct{ typ, id, rel string }{{"", "1", "viewer"}, {"document", "", "viewer"}, {"document", "1", ""}} {
		if _, err := eng.ExpandRelation(ctx, tc.typ, tc.id, tc.rel, WithCallTenantID("t1")); err == nil {
			t.Fatalf("ExpandRelation(%q, %q, %q): want an error", tc.typ, tc.id, tc.rel)
		}
	}
	if _, err := eng.ExpandRelation(ctx, "document", "1", "viewer"); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("no tenant: got %v, want ErrTenantRequired", err)
	}
	// The context's tenant counts, as for SubjectRoles.
	if _, err := eng.ExpandRelation(WithTenant(ctx, "app", "t1"), "document", "1", "viewer"); err != nil {
		t.Fatalf("context tenant: %v", err)
	}
}

// failingSubjectsStore fails the walk's per-hop read.
type failingSubjectsStore struct{ *memory.Store }

func (failingSubjectsStore) ListRelationSubjects(context.Context, string, []string, string, string, string, int) ([]*relation.Tuple, error) {
	return nil, errors.New("relations unavailable")
}

func TestExpandRelation_StoreFailure(t *testing.T) {
	rec := &storeErrorRecorder{}
	eng := newExpandEngine(t, failingSubjectsStore{memory.New()}, nil, WithMetrics(rec))
	if _, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1")); err == nil {
		t.Fatal("want the store's error")
	}
	if got := rec.snapshot(); !reflect.DeepEqual(got, []string{"graph_expand"}) {
		t.Fatalf("StoreError ops: got %v, want [graph_expand]", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec2 := &storeErrorRecorder{}
	eng = newExpandEngine(t, memory.New(), nil, WithMetrics(rec2))
	if _, err := eng.ExpandRelation(ctx, "document", "1", "viewer", WithCallTenantID("t1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: got %v, want context.Canceled", err)
	}
	if got := rec2.snapshot(); len(got) != 0 {
		t.Fatalf("a cancelled expansion is not a store failure: got %v", got)
	}
}

func TestExpandRelation_RecordsNoWalkerMetrics(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, chainSeeds(10))
	metrics := &fakeGraphMetrics{}
	eng := newExpandEngine(t, s, func(c *Config) { c.MaxGraphVisited = 3 }, WithMetrics(metrics))
	x, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if x.Stop != ExpandVisited {
		t.Fatalf("stop: got %q, want visited", x.Stop)
	}
	if metrics.budgetExceeded != 0 || len(metrics.nodesVisited) != 0 {
		t.Fatalf("expansion recorded walker metrics: %+v", metrics)
	}
}

// TestGraphWalker_MetricsCalls pins every metrics call Walk makes, per way
// a walk ends, so sharing its traversal cannot change them.
func TestGraphWalker_MetricsCalls(t *testing.T) {
	s := memory.New()
	seedTuples(t, s, chainSeeds(4))
	for _, tc := range []struct {
		name                   string
		depth, visited, fanout int
		subject                string
		wantErr                error
		wantBudget             int
		wantVisits             []int
	}{
		{name: "match", depth: 10, subject: "bob", wantVisits: []int{6}},
		{name: "drained", depth: 10, subject: "nobody", wantVisits: []int{6}},
		{name: "depth", depth: 2, subject: "bob", wantErr: ErrGraphDepthExceeded},
		{name: "visited", depth: 10, visited: 2, subject: "bob", wantErr: ErrGraphBudgetExceeded, wantBudget: 1, wantVisits: []int{3}},
		{name: "fanout", depth: 10, fanout: 1, subject: "bob", wantErr: ErrGraphBudgetExceeded, wantBudget: 1, wantVisits: []int{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &fakeGraphMetrics{}
			_, _, err := NewGraphWalker(tc.depth, tc.visited, tc.fanout, m).Walk(context.Background(), s, "t1", "", &CheckRequest{
				Subject: Subject{Kind: SubjectUser, ID: tc.subject}, Action: Action{Name: "viewer"}, Resource: Resource{Type: "document", ID: "1"},
			})
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("err: got %v, want %v", err, tc.wantErr)
			}
			if m.budgetExceeded != tc.wantBudget || !reflect.DeepEqual(m.nodesVisited, tc.wantVisits) {
				t.Fatalf("metrics: got budget %d visits %v, want %d %v", m.budgetExceeded, m.nodesVisited, tc.wantBudget, tc.wantVisits)
			}
		})
	}
}

// TestExpandRelation_MatchesWalk runs Walk and ExpandRelation on the same
// seeds and budget: wherever Walk finds subject S, PathTo(S) is its path
// exactly; wherever Walk stops on its budget, the expansion stops for the
// same reason and has no path to S.
func TestExpandRelation_MatchesWalk(t *testing.T) {
	diamond := []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "a", subRel: "member"},
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "b", subRel: "member"},
		{objType: "group", objID: "a", rel: "member", subType: "team", subID: "x", subRel: "member"},
		{objType: "group", objID: "b", rel: "member", subType: "team", subID: "x", subRel: "member"},
		{objType: "group", objID: "b", rel: "member", subType: "user", subID: "bob"},
		{objType: "team", objID: "x", rel: "member", subType: "user", subID: "bob"},
		{objType: "team", objID: "x", rel: "member", subType: "user", subID: "carol"},
	}
	cycle := []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "a", subRel: "member"},
		{objType: "group", objID: "a", rel: "member", subType: "group", subID: "b", subRel: "member"},
		{objType: "group", objID: "b", rel: "member", subType: "group", subID: "a", subRel: "member"},
		{objType: "group", objID: "b", rel: "member", subType: "document", subID: "1", subRel: "viewer"},
		{objType: "group", objID: "b", rel: "member", subType: "user", subID: "bob"},
	}
	setAndSingle := []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "dan", subRel: "friend"},
		{objType: "user", objID: "dan", rel: "friend", subType: "user", subID: "erin"},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "erin"},
	}
	var wide []expandSeed
	for i := 0; i < 4; i++ {
		g := "g" + strconv.Itoa(i)
		wide = append(wide,
			expandSeed{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: g, subRel: "member"},
			expandSeed{objType: "group", objID: g, rel: "member", subType: "user", subID: "u" + strconv.Itoa(i)})
	}
	cases := []struct {
		name     string
		seeds    []expandSeed
		budget   func(*Config)
		subjects [][2]string
	}{
		{name: "diamond", seeds: diamond, subjects: [][2]string{{"user", "bob"}, {"user", "carol"}, {"team", "x"}, {"group", "b"}, {"user", "nobody"}}},
		{name: "cycle", seeds: cycle, subjects: [][2]string{{"user", "bob"}, {"group", "a"}, {"document", "1"}, {"user", "nobody"}}},
		{name: "set and single", seeds: setAndSingle, subjects: [][2]string{{"user", "dan"}, {"user", "erin"}}},
		{name: "chain at depth", seeds: chainSeeds(5), budget: func(c *Config) { c.MaxGraphDepth = 2 },
			subjects: [][2]string{{"group", "1"}, {"group", "2"}, {"group", "3"}, {"user", "bob"}}},
		{name: "chain at visited", seeds: chainSeeds(5), budget: func(c *Config) { c.MaxGraphVisited = 3 },
			subjects: [][2]string{{"group", "0"}, {"group", "3"}, {"group", "4"}, {"user", "bob"}}},
		{name: "wide at visited", seeds: wide, budget: func(c *Config) { c.MaxGraphVisited = 3 },
			subjects: [][2]string{{"group", "g3"}, {"user", "u0"}, {"user", "u1"}, {"user", "u2"}, {"user", "u3"}}},
		{name: "wide at fanout", seeds: wide, budget: func(c *Config) { c.MaxGraphFanout = 4 },
			subjects: [][2]string{{"group", "g0"}, {"user", "u0"}}},
	}
	ctx := context.Background()
	// branches counts which comparison each subject made, so the table
	// provably covers a found path, a miss and both kinds of budget stop.
	branches := map[string]int{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			seedTuples(t, s, tc.seeds)
			eng := newExpandEngine(t, s, tc.budget)
			x, err := eng.ExpandRelation(ctx, "document", "1", "viewer", WithCallTenantID("t1"))
			if err != nil {
				t.Fatal(err)
			}
			for _, sub := range tc.subjects {
				allowed, path, err := eng.graphWalker.Walk(ctx, s, "t1", "", &CheckRequest{
					Subject: Subject{Kind: SubjectKind(sub[0]), ID: sub[1]}, Action: Action{Name: "viewer"}, Resource: Resource{Type: "document", ID: "1"},
				})
				got := x.PathTo(sub[0], sub[1])
				switch {
				case errors.Is(err, ErrGraphDepthExceeded):
					branches["depth"]++
					if x.Stop != ExpandDepth || got != "" {
						t.Errorf("%s: Walk stopped at depth; expansion stop %q, path %q", sub, x.Stop, got)
					}
				case errors.Is(err, ErrGraphBudgetExceeded):
					branches["budget"]++
					if (x.Stop != ExpandVisited && x.Stop != ExpandFanout) || got != "" {
						t.Errorf("%s: Walk stopped on budget; expansion stop %q, path %q", sub, x.Stop, got)
					}
				case err != nil:
					t.Fatalf("%s: Walk: %v", sub, err)
				case allowed:
					branches["path"]++
					if got != path {
						t.Errorf("%s: PathTo %q, Walk path %q", sub, got, path)
					}
				default:
					branches["miss"]++
					if got != "" || x.Stop != ExpandComplete {
						t.Errorf("%s: Walk found nothing; expansion stop %q, path %q", sub, x.Stop, got)
					}
				}
			}
			if tc.name == "diamond" {
				// bob is two hops away through group:b and three through
				// group:a; BFS reaches group:b's direct tuple first.
				if got, want := x.PathTo("user", "bob"), "document:1#viewer -> group:b#member -> user:bob"; got != want {
					t.Errorf("diamond bob: got %q, want %q", got, want)
				}
			}
		})
	}
	for _, b := range []string{"path", "miss", "depth", "budget"} {
		if branches[b] == 0 {
			t.Errorf("no subject took the %s branch: %v", b, branches)
		}
	}
}
