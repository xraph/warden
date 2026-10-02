package contract

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// seedTypeWith writes a resource type with the given relations in tenant t1.
func seedTypeWith(t *testing.T, s *memory.Store, namespace, name string, rels ...resourcetype.RelationDef) *resourcetype.ResourceType {
	t.Helper()
	rt := &resourcetype.ResourceType{
		TenantID:      "t1",
		NamespacePath: namespace,
		Name:          name,
		Relations:     rels,
		Permissions:   []resourcetype.PermissionDef{{Name: "read", Expression: "viewer"}},
	}
	if err := s.CreateResourceType(context.Background(), rt); err != nil {
		t.Fatalf("create resource type %q: %v", name, err)
	}
	return rt
}

func graphEdge(from, rel, to, toRel string, declared bool) ResourceTypeGraphEdge {
	return ResourceTypeGraphEdge{From: from, Relation: rel, To: to, ToRelation: toRel, Declared: declared}
}

func TestResourceTypesGraphDrawsAnEdgePerAllowedSubject(t *testing.T) {
	s := memory.New()
	seedTypeWith(t, s, "", "document",
		resourcetype.RelationDef{Name: "viewer", AllowedSubjects: []string{"user", "group#member"}},
		resourcetype.RelationDef{Name: "parent", AllowedSubjects: []string{"folder"}},
	)
	seedTypeWith(t, s, "", "folder",
		resourcetype.RelationDef{Name: "viewer", AllowedSubjects: []string{"user"}},
	)
	seedTypeWith(t, s, "", "group",
		resourcetype.RelationDef{Name: "member", AllowedSubjects: []string{"user", "group#member"}},
	)
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if got.Truncated {
		t.Error("three types reported as truncated")
	}
	names := make([]string, 0, len(got.Nodes))
	for _, n := range got.Nodes {
		names = append(names, n.Name)
	}
	if strings.Join(names, ",") != "document,folder,group" {
		t.Errorf("nodes = %v, want document,folder,group in name order", names)
	}

	want := []ResourceTypeGraphEdge{
		// "user" names no type here: a subject kind, so not declared.
		graphEdge("document", "viewer", "user", "", false),
		graphEdge("document", "viewer", "group", "member", true),
		graphEdge("document", "parent", "folder", "", true),
		graphEdge("folder", "viewer", "user", "", false),
		graphEdge("group", "member", "user", "", false),
		// A group whose members are groups: an edge from a type to itself.
		graphEdge("group", "member", "group", "member", true),
	}
	if len(got.Edges) != len(want) {
		t.Fatalf("got %d edges %+v, want %d %+v", len(got.Edges), got.Edges, len(want), want)
	}
	for i := range want {
		if got.Edges[i] != want[i] {
			t.Errorf("edge %d = %+v, want %+v", i, got.Edges[i], want[i])
		}
	}
}

func TestResourceTypesGraphNodesCarryTheirDefinitions(t *testing.T) {
	s := memory.New()
	rt := seedTypeWith(t, s, "acme", "document",
		resourcetype.RelationDef{Name: "viewer", AllowedSubjects: []string{"user"}},
	)
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if len(got.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(got.Nodes))
	}
	n := got.Nodes[0]
	if n.ID != rt.ID.String() || n.NamespacePath != "acme" || n.Name != "document" {
		t.Errorf("node = %+v", n)
	}
	if len(n.Relations) != 1 || n.Relations[0].Name != "viewer" || n.Relations[0].AllowedSubjects[0] != "user" {
		t.Errorf("relations = %+v", n.Relations)
	}
	if len(n.Permissions) != 1 || n.Permissions[0].Name != "read" || n.Permissions[0].Expression != "viewer" {
		t.Errorf("permissions = %+v", n.Permissions)
	}
}

func TestResourceTypesGraphSlicesAreNeverNull(t *testing.T) {
	// A page doing data.edges.length on null throws.
	s := memory.New()
	seedTypeWith(t, s, "", "empty")
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{`"edges":[]`, `"relations":[]`} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("response lacks %s: %s", frag, raw)
		}
	}
	none, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t-empty"))
	if err != nil {
		t.Fatalf("empty tenant: %v", err)
	}
	raw, _ = json.Marshal(none)
	if !strings.Contains(string(raw), `"nodes":[]`) || !strings.Contains(string(raw), `"edges":[]`) {
		t.Errorf("empty graph = %s, want empty arrays", raw)
	}
}

func TestResourceTypesGraphNamespaceFilterLeavesTypesOutsideUndeclared(t *testing.T) {
	s := memory.New()
	seedTypeWith(t, s, "acme", "document",
		resourcetype.RelationDef{Name: "parent", AllowedSubjects: []string{"folder"}},
	)
	seedTypeWith(t, s, "other", "folder")
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	ns := "acme"
	got, err := h(context.Background(), ResourceTypeGraphInput{NamespacePath: &ns}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "document" {
		t.Fatalf("nodes = %+v, want only acme's document", got.Nodes)
	}
	// folder exists, but outside the filter: the edge stays and is not
	// declared, as the brief says for a type outside the namespace filter.
	if len(got.Edges) != 1 || got.Edges[0] != graphEdge("document", "parent", "folder", "", false) {
		t.Errorf("edges = %+v", got.Edges)
	}

	all, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("unfiltered: %v", err)
	}
	if len(all.Nodes) != 2 || !all.Edges[0].Declared {
		t.Errorf("unfiltered nodes %d, first edge %+v, want 2 nodes and a declared edge", len(all.Nodes), all.Edges)
	}
}

func TestResourceTypesGraphRefusesAnInvalidNamespace(t *testing.T) {
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, memory.New())})
	bad := "/acme"
	_, err := h(context.Background(), ResourceTypeGraphInput{NamespacePath: &bad}, principalFor("t1"))
	refusal(t, err, dashcontract.CodeBadRequest)
}

func TestResourceTypesGraphCapsAtFiveHundredTypes(t *testing.T) {
	s := memory.New()
	for i := 0; i < 501; i++ {
		seedTypeWith(t, s, "", "type"+strconv.Itoa(1000+i))
	}
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if len(got.Nodes) != 500 || !got.Truncated {
		t.Fatalf("501 types: got %d nodes truncated=%v, want 500 and true", len(got.Nodes), got.Truncated)
	}

	// Exactly 500 is not truncated.
	s2 := memory.New()
	for i := 0; i < 500; i++ {
		seedTypeWith(t, s2, "", "type"+strconv.Itoa(1000+i))
	}
	got, err = resourceTypesGraphHandler(Deps{Engine: engineOver(t, s2)})(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if len(got.Nodes) != 500 || got.Truncated {
		t.Fatalf("500 types: got %d nodes truncated=%v, want 500 and false", len(got.Nodes), got.Truncated)
	}
}

func TestResourceTypesGraphIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	seedTypeWith(t, s, "", "mine")
	if err := s.CreateResourceType(context.Background(), &resourcetype.ResourceType{
		TenantID: "t2", Name: "theirs",
		Relations: []resourcetype.RelationDef{{Name: "viewer", AllowedSubjects: []string{"user"}}},
	}); err != nil {
		t.Fatalf("create other tenant's type: %v", err)
	}
	h := resourceTypesGraphHandler(Deps{Engine: engineOver(t, s)})

	got, err := h(context.Background(), ResourceTypeGraphInput{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("resourceTypes.graph: %v", err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "mine" {
		t.Fatalf("nodes = %+v, want only t1's type", got.Nodes)
	}
	for _, e := range got.Edges {
		if e.From == "theirs" {
			t.Fatal("t1 can see t2's edge: tenant scoping is not applied")
		}
	}
}

// ---- relations.expand ----

type expandSeed struct {
	ns                     string
	objType, objID, rel    string
	subType, subID, subRel string
}

// seedExpand writes tuples in tenant t1 with strictly increasing creation
// times, so the memory store returns each hop's tuples in seed order.
func seedExpand(t *testing.T, s *memory.Store, seeds []expandSeed) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, sd := range seeds {
		if err := s.CreateRelation(context.Background(), &relation.Tuple{
			TenantID: "t1", NamespacePath: sd.ns,
			ObjectType: sd.objType, ObjectID: sd.objID, Relation: sd.rel,
			SubjectType: sd.subType, SubjectID: sd.subID, SubjectRelation: sd.subRel,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("create tuple %d: %v", i, err)
		}
	}
}

// groupChain is document:1#viewer -> group:0#member -> ... -> group:n#member
// -> user:bob, one subject set per hop.
func groupChain(n int) []expandSeed {
	seeds := []expandSeed{{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "0", subRel: "member"}}
	for i := 0; i < n; i++ {
		seeds = append(seeds, expandSeed{objType: "group", objID: strconv.Itoa(i), rel: "member", subType: "group", subID: strconv.Itoa(i + 1), subRel: "member"})
	}
	return append(seeds, expandSeed{objType: "group", objID: strconv.Itoa(n), rel: "member", subType: "user", subID: "bob"})
}

func expandIn(typ, id, rel string) RelationExpandInput {
	return RelationExpandInput{ObjectType: typ, ObjectID: id, Relation: rel}
}

func expandWith(t *testing.T, s *memory.Store, cfg warden.Config, in RelationExpandInput) RelationExpandResponse {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithConfig(cfg))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	got, err := relationsExpandHandler(Deps{Engine: eng})(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.expand: %v", err)
	}
	return got
}

func nodeByKey(t *testing.T, r RelationExpandResponse, key string) RelationExpandNode {
	t.Helper()
	for _, n := range r.Nodes {
		if n.Key == key {
			return n
		}
	}
	t.Fatalf("no node %q in %+v", key, r.Nodes)
	return RelationExpandNode{}
}

func TestRelationsExpandProjectsNodesAndEdgesWithKeys(t *testing.T) {
	s := memory.New()
	seedExpand(t, s, []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "group", subID: "eng", subRel: "member"},
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "carol"},
		{ns: "acme", objType: "group", objID: "eng", rel: "member", subType: "user", subID: "alice"},
	})
	in := expandIn("document", "1", "viewer")
	in.NamespacePath = "acme"
	got := expandWith(t, s, warden.Config{}, in)

	if got.Stop != "complete" || got.Limit != 0 || !got.ExactWalk || got.TruncatedNodes != 0 {
		t.Errorf("stop=%q limit=%d exact=%v truncated=%d, want complete 0 true 0", got.Stop, got.Limit, got.ExactWalk, got.TruncatedNodes)
	}
	want := []RelationExpandNode{
		{Key: "document:1#viewer", Type: "document", ID: "1", Relation: "viewer", Depth: 0, Walked: true},
		{Key: "group:eng#member", Type: "group", ID: "eng", Relation: "member", Depth: 1, Walked: true},
		{Key: "user:carol", Type: "user", ID: "carol", Depth: 1, Walked: false},
		{Key: "user:alice", Type: "user", ID: "alice", Depth: 2, Walked: false},
	}
	if len(got.Nodes) != len(want) {
		t.Fatalf("nodes = %+v, want %+v", got.Nodes, want)
	}
	for i := range want {
		if got.Nodes[i] != want[i] {
			t.Errorf("node %d = %+v, want %+v", i, got.Nodes[i], want[i])
		}
	}
	wantEdges := []RelationExpandEdge{
		{From: "document:1#viewer", To: "group:eng#member"},
		{From: "document:1#viewer", To: "user:carol"},
		{From: "group:eng#member", To: "user:alice", NamespacePath: "acme"},
	}
	if len(got.Edges) != len(wantEdges) {
		t.Fatalf("edges = %+v, want %+v", got.Edges, wantEdges)
	}
	for i := range wantEdges {
		if got.Edges[i] != wantEdges[i] {
			t.Errorf("edge %d = %+v, want %+v", i, got.Edges[i], wantEdges[i])
		}
	}
	if got.Path == nil || len(got.Path) != 0 {
		t.Errorf("path = %#v, want an empty non-nil slice when none was asked for", got.Path)
	}
}

func TestRelationsExpandSlicesAreNeverNull(t *testing.T) {
	got := expandWith(t, memory.New(), warden.Config{}, expandIn("document", "1", "viewer"))
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{`"edges":[]`, `"path":[]`, `"truncatedNodes":0`, `"exactWalk":true`, `"walked":true`} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("response lacks %s: %s", frag, raw)
		}
	}
}

func TestRelationsExpandSaysEveryStopReasonWithTheConfiguredLimit(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		s := memory.New()
		seedExpand(t, s, groupChain(6))
		got := expandWith(t, s, warden.Config{MaxGraphDepth: 2}, expandIn("document", "1", "viewer"))
		if got.Stop != "depth" || got.Limit != 2 {
			t.Fatalf("stop=%q limit=%d, want depth 2", got.Stop, got.Limit)
		}
		// Depth 3 was reached but not walked.
		if n := nodeByKey(t, got, "group:1#member"); n.Depth != 2 || !n.Walked {
			t.Errorf("group:1 = %+v, want depth 2 and walked", n)
		}
		if n := nodeByKey(t, got, "group:2#member"); n.Depth != 3 || n.Walked {
			t.Errorf("group:2 = %+v, want depth 3 and not walked", n)
		}
	})
	t.Run("visited", func(t *testing.T) {
		s := memory.New()
		seedExpand(t, s, groupChain(10))
		got := expandWith(t, s, warden.Config{MaxGraphDepth: 50, MaxGraphVisited: 3}, expandIn("document", "1", "viewer"))
		if got.Stop != "visited" || got.Limit != 3 {
			t.Fatalf("stop=%q limit=%d, want visited 3", got.Stop, got.Limit)
		}
		if n := nodeByKey(t, got, "group:2#member"); n.Walked {
			t.Errorf("group:2 = %+v, want reached but not walked", n)
		}
	})
	t.Run("fanout", func(t *testing.T) {
		s := memory.New()
		var seeds []expandSeed
		for i := 0; i < 3; i++ {
			seeds = append(seeds, expandSeed{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "u" + strconv.Itoa(i)})
		}
		seedExpand(t, s, seeds)
		got := expandWith(t, s, warden.Config{MaxGraphFanout: 3}, expandIn("document", "1", "viewer"))
		if got.Stop != "fanout" || got.Limit != 3 {
			t.Fatalf("stop=%q limit=%d, want fanout 3", got.Stop, got.Limit)
		}
		// The node whose hop tripped the limit has no edges and was not walked.
		if len(got.Nodes) != 1 || len(got.Edges) != 0 || got.Nodes[0].Walked {
			t.Errorf("nodes=%+v edges=%+v, want the root alone, not walked", got.Nodes, got.Edges)
		}
	})
	t.Run("complete", func(t *testing.T) {
		s := memory.New()
		seedExpand(t, s, groupChain(2))
		got := expandWith(t, s, warden.Config{}, expandIn("document", "1", "viewer"))
		if got.Stop != "complete" || got.Limit != 0 {
			t.Fatalf("stop=%q limit=%d, want complete 0", got.Stop, got.Limit)
		}
	})
}

func TestRelationsExpandPathMatchesTheEnginesPathTo(t *testing.T) {
	s := memory.New()
	seedExpand(t, s, groupChain(2))
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	h := relationsExpandHandler(Deps{Engine: eng})
	x, err := eng.ExpandRelation(context.Background(), "document", "1", "viewer", warden.WithCallTenantID("t1"))
	if err != nil {
		t.Fatal(err)
	}

	// A single subject: every key is the engine's own label.
	in := expandIn("document", "1", "viewer")
	in.PathToType, in.PathToID = "user", "bob"
	got, err := h(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.expand: %v", err)
	}
	want := []string{"document:1#viewer", "group:0#member", "group:1#member", "group:2#member", "user:bob"}
	if strings.Join(got.Path, ",") != strings.Join(want, ",") {
		t.Errorf("path = %v, want %v", got.Path, want)
	}
	if strings.Join(got.Path, " -> ") != x.PathTo("user", "bob") {
		t.Errorf("path %q differs from the engine's PathTo %q", strings.Join(got.Path, " -> "), x.PathTo("user", "bob"))
	}

	// A subject set: PathTo prints the target as type:id, the path names the
	// node, which is type:id#relation.
	in.PathToType, in.PathToID = "group", "1"
	got, err = h(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.expand: %v", err)
	}
	want = []string{"document:1#viewer", "group:0#member", "group:1#member"}
	if strings.Join(got.Path, ",") != strings.Join(want, ",") {
		t.Errorf("set path = %v, want %v", got.Path, want)
	}
	labels := append([]string{}, got.Path[:len(got.Path)-1]...)
	labels = append(labels, "group:1")
	if strings.Join(labels, " -> ") != x.PathTo("group", "1") {
		t.Errorf("set path %v differs from the engine's PathTo %q", got.Path, x.PathTo("group", "1"))
	}

	// Not reached: an empty path, not null.
	in.PathToType, in.PathToID = "user", "nobody"
	got, err = h(context.Background(), in, principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.expand: %v", err)
	}
	if got.Path == nil || len(got.Path) != 0 {
		t.Errorf("unreached path = %#v, want an empty non-nil slice", got.Path)
	}
}

func TestRelationsExpandRefusesHalfAPathTarget(t *testing.T) {
	h := relationsExpandHandler(Deps{Engine: engineOver(t, memory.New())})
	for _, in := range []RelationExpandInput{
		{ObjectType: "document", ObjectID: "1", Relation: "viewer", PathToType: "user"},
		{ObjectType: "document", ObjectID: "1", Relation: "viewer", PathToID: "bob"},
	} {
		_, err := h(context.Background(), in, principalFor("t1"))
		ce := refusal(t, err, dashcontract.CodeBadRequest)
		if !strings.Contains(ce.Message, "pathToType and pathToId") {
			t.Errorf("message = %q, want it to name pathToType and pathToId", ce.Message)
		}
	}
}

func TestRelationsExpandCapsNodesButKeepsTheRootAndThePath(t *testing.T) {
	s := memory.New()
	var seeds []expandSeed
	const subjects = 2005
	for i := 0; i < subjects; i++ {
		seeds = append(seeds, expandSeed{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "u" + strconv.Itoa(i)})
	}
	seedExpand(t, s, seeds)
	cfg := warden.Config{MaxGraphFanout: 100000}

	got := expandWith(t, s, cfg, expandIn("document", "1", "viewer"))
	if got.Stop != "complete" {
		t.Fatalf("stop = %q, want complete", got.Stop)
	}
	// The root plus 2005 subjects is 2006 nodes: 2000 stay, in the
	// expansion's order, and 6 are left out.
	if len(got.Nodes) != 2000 || got.TruncatedNodes != 6 {
		t.Fatalf("got %d nodes, truncatedNodes %d, want 2000 and 6", len(got.Nodes), got.TruncatedNodes)
	}
	if got.Nodes[0].Key != "document:1#viewer" || got.Nodes[1999].Key != "user:u1998" {
		t.Errorf("first %q last %q, want the root then the expansion's order up to user:u1998", got.Nodes[0].Key, got.Nodes[1999].Key)
	}
	// Edges to a dropped node are dropped with it.
	if len(got.Edges) != 1999 {
		t.Errorf("got %d edges, want 1999", len(got.Edges))
	}
	kept := map[string]bool{}
	for _, n := range got.Nodes {
		kept[n.Key] = true
	}
	for _, e := range got.Edges {
		if !kept[e.From] || !kept[e.To] {
			t.Fatalf("edge %+v touches a node that was dropped", e)
		}
	}

	// A node on the requested path stays even past the cap, with the edge
	// that reaches it.
	in := expandIn("document", "1", "viewer")
	in.PathToType, in.PathToID = "user", "u2004"
	got = expandWith(t, s, cfg, in)
	if len(got.Nodes) != 2001 || got.TruncatedNodes != 5 {
		t.Fatalf("with a path: got %d nodes, truncatedNodes %d, want 2001 and 5", len(got.Nodes), got.TruncatedNodes)
	}
	if strings.Join(got.Path, ",") != "document:1#viewer,user:u2004" {
		t.Fatalf("path = %v", got.Path)
	}
	nodeByKey(t, got, "user:u2004")
	if len(got.Edges) != 2000 {
		t.Errorf("got %d edges, want 2000 (the path's edge is kept)", len(got.Edges))
	}

	// Under the cap nothing is left out.
	small := memory.New()
	seedExpand(t, small, groupChain(2))
	if r := expandWith(t, small, warden.Config{}, expandIn("document", "1", "viewer")); r.TruncatedNodes != 0 {
		t.Errorf("truncatedNodes = %d under the cap, want 0", r.TruncatedNodes)
	}
}

func TestRelationsExpandCascadesFromAncestorNamespaces(t *testing.T) {
	s := memory.New()
	seedExpand(t, s, []expandSeed{
		{ns: "", objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "root"},
		{ns: "acme", objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "acme"},
		{ns: "acme/eng", objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "eng"},
		{ns: "acme/ops", objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "ops"},
	})
	in := expandIn("document", "1", "viewer")
	in.NamespacePath = "acme/eng"
	got := expandWith(t, s, warden.Config{}, in)

	byTo := map[string]string{}
	for _, e := range got.Edges {
		byTo[e.To] = e.NamespacePath
	}
	if len(byTo) != 3 || byTo["user:root"] != "" || byTo["user:acme"] != "acme" || byTo["user:eng"] != "acme/eng" {
		t.Errorf("edges by subject = %v, want root, acme and eng from the ancestors and the namespace itself, and not ops", byTo)
	}
}

func TestRelationsExpandRefusesWhatTheEngineCannotExpand(t *testing.T) {
	h := relationsExpandHandler(Deps{Engine: engineOver(t, memory.New())})
	for _, tc := range []struct {
		name string
		in   RelationExpandInput
		want string
	}{
		{"objectType", RelationExpandInput{ObjectID: "1", Relation: "viewer"}, "objectType is required"},
		{"objectId", RelationExpandInput{ObjectType: "document", Relation: "viewer"}, "objectId is required"},
		{"relation", RelationExpandInput{ObjectType: "document", ObjectID: "1"}, "relation is required"},
		{"namespace", RelationExpandInput{ObjectType: "document", ObjectID: "1", Relation: "viewer", NamespacePath: "a//b"}, "namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h(context.Background(), tc.in, principalFor("t1"))
			ce := refusal(t, err, dashcontract.CodeBadRequest)
			if !strings.Contains(ce.Message, tc.want) {
				t.Errorf("message = %q, want it to contain %q", ce.Message, tc.want)
			}
		})
	}
}

func TestRelationsExpandIsScopedToItsOwnTenant(t *testing.T) {
	s := memory.New()
	seedExpand(t, s, []expandSeed{
		{objType: "document", objID: "1", rel: "viewer", subType: "user", subID: "mine"},
	})
	if err := s.CreateRelation(context.Background(), &relation.Tuple{
		TenantID: "t2", ObjectType: "document", ObjectID: "1", Relation: "viewer",
		SubjectType: "user", SubjectID: "theirs",
	}); err != nil {
		t.Fatalf("create other tenant's tuple: %v", err)
	}
	got := expandWith(t, s, warden.Config{}, expandIn("document", "1", "viewer"))
	for _, n := range got.Nodes {
		if n.ID == "theirs" {
			t.Fatal("t1 can see t2's tuple: tenant scoping is not applied")
		}
	}
	if len(got.Nodes) != 2 {
		t.Errorf("nodes = %+v, want the root and t1's subject", got.Nodes)
	}
}

func TestRelationsExpandNotWalkedByACustomWalkerIsReported(t *testing.T) {
	s := memory.New()
	seedExpand(t, s, groupChain(1))
	eng, err := warden.NewEngine(warden.WithStore(s), warden.WithGraphWalker(notTheBuiltInWalker{}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := relationsExpandHandler(Deps{Engine: eng})(context.Background(), expandIn("document", "1", "viewer"), principalFor("t1"))
	if err != nil {
		t.Fatalf("relations.expand: %v", err)
	}
	if got.ExactWalk {
		t.Error("a custom walker's expansion reported exactWalk")
	}
}

type notTheBuiltInWalker struct{}

func (notTheBuiltInWalker) Walk(context.Context, relation.Store, string, string, *warden.CheckRequest) (bool, string, error) {
	return false, "", nil
}
