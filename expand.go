package warden

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/warden/relation"
)

// ExpandStop says why an expansion ended.
type ExpandStop string

const (
	ExpandComplete ExpandStop = "complete" // every reachable tuple was visited
	ExpandDepth    ExpandStop = "depth"    // a node beyond MaxGraphDepth was reached
	ExpandVisited  ExpandStop = "visited"  // more than MaxGraphVisited distinct nodes
	ExpandFanout   ExpandStop = "fanout"   // one hop returned at least MaxGraphFanout tuples
)

// ExpandNode is one (objectType, objectID, relation) the walk visited, or a
// single subject it reached.
type ExpandNode struct {
	Type, ID, Relation string // Relation is "" for a single subject
	Depth              int
	// Walked is true when the walk took this node off its queue, listed
	// its tuples and went through them, so its edges are all of them. It
	// is false for a node reached but not walked: one still queued when a
	// depth or visited stop ended the walk, or the node whose hop tripped
	// the fanout limit (its tuples were listed but not walked, so it has
	// no edges). A single subject is never walked, so it is always false
	// there. A walked subject set with no tuples is Walked with no edges.
	Walked bool
}

// ExpandEdge is one tuple: from the object node to its subject node.
type ExpandEdge struct {
	From, To      int // indexes into Nodes
	NamespacePath string
}

// Expansion is the walk Check would perform from one object and relation,
// with no target subject, so it visits everything reachable within the
// engine's budget.
type Expansion struct {
	Nodes []ExpandNode
	Edges []ExpandEdge
	Stop  ExpandStop
	// Limit is the effective value of the limit that stopped the walk,
	// the one named by Stop: the walker's own value, which is the
	// walker's default when Config holds 0 for it. 0 for ExpandComplete.
	Limit int
	// Parent maps a node index to the node it was first reached from (-1
	// for the root), in the walker's BFS order, so PathTo reproduces the
	// path Walk would report.
	Parent []int
	// ExactWalk is true when this is the walk Check makes: the engine's
	// graph walker is the built-in BFS walker, whether NewEngine built it
	// or WithGraphWalker installed one from NewGraphWalker or
	// DefaultGraphWalker. It is false when WithGraphWalker installed
	// another kind of walker: Check walks with that one, and the
	// expansion falls back to the built-in BFS walk with Config's budget,
	// so neither its shape nor PathTo is guaranteed to match Check.
	ExactWalk bool
}

// PathTo returns the walk's path from the root to the first node for
// subjectType:subjectID, formatted exactly as the walker's reconstructPath,
// or "" when the expansion never reached it.
//
// Edges are in the order the walk saw their tuples, so the first edge into
// a subjectType:subjectID node (a single subject or a subject set: Walk
// matches either) is the tuple Walk would have stopped on.
func (x *Expansion) PathTo(subjectType, subjectID string) string {
	for _, edge := range x.Edges {
		to := x.Nodes[edge.To]
		if to.Type != subjectType || to.ID != subjectID {
			continue
		}
		var labels []string
		for i := edge.From; i != -1; i = x.Parent[i] {
			n := x.Nodes[i]
			labels = append([]string{fmt.Sprintf("%s:%s#%s", n.Type, n.ID, n.Relation)}, labels...)
		}
		labels = append(labels, fmt.Sprintf("%s:%s", subjectType, subjectID))
		return strings.Join(labels, " -> ")
	}
	return ""
}

// ExpandRelation walks the relation graph from objectType:objectID#rel
// as Check's walker does, without a target, using the configured graph
// budget and the call's tenant and namespace (relations cascade from
// ancestors). It writes nothing.
//
// It records no walker metrics (GraphNodesVisited, GraphBudgetExceeded):
// those describe the walks checks make, and an expansion is someone
// looking. A store failure still counts under StoreError("graph_expand"),
// as SubjectRoles counts its own; a cancelled context does not.
func (e *Engine) ExpandRelation(ctx context.Context, objectType, objectID, rel string, opts ...CallOption) (*Expansion, error) {
	if objectType == "" {
		return nil, errors.New("warden: object type is required to expand a relation")
	}
	if objectID == "" {
		return nil, errors.New("warden: object ID is required to expand a relation")
	}
	if rel == "" {
		return nil, errors.New("warden: relation is required to expand a relation")
	}
	scope, _, err := e.resolveScope(ctx, "", "", opts)
	if err != nil {
		return nil, err
	}
	w, exact := e.expansionWalker()
	x, err := w.expand(ctx, e.store, scope.tenantID, scope.namespacePath, objectType, objectID, rel)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			e.metrics.StoreError("graph_expand")
		}
		return nil, fmt.Errorf("warden expand relation: %w", err)
	}
	x.ExactWalk = exact
	return x, nil
}

// expand runs the walker's traversal from objectType:objectID#rel with no
// target and records every tuple it sees. Nodes are deduplicated by the
// walker's own visit key, so a subject set is one node however many tuples
// reach it, and the node a hop belongs to is the one the walker visited.
func (w *bfsGraphWalker) expand(ctx context.Context, relStore relation.Store, tenantID, namespacePath, objectType, objectID, rel string) (*Expansion, error) {
	x := &Expansion{}
	sets := map[string]int{}       // walker visit key -> node index
	singles := map[[2]string]int{} // subject type, ID -> node index
	add := func(n ExpandNode, parent int) int {
		x.Nodes = append(x.Nodes, n)
		x.Parent = append(x.Parent, parent)
		return len(x.Nodes) - 1
	}
	sets[fmt.Sprintf("%s:%s#%s", objectType, objectID, rel)] = add(ExpandNode{Type: objectType, ID: objectID, Relation: rel}, -1)

	root := walkNode{
		objectType: objectType,
		objectID:   objectID,
		relation:   rel,
		depth:      0,
		parent:     -1,
		edgeLabel:  fmt.Sprintf("%s:%s#%s", objectType, objectID, rel),
	}

	// from is the node index of the hop being walked, set by walked before
	// the hop's tuples reach the visitor, since every tuple of one hop
	// shares it. The walker visits each key once, under the node the
	// expansion recorded for that key.
	from := 0
	walked := func(nodes []walkNode, idx int) {
		n := nodes[idx]
		from = sets[fmt.Sprintf("%s:%s#%s", n.objectType, n.objectID, n.relation)]
		x.Nodes[from].Walked = true
	}
	stop, _, err := w.traverse(ctx, relStore, tenantID, namespacePath, root, walked, func(nodes []walkNode, idx int, t *relation.Tuple) bool {
		depth := nodes[idx].depth + 1
		var to int
		if t.SubjectRelation != "" {
			key := fmt.Sprintf("%s:%s#%s", t.SubjectType, t.SubjectID, t.SubjectRelation)
			i, ok := sets[key]
			if !ok {
				i = add(ExpandNode{Type: t.SubjectType, ID: t.SubjectID, Relation: t.SubjectRelation, Depth: depth}, from)
				sets[key] = i
			}
			to = i
		} else {
			key := [2]string{t.SubjectType, t.SubjectID}
			i, ok := singles[key]
			if !ok {
				i = add(ExpandNode{Type: t.SubjectType, ID: t.SubjectID, Depth: depth}, from)
				singles[key] = i
			}
			to = i
		}
		x.Edges = append(x.Edges, ExpandEdge{From: from, To: to, NamespacePath: t.NamespacePath})
		return false
	})

	switch stop {
	case walkFailed:
		return nil, err
	case walkDepth:
		x.Stop, x.Limit = ExpandDepth, w.maxDepth
	case walkVisited:
		x.Stop, x.Limit = ExpandVisited, w.maxVisited
	case walkFanout:
		x.Stop, x.Limit = ExpandFanout, w.maxFanout
	default:
		x.Stop = ExpandComplete
	}
	return x, nil
}
