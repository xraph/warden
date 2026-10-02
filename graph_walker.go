package warden

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraph/warden/relation"
)

// GraphWalker traverses the relation graph for ReBAC evaluation.
//
// Walk is invoked with the namespace path of the request. Relations cascade
// like roles and policies: the walker follows tuples in the request namespace
// and every ancestor namespace (see AncestorNamespaces), so a relationship
// granted at a parent namespace is honored for descendant-scoped checks.
type GraphWalker interface {
	Walk(ctx context.Context, relStore relation.Store, tenantID, namespacePath string, req *CheckRequest) (allowed bool, path string, err error)
}

// DefaultGraphWalker returns a BFS graph walker with the given max depth
// and the given metrics sink. Fan-out and visited-node budgets default to
// 1000 and 5000 respectively; use NewGraphWalker to configure them from
// Config.
func DefaultGraphWalker(maxDepth int) GraphWalker {
	return NewGraphWalker(maxDepth, 0, 0, nil)
}

// NewGraphWalker returns a BFS graph walker bounded by maxDepth (hop
// count), maxVisited (distinct nodes visited before aborting), and
// maxFanout (subjects fetched per hop, passed through to
// ListRelationSubjects). Zero values fall back to sane defaults. A nil
// metrics sink uses NoopMetrics.
func NewGraphWalker(maxDepth, maxVisited, maxFanout int, metrics Metrics) GraphWalker {
	return newBFSGraphWalker(maxDepth, maxVisited, maxFanout, metrics)
}

// newBFSGraphWalker is NewGraphWalker with its concrete type, for
// ExpandRelation, which needs the walker's traversal and budget.
func newBFSGraphWalker(maxDepth, maxVisited, maxFanout int, metrics Metrics) *bfsGraphWalker {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	if maxVisited <= 0 {
		maxVisited = 5000
	}
	if maxFanout <= 0 {
		maxFanout = 1000
	}
	if metrics == nil {
		metrics = NoopMetrics{}
	}
	return &bfsGraphWalker{maxDepth: maxDepth, maxVisited: maxVisited, maxFanout: maxFanout, metrics: metrics}
}

type bfsGraphWalker struct {
	maxDepth   int
	maxVisited int
	maxFanout  int
	metrics    Metrics
}

// walkNode is a BFS queue entry. parent indexes into the walker's node
// table so the eventual match path can be reconstructed by following
// parent pointers instead of copying a growing path slice into every
// queued node (which was O(depth) allocation per node).
type walkNode struct {
	objectType string
	objectID   string
	relation   string
	depth      int
	parent     int // index into the node table; -1 for the root
	edgeLabel  string
}

func (w *bfsGraphWalker) Walk(ctx context.Context, relStore relation.Store, tenantID, namespacePath string, req *CheckRequest) (allowed bool, path string, err error) {
	targetSubjectType := string(req.Subject.Kind)
	targetSubjectID := req.Subject.ID

	root := walkNode{
		objectType: req.Resource.Type,
		objectID:   req.Resource.ID,
		relation:   req.Action.Name,
		depth:      0,
		parent:     -1,
		edgeLabel:  fmt.Sprintf("%s:%s#%s", req.Resource.Type, req.Resource.ID, req.Action.Name),
	}

	stop, visitedCount, err := w.traverse(ctx, relStore, tenantID, namespacePath, root, func(nodes []walkNode, idx int, t *relation.Tuple) bool {
		// Direct match: the subject we're looking for.
		if t.SubjectType == targetSubjectType && t.SubjectID == targetSubjectID {
			path = w.reconstructPath(nodes, idx, fmt.Sprintf("%s:%s", t.SubjectType, t.SubjectID))
			return true
		}
		return false
	})

	switch stop {
	case walkFailed:
		return false, "", err
	case walkDepth:
		return false, "", ErrGraphDepthExceeded
	case walkVisited, walkFanout:
		w.metrics.GraphBudgetExceeded()
		w.metrics.GraphNodesVisited(visitedCount)
		return false, "", ErrGraphBudgetExceeded
	case walkMatched:
		w.metrics.GraphNodesVisited(visitedCount)
		return true, path, nil
	}

	w.metrics.GraphNodesVisited(visitedCount)
	return false, "", nil
}

// walkStop says why traverse returned.
type walkStop int

const (
	walkDrained walkStop = iota // the queue emptied
	walkMatched                 // the visitor asked to stop
	walkDepth                   // a dequeued node was deeper than maxDepth
	walkVisited                 // more than maxVisited distinct nodes
	walkFanout                  // one hop returned at least maxFanout tuples
	walkFailed                  // ctx ended or the store failed; the error says which
)

// walkVisitor sees each tuple a hop returns, in order, before the walk
// decides whether to enqueue its subject set. nodes and idx are the node
// table and the node whose hop returned t; the table is only valid during
// the call. Returning true ends the walk with walkMatched.
type walkVisitor func(nodes []walkNode, idx int, t *relation.Tuple) (stop bool)

// traverse is the walker's BFS from root, shared by Walk (which stops on
// its target) and ExpandRelation (which records every tuple). It returns
// why it stopped and how many distinct nodes it visited; err is set only
// for walkFailed. It records no metrics: each caller decides its own.
func (w *bfsGraphWalker) traverse(ctx context.Context, relStore relation.Store, tenantID, namespacePath string, root walkNode, visit walkVisitor) (walkStop, int, error) {
	// Relations cascade: the whole walk considers the request namespace and
	// every ancestor. Computed once and reused for every node lookup.
	namespaces := AncestorNamespaces(namespacePath)

	// nodes is the append-only table every queue entry indexes into, so
	// path reconstruction on a match walks parent pointers instead of
	// copying a []string on every enqueue.
	nodes := []walkNode{root}
	queue := []int{0}

	visited := make(map[string]struct{})
	visitedCount := 0

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return walkFailed, visitedCount, ctx.Err()
		default:
		}

		idx := queue[0]
		queue = queue[1:]
		node := nodes[idx]

		if node.depth > w.maxDepth {
			return walkDepth, visitedCount, nil
		}

		visitKey := fmt.Sprintf("%s:%s#%s", node.objectType, node.objectID, node.relation)
		if _, seen := visited[visitKey]; seen {
			continue
		}
		visited[visitKey] = struct{}{}
		visitedCount++
		if visitedCount > w.maxVisited {
			return walkVisited, visitedCount, nil
		}

		tuples, err := relStore.ListRelationSubjects(ctx, tenantID, namespaces, node.objectType, node.objectID, node.relation, w.maxFanout)
		if err != nil {
			return walkFailed, visitedCount, fmt.Errorf("list subjects for %s: %w", visitKey, err)
		}
		if w.maxFanout > 0 && len(tuples) >= w.maxFanout {
			return walkFanout, visitedCount, nil
		}

		for _, t := range tuples {
			if visit(nodes, idx, t) {
				return walkMatched, visitedCount, nil
			}

			// Indirect: only a subject SET (t.SubjectRelation != "") denotes a
			// group/relation whose members should be enumerated, e.g.
			// `document:1#viewer@group:eng#member` means "every member of
			// group:eng's `member` relation is a viewer", so the walker must
			// recurse into (group:eng, member). A tuple with no
			// SubjectRelation names a single concrete subject (a user, an
			// api_key, ...): for Walk, that subject already failed the
			// visitor's direct-match check and must NOT be treated as another
			// subject set to traverse, or an unrelated subject with a
			// same-named relation would incorrectly grant access.
			if t.SubjectRelation != "" {
				nodes = append(nodes, walkNode{
					objectType: t.SubjectType,
					objectID:   t.SubjectID,
					relation:   t.SubjectRelation,
					depth:      node.depth + 1,
					parent:     idx,
					edgeLabel:  fmt.Sprintf("%s:%s#%s", t.SubjectType, t.SubjectID, t.SubjectRelation),
				})
				queue = append(queue, len(nodes)-1)
			}
		}
	}

	return walkDrained, visitedCount, nil
}

// reconstructPath walks parent pointers from idx back to the root, then
// appends the final matched subject label.
func (w *bfsGraphWalker) reconstructPath(nodes []walkNode, idx int, finalLabel string) string {
	var labels []string
	for i := idx; i != -1; i = nodes[i].parent {
		labels = append([]string{nodes[i].edgeLabel}, labels...)
	}
	labels = append(labels, finalLabel)
	return strings.Join(labels, " -> ")
}
