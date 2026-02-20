package warden

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraph/warden/relation"
)

// GraphWalker traverses the relation graph for ReBAC evaluation.
type GraphWalker interface {
	Walk(ctx context.Context, relStore relation.Store, tenantID string, req *CheckRequest) (allowed bool, path string, err error)
}

// DefaultGraphWalker returns a BFS graph walker with the given max depth.
func DefaultGraphWalker(maxDepth int) GraphWalker {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	return &bfsGraphWalker{maxDepth: maxDepth}
}

type bfsGraphWalker struct {
	maxDepth int
}

type walkNode struct {
	objectType string
	objectID   string
	relation   string
	depth      int
	path       []string
}

func (w *bfsGraphWalker) Walk(ctx context.Context, relStore relation.Store, tenantID string, req *CheckRequest) (allowed bool, path string, err error) {
	targetSubjectType := string(req.Subject.Kind)
	targetSubjectID := req.Subject.ID

	// Start BFS from the resource.
	queue := []walkNode{{
		objectType: req.Resource.Type,
		objectID:   req.Resource.ID,
		relation:   req.Action.Name,
		depth:      0,
		path:       []string{fmt.Sprintf("%s:%s#%s", req.Resource.Type, req.Resource.ID, req.Action.Name)},
	}}

	visited := make(map[string]struct{})

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if node.depth > w.maxDepth {
			return false, "", ErrGraphDepthExceeded
		}

		visitKey := fmt.Sprintf("%s:%s#%s", node.objectType, node.objectID, node.relation)
		if _, seen := visited[visitKey]; seen {
			continue
		}
		visited[visitKey] = struct{}{}

		tuples, err := relStore.ListRelationSubjects(ctx, tenantID, node.objectType, node.objectID, node.relation)
		if err != nil {
			return false, "", fmt.Errorf("list subjects for %s: %w", visitKey, err)
		}

		for _, t := range tuples {
			// Direct match: the subject we're looking for.
			if t.SubjectType == targetSubjectType && t.SubjectID == targetSubjectID {
				pathStr := strings.Join(append(node.path, fmt.Sprintf("%s:%s", t.SubjectType, t.SubjectID)), " -> ")
				return true, pathStr, nil
			}

			// Indirect: follow the subject's relation (subject set).
			if t.SubjectRelation != "" {
				queue = append(queue, walkNode{
					objectType: t.SubjectType,
					objectID:   t.SubjectID,
					relation:   t.SubjectRelation,
					depth:      node.depth + 1,
					path:       append(append([]string{}, node.path...), fmt.Sprintf("%s:%s#%s", t.SubjectType, t.SubjectID, t.SubjectRelation)),
				})
			} else {
				// Follow any relation from this intermediate subject.
				queue = append(queue, walkNode{
					objectType: t.SubjectType,
					objectID:   t.SubjectID,
					relation:   node.relation,
					depth:      node.depth + 1,
					path:       append(append([]string{}, node.path...), fmt.Sprintf("%s:%s", t.SubjectType, t.SubjectID)),
				})
			}
		}
	}

	return false, "", nil
}
