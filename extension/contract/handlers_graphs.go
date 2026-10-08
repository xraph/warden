// handlers_graphs.go: the two graph views, the schema graph and the rooted
// relation expansion.
//
// The schema graph is drawn from resource types alone: every relation a type
// declares names the subject types it accepts, and each one is an edge. It
// says what the schema allows, not what is stored.
//
// The expansion is the opposite. It runs the ReBAC walker's own traversal
// from one object and relation with no target (Engine.ExpandRelation), so it
// shows what is stored and reachable from there, under the engine's graph
// budget. It reads tuples only, so it needs no resource type grant.
package contract

import (
	"context"
	"sort"
	"strings"

	"github.com/xraph/warden"
	"github.com/xraph/warden/resourcetype"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

const (
	// maxSchemaGraphTypes is how many resource types the schema graph
	// draws. A graph of more is unreadable, and the response says so.
	maxSchemaGraphTypes = 500

	// maxExpandNodes is how many nodes an expansion returns. The engine's
	// budget (MaxGraphVisited) can be raised until a walk reaches millions
	// of edges, which the page cannot draw and the wire should not carry.
	maxExpandNodes = 2000

	// schemaGraphPage is the page size the schema graph reads types in.
	schemaGraphPage = 500
)

// ResourceTypeGraphInput filters the schema graph.
type ResourceTypeGraphInput struct {
	NamespacePath *string `json:"namespacePath,omitempty"`
}

// ResourceTypeGraphNode is one resource type with its definitions.
type ResourceTypeGraphNode struct {
	ID            string             `json:"id"`
	NamespacePath string             `json:"namespacePath"`
	Name          string             `json:"name"`
	Relations     []RelationDefDTO   `json:"relations"`
	Permissions   []PermissionDefDTO `json:"permissions"`
}

// ResourceTypeGraphEdge is one allowed subject of one relation.
type ResourceTypeGraphEdge struct {
	From string `json:"from"` // resource type name
	// FromID is the owning type's id. Two types can share a name in
	// different namespaces, and From alone cannot tell them apart.
	FromID   string `json:"fromId"`
	Relation string `json:"relation"` // the RelationDef's name
	To       string `json:"to"`       // allowed subject type
	// ToRelation is the subject set's relation for "type#rel", else "".
	ToRelation string `json:"toRelation,omitempty"`
	// Declared is false when To names no resource type in the graph (a
	// subject kind like "user", or a type outside the namespace filter).
	Declared bool `json:"declared"`
	// ToIDs is the id of every returned type whose name is To, in node
	// order. It is empty (never null) when the edge is undeclared.
	ToIDs []string `json:"toIds"`
}

// ResourceTypeGraphResponse is the schema graph.
type ResourceTypeGraphResponse struct {
	Nodes     []ResourceTypeGraphNode `json:"nodes"`
	Edges     []ResourceTypeGraphEdge `json:"edges"`
	Truncated bool                    `json:"truncated"` // more than 500 types
}

// RelationExpandInput names the object and relation to expand.
type RelationExpandInput struct {
	ObjectType    string `json:"objectType"`
	ObjectID      string `json:"objectId"`
	Relation      string `json:"relation"`
	NamespacePath string `json:"namespacePath"` // "" is the root
	// PathToType and PathToID, when both set, ask for the walk's path to
	// that subject.
	PathToType string `json:"pathToType,omitempty"`
	PathToID   string `json:"pathToId,omitempty"`
}

// RelationExpandNode is one node the walk reached.
type RelationExpandNode struct {
	Key      string `json:"key"` // "type:id#relation" or "type:id"
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation,omitempty"`
	Depth    int    `json:"depth"`
	// Walked is true when every one of the node's tuples is drawn: the walk
	// took the node off its queue and went through all of its tuples, and
	// none of its edges was left out by the node cap. It is false for a node
	// reached but never walked (a frontier node after a stop, the node that
	// tripped the fanout limit, every single subject) and for a walked node
	// with an edge to a node the cap dropped. Any edges drawn from a node
	// with walked false are not all of its tuples.
	Walked bool `json:"walked"`
	// Capped is true when the node cap removed any of this node's outgoing
	// edges, because the node at the other end was left out, and false
	// otherwise. It tells the two reasons for walked false apart: a node
	// that was never walked has capped false, and a node the walk did go
	// through, whose edges the cap then cut, has capped true. Together with
	// the node's drawn edges it says how much of the node is shown.
	Capped bool `json:"capped"`
}

// RelationExpandEdge is one tuple, between node keys.
type RelationExpandEdge struct {
	From          string `json:"from"`
	To            string `json:"to"`
	NamespacePath string `json:"namespacePath"`
}

// RelationExpandResponse is the expansion.
type RelationExpandResponse struct {
	Nodes []RelationExpandNode `json:"nodes"`
	Edges []RelationExpandEdge `json:"edges"`
	Stop  string               `json:"stop"` // complete | depth | visited | fanout
	// Limit is the limit that stopped the walk, as the walk ran with it: the
	// engine's own walker's when ExactWalk is true, Config's otherwise. 0
	// when the walk completed.
	Limit int `json:"limit"`
	// ExactWalk is false when the engine's graph walker is not the built-in
	// one: Check walks with that walker, so this expansion shows what the
	// built-in walk would find, which may differ.
	ExactWalk bool `json:"exactWalk"`
	// TruncatedNodes is how many nodes were left out past the node cap, 0
	// when none. Edges that touch a left-out node are left out too, and a
	// kept node that lost an edge that way reports walked false.
	TruncatedNodes int `json:"truncatedNodes"`
	// Path is the node keys of the walk's path to PathTo, root first, or
	// empty when not asked for or not reached.
	Path []string `json:"path"`
}

func resourceTypesGraphHandler(deps Deps) func(context.Context, ResourceTypeGraphInput, dashcontract.Principal) (ResourceTypeGraphResponse, error) {
	return func(ctx context.Context, in ResourceTypeGraphInput, p dashcontract.Principal) (ResourceTypeGraphResponse, error) {
		if err := requireEngine(deps); err != nil {
			return ResourceTypeGraphResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return ResourceTypeGraphResponse{}, err
		}
		if in.NamespacePath != nil {
			if err := validateNamespace(*in.NamespacePath); err != nil {
				return ResourceTypeGraphResponse{}, err
			}
		}
		// The cap keeps the first 500 types in namespace and name order, so
		// which survive does not depend on the store's order. That needs
		// every type, so read them all, a page at a time.
		var rows []*resourcetype.ResourceType
		for offset := 0; ; offset += schemaGraphPage {
			page, err := deps.Engine.Store().ListResourceTypes(ctx, &resourcetype.ListFilter{
				TenantID:      tenantID,
				NamespacePath: in.NamespacePath,
				Limit:         schemaGraphPage,
				Offset:        offset,
			})
			if err != nil {
				return ResourceTypeGraphResponse{}, mapWardenError(err)
			}
			rows = append(rows, page...)
			if len(page) < schemaGraphPage {
				break
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].NamespacePath != rows[j].NamespacePath {
				return rows[i].NamespacePath < rows[j].NamespacePath
			}
			if rows[i].Name != rows[j].Name {
				return rows[i].Name < rows[j].Name
			}
			return rows[i].ID.String() < rows[j].ID.String()
		})
		out := ResourceTypeGraphResponse{
			Nodes: make([]ResourceTypeGraphNode, 0, len(rows)),
			Edges: []ResourceTypeGraphEdge{},
		}
		if len(rows) > maxSchemaGraphTypes {
			out.Truncated = true
			rows = rows[:maxSchemaGraphTypes]
		}
		for _, rt := range rows {
			out.Nodes = append(out.Nodes, ResourceTypeGraphNode{
				ID:            rt.ID.String(),
				NamespacePath: rt.NamespacePath,
				Name:          rt.Name,
				Relations:     relationDefsToDTO(rt.Relations),
				Permissions:   permissionDefsToDTO(rt.Permissions),
			})
		}
		idsByName := make(map[string][]string, len(out.Nodes))
		for _, n := range out.Nodes {
			idsByName[n.Name] = append(idsByName[n.Name], n.ID)
		}
		for _, n := range out.Nodes {
			for _, rel := range n.Relations {
				for _, allowed := range rel.AllowedSubjects {
					to, toRel, _ := strings.Cut(allowed, "#")
					toIDs := append([]string{}, idsByName[to]...)
					out.Edges = append(out.Edges, ResourceTypeGraphEdge{
						From: n.Name, FromID: n.ID, Relation: rel.Name, To: to, ToRelation: toRel,
						Declared: len(toIDs) > 0, ToIDs: toIDs,
					})
				}
			}
		}
		return out, nil
	}
}

// expandKey is a node's key: type:id#relation for a subject set, type:id for
// a single subject, the labels the graph walker uses.
func expandKey(n warden.ExpandNode) string {
	if n.Relation == "" {
		return n.Type + ":" + n.ID
	}
	return n.Type + ":" + n.ID + "#" + n.Relation
}

// expansionPath returns the node indexes of the walk's path to the first node
// for subjectType:subjectID, root first, as Expansion.PathTo reconstructs it:
// the first edge into a node of that type and ID (a single subject or a
// subject set) is the tuple Walk would have stopped on. It is nil when the
// expansion never reached it.
func expansionPath(x *warden.Expansion, subjectType, subjectID string) []int {
	for _, edge := range x.Edges {
		to := x.Nodes[edge.To]
		if to.Type != subjectType || to.ID != subjectID {
			continue
		}
		var path []int
		for i := edge.From; i != -1; i = x.Parent[i] {
			path = append([]int{i}, path...)
		}
		return append(path, edge.To)
	}
	return nil
}

func relationsExpandHandler(deps Deps) func(context.Context, RelationExpandInput, dashcontract.Principal) (RelationExpandResponse, error) {
	return func(ctx context.Context, in RelationExpandInput, p dashcontract.Principal) (RelationExpandResponse, error) {
		if err := requireEngine(deps); err != nil {
			return RelationExpandResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return RelationExpandResponse{}, err
		}
		switch {
		case in.ObjectType == "":
			return RelationExpandResponse{}, badRequest("objectType is required")
		case in.ObjectID == "":
			return RelationExpandResponse{}, badRequest("objectId is required")
		case in.Relation == "":
			return RelationExpandResponse{}, badRequest("relation is required")
		case (in.PathToType == "") != (in.PathToID == ""):
			return RelationExpandResponse{}, badRequest("pathToType and pathToId go together: set both or neither")
		}
		if err := validateNamespace(in.NamespacePath); err != nil {
			return RelationExpandResponse{}, err
		}

		x, err := deps.Engine.ExpandRelation(ctx, in.ObjectType, in.ObjectID, in.Relation,
			warden.WithCallTenantID(tenantID),
			warden.WithCallNamespacePath(in.NamespacePath),
		)
		if err != nil {
			return RelationExpandResponse{}, mapWardenError(err)
		}

		var pathIdx []int
		if in.PathToType != "" {
			pathIdx = expansionPath(x, in.PathToType, in.PathToID)
		}

		// The first maxExpandNodes in the expansion's order stay, and so do
		// the root (index 0, inside the cap) and every node on the path.
		keep := make([]bool, len(x.Nodes))
		kept := 0
		for i := range x.Nodes {
			if i < maxExpandNodes {
				keep[i] = true
				kept++
			}
		}
		for _, i := range pathIdx {
			if !keep[i] {
				keep[i] = true
				kept++
			}
		}

		keys := make([]string, len(x.Nodes))
		out := RelationExpandResponse{
			Nodes:          make([]RelationExpandNode, 0, kept),
			Edges:          []RelationExpandEdge{},
			Stop:           string(x.Stop),
			Limit:          x.Limit,
			ExactWalk:      x.ExactWalk,
			TruncatedNodes: len(x.Nodes) - kept,
			Path:           []string{},
		}
		// A kept node with an edge to a dropped node no longer has all its
		// tuples drawn, so it is not reported as walked, and it is reported
		// as capped so that a walked node is not mistaken for an unwalked one.
		incomplete := make([]bool, len(x.Nodes))
		for _, e := range x.Edges {
			if keep[e.From] && !keep[e.To] {
				incomplete[e.From] = true
			}
		}
		for i, n := range x.Nodes {
			keys[i] = expandKey(n)
			if !keep[i] {
				continue
			}
			out.Nodes = append(out.Nodes, RelationExpandNode{
				Key: keys[i], Type: n.Type, ID: n.ID, Relation: n.Relation, Depth: n.Depth,
				Walked: n.Walked && !incomplete[i],
				Capped: incomplete[i],
			})
		}
		for _, e := range x.Edges {
			if !keep[e.From] || !keep[e.To] {
				continue
			}
			out.Edges = append(out.Edges, RelationExpandEdge{From: keys[e.From], To: keys[e.To], NamespacePath: e.NamespacePath})
		}
		for _, i := range pathIdx {
			out.Path = append(out.Path, keys[i])
		}
		return out, nil
	}
}
