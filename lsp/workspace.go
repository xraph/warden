package lsp

import (
	"sort"
	"strings"

	"github.com/xraph/warden/dsl"
)

// workspaceIndex aggregates symbols across every open document so the
// LSP can offer cross-file completions ("the role I'm declaring inherits
// from a role declared in another file").
//
// The index is rebuilt eagerly on every didOpen / didChange / didClose
// — cheap because each document is already re-parsed there. We hold a
// snapshot of every open document's parse tree, keyed by URI; lookup
// helpers flatten and dedupe across all URIs.
type workspaceIndex struct {
	progByURI map[string]*dsl.Program
}

func newWorkspaceIndex() *workspaceIndex {
	return &workspaceIndex{progByURI: map[string]*dsl.Program{}}
}

// set stores the parsed program for a URI, replacing any prior entry.
func (w *workspaceIndex) set(uri string, prog *dsl.Program) {
	if prog == nil {
		delete(w.progByURI, uri)
		return
	}
	w.progByURI[uri] = prog
}

// remove drops the program for a URI (typically on didClose).
func (w *workspaceIndex) remove(uri string) {
	delete(w.progByURI, uri)
}

// roleSlugs returns every distinct role slug across the workspace,
// sorted for stable completion ordering. originURI is the URI of the
// document where completion was triggered; we report which file each
// role came from in the Detail field for easy disambiguation.
func (w *workspaceIndex) roleSlugs() []roleHint {
	seen := map[string]roleHint{}
	for uri, prog := range w.progByURI {
		for _, r := range prog.Roles {
			key := r.NamespacePath + "/" + r.Slug
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = roleHint{
				Slug:          r.Slug,
				NamespacePath: r.NamespacePath,
				Name:          r.Name,
				Description:   r.Description,
				URI:           uri,
				Pos:           r.Pos,
			}
		}
	}
	out := make([]roleHint, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NamespacePath != out[j].NamespacePath {
			return out[i].NamespacePath < out[j].NamespacePath
		}
		return out[i].Slug < out[j].Slug
	})
	return out
}

// permissionNames returns every distinct permission name (the `<resource>:<action>` string)
// across the workspace.
func (w *workspaceIndex) permissionNames() []permissionHint {
	seen := map[string]permissionHint{}
	for uri, prog := range w.progByURI {
		for _, p := range prog.Permissions {
			key := p.NamespacePath + "/" + p.Name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = permissionHint{
				Name:          p.Name,
				Resource:      p.Resource,
				Action:        p.Action,
				NamespacePath: p.NamespacePath,
				Description:   p.Description,
				URI:           uri,
				Pos:           p.Pos,
			}
		}
	}
	out := make([]permissionHint, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// resourceTypeNames returns every distinct resource type name across the workspace.
func (w *workspaceIndex) resourceTypeNames() []resourceHint {
	seen := map[string]resourceHint{}
	for uri, prog := range w.progByURI {
		for _, rt := range prog.ResourceTypes {
			key := rt.NamespacePath + "/" + rt.Name
			if _, ok := seen[key]; ok {
				continue
			}
			rels := make([]string, 0, len(rt.Relations))
			perms := make([]string, 0, len(rt.Permissions))
			for _, rel := range rt.Relations {
				rels = append(rels, rel.Name)
			}
			for _, p := range rt.Permissions {
				perms = append(perms, p.Name)
			}
			seen[key] = resourceHint{
				Name:          rt.Name,
				NamespacePath: rt.NamespacePath,
				Relations:     rels,
				Permissions:   perms,
				URI:           uri,
				Pos:           rt.Pos,
			}
		}
	}
	out := make([]resourceHint, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// findResource returns relation/permission lists for a resource type
// declared anywhere in the workspace (used by expression completion).
func (w *workspaceIndex) findResource(name string) (resourceHint, bool) {
	for _, rh := range w.resourceTypeNames() {
		if rh.Name == name {
			return rh, true
		}
	}
	return resourceHint{}, false
}

// roleHint / permissionHint / resourceHint capture just enough info to
// build a CompletionItem with origin metadata.
type roleHint struct {
	Slug          string
	NamespacePath string
	Name          string
	Description   string
	URI           string
	Pos           dsl.Pos
}

type permissionHint struct {
	Name          string
	Resource      string
	Action        string
	NamespacePath string
	Description   string
	URI           string
	Pos           dsl.Pos
}

type resourceHint struct {
	Name          string
	NamespacePath string
	Relations     []string
	Permissions   []string
	URI           string
	Pos           dsl.Pos
}

// formatOriginDetail returns a human-readable "where this came from"
// label for a completion item — used in CompletionItem.Detail. Trims
// the URI's path-prefix so editors don't show a bare file:// URL.
func formatOriginDetail(uri string, pos dsl.Pos) string {
	short := uri
	if i := strings.LastIndex(short, "/"); i >= 0 {
		short = short[i+1:]
	}
	if pos.Line == 0 {
		return short
	}
	return short + ":" + itoaPad(pos.Line)
}

// itoaPad formats an int without depending on strconv.Itoa for speed —
// micro-optimization since this runs in the completion hot path.
func itoaPad(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
