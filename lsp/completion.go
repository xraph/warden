package lsp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Context-detection regular expressions. Each is anchored on the line
// prefix (text from start-of-line to cursor) so they describe what the
// user has typed *so far* on the current line.

var (
	// `role admin :` — possibly with whitespace. The trailing optional
	// `[a-z_-]*` allows for a partial identifier the user has begun
	// typing (e.g. `role admin : vie`).
	roleParentRegex = regexp.MustCompile(`^\s*role\s+[a-z][a-z0-9_-]*\s*:\s*[a-z0-9_/-]*$`)

	// Inside `grants = [` — captures both `[` and a partially-typed
	// string in the list. Matches multi-line lists by accepting
	// `[`, optional commas, and any whitespace.
	grantsListRegex = regexp.MustCompile(`grants\s*\+?=\s*\[[^\]]*$`)

	// `permission "x:y" (` — opening paren of the shorthand form.
	permResourceRegex = regexp.MustCompile(`^\s*permission\s+"[^"]*"\s*\(\s*[a-z0-9_]*$`)

	// `permission "x:y" (resource :` — captures the resource name. The
	// action is what we want to complete.
	permActionRegex = regexp.MustCompile(`^\s*permission\s+"[^"]*"\s*\(\s*([a-z][a-z0-9_]*)\s*:\s*[a-z0-9_*-]*$`)

	// On the right side of a `permission X =` expression in a resource
	// block. We accept any subexpression so far and trigger on pretty
	// much anything reasonable (the editor will filter as the user types).
	exprAfterEqualsRegex = regexp.MustCompile(`^\s*permission\s+[a-z][a-z0-9_]*\s*=\s*.*$`)

	// Inside a `when { context.X ` predicate, after the field path,
	// looking for an operator.
	conditionOpRegex = regexp.MustCompile(`^\s*[a-z][a-z0-9_.]*\.[a-z][a-z0-9_]*\s+[a-z=!<>~]*$`)
)

// handleCompletion produces context-aware suggestions for the cursor
// position. It inspects the line up to the cursor (and a small amount
// of surrounding text) to decide which of seven completion contexts
// applies, then defers to a dedicated generator.
//
// The seven contexts:
//
//  1. Top-level keyword       — start of line at file root
//  2. Role parent slug        — after `role <ident> :`
//  3. Role grants string      — inside `grants = [`
//  4. Permission resource ref — after `permission "..." (`
//  5. Permission action ref   — after `permission "..." (<resource> :`
//  6. Expression refs         — inside `permission read =` (in resource block)
//  7. Policy field / `when` keyword — inside `policy { ... }` / `when { ... }`
//
// Anything outside these contexts returns no items rather than a
// generic dump — completion noise is worse than no completion.
func (s *server) handleCompletion(raw json.RawMessage) any {
	var p completionParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	doc := s.getDoc(p.TextDocument.URI)
	if doc == nil {
		return emptyCompletionList()
	}
	off := doc.posToOffset(p.Position)
	prefix := lineUpToCursor(doc.text, off)
	beforeBlock := surroundingBlockText(doc.text, off)

	ctx := classifyContext(prefix, beforeBlock)

	s.mu.RLock()
	ws := s.workspace
	s.mu.RUnlock()

	switch ctx.kind {
	case ctxTopLevel:
		return wrapItems(topLevelKeywordItems())
	case ctxRoleParent:
		return wrapItems(roleParentItems(ws, ctx.namespacePath))
	case ctxRoleGrants:
		return wrapItems(permissionGrantItems(ws))
	case ctxPermissionResource:
		return wrapItems(resourceTypeItems(ws))
	case ctxPermissionAction:
		return wrapItems(resourceActionItems(ws, ctx.resourceName))
	case ctxResourceExpression:
		return wrapItems(expressionRefItems(ws, ctx.resourceName))
	case ctxPolicyField:
		return wrapItems(policyFieldItems())
	case ctxWhenOperator:
		return wrapItems(conditionOperatorItems())
	case ctxRoleField:
		return wrapItems(roleFieldItems())
	default:
		return emptyCompletionList()
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Context classification.
// ─────────────────────────────────────────────────────────────────────────

type completionCtxKind int

const (
	ctxNone completionCtxKind = iota
	ctxTopLevel
	ctxRoleParent
	ctxRoleGrants
	ctxRoleField
	ctxPermissionResource
	ctxPermissionAction
	ctxResourceExpression
	ctxPolicyField
	ctxWhenOperator
)

type completionContext struct {
	kind          completionCtxKind
	resourceName  string // for ctxPermissionAction / ctxResourceExpression
	namespacePath string // for ctxRoleParent — relative resolution scope
}

// classifyContext determines which completion context applies given the
// line prefix (text from the start of the cursor's line up to the
// cursor) and the surrounding block text (used to detect "we're inside
// a `role X { … }` block").
func classifyContext(prefix, blockText string) completionContext {
	trimmed := strings.TrimSpace(prefix)

	// Top-level keyword: empty or a single in-progress identifier at the
	// start of a line, AND we're not inside any block.
	if !inAnyBlock(blockText) {
		if trimmed == "" || isPartialIdent(trimmed) {
			return completionContext{kind: ctxTopLevel}
		}
	}

	// Role parent: `role <slug> :` with optional whitespace after the colon.
	// e.g. `role admin : ` or `role admin :` mid-typing.
	if m := roleParentRegex.FindStringSubmatch(prefix); m != nil {
		return completionContext{kind: ctxRoleParent}
	}

	// Inside a `grants = [...]` list.
	if grantsListRegex.MatchString(blockText + prefix) {
		return completionContext{kind: ctxRoleGrants}
	}

	// `permission "name" (` opens — completing resource type.
	if permResourceRegex.MatchString(prefix) {
		return completionContext{kind: ctxPermissionResource}
	}

	// `permission "name" (<resource> :` — completing action.
	if m := permActionRegex.FindStringSubmatch(prefix); m != nil {
		return completionContext{kind: ctxPermissionAction, resourceName: m[1]}
	}

	// Inside a resource block, on the right side of a `permission X =`
	// expression — completing relation names.
	if rname := enclosingResourceName(blockText); rname != "" {
		if exprAfterEqualsRegex.MatchString(prefix) {
			return completionContext{kind: ctxResourceExpression, resourceName: rname}
		}
	}

	// Inside a policy block — completing field names at the start of a line.
	if isInsidePolicyBlock(blockText) {
		// `when { context.X ` — completing operator.
		if conditionOpRegex.MatchString(prefix) {
			return completionContext{kind: ctxWhenOperator}
		}
		if isPartialIdent(trimmed) || trimmed == "" {
			return completionContext{kind: ctxPolicyField}
		}
	}

	// Inside a role block — completing field names.
	if isInsideRoleBlock(blockText) {
		if isPartialIdent(trimmed) || trimmed == "" {
			return completionContext{kind: ctxRoleField}
		}
	}

	return completionContext{kind: ctxNone}
}

// ─────────────────────────────────────────────────────────────────────────
// Item generators.
// ─────────────────────────────────────────────────────────────────────────

func topLevelKeywordItems() []completionItem {
	keywords := []struct{ word, doc string }{
		{"namespace", "Begin a namespace block — entities inside are scoped to this path."},
		{"resource", "Define a resource type with relations and permission expressions (ReBAC)."},
		{"permission", `Declare a permission, e.g. permission "doc:read" (document : read).`},
		{"role", "Declare a role with grants and an optional parent."},
		{"policy", "Declare an ABAC/PBAC policy with effect, conditions, and obligations."},
		{"relation", "Declare a relation tuple (initial state)."},
		{"import", `Import another .warden file — import "shared/policies.warden".`},
	}
	out := make([]completionItem, 0, len(keywords))
	for _, k := range keywords {
		out = append(out, completionItem{
			Label:         k.word,
			Kind:          completionItemKeyword,
			Detail:        "warden top-level keyword",
			Documentation: k.doc,
		})
	}
	return out
}

func roleParentItems(ws *workspaceIndex, _ string) []completionItem {
	roles := ws.roleSlugs()
	out := make([]completionItem, 0, len(roles))
	for _, r := range roles {
		label := r.Slug
		insert := r.Slug
		// Suggest the absolute form for cross-namespace references when
		// the role lives somewhere other than tenant root.
		if r.NamespacePath != "" {
			label = "/" + r.NamespacePath + "/" + r.Slug
			insert = label
		}
		detail := formatOriginDetail(r.URI, r.Pos)
		if r.Name != "" {
			detail = r.Name + " · " + detail
		}
		out = append(out, completionItem{
			Label:         label,
			Kind:          completionItemVariable,
			Detail:        detail,
			Documentation: r.Description,
			InsertText:    insert,
		})
	}
	return out
}

func permissionGrantItems(ws *workspaceIndex) []completionItem {
	perms := ws.permissionNames()
	out := make([]completionItem, 0, len(perms))
	for _, p := range perms {
		insert := p.Name
		// Inside a string list, the user typed the opening `"` (or will);
		// don't double-quote in InsertText — the editor handles the quote.
		out = append(out, completionItem{
			Label:         p.Name,
			Kind:          completionItemFunction,
			Detail:        formatOriginDetail(p.URI, p.Pos),
			Documentation: p.Description,
			InsertText:    insert,
		})
	}
	return out
}

func resourceTypeItems(ws *workspaceIndex) []completionItem {
	rts := ws.resourceTypeNames()
	out := make([]completionItem, 0, len(rts))
	for _, rt := range rts {
		out = append(out, completionItem{
			Label:      rt.Name,
			Kind:       completionItemClass,
			Detail:     formatOriginDetail(rt.URI, rt.Pos),
			InsertText: rt.Name,
		})
	}
	return out
}

func resourceActionItems(ws *workspaceIndex, resourceName string) []completionItem {
	rh, ok := ws.findResource(resourceName)
	if !ok {
		return nil
	}
	out := make([]completionItem, 0, len(rh.Permissions))
	for _, perm := range rh.Permissions {
		out = append(out, completionItem{
			Label:      perm,
			Kind:       completionItemEnumMember,
			Detail:     fmt.Sprintf("%s.%s", rh.Name, perm),
			InsertText: perm,
		})
	}
	return out
}

func expressionRefItems(ws *workspaceIndex, resourceName string) []completionItem {
	rh, ok := ws.findResource(resourceName)
	if !ok {
		return nil
	}
	out := make([]completionItem, 0, len(rh.Relations)+3)
	for _, rel := range rh.Relations {
		out = append(out, completionItem{
			Label:      rel,
			Kind:       completionItemProperty,
			Detail:     fmt.Sprintf("relation on %s", rh.Name),
			InsertText: rel,
		})
	}
	// Operator keywords usable inside the expression.
	for _, op := range []string{"or", "and", "not"} {
		out = append(out, completionItem{
			Label:    op,
			Kind:     completionItemKeyword,
			Detail:   "expression operator",
			SortText: "z" + op, // demote below relation refs
		})
	}
	return out
}

func policyFieldItems() []completionItem {
	fields := []struct{ k, doc string }{
		{"description", "Free-form description of the policy."},
		{"effect", "allow | deny — the policy effect."},
		{"priority", "Integer; lower priority wins when multiple policies match."},
		{"active", "Whether the policy is active. PBAC: see also not_before / not_after."},
		{"not_before", `PBAC: RFC3339 instant — policy is inactive before this time. e.g. "2026-06-01T00:00:00Z".`},
		{"not_after", `PBAC: RFC3339 instant — policy is inactive after this time.`},
		{"obligations", `PBAC: list of named side-effect actions emitted on match. e.g. ["audit-log","require-mfa"].`},
		{"actions", "List of action patterns (glob) the policy applies to."},
		{"resources", "List of resource patterns (glob) the policy applies to."},
		{"subjects", "List of subject matchers."},
		{"when", "Condition block: when { context.X == \"...\" }."},
		{"metadata", "Map of arbitrary metadata associated with the policy."},
	}
	out := make([]completionItem, 0, len(fields))
	for _, f := range fields {
		out = append(out, completionItem{
			Label:         f.k,
			Kind:          completionItemField,
			Detail:        "policy field",
			Documentation: f.doc,
		})
	}
	return out
}

func roleFieldItems() []completionItem {
	fields := []struct{ k, doc string }{
		{"name", "Display name for the role."},
		{"description", "Free-form description."},
		{"is_system", "Marks the role as system-managed."},
		{"is_default", "Marks the role as the default role for new subjects."},
		{"max_members", "Limit on the number of subjects assignable to the role."},
		{"grants", "List of permission names granted by this role. Use += to append to inherited grants."},
		{"metadata", "Map of arbitrary metadata."},
	}
	out := make([]completionItem, 0, len(fields))
	for _, f := range fields {
		out = append(out, completionItem{
			Label:         f.k,
			Kind:          completionItemField,
			Detail:        "role field",
			Documentation: f.doc,
		})
	}
	return out
}

func conditionOperatorItems() []completionItem {
	ops := []struct{ op, doc string }{
		{"==", "Equality."},
		{"!=", "Inequality."},
		{">", "Greater than."},
		{"<", "Less than."},
		{">=", "Greater than or equal."},
		{"<=", "Less than or equal."},
		{"in", "Value is in a list."},
		{"contains", "String contains substring."},
		{"starts_with", "String starts with prefix."},
		{"ends_with", "String ends with suffix."},
		{"=~", "Regex match."},
		{"exists", "Field is present."},
		{"ip_in_cidr", "IP address falls within a CIDR range."},
		{"time_after", "Time is after a threshold."},
		{"time_before", "Time is before a threshold."},
	}
	out := make([]completionItem, 0, len(ops))
	for _, o := range ops {
		out = append(out, completionItem{
			Label:         o.op,
			Kind:          completionItemKeyword,
			Detail:        "condition operator",
			Documentation: o.doc,
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

func wrapItems(items []completionItem) completionList {
	if items == nil {
		items = []completionItem{}
	}
	return completionList{IsIncomplete: false, Items: items}
}

func emptyCompletionList() completionList {
	return completionList{IsIncomplete: false, Items: []completionItem{}}
}

// lineUpToCursor returns the substring from the start of the line
// containing offset up to (but not including) offset.
func lineUpToCursor(text string, offset int) string {
	if offset > len(text) {
		offset = len(text)
	}
	start := offset
	for start > 0 && text[start-1] != '\n' {
		start--
	}
	return text[start:offset]
}

// surroundingBlockText returns the text from the start of the document
// up to the cursor — coarse but good enough for the simple "are we in a
// role/policy/resource block?" check we need. The classifier only looks
// at recent open/close braces.
func surroundingBlockText(text string, offset int) string {
	if offset > len(text) {
		offset = len(text)
	}
	return text[:offset]
}

func isPartialIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '_' && r != '-' &&
			(r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// inAnyBlock reports whether the cursor sits inside an open `{` block
// (i.e. there are more `{` than `}` so far). This is a structural
// heuristic, not a full parser — string literals and comments may
// confuse it. For the completion contexts we care about it's accurate
// enough.
func inAnyBlock(text string) bool {
	open := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '{':
			open++
		case '}':
			if open > 0 {
				open--
			}
		}
	}
	return open > 0
}

// enclosingResourceName returns the name of the innermost open
// `resource <name> { ... ` block, or "" if not inside one.
func enclosingResourceName(text string) string {
	return enclosingDeclName(text, "resource")
}

// isInsidePolicyBlock reports whether the cursor is inside an open
// `policy "..." { ... ` block.
func isInsidePolicyBlock(text string) bool {
	return enclosingDeclName(text, "policy") != ""
}

// isInsideRoleBlock reports whether the cursor is inside an open
// `role <slug> { ... ` block.
func isInsideRoleBlock(text string) bool {
	return enclosingDeclName(text, "role") != ""
}

// enclosingDeclName scans backwards looking for the most recent
// unterminated `<keyword> ... {` and returns the identifier (or quoted
// name) immediately following the keyword. Returns "" when no such
// block is open.
//
// Very lightweight: we only track brace depth, not string/comment
// boundaries. The resolver / formatter operate on the canonical AST;
// completion just needs a "good enough" hint.
func enclosingDeclName(text, keyword string) string {
	open := 0
	// Walk right-to-left so we encounter the innermost open `{` first.
	for i := len(text) - 1; i >= 0; i-- {
		switch text[i] {
		case '}':
			open++
		case '{':
			if open > 0 {
				open--
				continue
			}
			// Unmatched `{` — find the keyword on the same line.
			lineStart := i
			for lineStart > 0 && text[lineStart-1] != '\n' {
				lineStart--
			}
			line := text[lineStart:i]
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == keyword {
				name := strings.TrimSpace(fields[1])
				return strings.Trim(name, "\":")
			}
			return ""
		}
	}
	return ""
}
