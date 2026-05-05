package lsp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xraph/warden/dsl"
)

// handleInitialize advertises server capabilities. The client uses these
// to know which requests it can send.
func (s *server) handleInitialize(_ json.RawMessage) any {
	return initializeResult{
		Capabilities: serverCapabilities{
			TextDocumentSync:           1, // full text on every change
			HoverProvider:              true,
			DefinitionProvider:         true,
			DocumentFormattingProvider: true,
			CompletionProvider: &completionOptions{
				// Trigger after the most common context-defining characters.
				// Bare keystrokes inside an identifier still drive completion
				// because the editor batches them into a single request.
				TriggerCharacters: []string{":", "=", " ", ".", "/", "\""},
				ResolveProvider:   false,
			},
		},
		ServerInfo: &serverInfo{
			Name:    "warden-lsp",
			Version: "v1",
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Document lifecycle.
// ─────────────────────────────────────────────────────────────────────────

func (s *server) handleDidOpen(raw json.RawMessage) {
	var p didOpenParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	doc := s.setDoc(p.TextDocument.URI, p.TextDocument.Text)
	s.publishDiagnostics(doc)
}

func (s *server) handleDidChange(raw json.RawMessage) {
	var p didChangeParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	if len(p.ContentChanges) == 0 {
		return
	}
	// We advertised TextDocumentSync=1 (full sync), so the last change
	// contains the whole document text.
	text := p.ContentChanges[len(p.ContentChanges)-1].Text
	doc := s.setDoc(p.TextDocument.URI, text)
	s.publishDiagnostics(doc)
}

func (s *server) handleDidSave(raw json.RawMessage) {
	var p didSaveParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	if p.Text != "" {
		doc := s.setDoc(p.TextDocument.URI, p.Text)
		s.publishDiagnostics(doc)
	}
}

func (s *server) handleDidClose(raw json.RawMessage) {
	var p didCloseParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	s.deleteDoc(p.TextDocument.URI)
	// Clear diagnostics for the closed file.
	//nolint:errcheck // best-effort clear; client may have disconnected
	s.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{
		URI:         p.TextDocument.URI,
		Diagnostics: []lspDiagnostic{},
	})
}

// publishDiagnostics emits a textDocument/publishDiagnostics notification
// for the given document, converting parse + resolve diagnostics into LSP
// form.
func (s *server) publishDiagnostics(doc *document) {
	diags := make([]lspDiagnostic, 0, len(doc.diags))
	for _, d := range doc.diags {
		diags = append(diags, lspDiagnostic{
			Range:    dslRangeFromPos(d.Pos),
			Severity: diagError,
			Source:   "warden",
			Message:  formatErrorMsg(d.Msg),
		})
	}
	//nolint:errcheck // best-effort notification; client may have disconnected
	s.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{
		URI:         doc.uri,
		Diagnostics: diags,
	})
}

// ─────────────────────────────────────────────────────────────────────────
// Hover.
// ─────────────────────────────────────────────────────────────────────────

// handleHover returns markdown describing whatever's under the cursor.
// Recognized targets: role slugs, permission names, resource type names,
// relation names, policy names.
func (s *server) handleHover(raw json.RawMessage) any {
	var p textDocumentPositionParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	doc := s.getDoc(p.TextDocument.URI)
	if doc == nil {
		return nil
	}
	off := doc.posToOffset(p.Position)
	ident, start, end := identifierAt(doc.text, off)
	if ident == "" || doc.prog == nil {
		return nil
	}

	if md := lookupHover(doc.prog, ident); md != "" {
		return hoverResult{
			Contents: markupContent{Kind: "markdown", Value: md},
			Range: &lspRange{
				Start: offsetToPos(doc, start),
				End:   offsetToPos(doc, end),
			},
		}
	}
	return nil
}

// lookupHover resolves an identifier against the program's decls and
// returns formatted markdown for the matching entity.
func lookupHover(prog *dsl.Program, ident string) string {
	for _, r := range prog.Roles {
		if r.Slug != ident {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "**role** `%s`", r.Slug)
		if r.NamespacePath != "" {
			fmt.Fprintf(&b, " *(namespace: %s)*", r.NamespacePath)
		}
		b.WriteString("\n\n")
		if r.Name != "" {
			fmt.Fprintf(&b, "**Name:** %s\n\n", r.Name)
		}
		if r.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", r.Description)
		}
		if r.Parent != "" {
			fmt.Fprintf(&b, "Inherits from: `%s`\n\n", r.Parent)
		}
		if len(r.Grants) > 0 {
			b.WriteString("**Grants:**\n")
			for _, g := range r.Grants {
				fmt.Fprintf(&b, "- `%s`\n", g)
			}
		}
		return b.String()
	}
	for _, p := range prog.Permissions {
		if p.Name != ident && strings.Trim(ident, "\"") != p.Name {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "**permission** `%s`\n\n", p.Name)
		fmt.Fprintf(&b, "Resource: `%s` · Action: `%s`\n\n", p.Resource, p.Action)
		if p.Description != "" {
			fmt.Fprintf(&b, "%s\n", p.Description)
		}
		return b.String()
	}
	for _, rt := range prog.ResourceTypes {
		if rt.Name != ident {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "**resource type** `%s`\n\n", rt.Name)
		if rt.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", rt.Description)
		}
		b.WriteString("**Relations:**\n")
		for _, rel := range rt.Relations {
			fmt.Fprintf(&b, "- `%s`\n", rel.Name)
		}
		if len(rt.Permissions) > 0 {
			b.WriteString("\n**Permissions:**\n")
			for _, perm := range rt.Permissions {
				fmt.Fprintf(&b, "- `%s` = %s\n", perm.Name, dsl.FormatExpr(perm.Expr))
			}
		}
		return b.String()
	}
	for _, pol := range prog.Policies {
		if pol.Name == ident || strings.Trim(ident, "\"") == pol.Name {
			var b strings.Builder
			fmt.Fprintf(&b, "**policy** `%s`\n\n", pol.Name)
			fmt.Fprintf(&b, "Effect: `%s` · Priority: %d · Active: %t\n",
				pol.Effect, pol.Priority, pol.Active)
			return b.String()
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────
// Definition.
// ─────────────────────────────────────────────────────────────────────────

// handleDefinition jumps from a reference (parent slug, grant name, parent
// role in expression) to the matching declaration's position.
func (s *server) handleDefinition(raw json.RawMessage) any {
	var p textDocumentPositionParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	doc := s.getDoc(p.TextDocument.URI)
	if doc == nil {
		return nil
	}
	off := doc.posToOffset(p.Position)
	ident, _, _ := identifierAt(doc.text, off)
	if ident == "" || doc.prog == nil {
		return nil
	}

	target := lookupDefinition(doc.prog, ident)
	if target.Line == 0 {
		return nil
	}
	pos := dslPosToLSP(target)
	return []lspLocation{{
		URI: doc.uri,
		Range: lspRange{
			Start: pos,
			End:   lspPosition{Line: pos.Line, Character: pos.Character + len(ident)},
		},
	}}
}

// lookupDefinition finds the declaration position of the named entity.
// Searches roles, permissions, resource types, and policies in order.
func lookupDefinition(prog *dsl.Program, ident string) dsl.Pos {
	cleanName := strings.Trim(ident, "\"")
	for _, r := range prog.Roles {
		if r.Slug == ident {
			return r.Pos
		}
	}
	for _, p := range prog.Permissions {
		if p.Name == ident || p.Name == cleanName {
			return p.Pos
		}
	}
	for _, rt := range prog.ResourceTypes {
		if rt.Name == ident {
			return rt.Pos
		}
	}
	for _, pol := range prog.Policies {
		if pol.Name == ident || pol.Name == cleanName {
			return pol.Pos
		}
	}
	return dsl.Pos{}
}

// ─────────────────────────────────────────────────────────────────────────
// Formatting.
// ─────────────────────────────────────────────────────────────────────────

// handleFormatting returns a single TextEdit replacing the whole document
// with its canonical form. We use full-document replace rather than diff
// computation because the formatter is fast (~200 µs for typical configs)
// and the editor handles cursor preservation.
func (s *server) handleFormatting(raw json.RawMessage) any {
	var p formattingParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	doc := s.getDoc(p.TextDocument.URI)
	if doc == nil || doc.prog == nil {
		return nil
	}
	formatted := dsl.Format(doc.prog)
	if formatted == doc.text {
		return []lspTextEdit{} // already canonical
	}
	// Replace the entire document. The end position is line:0 of the line
	// after the last newline, which covers the trailing newline cleanly.
	endLine := len(doc.lineIdx) - 1
	if endLine < 0 {
		endLine = 0
	}
	return []lspTextEdit{{
		Range: lspRange{
			Start: lspPosition{Line: 0, Character: 0},
			End:   lspPosition{Line: endLine + 1, Character: 0},
		},
		NewText: formatted,
	}}
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

// offsetToPos converts a byte offset into an LSP position via the cached
// line index.
func offsetToPos(doc *document, off int) lspPosition {
	if off < 0 {
		off = 0
	}
	if off > len(doc.text) {
		off = len(doc.text)
	}
	// Binary search would be faster but linear is fine for editor-scale docs.
	line := 0
	for i, start := range doc.lineIdx {
		if start > off {
			break
		}
		line = i
	}
	col := off - doc.lineIdx[line]
	return lspPosition{Line: line, Character: col}
}
