# Editor support for the Warden DSL

This directory holds the source-of-truth assets that editors and IDEs use
to syntax-highlight and structurally understand `.warden` files. None of
it is required to build or run the warden binary or library — it's
distribution-only.

## Contents

- [`warden.tmLanguage.json`](./warden.tmLanguage.json) — TextMate grammar
  (VS Code, Sublime, IntelliJ). Hand-written, ~210 lines, declares all
  keywords, operators, identifiers, strings, comments, expressions.
- [`tree-sitter-warden/`](./tree-sitter-warden/) — Tree-sitter grammar
  scaffold (Helix, Neovim, Zed, GitHub web). `grammar.js` mirrors the
  parser in `../dsl/parser.go`; queries/highlights.scm maps grammar
  nodes to standard tree-sitter highlight names. See the directory's
  own README for the recipe to publish as `tree-sitter-warden`.
- [`vscode-warden/`](./vscode-warden/) — Ready-to-build VS Code
  extension. Bundles the TextMate grammar above and spawns
  [`warden-lsp`](../cmd/warden-lsp/) as a stdio language client to
  provide hover, completion, definition, formatting, and diagnostics.
  See its own README for the install / dev recipe.

## LSP server

Live language features (diagnostics, hover, go-to-definition, formatting)
are provided by the [`warden-lsp`](../cmd/warden-lsp/) binary, not by
files in this directory. Pair the TextMate grammar with the LSP server
for a complete editor experience.

Quick wiring:

| Editor | Recipe |
|---|---|
| Neovim (lspconfig) | Point `cmd = {'warden-lsp'}` and `filetypes = {'warden'}`. Use the tree-sitter grammar for highlighting. |
| VS Code | Build [`vscode-warden/`](./vscode-warden/) (`bun install && bun run build`) — wraps the TextMate grammar and spawns `warden-lsp` automatically. |
| Helix | Add `[[language]] name = "warden"` with `language-server = { command = "warden-lsp" }` and the tree-sitter grammar. |
| Zed | Use the tree-sitter grammar; `warden-lsp` runs via the language server config. |

## Synchronization

The grammars must stay in sync with the canonical Go parser. When the DSL
changes:

1. Update `dsl/parser.go` (canonical behavior).
2. Update `dsl/lexer.go` if the token set changed.
3. Update `editor/warden.tmLanguage.json` keyword/operator lists.
4. Update `editor/tree-sitter-warden/grammar.js` rules.
5. Update `editor/tree-sitter-warden/queries/highlights.scm` if new node
   types need capture rules.

All four artifacts can drift silently — no test enforces lockstep — so
include all five in any DSL surface change.
