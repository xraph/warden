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

## Syntax the grammars must know

`warden export` and the dashboard's schema editor write every form below, so
a grammar that doesn't know them will mark valid source as broken. They exist
so that anything a tenant stores can be exported and applied back unchanged.

### Policy subjects

```warden
policy "deny-contractors" {
    effect = deny
    subjects = [
        { kind = "user" },                          // every user
        { id = "alice" },                           // alice, whatever her kind
        { role = "contractor" },                    // anyone holding contractor
        { kind = "user", id = "bob", role = "temp" },
        {},                                         // the empty matcher: everyone
    ]
    actions = ["write"]
}
```

Each entry is a matcher with up to three string fields: `kind`, `id` and
`role`. The fields inside one matcher are AND-ed, and the policy applies when
any matcher matches. Leave the clause out and the policy stores no matchers.
You can drop the commas between fields. Format writes a single matcher inline,
and more than one a line each, always in the order kind, id, role.

### Qualified grants and `grants = []`

```warden
namespace "eng" {
    role dev {
        grants = [
            "deploy:run",                                // eng's deploy:run
            { namespace = "", name = "doc:read" },       // the root one, not eng's
            { namespace = "ops", name = "page:send" },
        ]
    }
}
```

A bare grant is looked up in the role's own namespace, then at the root.
Anything else needs the qualified form: a permission in a sibling namespace,
one in a parent that isn't the root, or a root permission that a same-named
permission in the role's namespace would shadow.

Once a role has a `grants` clause it owns its whole grant set. So `grants = []`
revokes everything. A role with no `grants` clause at all keeps whatever it
has in the store.

### Quoted names

```warden
tenant "0f3a-9c"

resource "role" {
    relation "name": user | "user:*"
    relation "on call":            // lists no subject type, so it takes any subject
}

permission "warden:role:read" {
    resource = "warden:role"
    action = read
}

relation document:"design doc.md" viewer = user:"bob@example.com"
```

Wherever the language takes a name, you can write a string literal instead of
an identifier. That covers the tenant and app in the header, resource types,
relations, allowed subject types, resource permissions, a permission's
resource and action, role slugs and parents, and every part of a relation
tuple. Format quotes a name only when a bare identifier wouldn't read back as
the same name: a keyword, a leading digit, a space, a colon or a glob.

Permissions use the shorthand `permission "doc:read" (doc : read)` until they
carry a description or are system permissions. Then Format switches to the
block form.

### Condition values and fields

A value can be a decimal (`0.75`), a negative number (`-3`), or a list mixing
strings, numbers and booleans (`[1, 2]`). `exists` and `not exists` take no
value, and the parser only reads one if it starts on the operator's own line,
so a following condition that opens with a quoted field is never swallowed.
Path segments may be keywords (`resource.name`, `subject.role`). If a field
can't be spelled as a bare path, quote the whole thing:
`"subject.attributes[\"team name\"]" == "core"`.

`negate`, `all_of` and `any_of` still parse, so the grammars should keep
them. The resolver refuses `negate` and any `any_of` that doesn't hold exactly
one condition, since the store keeps conditions as one AND-ed list with no
negation and no OR.

### Namespaces

Format writes root entities first, then one flat block per namespace path,
sorted, named by its full path: `namespace "eng/platform" { ... }`. Nested
blocks in your source mean the same thing and come back flat. An empty block
like `namespace "ops" {}` is kept, because it still tells prune that `ops` is
covered.

## Synchronization

The grammars must stay in sync with the canonical Go parser. When the DSL
changes:

1. Update `dsl/parser.go` (canonical behavior).
2. Update `dsl/lexer.go` if the token set changed.
3. Update `editor/warden.tmLanguage.json` keyword/operator lists.
4. Update `editor/tree-sitter-warden/grammar.js` rules.
5. Update `editor/tree-sitter-warden/queries/highlights.scm` if new node
   types need capture rules.
6. Describe any new form under "Syntax the grammars must know" above.

All four artifacts can drift silently — no test enforces lockstep — so
include all five in any DSL surface change.
