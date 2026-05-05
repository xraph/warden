# tree-sitter-warden (scaffold)

Tree-sitter grammar for the Warden DSL.

This directory holds the source-of-truth `grammar.js`. To use it in editors
that support tree-sitter (Helix, Neovim, Zed, GitHub web), publish it as a
standalone repo at `github.com/xraph/tree-sitter-warden`:

```sh
mkdir tree-sitter-warden && cd tree-sitter-warden
cp <warden-repo>/editor/tree-sitter-warden/grammar.js .
cp -r <warden-repo>/editor/tree-sitter-warden/queries .
npm init -y
npm install --save-dev tree-sitter-cli
npx tree-sitter init-repo
npx tree-sitter generate
npx tree-sitter test
```

The grammar mirrors the parser in
[../../dsl/parser.go](../../dsl/parser.go). Keep them in sync — the Go
parser is canonical for behavior; tree-sitter is editor-side only.

## Smoke test

```sh
npx tree-sitter parse <(cat <<'EOF'
warden config 1
tenant t1

resource document {
    relation owner: user
    relation viewer: user | group#member
    permission read = viewer or owner or parent->read
}

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}
EOF
)
```

Should produce a parse tree with no errors.

## Highlight queries

`queries/highlights.scm` maps grammar nodes to the standard tree-sitter
highlight names (`@keyword`, `@function`, `@type`, `@string`, `@comment`,
…). Editors using nvim-treesitter or similar will pick these up
automatically.

## Status

This scaffold is the source-of-truth grammar. Distribution lives in a
separate repo per the original plan; this file shouldn't be vendored into
build artifacts here.
