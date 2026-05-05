# Warden for Visual Studio Code

Authoring support for `.warden` files — the declarative authorization
DSL that powers RBAC, ReBAC, ABAC, and PBAC in the [Warden][warden]
engine.

> Published as **`xraph.vscode-warden`** on the
> [VS Code Marketplace][marketplace] and
> [Open VSX Registry][openvsx].

## Install

**From the Marketplace** (recommended):

```bash
code --install-extension xraph.vscode-warden
```

…or search for **"Warden"** in the Extensions panel
(`Cmd+Shift+X` / `Ctrl+Shift+X`).

**From Open VSX** (Cursor, VSCodium, other forks):

```bash
codium --install-extension xraph.vscode-warden
```

## Features

- **Syntax highlighting** for the full grammar (resources, relations,
  permission expressions, roles, policies, namespaces, conditions).
- **Completion** — context-aware suggestions for top-level keywords,
  role parents (cross-file), permission grants, resource and action
  references, expression operators, policy fields (including PBAC
  `not_before` / `not_after` / `obligations`), and condition operators.
- **Hover** — markdown summaries for roles, permissions, resource
  types, policies.
- **Go-to-definition** — jump from any reference (parent slug, grant
  string, expression ref) to its declaration.
- **Diagnostics** — parser and resolver errors as you type, with file,
  line, and column.
- **Formatting** — whole-document canonical formatter; `Shift+Alt+F`
  produces stable output that round-trips through parse + format.

## Requirements

- VS Code 1.80 or later.
- The `warden` CLI on your `PATH` for live diagnostics, completion,
  hover, and go-to-definition. Install with:

  ```bash
  go install github.com/xraph/warden/cmd/warden@latest
  ```

  The extension still provides syntax highlighting without it.

  The extension spawns `warden lsp` by default (the LSP server is a
  subcommand of the unified CLI). To use the standalone `warden-lsp`
  binary instead:

  ```bash
  go install github.com/xraph/warden/cmd/warden-lsp@latest
  ```

  ```jsonc
  // settings.json
  "warden.lsp.command": ["warden-lsp"]
  ```

## Settings

| Key | Default | Description |
|---|---|---|
| `warden.lsp.command` | `["warden", "lsp"]` | Argv for spawning the language server. Use `["warden-lsp"]` for the standalone shim, or `["/abs/path/to/warden", "lsp"]` to bypass `PATH`. |
| `warden.lsp.trace` | `off` | Verbose LSP trace output. `messages` for method names, `verbose` for full bodies. |
| `warden.lsp.disable` | `false` | Disable the language server entirely. Syntax highlighting still works. |

## Build From Source

For interactive iteration with the Extension Host:

```bash
# In editor/vscode-warden/
npm install
npm run compile
```

Then open this directory in VS Code and press **F5**. A new Extension
Host window opens with the extension loaded. Open any `.warden` file
in that window to exercise hover / completion / diagnostics /
formatting. F5 picks up source changes after a rebuild.

The TextMate grammar is sourced from `../warden.tmLanguage.json`. Run
`npm run sync-grammar` to refresh the in-extension copy whenever the
canonical grammar changes (CI enforces sync via the validate workflow).

`bun` works too — `bun install && bun run compile` is equivalent. The
project ships a `package-lock.json` for npm-based CI; bun reads
`package.json` directly and is fine.

## Package Locally

```bash
npm run package
```

Produces `vscode-warden-<version>.vsix`. Install via:

```bash
code --install-extension vscode-warden-0.1.0.vsix
```

## Release Process

The extension follows the same release pattern as
[forge-devtools][forge-pattern]:

| Trigger | Behavior |
|---|---|
| **Push** to a branch with changes under `editor/vscode-warden/**` | The `validate` job runs (lint → compile → package) and uploads the `.vsix` as a CI artifact. |
| **PR** touching `editor/vscode-warden/**` | Same — validation only, no publish. |
| **Tag** `vscode-warden/v<version>` (e.g. `vscode-warden/v0.2.0`) | Full pipeline: validate, publish to VS Code Marketplace, publish to Open VSX, and create a GitHub Release with the `.vsix` attached. |
| **Manual `workflow_dispatch`** | Optional `version` input overrides `package.json`; optional `dry_run` packages without publishing. |

To cut a release:

```bash
# 1. Bump the version in editor/vscode-warden/package.json
cd editor/vscode-warden
npm version 0.2.0 --no-git-tag-version

# 2. Commit + push the bump
git add package.json package-lock.json
git commit -m "chore(vscode): bump to 0.2.0"
git push origin main

# 3. Tag the release — the workflow handles the rest.
git tag vscode-warden/v0.2.0
git push origin vscode-warden/v0.2.0
```

Pre-release versions (e.g. `0.2.0-rc.1`) are auto-marked as prerelease
on the GitHub Release.

### Required secrets

| Secret | Purpose |
|---|---|
| `VSCE_PAT` | VS Code Marketplace personal access token. Get one from <https://dev.azure.com/> → User settings → Personal access tokens (scope: Marketplace > Manage). |
| `OVSX_PAT` | Open VSX namespace token. Get one from <https://open-vsx.org/user-settings/tokens>. Optional — the OVSX publish step is skipped if the secret is unset. |

Both go in **Settings → Secrets and variables → Actions** on the
GitHub repo.

## Layout

```text
editor/vscode-warden/
├── package.json                       Manifest + settings schema
├── package-lock.json                  npm lockfile (CI)
├── tsconfig.json                      TypeScript config
├── language-configuration.json        Brackets, comments, auto-close
├── src/extension.ts                   activate() — starts LanguageClient
├── syntaxes/warden.tmLanguage.json    Synced from ../warden.tmLanguage.json
├── icons/warden.svg                   File icon
└── out/extension.js                   Built bundle (esbuild, gitignored)
```

## Troubleshooting

**"Warden LSP failed to start"** — `warden` is not on `PATH`. Either
run `go install github.com/xraph/warden/cmd/warden@latest` or set
`warden.lsp.command` in your settings to the absolute argv (e.g.
`["/usr/local/bin/warden", "lsp"]`).

**No completions** — make sure the file has the `.warden` extension
and the language mode at the bottom-right of the status bar reads
"Warden".

**Diagnostics are stale after edits** — `warden.lsp.trace = verbose`
will show the full LSP message stream in the "Warden LSP (Trace)"
output channel. If `didChange` isn't firing, file an issue.

[warden]: https://github.com/xraph/warden
[marketplace]: https://marketplace.visualstudio.com/items?itemName=xraph.vscode-warden
[openvsx]: https://open-vsx.org/extension/xraph/vscode-warden
[forge-pattern]: https://github.com/xraph/forge/blob/main/.github/workflows/vscode-extension.yml
