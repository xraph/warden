# AGENTS.md

Warden is a tenant-scoped authorization engine for Go. It combines RBAC, ABAC, ReBAC and policy checks behind one `Engine.Check`, and ships with a declarative `.warden` config language, a CLI, a language server and a Forge extension.

The module is `github.com/xraph/warden`, a single `go.mod` at the root. The release workflow tags that root module (`vX.Y.Z`) and builds two binaries from it with GoReleaser, `warden` and `warden-lsp`. The VS Code extension in `editor/vscode-warden` is versioned and released separately.

`main` is protected. You land every change through a pull request, and you never push to `main`.

## Commands

Run these from the repo root. There's no `go.work`; use `GOWORK=off` if a workspace above this checkout could interfere, since CI builds without one.

| What | Command |
|---|---|
| Build everything | `GOWORK=off go build ./...` |
| Build the CLI | `make build` (writes `bin/warden` from `./cmd/warden`) |
| Unit tests | `make test` (`go test -race -v ./...`) |
| Integration tests | `make test-integration` (`go test -tags=integration -v -timeout 5m ./...`) |
| Coverage profile | `make test-coverage` (race, atomic, with `-tags=integration`) |
| Coverage gate | `make coverage-check` |
| Vet | `make vet` |
| Lint | `make lint`, or `make lint-fix` |
| Format | `make fmt` (`gofmt -s -w`, then `goimports -local github.com/xraph/warden`) |
| Format, vet, lint | `make check` |
| Dev tools | `make deps`, then `make check-deps` |
| Tidy | `make tidy` (`go mod tidy`, `go mod verify`) |
| Docs site | `make docs`, `make docs-build` (pnpm, in `docs/`) |
| VS Code extension | `make vscode-build`, `make vscode-install` |
| GoReleaser config | `make release-check`, `make release-snapshot` |

`CONTRIBUTING.md` asks you to run `make check`, `make test` and `make test-integration`, in that order, before you open a PR. If you touched `editor/vscode-warden`, also run `npm run compile` and `npm audit --omit=dev --audit-level=high` in that directory. If you touched `docs/`, run `pnpm build` there.

### What the tests need

`make test` needs nothing but Go. The memory and SQLite stores (SQLite is pure Go) run there, and so does everything above them.

Every Postgres and Mongo test that talks to a server sits behind `//go:build integration`, so a plain `go test ./...` never compiles them (`store/mongo/plain_test.go` needs no server and runs untagged). With the tag, each suite looks for a server in this order:

- Postgres: `WARDEN_TEST_DSN`, otherwise a testcontainers `postgres:16-alpine`. The DSN needs permission to create databases, because every test creates and drops its own.
- Mongo: `WARDEN_TEST_MONGO_URI`, otherwise a testcontainers `mongo:7`. Each test gets a randomly named database that's dropped on cleanup.

If neither the env var nor Docker is available, the tests call `t.Skipf("... container unavailable ...")` and the run still passes. A green `make test-integration` on a machine without Docker proves nothing, so read the output for skips.

```bash
WARDEN_TEST_DSN='postgres://warden:warden@localhost:5432/warden_admin?sslmode=disable' make test-integration
```

`store/contract` holds exported conformance suites (`RunTenantIsolationContract`, `RunUniquenessContract`, `RunPolicyVersionContract` and more). They don't run on their own. Each backend's tests call them, so if you add a store behaviour, write the contract there and call it from all four backends.

`make coverage-check` fails below 60% total (with `store/contract` filtered out) and below 60% for each of `api`, `middleware`, `store/memory` and `store/sqlite`. It runs `test-coverage` first, so it needs Docker or the two env vars too.

### CI

`.github/workflows/ci.yml` runs these jobs, and every one of them is a required status check on `main`:

| Check name | What runs |
|---|---|
| `ci / Test (ubuntu-latest, go1.26)` | shared `go-ci.yml`: `make test`, then `make test-coverage` |
| `ci / Lint` | golangci-lint with `.golangci.yml` |
| `ci / Verify` | `gofmt -l`, `make vet`, and a `go mod tidy` diff check |
| `ci / Security` | gosec and govulncheck |
| `Format` | `goimports -l -local github.com/xraph/warden .` must print nothing |
| `Docs` | pnpm type check, lint and build of `docs/` |
| `Integration (postgres)` | `make test-integration` against a Postgres service container |
| `Coverage check` | `make coverage-check` |

The shared workflow is pinned by commit SHA (with a `# v1.18.0` comment), not by `@v1`. The Go version is part of the test check's name. Change `go-versions` in `ci.yml` and the check gets a new name while the ruleset keeps waiting for the old one, so the ruleset has to be updated at the same time or every PR blocks.

`vscode-extension.yml` validates and packages the extension on pull requests that touch `editor/vscode-warden/**` or `editor/warden.tmLanguage.json`.

## Layout

| Path | What lives there |
|---|---|
| `warden.go`, `subject.go`, `actor.go` | Core request types: `Subject`, `Action`, `Resource`, `CheckRequest` |
| `engine.go` | `Engine`, `NewEngine`, `Check`, `Enforce`, `CanI` |
| `evaluator.go`, `graph_walker.go`, `expand.go`, `explain.go` | ABAC policy evaluation, the ReBAC graph walk, expansion and decision explanations |
| `options.go`, `call_options.go`, `config.go` | Engine `Option`s, per-call `CallOption`s, engine `Config` |
| `context.go`, `scope.go`, `namespace.go` | Tenant, app and namespace scoping |
| `cache*.go`, `cache/`, `checklog_writer.go`, `maintenance.go`, `metrics.go`, `metrics_sink.go`, `tracing.go` | Check cache, async check-log writer, retention maintenance, the metrics interface and its go-utils adapter, span names and attributes |
| `internal/telemetry/` | Span start and error marking shared by the engine and `dsl` |
| `errors.go`, `wardenerr/` | Sentinel errors. `wardenerr` is the leaf that defines them |
| `id/` | TypeID `ID` with prefixes `role`, `perm`, `asgn`, `wpol`, `rel`, `chklog`, `rtype`, `cond` |
| `role/`, `permission/`, `assignment/`, `relation/`, `policy/`, `resourcetype/`, `checklog/` | One entity each, with its own `Store` interface |
| `store/` | Composite `store.Store`, the `memory`, `sqlite`, `postgres` and `mongo` backends, and `contract/` |
| `dsl/` | `.warden` lexer, parser, resolver, formatter, loader, applier and exporter |
| `cmd/warden`, `cmd/warden-lsp`, `cmd/internal/cli` | CLI (`lint`, `apply`, `diff`, `fmt`, `export`, `lsp`) and the language server binary |
| `lsp/` | Language server implementation |
| `api/` | HTTP management API (`/v1/...`) and the AuthZEN endpoints (`/access/v1/...`) |
| `middleware/` | `Require`, `RequireAny`, `RequireAll` for an embedding app's own routes |
| `plugin/`, `plugin/auditlog/` | Opt-in lifecycle hook interfaces and the structured audit-log plugin |
| `keysmithbridge/` | Structural adapter for Keysmith's `warden_hook` (neither module imports the other) |
| `extension/` | Forge extension, its config and the admin bootstrap |
| `extension/contract/` | Dashboard contract contributor: `manifest.yaml` and intent handlers |
| `editor/` | VS Code extension, TextMate grammar, tree-sitter grammar |
| `_examples/` | Runnable examples (excluded from `errcheck` and `gosec`) |
| `docs/` | Fumadocs site |

`MIGRATION.md` maps each page of the old templ dashboard to its React route in forge-dashboard.

## Conventions

A new sentinel error goes in `wardenerr`, which imports nothing from warden, and you re-export it from `errors.go` as `warden.Err...`. They come in families. `ErrNotFound`, `ErrAlreadyExists` and `ErrStaleWrite` are the bases, and the specific errors (`ErrRoleNotFound`, `ErrDuplicateRole`, `ErrPolicyVersionConflict`) wrap them with `%w`, so you can match a whole family with one `errors.Is`. Store implementations import `wardenerr` directly and wrap driver errors as `warden: <operation>: %w`.

The tenant is part of every key. A by-ID lookup with the wrong tenant returns the same not-found sentinel as a missing row, on purpose, so the error never confirms that an ID exists in another tenant. An empty tenant in a list filter matches every tenant, which is why `keysmithbridge` refuses one. `RunTenantIsolationContract` and `RunEmptyTenantContract` pin both behaviours, and every backend has to pass them.

Scope comes from the context. `warden.WithTenant(ctx, appID, tenantID)` and `warden.WithNamespace` win when set, otherwise the engine reads `forge.Scope` (app ID and org ID). A single call can override that with `WithCallTenantID`, `WithCallAppID` or `WithCallNamespacePath`, and `WithCallDryRun` evaluates without touching the cache, the check log or plugin hooks.

`Check` fails closed. A store or evaluation error returns a nil result and the error, and still writes a check-log entry with decision `error` (except in a dry run). Keep that property in anything you add to the check path.

Engine options are functional (`type Option func(*Engine)`), and the extension has its own `Option`. You log through `github.com/xraph/go-utils/log`, or inside the extension through `e.Logger()` with `forge.F` fields.

Every backend implements `store.Store`, the subsystem interfaces plus `Migrate`, `Ping` and `Close`. Postgres, SQLite and Mongo are built on grove with a `migrate.NewGroup("warden")` group in each `migrations.go`. Add a migration with the next `Version` and don't edit shipped ones; the PR template asks whether each migration is reversible. Callers register the migration executor themselves with a blank import of `github.com/xraph/grove/drivers/pgdriver/pgmigrate` or `.../sqlitedriver/sqlitemigrate`, as `cmd/internal/cli/store.go` does.

The Forge extension reads YAML under `extensions.warden` or `warden` and validates it in `Register`. It refuses to mount the HTTP API when `auth.require_identity` is false unless you pass `WithInsecureAllowUnauthenticatedRoutes()`. Routes mount under `/warden` by default. For a store it takes a named grove DB (`WithGroveDatabase`), or else auto-discovers a `*grove.DB` from the vessel container, and it wires the DSL expression evaluator, the app's logger and metrics (`WithLogger`, `WithMetricsSink`) and, with `auth.audit_log` on, the `auditlog` plugin.

Telemetry has two rules that keep it safe on the check path. A metric label only ever takes a value from a closed set (see `metricDecision` and `metricSource`), never a subject, tenant, resource, action or policy name. A span never carries a subject ID, resource ID, tenant, reason or error message: mark failures with `telemetry.MarkError`, which records the error's type only. A caller-supplied name (action, resource type, or a decision a custom Evaluator sets) goes through `spanName`, which records `invalid` for anything that isn't a short schema name. Build span attributes behind `span.IsRecording()`, start a step inside a check with `telemetry.StartChildSpan` so an unsampled check starts nothing more, and give background work (the check-log flush, a maintenance run) a root span, with the loop's inherited span stripped where its context is made. `docs/content/docs/operations/monitoring.mdx` lists every metric and span, so update it with any change.

`extension/contract/manifest.yaml` lists every dashboard intent, and `manifest_test.go` checks it. An intent change touches the manifest, its handler and the test together.

From `.golangci.yml`, the rules that bite:

- `errcheck` runs with `check-blank` and `check-type-assertions`. `Close`, `sql.Rows.Close` and pgx/bun `Tx.Rollback` are exempt. Anything else you ignore needs `//nolint:errcheck // reason`, and `nolintlint` flags stale or bare directives.
- `govet` runs everything except `fieldalignment` and `shadow`, so `if err := f(); err != nil` inside a function with an outer `err` is fine here.
- `gosec` is on outside tests and `_examples/`. Where a finding is a false positive, the code carries a `#nosec` comment that names the rule (G304, G705 and so on) and says why, as in `cmd/warden/main.go`.
- `revive` checks error strings, receiver names, context as first argument and unused parameters. `errorlint` wants `errors.Is` and `errors.As`.

Commits are conventional (`feat:`, `fix(store):`, `docs:` and so on), with an imperative subject under about 72 characters. GoReleaser builds the release changelog from them. It groups `feat`, `fix`, `refactor`, `perf` and `docs`, and drops any subject that starts with a bare `docs:`, `test:`, `ci:` or `chore:` (a scoped `docs(api):` still shows up). Name branches after the change, like `fix/postgres-migration-order`.

## Dependencies

Warden depends on these xraph modules (see `go.mod` for versions): `grove` plus `drivers/mongodriver`, `drivers/pgdriver` and `drivers/sqlitedriver`, `forge`, `go-utils` and `vessel`. Downstream, `dispatch`, `trove/extension`, fabriq's `adapters/wardenauthz` and `authsome` import it.

Bump one xraph module at a time, then tidy:

```bash
GOWORK=off go get github.com/xraph/forge@vX.Y.Z
GOWORK=off go mod tidy
```

Grove releases its drivers at the same version as its root, so move all four together. `ci / Verify` runs `go mod tidy` and fails on any diff, which means you commit the tidied `go.mod` and `go.sum` in the same PR. Never commit a `replace` pointing at a sibling checkout like `../grove`.

## Releasing

You release by dispatching `release.yml`. Never push a tag by hand. Wait until `main` is green, make sure every upstream xraph change you need is released and pinned in `go.mod`, then run:

```bash
gh workflow run release.yml --ref main -f version=X.Y.Z
```

The version has no leading `v`; the workflow adds it. Add `-f dry_run=true` to rehearse without publishing, or `-f prerelease=true` to mark a pre-release (a version with a `-suffix`, such as `1.8.0-beta.1`, is marked automatically).

The jobs run in this order:

1. `detect` validates the version and resolves the tag. It's read-only.
2. `test` runs `go test -v -race -timeout=15m ./...` on Ubuntu and macOS.
3. `release-cli` (skipped on a dry run, and only after `test` passes) creates and pushes an annotated `vX.Y.Z` tag, runs govulncheck, then GoReleaser: `warden` and `warden-lsp` archives for linux, darwin and windows on amd64 and arm64 (not windows/arm64), SBOMs, a cosign-signed `checksums.txt`, build provenance attestations and the GitHub release. It finishes by asking the Go proxy to fetch the tag.
4. `dry-run` replaces `release-cli` when `dry_run` is true: `go build ./...` and `goreleaser release --snapshot --clean`.
5. `summary` writes the results to the run page.

A failing test never leaves a tag behind. A govulncheck finding is different. It runs after the tag push in `release-cli`, so it can leave a tag with no release, and you fix forward with the next patch.

The VS Code extension has its own pipeline. `gh workflow run vscode-extension.yml --ref main -f version=X.Y.Z` publishes it to the Marketplace and Open VSX and tags it `vscode-warden/vX.Y.Z`; leave `version` out to publish the version in `package.json`, or add `-f dry_run=true` to package without publishing.

After a warden release, downstream repos re-pin with `go get github.com/xraph/warden@vX.Y.Z`.

## Branch rules

`main` has a repository ruleset. You can't delete it or force-push to it. A merge needs a pull request with one approving review, including a code owner review (`.github/CODEOWNERS` assigns everything to @juicycleff), and stale approvals are dismissed when you push. All eight checks in the CI table above must pass, and the branch has to be up to date with `main` before it merges. Fill in the PR template's checklist: tests, security impact, migration reversibility, docs.
