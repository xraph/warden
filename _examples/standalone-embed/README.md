# standalone-embed

Boots a Warden engine, applies an embedded `.warden` config tree via
`//go:embed`, then looks up a role from the store.

Demonstrates:

- `dsl.ApplyFS(ctx, eng, fsys, root, opts, loadOpts...)` — the one-call
  helper that wraps `LoadFS` + parse-diagnostic check + `Apply`.
- `//go:embed all:config` — the `all:` prefix is required so Go bundles
  `_shared/`. Without it, leading-underscore directories are silently
  excluded.
- `dsl.WithVariables(...)` — `${TENANT}` / `${REGION}` substitution
  resolved at boot from environment + hard-coded values.
- `dsl.DiagnosticError` extraction via `errors.As` — print every
  diagnostic on a separate line, CI-friendly.

## Run

```bash
go run ./_examples/standalone-embed
WARDEN_VAR_REGION=eu-west-1 go run ./_examples/standalone-embed
```

Sample output:

```text
Applied embedded config:
  + resource_type//document
  + permission//doc:read
  + permission//doc:write
  + permission//doc:delete
  + role//viewer
  + role//editor
  + role//admin
  + policy//audit-writes

Looking up the 'admin' role from the store ...
  ID:     wrol_…
  Name:   Administrator (us-east-1)
  Parent: editor

Done.
```

A second invocation — without restarting (e.g. via the `bash -c` trick)
— would print zero `+` lines and the `(N unchanged)` summary, proving
idempotency.

## Layout

```
_examples/standalone-embed/
├── main.go             // //go:embed all:config + dsl.ApplyFS + Check
├── config/
│   ├── main.warden     // resource type, permissions, roles
│   └── _shared/
│       └── policies.warden   // PBAC policy with an obligation
└── README.md
```

The two `.warden` files are merged into one logical program at apply
time — see [DSL & Tooling](../../docs/content/docs/integration/dsl-tooling.mdx)
for the multi-file load semantics and conflict rules.
