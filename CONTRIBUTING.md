# Contributing to Warden

Thanks for taking the time to work on this. Here's what you need to know
before you open a PR.

## Getting set up

Fork the repo and branch off `main`. Name your branch after what it does:
`fix/postgres-migration-order`, `feat/rebac-caching`, that kind of thing. Keep
one change per branch; it makes review faster and reverts cleaner if
something goes wrong.

Install the dev tools with `make deps`, then check everything's in place with
`make check-deps`.

## Before you open a PR

Run these three, in order:

```bash
make check
make test
make test-integration
```

`make check` runs formatting, `go vet`, and the linter. `make test` runs the
unit suite with the race detector on. `make test-integration` needs either
Docker (for testcontainers) or a `WARDEN_TEST_DSN` pointing at a Postgres
instance; see the Makefile comment on that target if you don't have Docker
handy.

If you touched the VS Code extension, also run `npm run compile` and
`npm audit --omit=dev --audit-level=high` in `editor/vscode-warden`. If you
touched the docs site, run `pnpm build` in `docs`.

All of this runs in CI too, so a green local run is the best predictor of a
green PR. It's a lot faster to catch a broken test on your own machine than
to wait for the pipeline to tell you.

## Commit messages

We use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`, `ci:`, and so on, with an optional scope like `fix(store): handle
nil tenant`. The changelog is generated from these, so the prefix matters
more than it might seem to.

Write the subject line in the imperative: "add postgres index" rather than
"added" or "adds". Keep it under about 72 characters. If the change needs
more explanation than that, put it in the body.

## Pull requests

Fill out the PR template. It asks whether you added tests, whether there's a
security impact, and whether any migration is reversible. Those aren't
formalities; reviewers use them to decide how carefully to read the diff.

Keep PRs focused. A 2,000-line PR that mixes a refactor with a bug fix is
much harder to review than two smaller ones, and if something needs to be
reverted later, you want it to revert cleanly.

## Branch protection

`main` is protected. Nobody force-pushes to it, including maintainers.
If your branch needs a rebase, rebase your own branch and force-push that,
not `main`. Merges into `main` go through a PR with at least one approval and
a passing CI run; there's no bypass for "it's a small change."

## Code review

Expect questions, not just approvals. If a reviewer asks why you did
something a particular way, that's usually them trying to understand the
change, not a rejection. Answer in the PR thread so the reasoning is there
for whoever reads the history later.

## Reporting bugs vs. reporting vulnerabilities

Regular bugs go in GitHub Issues. If you've found something with security
implications, don't file a public issue; see `SECURITY.md` for how to report
it privately instead.
