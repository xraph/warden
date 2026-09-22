# Security Policy

## Supported versions

We support the latest minor release of Warden. If you're running an older
minor version, update before you file anything that isn't itself a security
report. Patch releases within the current minor always carry security fixes.

## Reporting a vulnerability

Don't open a public issue for a security problem. Use GitHub's private
advisory form instead:

https://github.com/xraph/warden/security/advisories/new

That keeps the report private between you and the maintainers until there's a
fix, so users aren't exposed while we work on it.

Tell us what you can: the affected version, a reproduction if you have one,
and what you think the impact is (data exposure, privilege escalation, denial
of service, whatever it is). You don't need a full writeup to get started; a
clear description of the bug and how to trigger it is enough for us to begin.

## What happens next

We acknowledge new reports within 3 business days. After that:

- High-severity issues: we aim to ship a fix within 30 days.
- Everything else: we aim to ship a fix within 90 days.

Those are targets, not guarantees. Some fixes are simple; some touch the
storage layer or the DSL evaluator and need more care. We'll keep you updated
on where things stand.

Once a fix is out, we'll coordinate on disclosure timing with you and credit
you in the advisory unless you'd rather stay anonymous.

## Scope

This covers the `warden` module itself: the engine, the DSL, the store
adapters (memory, SQLite, Postgres, Mongo), the CLI, and the language server.
The VS Code extension and the docs site are in scope too, though their attack
surface is smaller.

Dependency vulnerabilities that don't affect Warden's own behavior (for
example, an advisory in a transitive dev dependency we never call) are lower
priority, but still worth reporting if you're not sure.
