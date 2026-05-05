"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const goCode = `// Programmatic config — every entity created via the store API.
viewer := &role.Role{Name: "Viewer", Slug: "viewer"}
editor := &role.Role{Name: "Editor", Slug: "editor", ParentSlug: "viewer"}
store.CreateRole(ctx, viewer)
store.CreateRole(ctx, editor)

store.CreatePermission(ctx, &permission.Permission{
    Name: "doc:read", Resource: "document", Action: "read",
})
store.CreatePermission(ctx, &permission.Permission{
    Name: "doc:write", Resource: "document", Action: "edit",
})

store.AttachPermission(ctx, viewer.ID, permission.Ref{Name: "doc:read"})
store.AttachPermission(ctx, editor.ID, permission.Ref{Name: "doc:write"})

// Time-bound deny: incident freeze for the next 30 days.
notAfter := time.Now().AddDate(0, 0, 30)
store.CreatePolicy(ctx, &policy.Policy{
    Name:        "incident-freeze",
    Effect:      policy.EffectDeny,
    Priority:    1,
    IsActive:    true,
    NotAfter:    &notAfter,
    Actions:     []string{"deploy:*"},
    Obligations: []string{"notify-oncall", "audit-log"},
})`;

const dslCode = `// Same config as the Go on the left, in source-controlled form.
warden config 1
tenant t1

permission "doc:read"  (document : read)
permission "doc:write" (document : edit)

role viewer {
  grants = ["doc:read"]
}

role editor : viewer {
  grants += ["doc:write"]
}

// Time-bound deny: incident freeze for the next 30 days.
policy "incident-freeze" {
  effect      = deny
  priority    = 1
  active      = true
  not_after   = "2026-06-01T00:00:00Z"
  actions     = ["deploy:*"]
  obligations = ["notify-oncall", "audit-log"]
}`;

const applyCode = `# Lint, dry-run, and apply from a sibling config/ directory.
$ warden lint config/
warden lint: config/ — 2 roles, 2 permissions, 0 resource types, 1 policies — OK

$ warden apply --dry-run -f config/ --store sqlite:./warden.db
+ permission/doc:read
+ permission/doc:write
+ role/viewer
+ role/editor
+ policy/incident-freeze
5 created, 0 unchanged

$ warden apply -f config/ --store sqlite:./warden.db
✓ applied`;

export function DslShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28 bg-fd-muted/20">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Declarative DSL"
          title="One config language. Two ways to write it."
          description="Define your full RBAC + ABAC + ReBAC + PBAC topology programmatically in Go, or as source-controlled .warden files. Same engine, same store, same semantics — pick whichever fits your workflow."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-6">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-blue-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Programmatic (Go)
              </span>
            </div>
            <CodeBlock code={goCode} filename="setup.go" language="go" />
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-purple-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Declarative (.warden)
              </span>
            </div>
            <CodeBlock
              code={dslCode}
              filename="config/main.warden"
              language="warden"
            />
          </motion.div>
        </div>

        {/* Apply flow */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="mt-10"
        >
          <div className="mb-3 flex items-center gap-2">
            <div className="size-2 rounded-full bg-green-500" />
            <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
              Apply pipeline
            </span>
          </div>
          <CodeBlock
            code={applyCode}
            filename="terminal"
            language="shell"
            showLineNumbers={false}
          />
        </motion.div>

        {/* Capability bullets */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
        >
          <DslFeature
            title="Idempotent apply"
            body="Apply the same config twice; the second run reports zero changes. Re-runs after edits diff cleanly."
          />
          <DslFeature
            title="Embed via //go:embed"
            body="dsl.ApplyFS over an embed.FS ships your config inside the binary. One-line bootstrap on engine start."
          />
          <DslFeature
            title="Variable substitution"
            body="${TENANT}, ${REGION}, any ${VAR} you need. Bind at apply time via --var or WARDEN_VAR_*."
          />
          <DslFeature
            title="Round-trip export"
            body="warden export dumps live tenant state back to .warden source. apply(export(state)) is a no-op."
          />
        </motion.div>

        {/* CTA */}
        <div className="mt-12 text-center">
          <Link
            href="/docs/integration/dsl-reference"
            className="inline-flex items-center gap-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline"
          >
            Read the .warden language reference
            <svg
              className="size-4"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M17 8l4 4m0 0l-4 4m4-4H3"
              />
            </svg>
          </Link>
        </div>
      </div>
    </section>
  );
}

function DslFeature({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-fd-border bg-fd-card/40 p-4">
      <h4 className="text-sm font-semibold text-fd-foreground">{title}</h4>
      <p className="mt-1 text-xs text-fd-muted-foreground leading-relaxed">
        {body}
      </p>
    </div>
  );
}
