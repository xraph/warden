"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const installCode = `# Install from the VS Code Marketplace
$ code --install-extension xraph.vscode-warden
Installing extensions...
Extension 'xraph.vscode-warden' v0.1.0 was successfully installed.

# Or search "Warden" in the Extensions panel (Cmd+Shift+X).`;

// String concat avoids JS template-literal interpolation of `${TENANT}` —
// we want the literal characters in the rendered code block.
const wardenSample =
  "warden config 1\n" +
  "tenant ${TENANT}                       // template variable\n" +
  `

namespace "engineering" {
  permission "deploy:prod" (service : deploy)

  role eng-viewer {
    name = "Engineering Viewer"
  }

  namespace "platform" {
    role platform-admin : eng-viewer {     // ancestor walk
      name   = "Platform Admin"
      grants = ["deploy:prod"]
    }
  }
}

policy "incident-freeze" {
  effect      = deny
  priority    = 1
  active      = true
  not_after   = "2026-06-01T00:00:00Z"
  actions     = ["deploy:*"]
  obligations = ["notify-oncall", "audit-log"]
}`;

interface EditorFeature {
  title: string;
  body: string;
  icon: React.ReactNode;
}

const features: EditorFeature[] = [
  {
    title: "Syntax highlighting",
    body: "TextMate grammar covers every keyword, expression operator, and condition predicate. Tracks dsl/parser.go in lockstep.",
    icon: <DotIcon color="bg-purple-500" />,
  },
  {
    title: "Cross-file completion",
    body: "Workspace document index — completing a role parent suggests slugs declared anywhere in your config tree, not just the current file.",
    icon: <DotIcon color="bg-blue-500" />,
  },
  {
    title: "Inline diagnostics",
    body: "Parser + resolver errors as you type, with file:line:col precision. Undefined variables, unknown parents, traversal type mismatches.",
    icon: <DotIcon color="bg-rose-500" />,
  },
  {
    title: "Hover + go-to-definition",
    body: "Markdown summaries for roles, permissions, resource types, policies. Click a parent slug to jump to its declaration.",
    icon: <DotIcon color="bg-amber-500" />,
  },
  {
    title: "Whole-document formatter",
    body: "Canonical .warden output. Stable under reapply: fmt(parse(fmt(parse(src)))) ≡ fmt(parse(src)).",
    icon: <DotIcon color="bg-teal-500" />,
  },
  {
    title: "Same LSP everywhere",
    body: "warden lsp powers the VS Code extension and Neovim, Helix, Zed via stdio. One server, every editor.",
    icon: <DotIcon color="bg-indigo-500" />,
  },
];

export function EditorShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Editor Support"
          title="VS Code extension. Same LSP for every editor."
          description="One purpose-built language server (warden lsp) drives the VS Code extension and works as-is in Neovim, Helix, Zed, and any other LSP client. Install in one command — no Shell Command setup required on macOS."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-5 gap-6 items-start">
          {/* Left: editor mock with syntax-highlighted .warden */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="lg:col-span-3"
          >
            <CodeBlock
              code={wardenSample}
              filename="config/main.warden"
              language="warden"
            />
          </motion.div>

          {/* Right: feature list */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="lg:col-span-2 space-y-4"
          >
            {features.map((f) => (
              <div
                key={f.title}
                className="rounded-lg border border-fd-border bg-fd-card/40 p-4 hover:border-blue-500/20 hover:bg-fd-card/80 transition-all"
              >
                <div className="flex items-start gap-3">
                  <div className="mt-1 shrink-0">{f.icon}</div>
                  <div>
                    <h4 className="text-sm font-semibold text-fd-foreground">
                      {f.title}
                    </h4>
                    <p className="mt-1 text-xs text-fd-muted-foreground leading-relaxed">
                      {f.body}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </motion.div>
        </div>

        {/* Install command */}
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
              Install from the Marketplace
            </span>
          </div>
          <CodeBlock
            code={installCode}
            filename="terminal"
            language="shell"
            showLineNumbers={false}
          />
          <p className="mt-3 text-xs text-fd-muted-foreground">
            Published as{" "}
            <code className="font-mono text-fd-foreground">
              xraph.vscode-warden
            </code>{" "}
            on the VS Code Marketplace and Open VSX. Building from source is
            also supported — see the extension's{" "}
            <a
              href="https://github.com/xraph/warden/tree/main/editor/vscode-warden"
              target="_blank"
              rel="noreferrer"
              className="text-fd-foreground underline-offset-2 hover:underline"
            >
              README
            </a>{" "}
            for the dev recipe.
          </p>
        </motion.div>

        {/* Other editors */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-4"
        >
          <EditorCard
            name="Neovim"
            recipe="lspconfig.warden = { cmd = {'warden', 'lsp'} }"
          />
          <EditorCard
            name="Helix"
            recipe={'[[language]]\nname = "warden"\nlanguage-server = { command = "warden", args = ["lsp"] }'}
          />
          <EditorCard
            name="Zed"
            recipe="warden lsp via the language-server config"
          />
        </motion.div>

        {/* CTA */}
        <div className="mt-12 text-center">
          <Link
            href="/docs/integration/dsl-tooling#vs-code-extension"
            className="inline-flex items-center gap-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline"
          >
            See the full editor reference
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

function DotIcon({ color }: { color: string }) {
  return <div className={`size-2.5 rounded-full ${color}`} />;
}

function EditorCard({ name, recipe }: { name: string; recipe: string }) {
  return (
    <div className="rounded-lg border border-fd-border bg-fd-card/40 p-4">
      <h4 className="text-sm font-semibold text-fd-foreground mb-2">{name}</h4>
      <pre className="text-[11px] font-mono text-fd-muted-foreground leading-relaxed whitespace-pre-wrap">
        {recipe}
      </pre>
    </div>
  );
}
