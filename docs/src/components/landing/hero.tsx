"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { useState } from "react";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import {
  AuroraBackground,
  DotLed,
  GradientText,
  Marquee,
  Pill,
} from "./primitives";

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      fill="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.286-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

const editorSamples: Record<string, string> = {
  "main.warden": `warden config 1
tenant acme

permission "doc:read"  (document : read)
permission "doc:write" (document : edit)

resource document {
  relation owner:  user
  relation viewer: user
  permission read = viewer or owner
}

role viewer {
  grants = ["doc:read"]
}

role editor : viewer {
  grants += ["doc:write"]
}`,
  "policies.warden": `warden config 1
tenant acme

import "main.warden"

policy "incident-freeze" {
  effect      = deny
  active      = true
  not_after   = "2026-06-01T00:00:00Z"
  actions     = ["deploy:*"]
  obligations = ["notify-oncall", "audit-log"]
}

policy "owner-or-admin" {
  effect    = allow
  priority  = 100
  actions   = ["doc:read", "doc:write"]
  resources = ["document"]
  when {
    subject.id == resource.owner
    or subject.role == "admin"
  }
}

policy "after-hours-readonly" {
  effect  = deny
  active  = true
  actions = ["doc:write", "doc:delete"]
  when {
    time.hour < 9 or time.hour > 18
  }
}`,
};

const capabilityPills = [
  "RBAC",
  "ABAC",
  "ReBAC",
  "PBAC",
  "Declarative .warden DSL",
  "Language Server",
  "VS Code extension",
  "Nested namespaces",
  "Time-bound policies",
  "Obligations",
  "Multi-tenant",
  "TypeID identity",
  "Plugin lifecycle hooks",
  "Postgres · SQLite · Mongo · Memory",
  "Forge integration",
  "//go:embed apply",
];

// ─── Hero Section ────────────────────────────────────────────
export function Hero() {
  return (
    <section className="relative w-full overflow-hidden">
      {/* Background layers */}
      <AuroraBackground />
      <div className="absolute inset-0 bg-grid opacity-[0.04] dark:opacity-[0.08]" />
      <div className="absolute inset-0 bg-gradient-to-b from-fd-background/40 via-transparent to-fd-background" />

      <div className="relative container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <div className="pt-20 sm:pt-28 md:pt-32 pb-16">
          {/* Top eyebrow */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="flex items-center justify-center"
          >
            <Pill className="border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-300">
              <DotLed color="bg-blue-500" />
              <span>RBAC · ABAC · ReBAC · PBAC — one engine</span>
            </Pill>
          </motion.div>

          {/* Display headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="mx-auto mt-7 max-w-5xl text-center text-balance text-5xl font-bold tracking-tight text-fd-foreground sm:text-6xl md:text-7xl lg:text-[88px] lg:leading-[1.02]"
          >
            Authorization, <GradientText>declared.</GradientText>
          </motion.h1>

          {/* Subhead */}
          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="mx-auto mt-7 max-w-2xl text-center text-pretty text-lg text-fd-muted-foreground leading-relaxed sm:text-xl"
          >
            Four authorization models behind one{" "}
            <code className="font-mono text-fd-foreground text-base sm:text-lg">
              Check
            </code>{" "}
            API. A purpose-built{" "}
            <code className="font-mono text-fd-foreground text-base sm:text-lg">
              .warden
            </code>{" "}
            config language. A language server, VS Code extension, and CLI in
            the box.
          </motion.p>

          {/* CTAs + install command */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.5 }}
            className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center"
          >
            <Link
              href="/docs"
              className={cn(
                "inline-flex items-center justify-center rounded-full px-6 py-3 text-sm font-semibold transition-all",
                "bg-fd-foreground text-fd-background hover:bg-fd-foreground/90",
                "shadow-lg shadow-fd-foreground/10 hover:shadow-xl hover:-translate-y-0.5",
              )}
            >
              Get started
              <svg
                className="ml-1.5 size-4"
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
            <a
              href="https://github.com/xraph/warden"
              target="_blank"
              rel="noreferrer"
              className={cn(
                "inline-flex items-center gap-2 justify-center rounded-full px-6 py-3 text-sm font-semibold transition-all",
                "border border-fd-border bg-fd-background/60 backdrop-blur-sm hover:bg-fd-muted/60 text-fd-foreground",
              )}
            >
              <GitHubIcon className="size-4" />
              Star on GitHub
            </a>
          </motion.div>

          {/* Install command */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
            className="mt-6 flex justify-center"
          >
            <div className="inline-flex items-center gap-2 rounded-full border border-fd-border bg-fd-background/40 backdrop-blur-md px-4 py-1.5 font-mono text-xs sm:text-sm shadow-sm">
              <span className="text-fd-muted-foreground select-none">$</span>
              <code className="text-fd-foreground">
                go install github.com/xraph/warden/cmd/warden@latest
              </code>
            </div>
          </motion.div>
        </div>

        {/* Editor mock — large, perspective-tilted card */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.4 }}
          className="relative mx-auto max-w-5xl"
        >
          {/* Soft glow underneath */}
          <div className="absolute inset-x-8 -bottom-12 -z-10 h-40 bg-gradient-to-t from-blue-500/30 via-indigo-500/20 to-transparent blur-3xl" />

          <EditorWindow samples={editorSamples} />
        </motion.div>

        {/* Capability marquee */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.9 }}
          className="mt-16 sm:mt-20 pb-12"
        >
          <div className="text-center text-xs uppercase tracking-[0.2em] text-fd-muted-foreground/70 mb-5">
            What's in the box
          </div>
          <Marquee speed="slow">
            {capabilityPills.map((label) => (
              <Pill
                key={label}
                className="border-fd-border/40 bg-fd-card/30 text-fd-muted-foreground"
              >
                {label}
              </Pill>
            ))}
          </Marquee>
        </motion.div>
      </div>
    </section>
  );
}

// ─── EditorWindow ─────────────────────────────────────────────
//
// VS Code-style chrome: title bar, sidebar with file tree, tab strip,
// code area with syntax-highlighted .warden source, status bar
// indicating LSP is live. All static — designed to convey "this is
// what your editor looks like with the extension installed."

function EditorWindow({ samples }: { samples: Record<string, string> }) {
  const tabs = Object.keys(samples);
  const [activeTab, setActiveTab] = useState(tabs[0]);
  const code = samples[activeTab] ?? "";
  const lineCount = code.split("\n").length;

  return (
    <div className="rounded-2xl border border-fd-border bg-fd-card/80 backdrop-blur-xl shadow-2xl shadow-black/10 dark:shadow-black/40 overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-fd-border/60 bg-fd-muted/40">
        <div className="flex items-center gap-2">
          <div className="size-3 rounded-full bg-rose-400/80" />
          <div className="size-3 rounded-full bg-amber-400/80" />
          <div className="size-3 rounded-full bg-emerald-400/80" />
        </div>
        <div className="text-xs text-fd-muted-foreground font-mono">
          warden · vscode-warden 0.1.0
        </div>
        <div className="flex items-center gap-2 text-xs text-fd-muted-foreground">
          <DotLed color="bg-emerald-500" />
          <span>warden lsp</span>
        </div>
      </div>

      {/* Body */}
      <div className="grid grid-cols-12">
        {/* Sidebar */}
        <div className="col-span-3 hidden md:block border-r border-fd-border/60 bg-fd-muted/20 p-3 text-xs">
          <div className="px-2 mb-2 uppercase tracking-wider text-fd-muted-foreground/70 text-[10px]">
            Explorer
          </div>
          <ul className="space-y-0.5 font-mono">
            <FileNode label="config" folder open>
              {tabs.map((tab) => (
                <FileNode
                  key={tab}
                  label={tab}
                  active={tab === activeTab}
                  onClick={() => setActiveTab(tab)}
                />
              ))}
            </FileNode>
            <FileNode label="cmd" folder>
              <FileNode label="warden" folder />
              <FileNode label="warden-lsp" folder />
            </FileNode>
            <FileNode label="dsl" folder />
            <FileNode label="store" folder />
            <FileNode label="go.mod" />
          </ul>
        </div>

        {/* Editor */}
        <div className="col-span-12 md:col-span-9">
          {/* Tab strip */}
          <div className="flex items-center border-b border-fd-border/60 bg-fd-muted/20 text-xs">
            {tabs.map((tab) => {
              const active = tab === activeTab;
              return (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-2 border-r border-fd-border/60 font-mono transition-colors",
                    active
                      ? "bg-fd-card/60 text-fd-foreground"
                      : "text-fd-muted-foreground hover:text-fd-foreground hover:bg-fd-card/30",
                  )}
                  aria-pressed={active}
                >
                  {active && (
                    <div className="size-2 rounded-full bg-blue-500" />
                  )}
                  <span>{tab}</span>
                </button>
              );
            })}
            <div className="ml-auto px-3 py-2 text-fd-muted-foreground/70">
              ● LSP ready
            </div>
          </div>

          {/* Code */}
          <CodeBlock
            key={activeTab}
            code={code}
            language="warden"
            showLineNumbers={true}
            className="border-0 rounded-none bg-transparent"
          />

          {/* Status bar */}
          <div className="flex items-center justify-between px-3 py-1.5 border-t border-fd-border/60 bg-blue-500/10 text-[11px] font-mono">
            <div className="flex items-center gap-3 text-blue-600 dark:text-blue-300">
              <span className="flex items-center gap-1.5">
                <DotLed color="bg-emerald-500" /> warden-lsp
              </span>
              <span className="text-fd-muted-foreground">no problems</span>
            </div>
            <div className="text-fd-muted-foreground">
              UTF-8 · LF · Warden · {lineCount} lines
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

interface FileNodeProps {
  label: string;
  folder?: boolean;
  open?: boolean;
  active?: boolean;
  onClick?: () => void;
  children?: React.ReactNode;
}

function FileNode({
  label,
  folder = false,
  open = false,
  active = false,
  onClick,
  children,
}: FileNodeProps) {
  const rowClass = cn(
    "flex w-full items-center gap-1.5 px-2 py-1 rounded-md text-left transition-colors",
    active && "bg-fd-card/70 text-fd-foreground",
    !active && "text-fd-muted-foreground hover:text-fd-foreground",
    onClick && "cursor-pointer hover:bg-fd-card/40",
  );
  const inner = (
    <>
      {folder ? (
        <svg
          className={cn(
            "size-3 transition-transform",
            open ? "rotate-90 text-fd-foreground" : "text-fd-muted-foreground/60",
          )}
          viewBox="0 0 12 12"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M4 3l4 3-4 3z" />
        </svg>
      ) : (
        <span className="size-3 inline-flex items-center justify-center text-fd-muted-foreground/60">
          <svg viewBox="0 0 12 12" fill="currentColor" className="size-2.5">
            <circle cx="6" cy="6" r="1.6" />
          </svg>
        </span>
      )}
      <span>{label}</span>
    </>
  );

  return (
    <li>
      {onClick ? (
        <button
          type="button"
          onClick={onClick}
          className={rowClass}
          aria-pressed={active}
        >
          {inner}
        </button>
      ) : (
        <div className={rowClass}>{inner}</div>
      )}
      {folder && open && children && (
        <ul className="ml-4 border-l border-fd-border/40 pl-2 space-y-0.5">
          {children}
        </ul>
      )}
    </li>
  );
}
