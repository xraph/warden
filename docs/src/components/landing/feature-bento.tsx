"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import { DotLed, Pill, SpotlightCard } from "./primitives";
import { SectionHeader } from "./section-header";

// ─── Feature Bento ────────────────────────────────────────────
//
// Asymmetric grid (12-column) with a hero card that takes 7 cols and
// supporting cards filling the rest. Each card is a SpotlightCard so
// the cursor paints a soft highlight on hover.

interface CardProps {
  title: string;
  body: string;
  icon: React.ReactNode;
  className?: string;
  highlightColor?: string;
  children?: React.ReactNode;
  badge?: string;
}

function BentoCard({
  title,
  body,
  icon,
  className,
  highlightColor,
  children,
  badge,
}: CardProps) {
  return (
    <SpotlightCard
      className={cn("p-6 flex flex-col", className)}
      highlightColor={highlightColor}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-fd-foreground/5 text-fd-foreground">
            {icon}
          </div>
          <h3 className="text-base font-semibold text-fd-foreground">
            {title}
          </h3>
        </div>
        {badge && (
          <Pill className="border-fd-border/60 bg-fd-card/60 text-[10px] uppercase tracking-wider">
            {badge}
          </Pill>
        )}
      </div>
      <p className="mt-3 text-sm text-fd-muted-foreground leading-relaxed">
        {body}
      </p>
      {children && <div className="mt-5 flex-1">{children}</div>}
    </SpotlightCard>
  );
}

export function FeatureBento() {
  return (
    <section className="relative w-full py-24 sm:py-32">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Feature surface"
          title="Composable. Declarative. Observable."
          description="Mix authorization models freely, define your config in source-controlled .warden files, and edit them with first-class editor tooling. Every layer is built to compose with the next."
        />

        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-50px" }}
          variants={{
            hidden: {},
            visible: { transition: { staggerChildren: 0.08 } },
          }}
          className="mt-14 grid grid-cols-1 md:grid-cols-12 gap-4"
        >
          {/* Hero: DSL — span 7 */}
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-7"
          >
            <BentoCard
              icon={<DslIcon />}
              title="Declarative .warden DSL"
              body="Define your full RBAC + ABAC + ReBAC + PBAC topology as source-controlled files. One CLI: lint, apply, diff, fmt, export. Idempotent and prune-aware."
              badge="New"
              highlightColor="rgba(168, 85, 247, 0.18)"
              className="h-full"
            >
              <CodeBlock
                code={`warden config 1
tenant t1

permission "doc:read"  (document : read)
permission "doc:write" (document : edit)

role viewer {
  grants = ["doc:read"]
}

role editor : viewer {
  grants += ["doc:write"]
}`}
                language="warden"
                filename="config/main.warden"
                showLineNumbers={false}
                className="text-xs"
              />
            </BentoCard>
          </motion.div>

          {/* Hero: VS Code — span 5 */}
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-5"
          >
            <BentoCard
              icon={<EditorIcon />}
              title="VS Code · Neovim · Helix"
              body="Syntax highlighting, cross-file completion, hover, go-to-definition, diagnostics, formatting. One language server in the box, every editor."
              badge="LSP"
              highlightColor="rgba(59, 130, 246, 0.18)"
              className="h-full"
            >
              <div className="space-y-3">
                <FeatureRow
                  dotColor="bg-purple-500"
                  text="Workspace-wide completion of role parents"
                />
                <FeatureRow
                  dotColor="bg-blue-500"
                  text="Type-checked permission expressions"
                />
                <FeatureRow
                  dotColor="bg-emerald-500"
                  text="Inline diagnostics as you type"
                />
                <FeatureRow
                  dotColor="bg-amber-500"
                  text="Whole-document canonical formatter"
                />
                <FeatureRow
                  dotColor="bg-rose-500"
                  text="Hover docs · go-to-def across files"
                />
                <div className="mt-4 pt-3 border-t border-fd-border/60 text-xs text-fd-muted-foreground">
                  Install from the{" "}
                  <span className="text-fd-foreground font-medium">
                    VS Code Marketplace
                  </span>{" "}
                  — search{" "}
                  <code className="font-mono text-fd-foreground">
                    Warden
                  </code>{" "}
                  by{" "}
                  <code className="font-mono text-fd-foreground">xraph</code>.
                </div>
              </div>
            </BentoCard>
          </motion.div>

          {/* Row 2: Authorization models — span 4 each */}
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<RbacIcon />}
              title="RBAC"
              body="Hierarchical roles with permissions, resource-scoped assignments, and glob matching. Auto-ID + auto-timestamp on Create — no boilerplate."
              highlightColor="rgba(99, 102, 241, 0.18)"
              className="h-full"
            />
          </motion.div>
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<AbacIcon />}
              title="ABAC"
              body="Allow/deny policies with conditions on IP ranges, time windows, departments, and any context attribute. 15+ operators including ip_in_cidr and regex."
              highlightColor="rgba(168, 85, 247, 0.18)"
              className="h-full"
            />
          </motion.div>
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<RebacIcon />}
              title="ReBAC"
              body="Google Zanzibar-inspired relation tuples with BFS graph traversal. Subject sets via group#member. Configurable max depth and cycle detection."
              highlightColor="rgba(59, 130, 246, 0.18)"
              className="h-full"
            />
          </motion.div>

          {/* Row 3: PBAC (span 5) + Namespaces (span 7) */}
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-5"
          >
            <BentoCard
              icon={<ClockIcon />}
              title="PBAC — time-bound + obligations"
              body="not_before / not_after windows for incident freezes and scheduled grants. Plus obligations — named side-effects (audit-log, require-mfa) emitted on match."
              badge="New"
              highlightColor="rgba(244, 114, 182, 0.18)"
              className="h-full"
            >
              <div className="rounded-lg border border-fd-border/60 bg-fd-muted/20 p-3 font-mono text-[11px] leading-relaxed">
                <div className="text-fd-muted-foreground/70">
                  // incident freeze until 2026-06-01
                </div>
                <div>
                  <span className="text-purple-400">policy</span>{" "}
                  <span className="text-teal-400">"incident-freeze"</span>{" "}
                  &#123;
                </div>
                <div className="pl-3">
                  <span className="text-purple-400">effect</span> ={" "}
                  <span className="text-purple-400">deny</span>
                </div>
                <div className="pl-3">
                  <span className="text-purple-400">not_after</span> ={" "}
                  <span className="text-teal-400">"2026-06-01T00:00:00Z"</span>
                </div>
                <div className="pl-3">
                  <span className="text-purple-400">obligations</span> = [
                  <span className="text-teal-400">"notify-oncall"</span>]
                </div>
                <div>&#125;</div>
              </div>
            </BentoCard>
          </motion.div>

          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-7"
          >
            <BentoCard
              icon={<TreeIcon />}
              title="Multi-tenant + nested namespaces"
              body="Hard tenant walls plus a soft namespace hierarchy inside each tenant. Cascading inheritance from ancestors, sibling isolation, default-empty global scope."
              highlightColor="rgba(99, 102, 241, 0.18)"
              className="h-full"
            >
              <NamespaceTree />
            </BentoCard>
          </motion.div>

          {/* Row 4: Plugin + Embed + Stores */}
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<PluginIcon />}
              title="Plugin lifecycle hooks"
              body="Auto-discovered hooks for audit, metrics, and dispatcher integrations. PolicyObligationFired, RoleAssigned, RelationWritten, AfterCheck, more."
              highlightColor="rgba(34, 197, 94, 0.18)"
              className="h-full"
            />
          </motion.div>
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<EmbedIcon />}
              title="//go:embed your config"
              body="dsl.ApplyFS over an embed.FS ships your .warden tree inside the binary. One-line bootstrap on engine start. No external files in production."
              badge="New"
              highlightColor="rgba(34, 211, 238, 0.18)"
              className="h-full"
            />
          </motion.div>
          <motion.div
            variants={{
              hidden: { opacity: 0, y: 20 },
              visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
            }}
            className="md:col-span-4"
          >
            <BentoCard
              icon={<DatabaseIcon />}
              title="Four store backends"
              body="Postgres, SQLite, MongoDB, in-memory. Same composite Store interface; pick by DSN. Migrations managed by grove, idempotent and round-trip tested."
              highlightColor="rgba(245, 158, 11, 0.18)"
              className="h-full"
            />
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

function FeatureRow({ dotColor, text }: { dotColor: string; text: string }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className={cn("size-2 rounded-full shrink-0", dotColor)} />
      <span className="text-xs text-fd-muted-foreground">{text}</span>
    </div>
  );
}

function NamespaceTree() {
  return (
    <div className="rounded-lg border border-fd-border/60 bg-fd-muted/20 p-4 font-mono text-[11px] leading-relaxed text-fd-muted-foreground">
      <div className="text-fd-foreground">acme</div>
      <div className="pl-3">├── engineering</div>
      <div className="pl-3">│   ├── platform</div>
      <div className="pl-3">│   │   └── sre</div>
      <div className="pl-3">│   └── frontend</div>
      <div className="pl-3">└── billing</div>
      <div className="mt-2 pt-2 border-t border-fd-border/40 text-fd-muted-foreground/70">
        Roles defined at <span className="text-fd-foreground">engineering</span>{" "}
        cascade to <span className="text-fd-foreground">platform</span> and{" "}
        <span className="text-fd-foreground">frontend</span> — but never to{" "}
        <span className="text-fd-foreground">billing</span>.
      </div>
    </div>
  );
}

// ─── Icons ────────────────────────────────────────────────────────

function IconBase({
  children,
  size = 5,
}: {
  children: React.ReactNode;
  size?: number;
}) {
  return (
    <svg
      className={cn(`size-${size}`, "size-5")}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

function DslIcon() {
  return (
    <IconBase>
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
      <path d="M14 2v6h6M9 13h6M9 17h6" />
    </IconBase>
  );
}
function EditorIcon() {
  return (
    <IconBase>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 9l-3 3 3 3M15 9l3 3-3 3M13 7l-2 10" />
    </IconBase>
  );
}
function RbacIcon() {
  return (
    <IconBase>
      <path d="M12 2L2 7l10 5 10-5-10-5z" />
      <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
    </IconBase>
  );
}
function AbacIcon() {
  return (
    <IconBase>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </IconBase>
  );
}
function RebacIcon() {
  return (
    <IconBase>
      <circle cx="5" cy="6" r="3" />
      <circle cx="19" cy="6" r="3" />
      <circle cx="12" cy="18" r="3" />
      <path d="M7.5 8l3 7M16.5 8l-3 7" />
    </IconBase>
  );
}
function ClockIcon() {
  return (
    <IconBase>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </IconBase>
  );
}
function TreeIcon() {
  return (
    <IconBase>
      <path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z" />
      <path d="M10 6h4M10 17h4M6 10v4M17 10v4" />
    </IconBase>
  );
}
function PluginIcon() {
  return (
    <IconBase>
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <path d="M9 9h6M9 13h6M9 17h4" />
    </IconBase>
  );
}
function EmbedIcon() {
  return (
    <IconBase>
      <path d="M8 9l-4 3 4 3M16 9l4 3-4 3M14 4l-4 16" />
    </IconBase>
  );
}
function DatabaseIcon() {
  return (
    <IconBase>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14a9 3 0 0018 0V5" />
      <path d="M3 12a9 3 0 0018 0" />
    </IconBase>
  );
}

// Avoid unused-import warnings while keeping symbols available for future
// expansion (we re-export DotLed from primitives via this module's tree).
export const _bentoExports = { DotLed };
