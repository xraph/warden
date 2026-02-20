"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { SectionHeader } from "./section-header";

// ─── Cycling Authorization Action ────────────────────────────
const pipelineActions = ["authz.check", "rbac.evaluate", "rebac.traverse"];

function CyclingAuthzAction() {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setIndex((prev) => (prev + 1) % pipelineActions.length);
    }, 3500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative h-5 overflow-hidden">
      <AnimatePresence mode="wait">
        <motion.span
          key={pipelineActions[index]}
          initial={{ y: 12, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -12, opacity: 0 }}
          transition={{ duration: 0.3 }}
          className="absolute inset-0 text-blue-500 dark:text-blue-400 font-mono text-xs font-medium"
        >
          {pipelineActions[index]}
        </motion.span>
      </AnimatePresence>
    </div>
  );
}

// ─── Pipeline Stage ──────────────────────────────────────────
interface StageProps {
  label: string;
  sublabel?: React.ReactNode;
  color: string;
  borderColor: string;
  bgColor: string;
  pulse?: boolean;
  delay: number;
}

function Stage({
  label,
  sublabel,
  color,
  borderColor,
  bgColor,
  pulse,
  delay,
}: StageProps) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.85 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.4, delay }}
      className={cn(
        "relative flex flex-col items-center gap-1 rounded-xl border px-4 py-3 min-w-[90px]",
        borderColor,
        bgColor,
      )}
    >
      {pulse && (
        <motion.div
          className={cn("absolute inset-0 rounded-xl border", borderColor)}
          animate={{ opacity: [0.4, 0], scale: [1, 1.12] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeOut" }}
        />
      )}
      <span className={cn("text-xs font-semibold font-mono", color)}>
        {label}
      </span>
      {sublabel && (
        <span className="text-[10px] text-fd-muted-foreground">{sublabel}</span>
      )}
    </motion.div>
  );
}

// ─── Animated Connection ─────────────────────────────────────
function Connection({
  color = "blue",
  delay = 0,
  horizontal = true,
}: {
  color?: "blue" | "indigo" | "green" | "red";
  delay?: number;
  horizontal?: boolean;
}) {
  const colorMap = {
    blue: { line: "bg-blue-500/30", particle: "bg-blue-400" },
    indigo: { line: "bg-indigo-500/30", particle: "bg-indigo-400" },
    green: { line: "bg-green-500/30", particle: "bg-green-400" },
    red: { line: "bg-red-500/30", particle: "bg-red-400" },
  };

  const c = colorMap[color];

  if (!horizontal) {
    return (
      <div className="relative flex flex-col items-center h-6 w-px">
        <div
          className={cn("absolute inset-0 w-[1.5px] rounded-full", c.line)}
        />
        <motion.div
          className={cn("absolute size-1.5 rounded-full", c.particle)}
          animate={{ y: [-2, 22], opacity: [0, 1, 1, 0] }}
          transition={{
            duration: 1.2,
            repeat: Infinity,
            ease: "linear",
            delay,
          }}
        />
      </div>
    );
  }

  return (
    <div className="relative flex items-center h-px w-8 md:w-12 shrink-0">
      <div
        className={cn(
          "absolute inset-0 h-[1.5px] rounded-full my-auto",
          c.line,
        )}
      />
      <motion.div
        className={cn("absolute size-1.5 rounded-full", c.particle)}
        animate={{ x: [-2, 40], opacity: [0, 1, 1, 0] }}
        transition={{ duration: 1.4, repeat: Infinity, ease: "linear", delay }}
      />
      {/* Arrow */}
      <div
        className="absolute right-0 border-l-[4px] border-y-[2.5px] border-y-transparent border-l-current opacity-30"
        style={{
          color:
            color === "blue"
              ? "#3b82f6"
              : color === "indigo"
                ? "#6366f1"
                : color === "green"
                  ? "#22c55e"
                  : "#ef4444",
        }}
      />
    </div>
  );
}

// ─── Event Row ───────────────────────────────────────────────
function EventRow({
  action,
  status,
  statusLabel,
  lineColor,
  delay,
}: {
  action: string;
  status: "success" | "processing" | "indexed";
  statusLabel: string;
  lineColor: "green" | "blue" | "indigo" | "red";
  delay: number;
}) {
  const statusColors = {
    success:
      "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/20",
    processing:
      "text-blue-600 dark:text-blue-400 bg-blue-500/10 border-blue-500/20",
    indexed:
      "text-green-600 dark:text-green-400 bg-green-500/10 border-green-500/20",
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.4, delay }}
      className="flex items-center gap-0"
    >
      <Connection color={lineColor} delay={delay * 2} />
      <div className="rounded-lg border border-fd-border bg-fd-card/60 px-3 py-1.5 font-mono text-[10px] text-fd-muted-foreground min-w-[110px] text-center">
        {action}
      </div>
      <Connection color={lineColor} delay={delay * 2 + 0.5} />
      <div
        className={cn(
          "rounded-md border px-2 py-1 font-mono text-[10px] font-medium whitespace-nowrap",
          statusColors[status],
        )}
      >
        {statusLabel}
      </div>
    </motion.div>
  );
}

// ─── Authorization Pipeline Diagram ─────────────────────────
function AuthzPipelineDiagram() {
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setPhase((prev) => (prev + 1) % 3);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      whileInView={{ opacity: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className="relative"
    >
      {/* Background glow */}
      <div className="absolute inset-0 -m-6 bg-gradient-to-br from-blue-500/5 via-transparent to-indigo-500/5 rounded-3xl blur-xl" />

      <div className="relative p-3 sm:p-6 rounded-2xl border border-fd-border/50 bg-fd-card/30 backdrop-blur-sm">
        <div className="flex flex-col items-center gap-4">
          {/* Pipeline stages */}
          <div className="flex items-center gap-0 flex-wrap justify-center">
            <Stage
              label="Request"
              sublabel={<CyclingAuthzAction />}
              color="text-blue-600 dark:text-blue-400"
              borderColor="border-blue-500/30"
              bgColor="bg-blue-500/5"
              delay={0.1}
            />
            <Connection color="blue" delay={0} />
            <Stage
              label="Evaluate"
              sublabel="3 models"
              color="text-indigo-600 dark:text-indigo-400"
              borderColor="border-indigo-500/30"
              bgColor="bg-indigo-500/5"
              delay={0.2}
            />
            <Connection color="blue" delay={0.5} />
            <Stage
              label="Merge"
              sublabel="decision"
              color="text-blue-600 dark:text-blue-400"
              borderColor="border-blue-500/30"
              bgColor="bg-blue-500/8"
              pulse
              delay={0.3}
            />
          </div>

          {/* Vertical connection to events */}
          <Connection color="blue" horizontal={false} delay={1} />

          {/* Event rows with outcomes */}
          <div className="flex flex-col items-start gap-2.5">
            <EventRow
              action="rbac.matched"
              status="success"
              statusLabel="Allowed"
              lineColor="green"
              delay={0.5}
            />
            <EventRow
              action="abac.evaluated"
              status={phase === 1 ? "indexed" : "processing"}
              statusLabel={phase === 1 ? "No Opinion" : "Evaluating"}
              lineColor={phase === 1 ? "green" : "blue"}
              delay={0.6}
            />
            <EventRow
              action="rebac.traversed"
              status="indexed"
              statusLabel="Path Found"
              lineColor="green"
              delay={0.7}
            />
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-4 text-[10px] text-fd-muted-foreground">
            <div className="flex items-center gap-1.5">
              <div className="size-2 rounded-full bg-green-500" />
              <span>Allowed</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="size-2 rounded-full bg-blue-500" />
              <span>Evaluating</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="size-2 rounded-full bg-indigo-400" />
              <span>No Opinion</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="size-2 rounded-full bg-red-500" />
              <span>Denied</span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ─── Feature Bullet ──────────────────────────────────────────
function FeatureBullet({
  title,
  description,
  delay,
}: {
  title: string;
  description: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.4, delay }}
      className="flex items-start gap-3"
    >
      <div className="mt-1 flex items-center justify-center size-5 rounded-md bg-blue-500/10 shrink-0">
        <svg
          className="size-3 text-blue-500"
          viewBox="0 0 12 12"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M2 6l3 3 5-5"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <div>
        <h4 className="text-sm font-semibold text-fd-foreground">{title}</h4>
        <p className="text-xs text-fd-muted-foreground mt-0.5 leading-relaxed">
          {description}
        </p>
      </div>
    </motion.div>
  );
}

// ─── Authorization Pipeline Section ─────────────────────────
export function DeliveryFlowSection() {
  return (
    <section className="relative w-full py-20 sm:py-28 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-blue-500/[0.02] to-transparent" />

      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <div className="grid gap-12 lg:grid-cols-2 lg:gap-16 items-center">
          {/* Left: Text content */}
          <div className="flex flex-col">
            <SectionHeader
              badge="Authorization Pipeline"
              title="From request to decision."
              description="Warden orchestrates the entire authorization lifecycle — RBAC evaluation, ABAC policy matching, ReBAC graph traversal, and decision merging."
              align="left"
            />

            <div className="mt-8 space-y-5">
              <FeatureBullet
                title="Three Models, One Check"
                description="RBAC, ABAC, and ReBAC are evaluated in parallel and their decisions merged with deny-overrides priority. A single Check() call handles everything."
                delay={0.2}
              />
              <FeatureBullet
                title="BFS Graph Traversal"
                description="ReBAC uses breadth-first search with cycle detection and configurable max depth to traverse relation graphs and find transitive permissions."
                delay={0.3}
              />
              <FeatureBullet
                title="Audit Trail & Metrics"
                description="Every check is logged with subject, action, resource, decision, and duration. Wire in Chronicle for audit events or Prometheus for metrics via the plugin system."
                delay={0.4}
              />
            </div>

            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.5 }}
              className="mt-8"
            >
              <a
                href="/docs/architecture"
                className="inline-flex items-center gap-1 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-500 transition-colors"
              >
                Learn about the architecture
                <svg
                  className="size-3.5"
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden="true"
                >
                  <path
                    d="M6 4l4 4-4 4"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </a>
            </motion.div>
          </div>

          {/* Right: Pipeline diagram */}
          <div className="relative">
            <AuthzPipelineDiagram />
          </div>
        </div>
      </div>
    </section>
  );
}
