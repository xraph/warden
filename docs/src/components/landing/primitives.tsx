"use client";

import { motion, useMotionTemplate, useMotionValue } from "framer-motion";
import {
  type CSSProperties,
  type MouseEvent,
  type ReactNode,
  useId,
} from "react";
import { cn } from "@/lib/cn";

// ─── AuroraBackground ─────────────────────────────────────────────
//
// Soft mesh-gradient layer for hero / CTA sections. Optional `animated`
// flag adds a slow drift via the `aurora-shift` keyframe (defined in
// global.css).

interface AuroraBackgroundProps {
  className?: string;
  animated?: boolean;
}

export function AuroraBackground({
  className,
  animated = true,
}: AuroraBackgroundProps) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        "pointer-events-none absolute inset-0 bg-aurora opacity-60 dark:opacity-40",
        animated && "aurora-shift",
        className,
      )}
    />
  );
}

// ─── GradientText ─────────────────────────────────────────────────
//
// Inline gradient-clipped text. Used for hero accents.

interface GradientTextProps {
  children: ReactNode;
  className?: string;
}

export function GradientText({ children, className }: GradientTextProps) {
  return (
    <span className={cn("text-gradient-warden", className)}>{children}</span>
  );
}

// ─── Marquee ──────────────────────────────────────────────────────
//
// Infinite horizontal scroller. Doubles its children inline so the
// CSS `marquee` keyframe can translate −50% and seamlessly loop.

interface MarqueeProps {
  children: ReactNode;
  className?: string;
  reverse?: boolean;
  pauseOnHover?: boolean;
  speed?: "slow" | "normal" | "fast";
}

export function Marquee({
  children,
  className,
  reverse = false,
  pauseOnHover = true,
  speed = "normal",
}: MarqueeProps) {
  const durationStyle: CSSProperties = {
    animationDuration:
      speed === "slow" ? "60s" : speed === "fast" ? "20s" : "32s",
    animationDirection: reverse ? "reverse" : "normal",
  };
  return (
    <div
      className={cn(
        "group relative flex w-full overflow-hidden mask-fade-x",
        className,
      )}
    >
      <div
        className={cn(
          "flex shrink-0 gap-4 animate-marquee",
          pauseOnHover && "group-hover:[animation-play-state:paused]",
        )}
        style={durationStyle}
      >
        {children}
        {children}
      </div>
    </div>
  );
}

// ─── Spotlight ────────────────────────────────────────────────────
//
// Card wrapper that paints a subtle radial highlight under the cursor.
// Implementation: a CSS mask on a sibling pseudo-element, position
// driven by a Framer motion value bound to mousemove. Costs nothing
// when not hovered (background mask is fully transparent away from
// the cursor) and zero JS for non-hovered cards.

interface SpotlightCardProps {
  children: ReactNode;
  className?: string;
  // Tailwind color tokens for the spotlight highlight (CSS named or
  // hex; default is a soft blue/indigo).
  highlightColor?: string;
}

export function SpotlightCard({
  children,
  className,
  highlightColor = "rgba(99, 102, 241, 0.18)",
}: SpotlightCardProps) {
  const x = useMotionValue(-100);
  const y = useMotionValue(-100);
  const id = useId();

  function handleMouseMove(e: MouseEvent<HTMLDivElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    x.set(e.clientX - rect.left);
    y.set(e.clientY - rect.top);
  }

  function handleMouseLeave() {
    x.set(-200);
    y.set(-200);
  }

  const background = useMotionTemplate`radial-gradient(220px circle at ${x}px ${y}px, ${highlightColor}, transparent 80%)`;

  return (
    <div
      key={id}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={cn(
        "group relative rounded-xl overflow-hidden",
        "border border-fd-border bg-fd-card/40 backdrop-blur-sm",
        "transition-colors hover:border-fd-border/80",
        className,
      )}
    >
      <motion.div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{ background }}
      />
      {children}
    </div>
  );
}

// ─── Pill ─────────────────────────────────────────────────────────
//
// Small label chip used in marquees and category badges.

interface PillProps {
  children: ReactNode;
  className?: string;
}

export function Pill({ children, className }: PillProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-fd-border/60 bg-fd-card/60 px-3 py-1 text-xs font-medium text-fd-foreground/80 backdrop-blur-sm whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

// ─── DotLed ───────────────────────────────────────────────────────
//
// Pulsing dot used in status indicators.

export function DotLed({ color = "bg-emerald-500" }: { color?: string }) {
  return (
    <span className="relative inline-flex shrink-0 items-center">
      <span
        className={cn("absolute inline-flex size-2 rounded-full", color)}
      />
      <span
        className={cn(
          "absolute inline-flex size-2 rounded-full opacity-75 animate-ping",
          color,
        )}
      />
      <span className="invisible inline-flex size-2 rounded-full" />
    </span>
  );
}
