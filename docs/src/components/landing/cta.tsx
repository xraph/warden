"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { cn } from "@/lib/cn";
import { AuroraBackground, GradientText, Pill } from "./primitives";

export function CTA() {
  return (
    <section className="relative w-full py-24 sm:py-32 overflow-hidden">
      <AuroraBackground className="opacity-50 dark:opacity-30" />
      <div className="absolute inset-0 bg-grid opacity-[0.03] dark:opacity-[0.06]" />
      <div className="absolute inset-0 bg-gradient-to-b from-fd-background via-transparent to-fd-background" />

      <div className="relative container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="relative mx-auto max-w-4xl"
        >
          {/* Outer glow */}
          <div className="absolute inset-x-12 -bottom-16 -z-10 h-32 bg-gradient-to-t from-blue-500/30 via-indigo-500/20 to-transparent blur-3xl" />

          <div className="relative rounded-3xl border border-fd-border bg-fd-card/70 backdrop-blur-xl p-10 sm:p-14 text-center shadow-2xl shadow-black/[0.04] dark:shadow-black/40">
            {/* Eyebrow */}
            <Pill className="border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-300">
              Ready when you are
            </Pill>

            <h2 className="mt-5 text-balance text-4xl font-bold tracking-tight text-fd-foreground sm:text-5xl md:text-6xl">
              Ship authorization,{" "}
              <GradientText>without the boilerplate.</GradientText>
            </h2>

            <p className="mx-auto mt-5 max-w-2xl text-pretty text-base sm:text-lg text-fd-muted-foreground leading-relaxed">
              One Go module. One CLI. One language server. Define your full
              authorization topology in source-controlled{" "}
              <code className="font-mono text-fd-foreground text-sm">
                .warden
              </code>{" "}
              files, ship it inside your binary, and Check at runtime — across
              every model.
            </p>

            {/* Install command */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="mx-auto mt-8 inline-flex w-fit items-center gap-2 rounded-full border border-fd-border bg-fd-background/40 backdrop-blur-md px-4 py-1.5 font-mono text-xs sm:text-sm shadow-sm"
            >
              <span className="text-fd-muted-foreground select-none">$</span>
              <code className="text-fd-foreground">
                go install github.com/xraph/warden/cmd/warden@latest
              </code>
            </motion.div>

            {/* CTAs */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-3"
            >
              <Link
                href="/docs/getting-started"
                className={cn(
                  "inline-flex items-center justify-center rounded-full px-6 py-3 text-sm font-semibold transition-all",
                  "bg-fd-foreground text-fd-background hover:bg-fd-foreground/90",
                  "shadow-lg shadow-fd-foreground/10 hover:shadow-xl hover:-translate-y-0.5",
                )}
              >
                Read the quickstart
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
              <Link
                href="/docs/integration/dsl-reference"
                className={cn(
                  "inline-flex items-center justify-center rounded-full px-6 py-3 text-sm font-semibold transition-all",
                  "border border-fd-border bg-fd-background/60 hover:bg-fd-muted/60 text-fd-foreground",
                )}
              >
                .warden language reference
              </Link>
            </motion.div>

            {/* Tertiary chip row */}
            <div className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-fd-muted-foreground">
              <Link
                href="/docs/integration/dsl-tooling"
                className="hover:text-fd-foreground transition-colors"
              >
                CLI &amp; LSP
              </Link>
              <span className="text-fd-border">·</span>
              <Link
                href="/docs/concepts/namespaces"
                className="hover:text-fd-foreground transition-colors"
              >
                Nested namespaces
              </Link>
              <span className="text-fd-border">·</span>
              <Link
                href="/docs/authorization/policies-conditions"
                className="hover:text-fd-foreground transition-colors"
              >
                PBAC &amp; obligations
              </Link>
              <span className="text-fd-border">·</span>
              <a
                href="https://github.com/xraph/warden"
                target="_blank"
                rel="noreferrer"
                className="hover:text-fd-foreground transition-colors"
              >
                GitHub
              </a>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
