"use client";

import { motion } from "framer-motion";

interface Stat {
  value: string;
  label: string;
  detail: string;
}

const stats: Stat[] = [
  {
    value: "4",
    label: "Auth models",
    detail: "RBAC · ABAC · ReBAC · PBAC",
  },
  {
    value: "4",
    label: "Store backends",
    detail: "Postgres · SQLite · Mongo · Memory",
  },
  {
    value: "1",
    label: "Config language",
    detail: "Lex · parse · resolve · apply",
  },
  {
    value: "8",
    label: "Namespace depth",
    detail: "Cascading scope inheritance",
  },
];

export function StatsBar() {
  return (
    <section className="relative w-full -mt-8 z-10">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-30px" }}
          transition={{ duration: 0.5 }}
          className="rounded-2xl border border-fd-border bg-fd-card/80 backdrop-blur-xl shadow-xl shadow-black/[0.03] dark:shadow-black/30 overflow-hidden"
        >
          <div className="grid grid-cols-2 lg:grid-cols-4 divide-y divide-x divide-fd-border/60 lg:divide-y-0">
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: 0.1 + i * 0.08 }}
                className="px-6 py-7 sm:py-9"
              >
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl sm:text-5xl font-bold tracking-tight text-fd-foreground tabular-nums">
                    {stat.value}
                  </span>
                  <span className="text-sm font-medium text-fd-muted-foreground">
                    {stat.label}
                  </span>
                </div>
                <p className="mt-2 text-xs text-fd-muted-foreground/80 leading-relaxed">
                  {stat.detail}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
