"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";

interface SectionHeaderProps {
  badge?: string;
  title: string;
  description?: string;
  className?: string;
  align?: "left" | "center";
}

export function SectionHeader({
  badge,
  title,
  description,
  className,
  align = "center",
}: SectionHeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      className={cn(
        "max-w-3xl",
        align === "center" && "mx-auto text-center",
        className,
      )}
    >
      {badge && (
        <div className="inline-flex items-center rounded-full border border-fd-border/60 bg-fd-card/60 backdrop-blur-sm px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-fd-muted-foreground mb-5">
          {badge}
        </div>
      )}
      <h2 className="text-balance text-3xl font-bold tracking-tight text-fd-foreground sm:text-4xl md:text-5xl">
        {title}
      </h2>
      {description && (
        <p className="mt-5 text-pretty text-base sm:text-lg text-fd-muted-foreground leading-relaxed">
          {description}
        </p>
      )}
    </motion.div>
  );
}
