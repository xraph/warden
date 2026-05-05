import { CodeShowcase } from "@/components/landing/code-showcase";
import { CTA } from "@/components/landing/cta";
import { DeliveryFlowSection } from "@/components/landing/delivery-flow-section";
import { DslShowcase } from "@/components/landing/dsl-showcase";
import { EditorShowcase } from "@/components/landing/editor-showcase";
import { FeatureBento } from "@/components/landing/feature-bento";
import { Hero } from "@/components/landing/hero";
import { StatsBar } from "@/components/landing/stats-bar";

export default function HomePage() {
  return (
    <main className="flex flex-col items-center overflow-x-hidden relative">
      <Hero />
      <StatsBar />
      <FeatureBento />
      <DslShowcase />
      <EditorShowcase />
      <DeliveryFlowSection />
      <CodeShowcase />
      <CTA />
    </main>
  );
}
