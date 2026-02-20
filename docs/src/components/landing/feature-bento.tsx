"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

interface FeatureCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  code: string;
  filename: string;
  colSpan?: number;
}

const features: FeatureCard[] = [
  {
    title: "Role-Based Access Control",
    description:
      "Hierarchical roles with permissions, resource-scoped assignments, and glob-based permission matching. The most common authorization model.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 2L2 7l10 5 10-5-10-5z" />
        <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
      </svg>
    ),
    code: `// Create role with permissions
r := &role.Role{ID: id.NewRoleID(), Name: "Editor", Slug: "editor"}
store.CreateRole(ctx, r)
store.AttachPermission(ctx, r.ID, permID)

// Assign to user
store.CreateAssignment(ctx, &assignment.Assignment{
    RoleID: r.ID, SubjectKind: "user", SubjectID: "user-42",
})`,
    filename: "rbac.go",
  },
  {
    title: "Attribute-Based Policies",
    description:
      "Define deny/allow policies with conditions on IP ranges, time windows, departments, and custom attributes. Conditions support 12+ operators.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    code: `p := &policy.Policy{
    Name:    "Office Hours Only",
    Effect:  policy.EffectDeny,
    Actions: []string{"write", "delete"},
    Conditions: []policy.Condition{{
        Field: "time", Operator: policy.OpTimeAfter,
        Value: "18:00",
    }},
    IsActive: true,
}`,
    filename: "abac.go",
  },
  {
    title: "Relationship-Based (ReBAC)",
    description:
      "Google Zanzibar-inspired relation tuples with BFS graph traversal. Model document sharing, team membership, and org hierarchies.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <circle cx="5" cy="6" r="3" />
        <circle cx="19" cy="6" r="3" />
        <circle cx="12" cy="18" r="3" />
        <path d="M7.5 8l3 7M16.5 8l-3 7" />
      </svg>
    ),
    code: `// user:42 is viewer of document:123
store.CreateRelation(ctx, &relation.Tuple{
    ObjectType: "document", ObjectID: "doc-123",
    Relation:   "viewer",
    SubjectType: "user", SubjectID: "user-42",
})
// Transitive: user → team → project`,
    filename: "rebac.go",
  },
  {
    title: "Unified Check API",
    description:
      "A single Check() call evaluates RBAC, ABAC, and ReBAC together. Explicit deny beats allow, which beats default deny.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M9 11l3 3L22 4" />
        <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
      </svg>
    ),
    code: `result, _ := eng.Check(ctx, &warden.CheckRequest{
    Subject:      warden.Subject{Kind: "user", ID: "user-42"},
    Action:       "read",
    ResourceType: "document",
    ResourceID:   "doc-123",
    Context:      map[string]any{"ip": "10.0.1.5"},
})
// result.Allowed, result.Reason, result.Sources`,
    filename: "check.go",
  },
  {
    title: "Multi-Tenant Isolation",
    description:
      "Every operation is scoped to a tenant via context. Cross-tenant access is structurally impossible at the store layer.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),
    code: `// With Forge (automatic)
ctx = forge.WithScope(ctx, forge.Scope{
    AppID: "myapp", TenantID: "tenant-123",
})

// Standalone
ctx = warden.WithTenant(ctx, "myapp", "tenant-123")
// All operations scoped automatically`,
    filename: "tenancy.go",
  },
  {
    title: "Plugin System",
    description:
      "Register plugins that implement lifecycle hooks for audit logging, metrics, and custom behavior. Auto-discovered via type assertion.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <rect x="4" y="4" width="16" height="16" rx="2" />
        <path d="M9 9h6M9 13h6M9 17h4" />
      </svg>
    ),
    code: `eng, _ := warden.NewEngine(
    warden.WithStore(store),
    warden.WithPlugin(audit_hook.New(chronicle)),
    warden.WithPlugin(observability.New()),
)
// Hooks: BeforeCheck, AfterCheck, RoleCreated,
// PolicyUpdated, RelationWritten, ...`,
    filename: "plugins.go",
    colSpan: 2,
  },
];

const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: "easeOut" as const },
  },
};

export function FeatureBento() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Features"
          title="Everything you need for authorization"
          description="Warden handles the hard parts — role hierarchies, policy evaluation, graph traversal, and decision merging — so you can focus on your application."
        />

        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-50px" }}
          className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          {features.map((feature) => (
            <motion.div
              key={feature.title}
              variants={itemVariants}
              className={cn(
                "group relative rounded-xl border border-fd-border bg-fd-card/50 backdrop-blur-sm p-6 hover:border-blue-500/20 hover:bg-fd-card/80 transition-all duration-300",
                feature.colSpan === 2 && "md:col-span-2",
              )}
            >
              {/* Header */}
              <div className="flex items-start gap-3 mb-4">
                <div className="flex items-center justify-center size-9 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 shrink-0">
                  {feature.icon}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fd-foreground">
                    {feature.title}
                  </h3>
                  <p className="text-xs text-fd-muted-foreground mt-1 leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              </div>

              {/* Code snippet */}
              <CodeBlock
                code={feature.code}
                filename={feature.filename}
                showLineNumbers={false}
                className="text-xs"
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
