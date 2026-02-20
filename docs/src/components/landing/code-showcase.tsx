"use client";

import { motion } from "framer-motion";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const rbacCode = `package main

import (
  "context"
  "fmt"
  "time"

  "github.com/xraph/warden"
  "github.com/xraph/warden/assignment"
  "github.com/xraph/warden/id"
  "github.com/xraph/warden/permission"
  "github.com/xraph/warden/role"
  "github.com/xraph/warden/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()
  eng, _ := warden.NewEngine(warden.WithStore(st))

  now := time.Now()
  perm := &permission.Permission{
    ID: id.NewPermissionID(), Resource: "document",
    Action: "read", Name: "Read Docs",
    CreatedAt: now, UpdatedAt: now,
  }
  r := &role.Role{
    ID: id.NewRoleID(), Name: "Viewer", Slug: "viewer",
    CreatedAt: now, UpdatedAt: now,
  }
  _ = st.CreatePermission(ctx, perm)
  _ = st.CreateRole(ctx, r)
  _ = st.AttachPermission(ctx, r.ID, perm.ID)
  _ = st.CreateAssignment(ctx, &assignment.Assignment{
    ID: id.NewAssignmentID(), RoleID: r.ID,
    SubjectKind: "user", SubjectID: "alice",
    CreatedAt: now,
  })

  result, _ := eng.Check(ctx, &warden.CheckRequest{
    Subject:      warden.Subject{Kind: "user", ID: "alice"},
    Action:       "read",
    ResourceType: "document",
  })
  fmt.Printf("allowed=%v reason=%q\\n",
    result.Allowed, result.Reason)
  // allowed=true reason="rbac: granted"
}`;

const rebacCode = `package main

import (
  "context"
  "fmt"
  "time"

  "github.com/xraph/warden"
  "github.com/xraph/warden/id"
  "github.com/xraph/warden/relation"
  "github.com/xraph/warden/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()
  eng, _ := warden.NewEngine(warden.WithStore(st))

  now := time.Now()

  // user:alice is member of team:eng
  _ = st.CreateRelation(ctx, &relation.Tuple{
    ID: id.NewRelationID(),
    ObjectType: "team", ObjectID: "eng",
    Relation: "member",
    SubjectType: "user", SubjectID: "alice",
    CreatedAt: now,
  })

  // team:eng is editor of project:alpha
  _ = st.CreateRelation(ctx, &relation.Tuple{
    ID: id.NewRelationID(),
    ObjectType: "project", ObjectID: "alpha",
    Relation: "editor",
    SubjectType: "team", SubjectID: "eng",
    CreatedAt: now,
  })

  // Can alice edit project:alpha?
  // Traverses: alice → team:eng → project:alpha
  result, _ := eng.Check(ctx, &warden.CheckRequest{
    Subject:      warden.Subject{Kind: "user", ID: "alice"},
    Action:       "write",
    ResourceType: "project",
    ResourceID:   "alpha",
  })
  fmt.Printf("allowed=%v\\n", result.Allowed)
  // allowed=true (via transitive relation)
}`;

export function CodeShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Developer Experience"
          title="Simple API. Powerful primitives."
          description="Set up role-based access or traverse a relationship graph in under 30 lines. Warden handles evaluation, merging, and audit logging."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* RBAC side */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-blue-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                RBAC
              </span>
            </div>
            <CodeBlock code={rbacCode} filename="rbac.go" />
          </motion.div>

          {/* ReBAC side */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-indigo-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                ReBAC
              </span>
            </div>
            <CodeBlock code={rebacCode} filename="rebac.go" />
          </motion.div>
        </div>
      </div>
    </section>
  );
}
