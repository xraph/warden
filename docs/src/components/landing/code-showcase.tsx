"use client";

import { motion } from "framer-motion";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const rbacCode = `package main

import (
  "context"
  "fmt"

  "github.com/xraph/warden"
  "github.com/xraph/warden/assignment"
  "github.com/xraph/warden/permission"
  "github.com/xraph/warden/role"
  "github.com/xraph/warden/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()
  eng, _ := warden.NewEngine(warden.WithStore(st))

  // IDs and timestamps are auto-assigned by the store.
  perm := &permission.Permission{
    Name: "doc:read", Resource: "document", Action: "read",
  }
  r := &role.Role{Name: "Viewer", Slug: "viewer"}
  _ = st.CreatePermission(ctx, perm)
  _ = st.CreateRole(ctx, r)
  _ = st.AttachPermission(ctx, r.ID, permission.Ref{Name: "doc:read"})

  _ = st.CreateAssignment(ctx, &assignment.Assignment{
    RoleID:      r.ID,
    SubjectKind: "user", SubjectID: "alice",
  })

  result, _ := eng.Check(ctx, &warden.CheckRequest{
    Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
    Action:   warden.Action{Name: "read"},
    Resource: warden.Resource{Type: "document", ID: "doc-1"},
  })
  fmt.Printf("allowed=%v reason=%q\\n",
    result.Allowed, result.Reason)
  // allowed=true reason="role.viewer grants doc:read"
}`;

const rebacCode = `package main

import (
  "context"
  "fmt"

  "github.com/xraph/warden"
  "github.com/xraph/warden/relation"
  "github.com/xraph/warden/store/memory"
)

func main() {
  ctx := context.Background()
  st := memory.New()
  eng, _ := warden.NewEngine(warden.WithStore(st))

  // user:alice is member of team:eng
  _ = st.CreateRelation(ctx, &relation.Tuple{
    ObjectType:  "team", ObjectID: "eng",
    Relation:    "member",
    SubjectType: "user", SubjectID: "alice",
  })

  // team:eng is editor of project:alpha (via subject set #member)
  _ = st.CreateRelation(ctx, &relation.Tuple{
    ObjectType:      "project", ObjectID: "alpha",
    Relation:        "editor",
    SubjectType:     "team", SubjectID: "eng",
    SubjectRelation: "member",
  })

  // Can alice edit project:alpha?
  // BFS: alice → team:eng#member → project:alpha
  result, _ := eng.Check(ctx, &warden.CheckRequest{
    Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
    Action:   warden.Action{Name: "write"},
    Resource: warden.Resource{Type: "project", ID: "alpha"},
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
