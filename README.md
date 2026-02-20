# Warden — Composable permissions & authorization engine

[![Go Reference](https://pkg.go.dev/badge/github.com/xraph/warden.svg)](https://pkg.go.dev/github.com/xraph/warden)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue)](https://go.dev)
[![CI](https://github.com/xraph/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/xraph/warden/actions/workflows/ci.yml)

Warden is a composable authorization engine supporting **RBAC**, **ABAC**, and **ReBAC** in a single unified API. It answers "are you allowed to do this?" and integrates natively with the Forge ecosystem.

## Features

- **RBAC** — Roles, permissions, role inheritance, resource-scoped assignments
- **ABAC** — Attribute-based policies with conditions (IP ranges, time windows, regex, etc.)
- **ReBAC** — Zanzibar-style relation tuples with BFS graph walking
- **Multi-model** — Use RBAC, ABAC, and ReBAC together; explicit deny > allow > default deny
- **Multi-tenant** — All data is tenant-scoped via `forge.Scope` or standalone context helpers
- **Extensible** — Plugin hooks for audit logging, metrics, and custom lifecycle events
- **Caching** — Built-in in-memory LRU cache with TTL and per-tenant/subject invalidation
- **Forge native** — Drop-in Forge extension with DI, API routes, and middleware

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/xraph/warden"
    "github.com/xraph/warden/assignment"
    "github.com/xraph/warden/id"
    "github.com/xraph/warden/permission"
    "github.com/xraph/warden/role"
    "github.com/xraph/warden/store/memory"
)

func main() {
    ctx := warden.WithTenant(context.Background(), "myapp", "tenant-1")
    s := memory.New()

    eng, err := warden.NewEngine(warden.WithStore(s))
    if err != nil {
        log.Fatal(err)
    }

    // Create role + permission.
    roleID := id.NewRoleID()
    permID := id.NewPermissionID()
    _ = s.CreateRole(ctx, &role.Role{ID: roleID, TenantID: "tenant-1", Name: "editor", Slug: "editor"})
    _ = s.CreatePermission(ctx, &permission.Permission{ID: permID, TenantID: "tenant-1", Name: "doc:read", Resource: "doc", Action: "read"})
    _ = s.AttachPermission(ctx, roleID, permID)

    // Assign role to user.
    _ = s.CreateAssignment(ctx, &assignment.Assignment{
        ID: id.NewAssignmentID(), TenantID: "tenant-1",
        RoleID: roleID, SubjectKind: "user", SubjectID: "alice",
    })

    // Check authorization.
    result, err := eng.Check(ctx, &warden.CheckRequest{
        Subject:  warden.Subject{Kind: warden.SubjectUser, ID: "alice"},
        Action:   warden.Action{Name: "read"},
        Resource: warden.Resource{Type: "doc", ID: "d1"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Allowed: %v\n", result.Allowed) // true
}
```

## Installation

```bash
go get github.com/xraph/warden
```

## Architecture

```
Check Request
     |
     v
+----------+     +---------+     +---------+
|   RBAC   | --> |  ReBAC  | --> |  ABAC   |
| roles &  |     | relation|     | policy  |
| perms    |     | tuples  |     | engine  |
+----------+     +---------+     +---------+
     |                |               |
     +-------+--------+-------+------+
             |                 |
       mergeDecisions    explicit deny
             |            > allow
             v            > default deny
       CheckResult
```

The engine evaluates all three models and merges results:
1. **Explicit deny** (from ABAC) always wins
2. **Any allow** from any model grants access
3. **Default deny** if no rules match

## Authorization Models

### RBAC (Role-Based Access Control)

Roles contain permissions. Users are assigned roles (globally or scoped to specific resources). Roles support inheritance via parent chains.

### ReBAC (Relationship-Based Access Control)

Zanzibar-style relation tuples (`object#relation@subject`) with BFS graph walking for transitive permissions. Subject sets enable hierarchical access (e.g., folder membership granting document access).

### ABAC (Attribute-Based Access Control)

Policies with conditions evaluate against subject attributes, resource attributes, and request context. Supported operators: `eq`, `neq`, `in`, `not_in`, `contains`, `starts_with`, `gt`, `lt`, `ip_in_cidr`, `time_after`, `time_before`, `regex`, and more.

## Forge Integration

```go
import (
    "github.com/xraph/forge"
    wardenext "github.com/xraph/warden/extension"
    wardenmw "github.com/xraph/warden/middleware"
)

// Register as Forge extension.
app := forge.New(
    forge.WithExtensions(
        wardenext.New(
            wardenext.WithStore(store),
        ),
    ),
)

// Use middleware for route protection.
router.GET("/documents/:id", handler,
    forge.WithMiddleware(wardenmw.Require(eng, "read", "document")),
)
```

## Store Backends

| Backend | Package | Use case |
|---------|---------|----------|
| Memory | `store/memory` | Testing, development |
| PostgreSQL | `store/postgres` | Production |

## Examples

See the `_examples/` directory:

- `_examples/standalone/` — Warden without Forge
- `_examples/forge/` — Warden as Forge extension
- `_examples/rbac/` — Pure RBAC with role inheritance
- `_examples/rebac/` — Zanzibar-style ReBAC
- `_examples/abac/` — Attribute-based policies

## License

Part of the Forge ecosystem.
