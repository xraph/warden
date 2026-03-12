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

## Store Backends

Warden ships with four pluggable store backends. All implement the composite `Store` interface from `store/store.go`.

| Backend | Package | Use case |
| --- | --- | --- |
| Memory | `store/memory` | Testing, development |
| PostgreSQL | `store/postgres` | Production (Grove ORM, migrations, transactions) |
| SQLite | `store/sqlite` | Embedded / edge deployments (Grove ORM) |
| MongoDB | `store/mongo` | NoSQL / document-oriented workloads (BSON, compound indexes) |

```go
import "github.com/xraph/warden/store/memory"
import "github.com/xraph/warden/store/postgres"
import "github.com/xraph/warden/store/sqlite"
import "github.com/xraph/warden/store/mongo"

// Memory (no config needed)
s := memory.New()

// PostgreSQL / SQLite — pass a Grove database instance
s := postgres.New(groveDB)

// MongoDB — pass a Grove MongoDB instance
s := mongo.New(mongoDB)

// All stores support Migrate() for schema setup
_ = s.Migrate(ctx)
```

## Plugin System

Warden provides a granular plugin system with **18 lifecycle hooks**. Plugins implement the base `plugin.Plugin` interface (just `Name() string`) and opt in to specific hooks by implementing additional interfaces.

```go
import "github.com/xraph/warden/plugin"

type AuditPlugin struct{}

func (p *AuditPlugin) Name() string { return "audit" }

// Opt in to the hooks you care about:
func (p *AuditPlugin) RoleCreated(ctx context.Context, r *role.Role) error {
    log.Printf("role created: %s", r.Name)
    return nil
}
func (p *AuditPlugin) AfterCheck(ctx context.Context, req, result any) error {
    log.Printf("check completed")
    return nil
}
```

### Available Hooks

| Category | Hook | Trigger |
| --- | --- | --- |
| Check | `BeforeCheck(ctx, req)` | Before authorization evaluation |
| Check | `AfterCheck(ctx, req, result)` | After authorization evaluation |
| Roles | `RoleCreated(ctx, role)` | Role created |
| Roles | `RoleUpdated(ctx, role)` | Role modified |
| Roles | `RoleDeleted(ctx, roleID)` | Role removed |
| Permissions | `PermissionCreated(ctx, perm)` | Permission created |
| Permissions | `PermissionDeleted(ctx, permID)` | Permission removed |
| Permissions | `PermissionAttached(ctx, roleID, permID)` | Permission attached to role |
| Permissions | `PermissionDetached(ctx, roleID, permID)` | Permission detached from role |
| Assignments | `RoleAssigned(ctx, assignment)` | Role assigned to subject |
| Assignments | `RoleUnassigned(ctx, assignment)` | Role unassigned from subject |
| Relations | `RelationWritten(ctx, tuple)` | Relation tuple created |
| Relations | `RelationDeleted(ctx, relID)` | Relation tuple removed |
| Policies | `PolicyCreated(ctx, policy)` | ABAC policy created |
| Policies | `PolicyUpdated(ctx, policy)` | ABAC policy modified |
| Policies | `PolicyDeleted(ctx, polID)` | ABAC policy removed |
| Lifecycle | `Shutdown(ctx)` | Engine shutting down |

Hook errors are logged as warnings but never block the caller.

## Caching

Warden includes a built-in in-memory LRU cache for `Check()` results with TTL-based expiration and scoped invalidation.

```go
import "github.com/xraph/warden/cache"

c := cache.NewMemory(
    cache.WithTTL(5 * time.Minute),   // Default: 5m
    cache.WithMaxSize(10000),          // Default: 10,000 entries
)

eng, _ := warden.NewEngine(
    warden.WithStore(s),
    warden.WithCache(c),
)
```

Cache keys are scoped by `tenantID:subjectKind:subjectID:action:resourceType:resourceID`.

### Invalidation

```go
// Invalidate all cached results for a tenant.
c.InvalidateTenant(ctx, "tenant-1")

// Invalidate all cached results for a specific subject.
c.InvalidateSubject(ctx, "tenant-1", warden.SubjectUser, "alice")
```

The cache automatically invalidates when roles, permissions, or assignments are modified through the engine.

## Middleware

Warden provides HTTP middleware for Forge route protection.

```go
import wardenmw "github.com/xraph/warden/middleware"

// Require a single permission — returns 403 if denied.
router.GET("/documents/:id", handler,
    forge.WithMiddleware(wardenmw.Require(eng, "read", "document")),
)

// RequireAny — allows if ANY check passes (OR logic).
router.POST("/admin/action", handler,
    forge.WithMiddleware(wardenmw.RequireAny(eng,
        warden.CheckRequest{Action: warden.Action{Name: "admin"}, Resource: warden.Resource{Type: "system"}},
        warden.CheckRequest{Action: warden.Action{Name: "write"}, Resource: warden.Resource{Type: "config"}},
    )),
)

// RequireAll — allows only if ALL checks pass (AND logic).
router.DELETE("/documents/:id", handler,
    forge.WithMiddleware(wardenmw.RequireAll(eng,
        warden.CheckRequest{Action: warden.Action{Name: "delete"}, Resource: warden.Resource{Type: "document"}},
        warden.CheckRequest{Action: warden.Action{Name: "admin"}, Resource: warden.Resource{Type: "document"}},
    )),
)
```

Subject resolution priority:

1. Authenticated user ID from `forge.UserIDFromContext()`
2. Falls back to `unknown:anonymous`

## Configuration

```go
eng, err := warden.NewEngine(
    warden.WithStore(store),                  // Required: store backend
    warden.WithCache(cache),                  // Optional: check result cache
    warden.WithConfig(warden.Config{
        MaxGraphDepth: 10,                    // ReBAC graph traversal depth (default: 10)
        CacheTTL:      5 * time.Minute,       // Check result cache TTL (0 = disabled)
        EnableRBAC:    ptrBool(true),         // Enable RBAC evaluation (default: true)
        EnableABAC:    ptrBool(true),         // Enable ABAC evaluation (default: true)
        EnableReBAC:   ptrBool(true),         // Enable ReBAC evaluation (default: true)
    }),
    warden.WithPlugin(auditPlugin),           // Optional: lifecycle plugins
    warden.WithEvaluator(customEvaluator),    // Optional: custom ABAC evaluator
    warden.WithGraphWalker(customWalker),     // Optional: custom ReBAC graph walker
    warden.WithLogger(logger),                // Optional: structured logger
)
```

## ID System

Warden uses **TypeID** — UUIDv7-based, K-sortable, URL-safe identifiers with type prefixes for all entities.

```text
role_01h2xcejqtf2nbrexx3vqjhp41
perm_01h2xcejqtf2nbrexx3vqjhp41
asgn_01h2xcejqtf2nbrexx3vqjhp41
```

### Prefixes

| Prefix | Entity | Constructor |
| --- | --- | --- |
| `role` | Role | `id.NewRoleID()` |
| `perm` | Permission | `id.NewPermissionID()` |
| `asgn` | Assignment | `id.NewAssignmentID()` |
| `wpol` | Policy | `id.NewPolicyID()` |
| `rel` | Relation | `id.NewRelationID()` |
| `chklog` | Check log | `id.NewCheckLogID()` |
| `rtype` | Resource type | `id.NewResourceTypeID()` |
| `cond` | Condition | `id.NewConditionID()` |

```go
import "github.com/xraph/warden/id"

// Create
roleID := id.NewRoleID()       // role_01h2xce...
permID := id.NewPermissionID() // perm_01h2xce...

// Parse
parsed, err := id.ParseRoleID("role_01h2xcejqtf2nbrexx3vqjhp41")

// Check
if roleID.IsNil() { /* zero-value */ }

// Database support: SQL (Value/Scan), BSON (MarshalBSONValue/UnmarshalBSONValue)
```

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

## Examples

See the `_examples/` directory:

- `_examples/standalone/` — Warden without Forge
- `_examples/forge/` — Warden as Forge extension
- `_examples/rbac/` — Pure RBAC with role inheritance
- `_examples/rebac/` — Zanzibar-style ReBAC
- `_examples/abac/` — Attribute-based policies

## License

Part of the Forge ecosystem.
