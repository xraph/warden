# What the templ dashboard did, and where it went

Warden used to ship its own dashboard: templ pages under `dashboard/`, rendered by
Forge's templ dashboard and driven with HTMX and Alpine. That directory is
deleted. Its replacement is the React plugin `packages/plugin-warden` in the
forge-dashboard repository, which talks to warden only through the contract in
`extension/contract/` (`manifest.yaml` lists every intent).

This file is the only record of what the old pages showed and did. If you are
looking for a column, a button or a filter you remember, find its page below and
the Where-now cell tells you which React route and which intent does that job
today, or why nothing does. Every file that lived in `dashboard/` is named here
by its path from warden's root, so you can grep for it.

React routes are written as the plugin declares them, relative to wherever your
shell mounts warden. Templ routes are written as `contributor.go` dispatched
them.

## Status key

| Status | Meaning |
|---|---|
| migrated | The React dashboard does this. The Where-now cell names the route and the intent, and says so when it works differently (a modal that became a page, a column that moved to the detail page). |
| dropped | Deliberately not carried over. The reason is a fact about warden or about the old code. |
| blocked | Not possible today. The cell says what would be needed and why the contract cannot provide it yet. |
| gap | The contract already serves what this needs, and the React dashboard does not use it yet. |
| bug fixed | The templ version did not work as it looked. The React version does the job correctly, so this is recorded as a fix, not as a feature. |

## Overview

Templ route `/`, source `dashboard/pages/overview.templ`. React route `/`
(`pages/overview.tsx`). When no tenant resolved from the request context, the
overview, every templ list page and both widgets rendered the "Select a tenant" empty state
instead of querying (see Shared infrastructure).

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Heading "Authorization Overview" and its subtitle | `dashboard/pages/overview.templ:22-23` | migrated | `/` page header "Warden". |
| Six stat cards: Roles, Permissions, Assignments, Relations, Policies, Resource Types, each with a subtitle | `dashboard/pages/overview.templ:27-34` | migrated | `/` stat grid from `overview.stats`. Labels only, no subtitles. |
| Quick Actions card: Create Role, Create Permission, Assign Role, Write Relation (each opened a modal on the overview) | `dashboard/pages/overview.templ:50-89`, `:233-236` | migrated | Each create lives on its own list page: New role on `/roles` (`roles.create`), New permission on `/permissions` (`permissions.create`), New assignment on `/assignments` (`assignments.create`), New relation on `/relations` (`relations.create`). The overview has no shortcuts. |
| Quick Actions: Create Policy, Create Resource Type (links to the full-page forms) | `dashboard/pages/overview.templ:90-115` | migrated | New policy on `/policies` (`policies.create`), New resource type on `/resource-types` (`resourceTypes.create`). |
| Engine Status card: RBAC, ABAC, ReBAC Enabled/Disabled badges; Max Graph Depth when above 0; Cache TTL when above 0 | `dashboard/pages/overview.templ:121-158`, `:253-263` | migrated | Moved to `/config` (`config.detail`): model badges, graph depth limit, decision cache. |
| Recent Authorization Checks card: last 10 checks, columns Subject, Action, Resource, Decision (Allow, or Deny for anything else), Time | `dashboard/pages/overview.templ:162-227`, `:241-251` | migrated | `/` Recent checks table from `overview.recentChecks` with `limit: 10`. Columns When (links to the check), Subject, Action, Resource, Namespace, Decision (the real decision string), Detail, Cached. |
| View All button on the recent checks card | `dashboard/pages/overview.templ:174-184` | migrated | "View the check log" link to `/check-log`. |
| Empty state "No check logs recorded yet." | `dashboard/pages/overview.templ:188-189` | migrated | "No checks are in the log." |
| Plugin-contributed sections slot | `dashboard/pages/overview.templ:229-230`, `dashboard/contributor.go:207-211` | dropped | Nothing implements the plugin interface it rendered (`dashboard/plugin_iface.go`). No Go file outside `dashboard/` under the xraph tree imports `github.com/xraph/warden/dashboard`, which a plugin would need to name `PluginWidget`. |

## Playground

Templ route `/playground`, source `dashboard/pages/playground.templ`. React routes
`/playground` and `/playground/check/:checkId` (`pages/playground.tsx`,
`components/playground-lanes.tsx`), intent `playground.explain`.

This is the one page where the old screen is worth describing in full, because
nothing else records it.

### What the templ playground looked like

You got two cards side by side. The left card, "Request Builder", had six inputs:

| Input | Control | Rule |
|---|---|---|
| Subject Kind | select: User, API Key, Service, Service Account (`user`, `api_key`, `service`, `service_acct`) | defaulted to `user` |
| Subject ID | text, placeholder `user-123` | required |
| Action | text, placeholder `read` | required |
| Resource Type | text, placeholder `document` | required |
| Resource ID (optional) | text, placeholder `doc-456` | optional |
| Context JSON (optional) | monospace textarea, placeholder `{"ip": "192.168.1.1"}` | parsed with `JSON.parse` on submit; a parse failure showed "Invalid JSON in context field" and sent nothing |

The Check Access button stayed disabled until Subject ID, Action and Resource
Type were all filled, and read "Checking..." while the request was out
(`dashboard/pages/playground.templ:120-132`).

When you pressed it, the page sent a POST to `<basePath>/v1/authz/check` with the
fields as snake_case JSON, leaving context out when it was empty
(`dashboard/pages/playground.templ:34-52`). That is warden's real check endpoint,
so a playground run was production traffic as far as warden could tell: it fired
the after-check plugin hooks, wrote a check log row when check logging was on,
and filled the decision cache when the cache was on. With the cache on, press
it twice with the same input and the second answer came from the cache, so the
eval time you saw was the cache lookup.

The right card, "Result", had three states:

1. Before any run: a large lightning icon and "Run an authorization check to see results here."
2. On a failed request: a red box with the server's `error` or `message`, or "Check failed".
3. On a result: a large banner, green with a check-circle and the word ALLOWED when `allowed` was true, red with an x-circle and DENIED otherwise. Under it a definition list of Decision (the raw `decision` string), Reason (or `-`) and Eval Time (`eval_time_ns` shown as ns below 1000, `us` with one decimal below 1,000,000, ms with one decimal above).

When the response carried a non-empty `matched_by`, a "Matched By" table followed
with three columns: Source (an outline badge holding `rbac`, `rebac` or `abac`),
Rule ID (or `-`) and Detail (or `-`) (`dashboard/pages/playground.templ:185-213`).

That table was the whole explanation. Warden fills `matched_by` for an allow and
for a deny policy that matched (`evaluator.go:112-135`). Any other denial gave
you the red banner and one reason sentence, and told you nothing about the two models that
did not supply that sentence.

### Where each piece went

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Subject kind, subject id, action, resource type, resource id inputs | `dashboard/pages/playground.templ:71-111` | migrated | `/playground` builder, same four kinds. Adds namespace, subject attributes and resource attributes. |
| Context JSON input and its parse error | `dashboard/pages/playground.templ:38-44`, `:112-119` | migrated | "Context" textarea under "attributes and context". Errors read "This is not valid JSON." or "This must be a JSON object." |
| Run disabled until the three required fields are filled | `dashboard/pages/playground.templ:124` | migrated | Run button, same three fields (`canRun`). |
| The check itself (real, logged, cached, hook-firing) | `dashboard/pages/playground.templ:45-50` | migrated | `playground.explain`, which is a dry run: no check log row, no hooks, no cache. Your own permission to run it is checked, and that check is logged. |
| Empty result state | `dashboard/pages/playground.templ:149-155` | migrated | "Run a check to see its verdict and what each model did." |
| Error box | `dashboard/pages/playground.templ:146-147` | migrated | "Could not run the check." alert carrying the contract error. |
| ALLOWED / DENIED banner | `dashboard/pages/playground.templ:159-173` | migrated | A badge with the decision string (`allow`, `deny_no_roles`, and so on), next to the reason, or the error when the decision is `error`. |
| Decision, Reason, Eval Time list | `dashboard/pages/playground.templ:176-183` | migrated | Decision badge, reason text, and "evaluated in ..." (hidden when the check failed). |
| Matched By table (source, rule id, detail) | `dashboard/pages/playground.templ:185-213` | migrated | One row per model (RBAC, ReBAC, ABAC) with its state, the lane that decided it marked, and each match under its own model. Role and policy rule ids link to `/roles/:id` and `/policies/:id`. A denial now shows what every model did. |

## Roles

Templ route `/roles`, source `dashboard/pages/roles.templ`, rows built by
`dashboard/pages/role_view.go` and `enrichRoleRows` in `dashboard/data.go`.
React route `/roles` (`pages/roles.tsx`), intent `roles.list`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "Roles" with a total count badge | `dashboard/pages/roles.templ:20` | migrated | Page header "Roles", table caption "N roles" from the server total. |
| Create Role button | `dashboard/pages/roles.templ:21`, `:203-212` | migrated | New role, which opens an inline form (`roles.create`). |
| Search box, 300 ms debounce | `dashboard/pages/roles.templ:25-40` | migrated | Search by name (`search` on `roles.list`). |
| Column Name, a link to the detail page | `dashboard/pages/roles.templ:51`, `:65-74` | migrated | Name column. The link is the row's Details action. |
| Column Slug | `dashboard/pages/roles.templ:52`, `:75-77` | migrated | Slug column. |
| Column Parent: parent role name as a link, else a dash | `dashboard/pages/roles.templ:53`, `:78-91`; lookup at `dashboard/data.go:376` | bug fixed | The templ cell never showed a parent. `enrichRoleRows` cached parents under tenant, namespace and slug (`dashboard/data.go:338-345`) but looked them up under tenant and slug only (`dashboard/data.go:376`), so the lookup always missed and every row showed the dash. React shows the parent slug in the Inherits column. |
| Column Permissions: count of attached permissions | `dashboard/pages/roles.templ:54`, `:92-100`; `dashboard/data.go:369-371` | migrated | Not a list column. The grants table on `/roles/:id` captions the count ("N permissions", `roles.detail`). |
| Column Relations: count of tuples with the role as object or subject | `dashboard/pages/roles.templ:55`, `:101-109`; `dashboard/data.go:383-392` | dropped | The count was taken with no tenant in the filter (`dashboard/data.go:384-391`), and an empty tenant matches every tenant's rows (`dashboard/contributor.go:53-58`), so in a multi-tenant deployment the number summed tuples across tenants. To see the tuples themselves, filter `/relations` by object type `role` and object id, or subject type `role` and subject id (`relations.list`). |
| Column Flags: System and Default badges | `dashboard/pages/roles.templ:56`, `:110-123` | migrated | Flags column, `system` and `default` badges. |
| Column Description, "No description" when empty | `dashboard/pages/roles.templ:57`, `:124-130` | migrated | On `/roles/:id` in the details list. |
| Column Created | `dashboard/pages/roles.templ:58`, `:131-134` | gap | `roles.list` and `roles.detail` return `createdAt`. No React page shows when a role was created; the list shows Updated. |
| Row menu: View Details | `dashboard/pages/roles.templ:143-152` | migrated | Details link to `/roles/:id`. |
| Row menu: Delete, hidden on system roles, with a confirm | `dashboard/pages/roles.templ:153-176` | migrated | Delete button, hidden on system roles, confirm dialog (`roles.delete`). |
| Empty state "No roles found." | `dashboard/pages/roles.templ:45-46` | migrated | "No roles yet", or a message naming the search and namespace when filtered. |
| Pagination, 20 per page | `dashboard/pages/roles.templ:186-189`, `:214-265` | migrated | Table pagination, 25 per page, offset paging. |
| `?create=1` opened the create dialog on load | `dashboard/pages/roles.templ:195-199` | dropped | No Go, templ or TypeScript source under the xraph tree builds a URL with `create=1`, so no link ever used it. |

### Create role dialog

Source `dashboard/pages/role_form.templ` (`RoleCreateDialog`, lines 19-85).

| Field | Templ source | Status | Where now |
|---|---|---|---|
| Name, required | `dashboard/pages/role_form.templ:39-42` | migrated | Name, required. |
| Slug, required | `dashboard/pages/role_form.templ:43-46` | migrated | Slug, required. Trimmed before sending. |
| Description textarea | `dashboard/pages/role_form.templ:47-50` | migrated | Description. |
| Parent Role select of existing roles | `dashboard/pages/role_form.templ:51-63` | migrated | Not on the create form. Set it afterwards with Edit on `/roles/:id` (`roles.update`, Inherits from). |
| Max Members number, 0 for unlimited | `dashboard/pages/role_form.templ:64-67` | migrated | Not on the create form. Member cap on the Edit form, blank for unlimited. |
| Default Role switch | `dashboard/pages/role_form.templ:68-71` | migrated | Not on the create form. Default role checkbox on the Edit form. |

## Role detail

Templ route `/roles/detail?id=...`, source `dashboard/pages/role_detail.templ`,
with the attach and detach dialogs in `dashboard/pages/role_permissions.templ`
and the edit dialog in `dashboard/pages/role_form.templ`. Nav never linked here;
you reached it from a role name. React route `/roles/:id`
(`pages/role-detail.tsx`), intent `roles.detail`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Heading with System and Default badges, description under it | `dashboard/pages/role_detail.templ:21-39` | migrated | Page header with the role name. A system role gets an alert saying it cannot be changed. Default and description are in the details list. |
| Edit button, hidden on system roles | `dashboard/pages/role_detail.templ:41-50` | migrated | Edit, hidden on system roles. Opens an inline form (`roles.update`), not a modal. |
| Delete button with confirm, hidden on system roles | `dashboard/pages/role_detail.templ:51-59`, `:217-227` | migrated | Not on the detail page. Delete on the role's row at `/roles` (`roles.delete`). |
| Details: ID | `dashboard/pages/role_detail.templ:73-74` | migrated | Not printed. It is the `:id` in the page URL. |
| Details: Slug, Parent Role (when set), Max Members (when above 0) | `dashboard/pages/role_detail.templ:75-84` | migrated | Slug, Inherits from, Member cap ("Unlimited" when 0). |
| Details: Created | `dashboard/pages/role_detail.templ:85-86` | gap | Same as the list's Created column: `roles.detail` returns `createdAt` and the page does not show it. |
| Details: Updated | `dashboard/pages/role_detail.templ:87-88` | migrated | Updated. |
| Attached Permissions table: Name, Resource, Action | `dashboard/pages/role_detail.templ:96-163` | migrated | Grants table: Permission, Resource, Action, Namespace, with a Details link to `/permissions/:id`. |
| Detach button (X) per permission, with confirm "Remove permission ... from this role?" | `dashboard/pages/role_detail.templ:144-155`; `dashboard/pages/role_permissions.templ:57-67` | migrated | Revoke per grant, hidden on system roles (`roles.detachPermission`). |
| Attach button and dialog: select of every permission as "name (resource:action)" | `dashboard/pages/role_detail.templ:107-116`, `:228`; `dashboard/pages/role_permissions.templ:11-55` | migrated | Attach permission dialog (`roles.attachPermission`). Lists only permissions the role does not hold, and says when the list is truncated. |
| Empty state "No permissions attached." | `dashboard/pages/role_detail.templ:120-121` | migrated | "This role grants nothing." |
| Child Roles table, shown only when there are children: Name (link), Slug, Created | `dashboard/pages/role_detail.templ:165-211` | migrated | Children table, always shown, "Nothing inherits from this role." when empty. Columns Role, Slug, Namespace, Flags, with a Details link. Created is part of the role Created gap above. |
| Plugin-contributed sections slot | `dashboard/pages/role_detail.templ:213-214`; `dashboard/contributor.go:535-546` | dropped | No type implements `RoleDetailContributor` (`dashboard/plugin_iface.go:45-47`). A search of every Go file under the xraph tree finds the method name only inside `dashboard/`. |

### Edit role dialog

Source `dashboard/pages/role_form.templ` (`RoleEditDialog`, lines 88-148).

| Field | Templ source | Status | Where now |
|---|---|---|---|
| Name | `dashboard/pages/role_form.templ:104-107` | migrated | Name, refused when blank. |
| Description | `dashboard/pages/role_form.templ:108-111` | migrated | Description. |
| Parent Role select, excluding this role | `dashboard/pages/role_form.templ:112-126` | migrated | Inherits from, a text field taking another role's slug. |
| Max Members | `dashboard/pages/role_form.templ:127-130` | migrated | Member cap, a whole number or blank for unlimited. |
| Default Role switch | `dashboard/pages/role_form.templ:131-134` | migrated | Default role checkbox. Only changed fields are sent. |

## Permissions

Templ route `/permissions`, source `dashboard/pages/permissions.templ`. React route
`/permissions` (`pages/permissions.tsx`), intent `permissions.list`. The templ
dashboard had no permission detail page; React adds `/permissions/:id`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "Permissions" with a total count badge | `dashboard/pages/permissions.templ:20` | migrated | Page header and caption "N permissions". |
| Create Permission button | `dashboard/pages/permissions.templ:21-28` | migrated | New permission, inline form (`permissions.create`). |
| Search box | `dashboard/pages/permissions.templ:33-46` | migrated | Search by name. |
| Resource filter, exact match | `dashboard/pages/permissions.templ:47-60` | gap | `permissions.list` accepts `resource`. The page sends only search and namespace. |
| Action filter, exact match | `dashboard/pages/permissions.templ:61-74` | gap | `permissions.list` accepts `action`. The page sends only search and namespace. |
| Columns Name, Resource, Action | `dashboard/pages/permissions.templ:86-88`, `:97-105` | migrated | Same three columns. |
| Column System (badge) | `dashboard/pages/permissions.templ:89`, `:106-112` | migrated | Flags column, `system` badge. |
| Column Created | `dashboard/pages/permissions.templ:90`, `:113-116` | migrated | On `/permissions/:id` (Created). The list shows Updated. |
| Row menu Delete with confirm, hidden on system permissions | `dashboard/pages/permissions.templ:117-145` | migrated | Delete, hidden on system permissions (`permissions.delete`). |
| Empty state "No permissions found." | `dashboard/pages/permissions.templ:80-81` | migrated | "No permissions yet", or a filtered message. |
| Pagination | `dashboard/pages/permissions.templ:155-157` | migrated | Table pagination. |
| `?create=1` | `dashboard/pages/permissions.templ:162-166` | dropped | Nothing builds a URL with `create=1`. |

### Create permission dialog

Source `dashboard/pages/permission_form.templ`.

| Field | Templ source | Status | Where now |
|---|---|---|---|
| Resource, required | `dashboard/pages/permission_form.templ:34-40` | migrated | Resource, required, trimmed. |
| Action, required | `dashboard/pages/permission_form.templ:41-47` | migrated | Action, required, trimmed. |
| Name, prefilled as `resource:action` and editable | `dashboard/pages/permission_form.templ:48-55` | dropped | React shows the derived name and does not let you change it. `permissions.create` refuses any name other than `resource:action` (`extension/contract/handlers_permissions.go:234-245`). |
| Description | `dashboard/pages/permission_form.templ:56-59` | migrated | Description. |
| System Permission switch | `dashboard/pages/permission_form.templ:60-63` | dropped | It never did anything. The HTTP API's `CreatePermissionRequest` has no `is_system` field (`api/requests.go:107-111`) and nothing in `api/` reads one, so the switch was ignored. The contract also refuses every write to a system permission (`extension/contract/immutable.go`). |

## Assignments

Templ route `/assignments`, source `dashboard/pages/assignments.templ`. React
route `/assignments` (`pages/assignments.tsx`), intent `assignments.list`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "Role Assignments" with a total count badge | `dashboard/pages/assignments.templ:22` | migrated | "Assignments" and caption "N assignments". |
| Assign Role button | `dashboard/pages/assignments.templ:23-30` | migrated | New assignment, dialog (`assignments.create`). |
| Subject kind filter: All, User, API Key, Service, Service Account | `dashboard/pages/assignments.templ:35-49` | gap | `assignments.list` accepts `subjectKind`. The page sends only namespace. |
| Subject ID filter | `dashboard/pages/assignments.templ:50-63` | gap | `assignments.list` accepts `subjectId`. The page sends only namespace. For one known subject, `/subjects/:kind/:id` lists all of its assignments (`subjects.detail`). |
| Role filter, a select of roles | `dashboard/pages/assignments.templ:64-77` | gap | `assignments.list` accepts `roleId`. The page sends only namespace, and `/roles/:id` does not list holders. |
| Column Subject `kind:id` | `dashboard/pages/assignments.templ:89`, `:101-103` | migrated | Subject column, linking to `/subjects/:kind/:id`. |
| Column Role ID (raw typeid) | `dashboard/pages/assignments.templ:90`, `:104-106` | migrated | Role column showing the slug, linking to `/roles/:id`. The id shows only when the role could not be resolved. |
| Column Resource Scope, "Global" when unscoped | `dashboard/pages/assignments.templ:91`, `:107-113` | migrated | Scope column. Unscoped rows show an empty marker, and half-scoped rows explain what warden actually does with them. |
| Column Status: Expired, "Expires Jan 02", or Active | `dashboard/pages/assignments.templ:92`, `:114-116`, `:179-194` | migrated | Expires column (a timestamp or "Never") and Status column (an Expired badge computed by the server). |
| Column Granted By | `dashboard/pages/assignments.templ:93`, `:117-123` | gap | `assignments.list` returns `grantedBy`. The page does not show it. |
| Column Created | `dashboard/pages/assignments.templ:94`, `:124-127` | gap | `assignments.list` returns `createdAt`. The page does not show it. |
| Row menu Revoke with confirm "Revoke role from kind:id?" | `dashboard/pages/assignments.templ:128-155` | migrated | Delete with confirm (`assignments.delete`). |
| Empty state "No role assignments found." | `dashboard/pages/assignments.templ:83-84` | migrated | "No assignments yet", or a filtered message. |
| Pagination | `dashboard/pages/assignments.templ:164-166` | migrated | Table pagination. |
| `?create=1` | `dashboard/pages/assignments.templ:171-175` | dropped | Nothing builds a URL with `create=1`. |

### Assign role dialog

Source `dashboard/pages/assignment_form.templ`.

| Field | Templ source | Status | Where now |
|---|---|---|---|
| Role select, required | `dashboard/pages/assignment_form.templ:32-45` | migrated | Role select, options as `slug (namespace)`. |
| Subject Kind select, four kinds | `dashboard/pages/assignment_form.templ:46-59` | migrated | Subject kind, same four. |
| Subject ID, required | `dashboard/pages/assignment_form.templ:60-63` | migrated | Subject id, required. |
| Resource Type (optional), Resource ID (optional) | `dashboard/pages/assignment_form.templ:64-71` | migrated | Same two fields. Both or neither, as `assignments.create` requires. |
| Expires At (optional), datetime input | `dashboard/pages/assignment_form.templ:72-75` | migrated | Expires (optional). A value that does not parse blocks the create. |

## Policies

Templ route `/policies`, source `dashboard/pages/policies.templ`. React route
`/policies` (`pages/policies.tsx`), intent `policies.list`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "ABAC Policies" with count and description | `dashboard/pages/policies.templ:20` | migrated | "Policies", caption "N policies", explanatory paragraph. |
| Create Policy button, to the full-page form | `dashboard/pages/policies.templ:21-30` | migrated | New policy opens a dialog for name, effect and namespace (`policies.create`), then lands on `/policies/:id/edit` for the rest. |
| Search | `dashboard/pages/policies.templ:35-48` | migrated | Search by name. |
| Effect filter: All, Allow, Deny | `dashboard/pages/policies.templ:49-61` | migrated | Effect filter. |
| Status filter: All, Active, Inactive | `dashboard/pages/policies.templ:62-74` | migrated | Active filter. |
| Column Name, link to detail | `dashboard/pages/policies.templ:86`, `:98-107` | migrated | Name links to `/policies/:id`. |
| Column Effect badge | `dashboard/pages/policies.templ:87`, `:108-110`, `:197-207` | migrated | Effect column. |
| Column Priority | `dashboard/pages/policies.templ:88`, `:111-113` | migrated | Priority column. |
| Column Active: Active or Inactive badge | `dashboard/pages/policies.templ:89`, `:114-124` | migrated | Status column, which also flags scheduled, expired, never-in-effect, fails-closed and never-applies policies. |
| Column Conditions (a count) | `dashboard/pages/policies.templ:90`, `:125-127` | migrated | Not a list column. Each condition is listed on `/policies/:id`. |
| Column Created | `dashboard/pages/policies.templ:91`, `:128-131` | migrated | On `/policies/:id` (Created). The list shows Updated. |
| Row menu: View Details, Edit | `dashboard/pages/policies.templ:140-159` | migrated | The name links to the detail page, which has Edit. |
| Row menu: Delete with confirm | `dashboard/pages/policies.templ:160-179` | migrated | Delete on `/policies/:id` (`policies.delete`). The list has no row actions. |
| Delete endpoint posted with no base path | `dashboard/pages/policies.templ:177` | bug fixed | See "Requests that ignored the base path" below. |
| Empty state "No policies found." | `dashboard/pages/policies.templ:80-81` | migrated | A message naming whatever filters are set. |
| Pagination | `dashboard/pages/policies.templ:189-191` | migrated | Table pagination. |

## Policy detail

Templ route `/policies/detail?id=...`, source `dashboard/pages/policy_detail.templ`.
React route `/policies/:id` (`pages/policy-detail.tsx`,
`components/policy-rule.tsx`), intent `policies.detail`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Heading with Effect and Active badges, description under it | `dashboard/pages/policy_detail.templ:20-38` | migrated | Page header with name and description. The rule block heads with Allow or Deny, and a state line says whether it is in effect, with Activate when inactive (`policies.setActive`). |
| Edit button | `dashboard/pages/policy_detail.templ:40-50` | migrated | Edit, to `/policies/:id/edit`. |
| Delete button and confirm | `dashboard/pages/policy_detail.templ:51-59`, `:232-240` | migrated | Delete with confirm (`policies.delete`). |
| Delete endpoint posted with no base path | `dashboard/pages/policy_detail.templ:238` | bug fixed | See "Requests that ignored the base path". |
| Details: ID | `dashboard/pages/policy_detail.templ:72-73` | migrated | Not printed. It is the `:id` in the URL. |
| Details: Effect, Priority, Version, Created, Updated | `dashboard/pages/policy_detail.templ:74-83` | migrated | Rule heading, Priority, Version, Created, Updated. |
| Scope card: Actions and Resources as badges, "All actions" / "All resources" when empty | `dashboard/pages/policy_detail.templ:89-131` | migrated | Rule rows `action` and `resource`, "any action" and "any resource" when unrestricted. |
| Subject Matches table, shown when there are subjects: Kind, ID, Role, "Any" for an empty part | `dashboard/pages/policy_detail.templ:133-185` | migrated | Rule row `subject`, one chip per matcher, "anyone" when unrestricted, and a note when a matcher is empty. |
| Conditions table, shown when there are conditions: Field, Operator badge, Value | `dashboard/pages/policy_detail.templ:187-227` | migrated | Rule rows `when` and `and`, the operator in words, with notes on conditions that cannot be evaluated or can never hold. |
| Plugin-contributed sections slot | `dashboard/pages/policy_detail.templ:229-230`; `dashboard/contributor.go:548-559` | dropped | No type implements `PolicyDetailContributor` (`dashboard/plugin_iface.go:51-53`), and the method name appears only inside `dashboard/`. |

## Policy create and edit form

Templ routes `/policies/create` and `/policies/edit?id=...`, source
`dashboard/pages/policy_form.templ`, a full page driven by Alpine. React: the
New policy dialog on `/policies`, then `/policies/:id/edit`
(`pages/policy-detail.tsx`, `components/policy-editor.tsx`), intents
`policies.create`, `policies.update`, `policies.validate`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Cancel and Create Policy / Save Changes buttons, "Saving..." while busy | `dashboard/pages/policy_form.templ:49-75` | migrated | The editor's save and cancel. |
| Error box from the server's `error` or `message` | `dashboard/pages/policy_form.templ:78-79` | migrated | Contract errors shown in the editor, and `policies.validate` diagnostics on the row they concern. |
| Name, required | `dashboard/pages/policy_form.templ:88-94` | migrated | Name (create dialog and editor). |
| Description | `dashboard/pages/policy_form.templ:95-101` | migrated | Description in the editor. |
| Effect select Allow / Deny | `dashboard/pages/policy_form.templ:103-113` | migrated | Effect in the create dialog and the editor. |
| Priority number | `dashboard/pages/policy_form.templ:114-120` | migrated | Priority, refused unless a whole number. |
| Active switch, on by default for a new policy | `dashboard/pages/policy_form.templ:122-128`, `:286` | migrated | A new policy is always stored inactive. Activate and Deactivate are on `/policies/:id` (`policies.setActive`). |
| Subjects: add rows of Kind (Any or one of four), ID, Role; remove a row; "No subject filters" when empty | `dashboard/pages/policy_form.templ:134-184` | migrated | Subject matchers in the editor (kind, id, role), with removal. |
| Actions and Resources as comma-separated text | `dashboard/pages/policy_form.templ:187-212` | migrated | Action and resource chip inputs. |
| Conditions: add rows of Field, Operator (17 operators, eq through regex), Value; remove a row; "No conditions" when empty | `dashboard/pages/policy_form.templ:215-274` | migrated | Condition rows, same operator set, each value typed to its operator (list, CIDR, time, number, pattern, none, text). |
| Edit form rewrote every condition value as a string | `dashboard/pages/policy_form.templ:351-360`, `:338` | bug fixed | `buildConditionsJSON` formatted each stored value with `%v` into a string, and the form sent it back as typed text, so saving a policy whose condition held a list wrote back a string like `[a b]`. The React editor sends arrays, numbers and strings as their own JSON types. |
| Create posted to `/v1/policies` with no base path | `dashboard/pages/policy_form.templ:303` | bug fixed | See "Requests that ignored the base path". |
| Edit posted to `/v1/policies/:id` with no base path | `dashboard/pages/policy_form.templ:340` | bug fixed | See "Requests that ignored the base path". |

## Relations

Templ route `/relations`, source `dashboard/pages/relations.templ`. React route
`/relations` (`pages/relations.tsx`), intent `relations.list`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "Relation Tuples", count, description | `dashboard/pages/relations.templ:20` | migrated | "Relations", caption "N relations", explanatory text. |
| Write Relation button | `dashboard/pages/relations.templ:21-28` | migrated | New relation dialog (`relations.create`). |
| Filters Object Type, Relation, Subject Type | `dashboard/pages/relations.templ:32-75` | migrated | Filter by tuple part: object type, object id, relation, subject type, subject id, subject relation. |
| Columns Object, Relation (badge), Subject with `#subjectRelation`, Tuple | `dashboard/pages/relations.templ:86-89`, `:97-113`, `:169-175` | migrated | One Tuple column, `object#relation@subject` with the userset suffix. |
| Column Created | `dashboard/pages/relations.templ:90`, `:114-117` | migrated | Created column. |
| Row menu Delete with confirm | `dashboard/pages/relations.templ:118-145` | bug fixed | The confirm button posted to `/v1/relations/delete` with no body (`dashboard/components/confirm_dialog.templ:54-60` sends no fields), and the API refuses a delete without all five tuple fields (`api/relation_handler.go:115-118`). No delete from this page ever succeeded. React deletes by id (`relations.delete`). |
| Empty state "No relation tuples found." | `dashboard/pages/relations.templ:80-81` | migrated | Empty message naming the filter as a tuple pattern. |
| Pagination | `dashboard/pages/relations.templ:154-156` | migrated | Table pagination. |
| `?create=1` | `dashboard/pages/relations.templ:161-165` | dropped | Nothing builds a URL with `create=1`. |

### Write relation dialog

Source `dashboard/pages/relation_form.templ`.

| Field | Templ source | Status | Where now |
|---|---|---|---|
| Object Type, Object ID, Relation, Subject Type, Subject ID, all required | `dashboard/pages/relation_form.templ:32-70` | migrated | Same five, all required. |
| Subject Relation (optional) | `dashboard/pages/relation_form.templ:71-77` | migrated | Subject relation (optional). |
| Live tuple preview | `dashboard/pages/relation_form.templ:78-82` | migrated | "Writes:" line with the tuple string. |

## Resource types

Templ route `/resource-types`, source `dashboard/pages/resource_types.templ`.
React route `/resource-types` (`pages/resource-types.tsx`), which opens on a
schema graph with a Table view beside it; intents `resourceTypes.list` and
`resourceTypes.graph`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header with count and description | `dashboard/pages/resource_types.templ:20` | migrated | "Resource types", caption in the Table view. |
| Create Resource Type button, to a full-page form | `dashboard/pages/resource_types.templ:21-30` | migrated | New resource type dialog (`resourceTypes.create`). |
| Search | `dashboard/pages/resource_types.templ:34-49` | migrated | Search by name, in the Table view. |
| Column Name, link to detail | `dashboard/pages/resource_types.templ:60`, `:71-80` | migrated | Name column and a Details link. |
| Column Description, "No description" when empty | `dashboard/pages/resource_types.templ:61`, `:81-87` | migrated | On `/resource-types/:id`. |
| Columns Relations and Permissions (counts) | `dashboard/pages/resource_types.templ:62-63`, `:88-97` | migrated | Relations and Permissions columns. |
| Column Created | `dashboard/pages/resource_types.templ:64`, `:98-101` | migrated | On `/resource-types/:id`. The list shows Updated. |
| Row menu View Details and Delete | `dashboard/pages/resource_types.templ:102-139` | migrated | Details link and Delete with confirm (`resourceTypes.delete`). |
| Delete endpoint posted with no base path | `dashboard/pages/resource_types.templ:137` | bug fixed | See "Requests that ignored the base path". |
| Empty state "No resource types found." | `dashboard/pages/resource_types.templ:54-55` | migrated | Filtered or "No resource types yet". |
| Pagination | `dashboard/pages/resource_types.templ:149-151` | migrated | Table pagination. |

## Resource type detail

Templ route `/resource-types/detail?id=...`, source
`dashboard/pages/resource_type_detail.templ`. Reached only from a row. React route
`/resource-types/:id` (`pages/resource-type-detail.tsx`), intent
`resourceTypes.detail`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Heading and description | `dashboard/pages/resource_type_detail.templ:19-25` | migrated | Page header, Description in the details list. |
| Delete button and confirm | `dashboard/pages/resource_type_detail.templ:26-36`, `:144-152` | migrated | Not on the detail page. Delete on the row at `/resource-types`. |
| Delete endpoint posted with no base path | `dashboard/pages/resource_type_detail.templ:150` | bug fixed | See "Requests that ignored the base path". |
| Details: ID, Name, Created, Updated | `dashboard/pages/resource_type_detail.templ:47-56` | migrated | Name in the header, Created and Updated in the list. The id is the `:id` in the URL. |
| Relations table: Name, Allowed Subjects badges; "No relations defined." | `dashboard/pages/resource_type_detail.templ:62-104` | migrated | Relation and Allowed subject types; "This type declares no relations." |
| Derived Permissions table: Name, Expression; "No permission rules defined." | `dashboard/pages/resource_type_detail.templ:106-142` | migrated | Permission and Expression; "This type declares no permissions." |

## Resource type create form

Templ route `/resource-types/create`, source
`dashboard/pages/resource_type_form.templ`, a full page driven by Alpine.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Cancel and Create Resource Type buttons, "Creating..." while busy; error box | `dashboard/pages/resource_type_form.templ:57-81` | migrated | The New resource type dialog's confirm, with errors in the dialog. |
| Name, required; Description | `dashboard/pages/resource_type_form.templ:90-103` | migrated | Name and Description in the dialog. The name cannot change later. |
| Relations rows: name and comma-separated allowed subjects, add and remove, "No relations defined yet." | `dashboard/pages/resource_type_form.templ:109-146` | migrated | Not at create time. Added with Edit on `/resource-types/:id` (`resourceTypes.update`). |
| Derived Permissions rows: name and expression, add and remove, "No derived permissions defined yet." | `dashboard/pages/resource_type_form.templ:149-186` | migrated | Not at create time. Added with Edit on `/resource-types/:id`, with expression diagnostics from the server. |
| Create posted to `/v1/resource-types` with no base path | `dashboard/pages/resource_type_form.templ:44` | bug fixed | See "Requests that ignored the base path". |

## Check logs

Templ route `/check-logs`, source `dashboard/pages/check_logs.templ`. React route
`/check-log` (singular) and `/check-log/:id` (`pages/check-log.tsx`,
`pages/check-log-detail.tsx`), intents `checkLogs.list` and `checkLogs.detail`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Header "Authorization Check Logs", count, description | `dashboard/pages/check_logs.templ:18-19` | migrated | "Check log", caption "N checks". |
| Subject kind filter | `dashboard/pages/check_logs.templ:23-37` | migrated | Subject kind select. |
| Subject ID, Action, Resource Type filters | `dashboard/pages/check_logs.templ:38-79` | migrated | Subject id, Action, Resource type, applied together with an Apply button. |
| Decision filter: All, Allow, Deny | `dashboard/pages/check_logs.templ:80-92` | migrated | Decision filter listing every decision `checkLogs.list` accepts, `deny_no_roles` and `error` among them. |
| `after` query parameter (no control on the page; reachable only by editing the URL) | `dashboard/data.go:224`; named in the `hx-include` lists, e.g. `dashboard/pages/check_logs.templ:30` | migrated | Time window select (last hour, 24 hours, 7 days, 30 days). |
| `before` query parameter (no control on the page) | `dashboard/data.go:225`; `dashboard/pages/check_logs.templ:30` | gap | `checkLogs.list` accepts `before`. The page sends only `after`. |
| Columns Subject, Action, Resource | `dashboard/pages/check_logs.templ:104-106`, `:117-125` | migrated | Same, Subject linking to `/subjects/:kind/:id`. |
| Column Decision: Allow, or Deny for every other value | `dashboard/pages/check_logs.templ:107`, `:126-128`, `:170-180` | migrated | Decision badge with the actual decision string. |
| Column Reason, `-` when empty | `dashboard/pages/check_logs.templ:108`, `:129-135` | migrated | Detail column: the error when there is one, else the reason. |
| Column Eval Time | `dashboard/pages/check_logs.templ:109`, `:136-138`, `:182-191` | migrated | On `/check-log/:id`. |
| Column IP | `dashboard/pages/check_logs.templ:110`, `:139-145` | migrated | Request IP on `/check-log/:id`. |
| Column Time | `dashboard/pages/check_logs.templ:111`, `:146-149` | migrated | When column, linking to `/check-log/:id`. |
| Empty state "No check logs found." | `dashboard/pages/check_logs.templ:98-99` | migrated | "No checks match these filters." or "No checks are in the log." |
| Pagination, 50 per page | `dashboard/pages/check_logs.templ:158-166`; `dashboard/contributor.go:447` | migrated | Table pagination, 25 per page. |

## Widgets

Forge's templ dashboard rendered these two from their descriptors, in
`dashboard/manifest.go:101-120` and again in `dashboard/forge.contributor.yaml:51-61`;
rendered by `dashboard/contributor.go:149-174`.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| `warden-stats` "Authz Stats", size md, refresh 60 s: six stat cards | `dashboard/widgets/stats.templ`; `dashboard/manifest.go:103-110` | migrated | The same six counts on warden's `/` (`overview.stats`, stale after 15 s). Warden contributes no widget to any other plugin's page. |
| `warden-recent-checks` "Recent Checks", size lg, refresh 15 s: Subject, Action, Resource, Decision, Time (HH:MM:SS); "No recent checks." | `dashboard/widgets/recent_checks.templ`; `dashboard/manifest.go:111-118` | migrated | The Recent checks table on `/` (`overview.recentChecks`, last 10, stale after 15 s). |
| Plugin-contributed widgets | `dashboard/contributor.go:157-164`; `dashboard/manifest.go:64-72` | dropped | No plugin implements `Plugin` (`dashboard/plugin_iface.go:34-41`); nothing outside `dashboard/` imports the package that declares it. |

## Settings

Descriptor `warden-config` in `dashboard/manifest.go:123-133` (titled
"Authorization Settings") and `dashboard/forge.contributor.yaml:63-68` (titled
"Warden Settings"). Panel `dashboard/settings/config.templ`, rendered by
`dashboard/contributor.go:486-498`.

The panel was a display. It had no form and no inputs at all: every value was
text in a definition list or a badge, and `dashboard/settings/config.templ:84` is
the "Disabled" label on a model badge. Warden's `Config` comes from Forge config,
not from a store, so there is nothing for a settings page to write to. React
shows the same values read-only on `/config` (`pages/config.tsx`, intent
`config.detail`), and says so on the page.

| Item | Templ source | Status | Where now |
|---|---|---|---|
| Max Graph Depth | `dashboard/settings/config.templ:26-27` | migrated | `/config`, Graph depth limit. |
| Cache TTL, shown when above 0 | `dashboard/settings/config.templ:28-31` | migrated | `/config`, Decision cache ("Off" when 0). |
| RBAC, ABAC, ReBAC Enabled / Disabled badges | `dashboard/settings/config.templ:34-47`, `:77-87` | migrated | `/config` model badges, "off" in red when disabled. |
| Enabled Plugins card: one badge per registered plugin name | `dashboard/settings/config.templ:50-71`; `dashboard/contributor.go:489-492` | blocked | Needs `config.detail` to return the registered plugin names. `ConfigDetail` (`extension/contract/handlers_config.go:19-35`) has no such field today. The names are available to the handler through `Engine.Plugins().Plugins()`. |
| Plugin-contributed settings slot | `dashboard/settings/config.templ:72-73`; `dashboard/contributor.go:524-533` | dropped | No plugin implements `DashboardSettingsPanel`; nothing outside `dashboard/` imports the package. |

## Nav

The templ dashboard declared its nav twice, and the two disagreed.
`dashboard/manifest.go:79-98` is what `NewManifest` returned: nine entries in four
groups. `dashboard/forge.contributor.yaml:9-49` listed eight entries in one group,
"Warden", with no Playground and different priorities.

| Templ entry (manifest.go) | Templ path | Status | React entry |
|---|---|---|---|
| Overview (group Warden) | `/` | migrated | Overview, group Overview, `/` |
| Playground (Warden) | `/playground` | migrated | Playground, group Operations, `/playground` |
| Roles (Access Control) | `/roles` | migrated | Roles, group Authorization |
| Permissions (Access Control) | `/permissions` | migrated | Permissions, group Authorization |
| Assignments (Access Control) | `/assignments` | migrated | Assignments, group Authorization |
| Policies (Policy & Relations) | `/policies` | migrated | Policies, group Authorization |
| Relations (Policy & Relations) | `/relations` | migrated | Relations, group Relationships |
| Resource Types (Policy & Relations) | `/resource-types` | migrated | Resource types, group Relationships |
| Check Logs (Monitoring) | `/check-logs` | migrated | Check log, group Operations, `/check-log` |
| Plugin nav items from `PageContributor` and `Plugin.DashboardPages` | `dashboard/manifest.go:42-62` | dropped | No plugin implements either interface. |

React also has Schema (`/schema`) and Config (`/config`) in its nav, which the
templ dashboard never had.

## Requests that ignored the base path

Warden's HTTP API is mounted under a base path (`/warden` by default). Most templ
forms prefixed it. These requests did not, so they only reached the API when it
happened to be mounted at the host's root. The spec named the first two; the
same defect was in seven more places. The React dashboard sends nothing to the
HTTP API: every one of these goes through a contract intent.

| Request | Templ source | Status | Where now |
|---|---|---|---|
| Create policy, `POST /v1/policies` | `dashboard/pages/policy_form.templ:303` | bug fixed | `policies.create` |
| Create resource type, `POST /v1/resource-types` | `dashboard/pages/resource_type_form.templ:44` | bug fixed | `resourceTypes.create` |
| Update policy, `PUT /v1/policies/:id` | `dashboard/pages/policy_form.templ:340` | bug fixed | `policies.update` |
| Delete policy from the list | `dashboard/pages/policies.templ:177` | bug fixed | `policies.delete` |
| Delete policy from its detail page | `dashboard/pages/policy_detail.templ:238` | bug fixed | `policies.delete` |
| Delete resource type from the list | `dashboard/pages/resource_types.templ:137` | bug fixed | `resourceTypes.delete` |
| Delete resource type from its detail page | `dashboard/pages/resource_type_detail.templ:150` | bug fixed | `resourceTypes.delete` |
| Attach permission to role | `dashboard/pages/role_permissions.templ:25` | bug fixed | `roles.attachPermission` |
| Detach permission from role | `dashboard/pages/role_permissions.templ:64` | bug fixed | `roles.detachPermission` |

## Shared infrastructure

None of this has a page of its own. Each line says what replaced it.

| File | What it did | Status | Replaced by |
|---|---|---|---|
| `dashboard/contributor.go` | Forge templ `LocalContributor`: dispatched page routes (`/roles/detail?id=`, `/policies/create`, and so on), widgets and settings; resolved the tenant from the request context; rendered "Select a tenant" with no tenant in scope; wrapped pages in the path rewriter. | migrated | The contract (`extension/contract/contract.go`) registers intents, the React plugin (`src/index.tsx`) declares routes with path parameters (`/roles/:id`, `/policies/:id/edit`). The tenant comes from the principal or `Deps.DefaultTenantID`, and a request with none is refused with "no tenant in scope", which the page shows as an error. |
| `dashboard/contributor_test.go` | Asserted that forms and delete dialogs posted under the configured base path. | migrated | Nothing posts to the HTTP API any more. The contract's own tests live beside it in `extension/contract/`. |
| `dashboard/data.go` | Store reads: paged lists (default 20, check logs 50, clamp 500), dropdown option reads capped at 500, entity counts, role row enrichment. | migrated | Contract handlers. Paging is offset based with a default of 25 and a cap of 200 (`extension/contract/paging.go`). React pickers read up to 200, and the role page's attach and replace pickers say when that cuts the list short. |
| `dashboard/data_test.go` | Tested the dropdown caps and the limit clamp. | migrated | `extension/contract/paging_test.go`. |
| `dashboard/manifest.go` | Contributor manifest: name, icon `shield-check`, version 0.1.0, extension layout, sidebar, topbar (title, accent `#f59e0b`, search on), nav, widgets, settings, plus plugin merging. | migrated | The `contributor.app` block in `extension/contract/manifest.yaml` (display name, slug, icon, priority, home) and `definePlugin` in the React plugin. Nav, widgets and settings are covered in their own sections above. |
| Topbar "API Docs" action and sidebar footer link, both to `/docs` | `dashboard/manifest.go:29-33`; `dashboard/components/footer_links.templ` | dropped | The href was a fixed `/docs` on the host root. Warden registers no `/docs` route, so whether it went anywhere depended on the host app. |
| `searchable` capability and topbar search | `dashboard/manifest.go:28`, `:37-39`; `dashboard/forge.contributor.yaml:70` | dropped | It was a flag for Forge's templ dashboard. Neither `extension/contract/manifest.yaml` nor the React plugin declares anything for a shell search to use. |
| `dashboard/forge.contributor.yaml` | A second, out-of-date copy of the manifest (`type: templ`, eight nav entries, widgets, settings). | dropped | Superseded by `extension/contract/manifest.yaml`. Its nav disagreed with `manifest.go` (see Nav). |
| `dashboard/plugin_iface.go` | `Plugin`, `RoleDetailContributor`, `PolicyDetailContributor`, `PageContributor` interfaces, and `WithTenantID` / `TenantIDFromContext`. | dropped | Nothing implements the four interfaces, and nothing outside `dashboard/` calls the two tenant helpers. React sub-plugins use the shell's slot API (`overview.widgets` and others in forge-dashboard `packages/plugin/src/types.ts`) if one is ever needed. |
| `dashboard/components/confirm_dialog.templ` | Reusable confirm dialog that sent an HTMX DELETE or POST and reloaded the page. | migrated | `ConfirmDialog` from `@forge-go/dashboard-kit`, with the command's error shown inside the dialog. |
| `dashboard/components/dialog_helpers.templ` | `tuiOpenDialog` / `tuiCloseDialog` scripts, Escape and backdrop handling. | migrated | The kit's dialog components. |
| `dashboard/components/empty_state.templ` | Centered icon, title and description, used for "Select a tenant". | migrated | `ResourceTable`'s `emptyMessage` and `QueryBoundary` error states. |
| `dashboard/components/page_header.templ` | Title, count badge, description, actions slot. | migrated | Kit `PageHeader`; counts moved to table captions. |
| `dashboard/components/pagination_meta.go` | Page math (total pages, current page) from total, limit, offset. | migrated | Kit `ResourceTable` pagination from the contract's `total`, `limit`, `offset`. |
| `dashboard/components/path_rewriter.templ` | HTMX `configRequest` hook that rewrote bare page paths to `/ext/warden/pages/...` and skipped `/v1/` API paths. | migrated | `PluginLink`, which resolves scope-relative paths in the shell. It left any path starting with `/v1/` alone, so it never added the missing base path to the requests listed under "Requests that ignored the base path". |
| `dashboard/components/plugin_sections.templ` | Rendered plugin sections separated by rules. | dropped | Only ever fed by the plugin interfaces nobody implements. |
| `dashboard/components/stat_card.templ` | Icon, label, value, subtitle card. | migrated | Kit `StatGrid`. |
| `dashboard/pages/helpers.templ` | Small `emptyState` and the icon set it used. | migrated | `ResourceTable` empty messages. |
| `dashboard/pages/form_helpers.go` | `htmxFormAttrs`: JSON-encoded HTMX form that closed its dialog and reloaded on success. | migrated | `useCommand` in each form; the contract's `invalidates` lists refresh the affected queries. |
| `dashboard/pages/role_view.go` | `RoleRow` view model (permission count, parent name and id, relation count) and `extractRoles`. | migrated | `RoleSummary` and `RoleDetail` from `roles.list` and `roles.detail`. See the Roles section for each field. |

## Gaps and blocked items

Blocked, one item. You cannot get this from the React dashboard until the
contract grows a field:

- Enabled Plugins list on the settings panel, `dashboard/settings/config.templ:50-71`. Needs `config.detail` to return the registered plugin names.

Gaps, nine items. The contract already serves each of these and the React page
does not ask for it yet:

- Role created time, nowhere in React: `dashboard/pages/roles.templ:58` (list column), `dashboard/pages/role_detail.templ:85-86` (detail), `dashboard/pages/role_detail.templ:182` (child roles). `roles.list` and `roles.detail` return `createdAt`.
- Permission resource filter, `dashboard/pages/permissions.templ:47-60`. `permissions.list` takes `resource`.
- Permission action filter, `dashboard/pages/permissions.templ:61-74`. `permissions.list` takes `action`.
- Assignment subject kind filter, `dashboard/pages/assignments.templ:35-49`. `assignments.list` takes `subjectKind`.
- Assignment subject id filter, `dashboard/pages/assignments.templ:50-63`. `assignments.list` takes `subjectId`.
- Assignment role filter, `dashboard/pages/assignments.templ:64-77`. `assignments.list` takes `roleId`.
- Assignment Granted By column, `dashboard/pages/assignments.templ:93`. `assignments.list` returns `grantedBy`.
- Assignment Created column, `dashboard/pages/assignments.templ:94`. `assignments.list` returns `createdAt`.
- Check log upper time bound, `dashboard/data.go:225` (the templ page had no control for it; `dashboard/pages/check_logs.templ:30` names a `before` field that does not exist). `checkLogs.list` takes `before`.
