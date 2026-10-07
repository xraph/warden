// Package keysmithbridge lets Keysmith's warden_hook extension drive Warden.
//
// Keysmith defines a small WardenBridge interface of its own so that it never
// imports Warden. Bridge is the Warden side of that seam: it has the same three
// methods, so you can hand one straight to the hook:
//
//	eng, _ := warden.NewEngine(warden.WithStore(st))
//	hook := wardenhook.New(keysmithbridge.New(eng))
//
// Neither module imports the other. The match is structural, and the test in
// this package keeps it honest.
//
// Every method needs a tenant. In Warden an empty tenant in a filter matches
// every tenant, so the bridge refuses one instead of letting a key event touch
// rows it does not own. Everything the bridge reads or writes lives in the
// tenant's root namespace.
//
// The role a key is given must already exist. The bridge does not create
// roles, because choosing what a role may do is an administrator's decision.
// Create the role (Keysmith's hook defaults to the slug "api-key") and attach
// the permissions it should grant. SyncScopesToPermissions only makes sure the
// permissions named by a key's scopes exist; it never attaches them to a role.
//
// # Scope names to permissions
//
// Keysmith writes a scope action first: "read:users" is a child of "read" in
// Keysmith's own scope tree. Warden names a permission the other way round,
// because its evaluator matches a check against Resource + ":" + Action and
// every permission Warden writes itself is named that way. The bridge reads
// the scope Keysmith's way and names the permission Warden's way:
//
//   - "read:users" becomes name "users:read", resource "users", action
//     "read". A check for action "read" on resource type "users" then finds it.
//   - The split is at the first colon, and the resource is everything after
//     it. So "read:users:profile" becomes name "users:profile:read", resource
//     "users:profile", action "read".
//   - A scope with no colon, such as "read" or "admin", is skipped. It names
//     an action on every resource, and Warden can only say that with a
//     wildcard, which the bridge never creates. There is no error, and the
//     rest of the list still syncs. If a key should hold that much, put a
//     wildcard on its role yourself.
//   - A scope with an empty side (":users", "read:") or a "*" anywhere in it
//     is refused with an error. The bridge never creates a wildcard
//     permission, because one grant would then cover every matching check. If
//     a key should hold a broad grant, give its role a wildcard on purpose.
//
// An existing permission with the same name is left exactly as it is.
//
// # Caches and hooks
//
// Each assignment write drops the key's cached decisions through
// Engine.InvalidateSubject, so a new or revoked key takes effect at once.
// The bridge also emits the same plugin events the REST API does (role
// assigned and unassigned, permission created, and the audit event), so audit
// plugins see keysmith-driven changes.
package keysmithbridge
