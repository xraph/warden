// Package mongo provides a MongoDB Store implementation for the Warden store.
//
// # Transactions
//
// SetRolePermissions and AttachPermission touch more than one document (the
// junction rows, and, for AttachPermission, a role-existence check ahead
// of the write) and use a session transaction when the server supports one.
// Multi-document transactions require a replica set or sharded cluster; a
// standalone mongod (notably the default single-node container the test
// harness starts when WARDEN_TEST_MONGO_URI is unset) rejects them. Both
// methods detect this via a one-time, cached `hello` command (checking for
// "setName" or a mongos "isdbgrid" response) rather than by probing
// session.StartTransaction/AbortTransaction: those are local, lazy
// client-side calls in the v2 driver that never touch the wire until the
// first real command inside the transaction, so they can't actually detect
// a standalone deployment. They only defer the failure to the first live
// write. When the deployment doesn't support transactions, the same writes
// run sequentially against the plain (session-less) context instead, without
// atomicity. Callers that need the transactional guarantee should run
// against a replica set (a single-node replica set is enough) or set
// WARDEN_TEST_MONGO_URI / the production connection string accordingly.
package mongo
