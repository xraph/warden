// Package mongo provides a MongoDB Store implementation for the Warden store.
//
// # Transactions
//
// SetRolePermissions and AttachPermission touch more than one document (the
// junction rows, and — for AttachPermission — a role-existence check ahead
// of the write) and use a session transaction when the server supports one.
// Multi-document transactions require a replica set or sharded cluster; a
// standalone mongod — notably the default single-node container the test
// harness starts when WARDEN_TEST_MONGO_URI is unset — rejects them. Both
// methods detect this (by probing session.StartTransaction) and fall back
// to running the same writes sequentially, without atomicity. Point-in-time
// callers that need the transactional guarantee should run against a
// replica set (a single-node replica set is enough) or set
// WARDEN_TEST_MONGO_URI / the production connection string accordingly.
package mongo
