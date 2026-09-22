// Package sqlite provides a SQLite Store implementation for embedded/edge use.
//
// # Busy timeout
//
// SQLite is single-writer: a second connection that tries to write while
// another holds the lock fails immediately with SQLITE_BUSY unless a
// busy_timeout is configured, in which case it retries for that long before
// giving up. busy_timeout is a per-connection setting, and grove's sqlite
// driver opens a pool of connections (default size 10), so setting it after
// the pool exists — as Store's WithBusyTimeout option does — only reaches
// whichever connection that call happens to land on.
//
// For a setting that reliably reaches every connection the pool ever opens,
// set it in the DSN instead, using modernc.org/sqlite's _pragma query
// parameter, which is applied at connection-open time:
//
//	file:warden.db?_pragma=busy_timeout(5000)
//
// Combine with other pragmas by repeating the parameter:
//
//	file:warden.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)
package sqlite
