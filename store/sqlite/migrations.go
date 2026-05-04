package sqlite

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Warden store (SQLite).
var Migrations = migrate.NewGroup("warden")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_roles",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_roles (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 0,
    is_default      INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    max_members     INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_warden_roles_tenant ON warden_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_parent ON warden_roles (parent_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_system ON warden_roles (tenant_id, is_system);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_roles`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_permissions",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_permissions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    resource        TEXT NOT NULL,
    action          TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_permissions_tenant ON warden_permissions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_permissions_resource ON warden_permissions (tenant_id, resource, action);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_permissions`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_role_permissions",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_role_permissions (
    role_id         TEXT NOT NULL REFERENCES warden_roles(id) ON DELETE CASCADE,
    permission_id   TEXT NOT NULL REFERENCES warden_permissions(id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS idx_warden_role_perms_role ON warden_role_permissions (role_id);
CREATE INDEX IF NOT EXISTS idx_warden_role_perms_perm ON warden_role_permissions (permission_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_role_permissions`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_assignments",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    role_id         TEXT NOT NULL REFERENCES warden_roles(id) ON DELETE CASCADE,
    subject_kind    TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    resource_type   TEXT NOT NULL DEFAULT '',
    resource_id     TEXT NOT NULL DEFAULT '',
    expires_at      TEXT,
    granted_by      TEXT NOT NULL DEFAULT '',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, role_id, subject_kind, subject_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_warden_assign_tenant ON warden_assignments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_subject ON warden_assignments (tenant_id, subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_role ON warden_assignments (role_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_resource ON warden_assignments (tenant_id, subject_kind, subject_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_expires ON warden_assignments (expires_at);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_assignments`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_relations",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_relations (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    app_id            TEXT NOT NULL DEFAULT '',
    object_type       TEXT NOT NULL,
    object_id         TEXT NOT NULL,
    relation          TEXT NOT NULL,
    subject_type      TEXT NOT NULL,
    subject_id        TEXT NOT NULL,
    subject_relation  TEXT NOT NULL DEFAULT '',
    metadata          TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
);

CREATE INDEX IF NOT EXISTS idx_warden_rel_object ON warden_relations (tenant_id, object_type, object_id, relation);
CREATE INDEX IF NOT EXISTS idx_warden_rel_subject ON warden_relations (tenant_id, subject_type, subject_id, relation);
CREATE INDEX IF NOT EXISTS idx_warden_rel_check ON warden_relations (tenant_id, object_type, object_id, relation, subject_type, subject_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_relations`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_policies",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_policies (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    effect          TEXT NOT NULL DEFAULT 'allow',
    priority        INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    version         INTEGER NOT NULL DEFAULT 1,
    subjects        TEXT NOT NULL DEFAULT '[]',
    actions         TEXT NOT NULL DEFAULT '[]',
    resources       TEXT NOT NULL DEFAULT '[]',
    conditions      TEXT NOT NULL DEFAULT '[]',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_policies_tenant ON warden_policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_policies_active ON warden_policies (tenant_id, is_active, priority);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_policies`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_resource_types",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_resource_types (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    relations       TEXT NOT NULL DEFAULT '[]',
    permissions     TEXT NOT NULL DEFAULT '[]',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_rtypes_tenant ON warden_resource_types (tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_resource_types`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "namespaces",
			Version: "20260101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_roles          ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_permissions    ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_policies       ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_resource_types ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_assignments    ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_relations      ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_check_logs     ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_warden_roles_ns         ON warden_roles         (tenant_id, namespace_path);
CREATE INDEX IF NOT EXISTS idx_warden_perms_ns         ON warden_permissions   (tenant_id, namespace_path);
CREATE INDEX IF NOT EXISTS idx_warden_policies_ns      ON warden_policies      (tenant_id, namespace_path);
CREATE INDEX IF NOT EXISTS idx_warden_rtypes_ns        ON warden_resource_types(tenant_id, namespace_path);
CREATE INDEX IF NOT EXISTS idx_warden_assign_ns        ON warden_assignments   (tenant_id, namespace_path, subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS idx_warden_rel_ns           ON warden_relations     (tenant_id, namespace_path, object_type, object_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				// SQLite cannot drop columns easily; for the down path we just drop the indexes.
				// Full down would require table-recreate per entity — intentionally skipped.
				_, err := exec.Exec(ctx, `
DROP INDEX IF EXISTS idx_warden_roles_ns;
DROP INDEX IF EXISTS idx_warden_perms_ns;
DROP INDEX IF EXISTS idx_warden_policies_ns;
DROP INDEX IF EXISTS idx_warden_rtypes_ns;
DROP INDEX IF EXISTS idx_warden_assign_ns;
DROP INDEX IF EXISTS idx_warden_rel_ns;
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "role_parent_slug",
			Version: "20260101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				// SQLite cannot drop columns or change FK constraints in place,
				// so recreate the table with the new schema.
				_, err := exec.Exec(ctx, `
CREATE TABLE warden_roles_new (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 0,
    is_default      INTEGER NOT NULL DEFAULT 0,
    parent_slug     TEXT,
    max_members     INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, slug),
    FOREIGN KEY (tenant_id, parent_slug) REFERENCES warden_roles_new(tenant_id, slug) ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO warden_roles_new (
    id, tenant_id, app_id, name, description, slug, is_system, is_default,
    parent_slug, max_members, metadata, created_at, updated_at
)
SELECT
    c.id, c.tenant_id, c.app_id, c.name, c.description, c.slug, c.is_system, c.is_default,
    (SELECT p.slug FROM warden_roles p WHERE p.id = c.parent_id AND p.tenant_id = c.tenant_id),
    c.max_members, c.metadata, c.created_at, c.updated_at
FROM warden_roles c;

DROP INDEX IF EXISTS idx_warden_roles_tenant;
DROP INDEX IF EXISTS idx_warden_roles_parent;
DROP INDEX IF EXISTS idx_warden_roles_system;
DROP TABLE warden_roles;
ALTER TABLE warden_roles_new RENAME TO warden_roles;

CREATE INDEX IF NOT EXISTS idx_warden_roles_tenant ON warden_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_parent_slug ON warden_roles (tenant_id, parent_slug) WHERE parent_slug IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_warden_roles_system ON warden_roles (tenant_id, is_system);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE warden_roles_old (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    slug            TEXT NOT NULL,
    is_system       INTEGER NOT NULL DEFAULT 0,
    is_default      INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    max_members     INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(tenant_id, slug)
);

INSERT INTO warden_roles_old (
    id, tenant_id, app_id, name, description, slug, is_system, is_default,
    parent_id, max_members, metadata, created_at, updated_at
)
SELECT
    c.id, c.tenant_id, c.app_id, c.name, c.description, c.slug, c.is_system, c.is_default,
    (SELECT p.id FROM warden_roles p WHERE p.slug = c.parent_slug AND p.tenant_id = c.tenant_id),
    c.max_members, c.metadata, c.created_at, c.updated_at
FROM warden_roles c;

DROP INDEX IF EXISTS idx_warden_roles_tenant;
DROP INDEX IF EXISTS idx_warden_roles_parent_slug;
DROP INDEX IF EXISTS idx_warden_roles_system;
DROP TABLE warden_roles;
ALTER TABLE warden_roles_old RENAME TO warden_roles;

CREATE INDEX IF NOT EXISTS idx_warden_roles_tenant ON warden_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_parent ON warden_roles (parent_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_system ON warden_roles (tenant_id, is_system);
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_check_logs",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS warden_check_logs (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    app_id          TEXT NOT NULL DEFAULT '',
    subject_kind    TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    eval_time_ns    INTEGER NOT NULL DEFAULT 0,
    request_ip      TEXT NOT NULL DEFAULT '',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_warden_clogs_tenant ON warden_check_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_clogs_subject ON warden_check_logs (tenant_id, subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS idx_warden_clogs_resource ON warden_check_logs (tenant_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_warden_clogs_decision ON warden_check_logs (tenant_id, decision);
CREATE INDEX IF NOT EXISTS idx_warden_clogs_created ON warden_check_logs (created_at);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_check_logs`)
				return err
			},
		},
	)
}
