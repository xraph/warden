package postgres

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Warden store.
// It can be registered with the grove extension for orchestrated migration
// management (locking, version tracking, rollback support).
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
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,
    parent_id       TEXT,
    max_members     INT NOT NULL DEFAULT 0,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_warden_roles_tenant ON warden_roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_parent ON warden_roles (parent_id);
CREATE INDEX IF NOT EXISTS idx_warden_roles_system ON warden_roles (tenant_id, is_system);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_roles CASCADE`)
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
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_permissions_tenant ON warden_permissions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_permissions_resource ON warden_permissions (tenant_id, resource, action);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_permissions CASCADE`)
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
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_role_permissions CASCADE`)
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
    expires_at      TIMESTAMPTZ,
    granted_by      TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, role_id, subject_kind, subject_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_warden_assign_tenant ON warden_assignments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_subject ON warden_assignments (tenant_id, subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_role ON warden_assignments (role_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_resource ON warden_assignments (tenant_id, subject_kind, subject_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_warden_assign_expires ON warden_assignments (expires_at) WHERE expires_at IS NOT NULL;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_assignments CASCADE`)
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
    metadata          JSONB NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
);

CREATE INDEX IF NOT EXISTS idx_warden_rel_object ON warden_relations (tenant_id, object_type, object_id, relation);
CREATE INDEX IF NOT EXISTS idx_warden_rel_subject ON warden_relations (tenant_id, subject_type, subject_id, relation);
CREATE INDEX IF NOT EXISTS idx_warden_rel_check ON warden_relations (tenant_id, object_type, object_id, relation, subject_type, subject_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_relations CASCADE`)
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
    priority        INT NOT NULL DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    version         INT NOT NULL DEFAULT 1,
    subjects        JSONB NOT NULL DEFAULT '[]',
    actions         JSONB NOT NULL DEFAULT '[]',
    resources       JSONB NOT NULL DEFAULT '[]',
    conditions      JSONB NOT NULL DEFAULT '[]',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_policies_tenant ON warden_policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_warden_policies_active ON warden_policies (tenant_id, is_active, priority);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_policies CASCADE`)
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
    relations       JSONB NOT NULL DEFAULT '[]',
    permissions     JSONB NOT NULL DEFAULT '[]',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_warden_rtypes_tenant ON warden_resource_types (tenant_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_resource_types CASCADE`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "role_permissions_natural_key",
			Version: "20260101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_role_permissions
    ADD COLUMN perm_namespace_path TEXT,
    ADD COLUMN perm_name           TEXT;

UPDATE warden_role_permissions rp
SET perm_namespace_path = p.namespace_path,
    perm_name           = p.name
FROM warden_permissions p
WHERE rp.permission_id = p.id;

ALTER TABLE warden_role_permissions
    ALTER COLUMN perm_namespace_path SET NOT NULL,
    ALTER COLUMN perm_name           SET NOT NULL;

ALTER TABLE warden_role_permissions DROP CONSTRAINT warden_role_permissions_pkey;
ALTER TABLE warden_role_permissions DROP COLUMN permission_id;

ALTER TABLE warden_role_permissions
    ADD PRIMARY KEY (role_id, perm_namespace_path, perm_name);

DROP INDEX IF EXISTS idx_warden_role_perms_perm;
CREATE INDEX idx_warden_role_perms_perm
    ON warden_role_permissions (perm_namespace_path, perm_name);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_role_permissions ADD COLUMN permission_id TEXT;

UPDATE warden_role_permissions rp
SET permission_id = p.id
FROM warden_roles r
JOIN warden_permissions p
  ON p.tenant_id = r.tenant_id
 AND p.namespace_path = rp.perm_namespace_path
 AND p.name = rp.perm_name
WHERE rp.role_id = r.id;

ALTER TABLE warden_role_permissions ALTER COLUMN permission_id SET NOT NULL;

ALTER TABLE warden_role_permissions DROP CONSTRAINT warden_role_permissions_pkey;
ALTER TABLE warden_role_permissions
    DROP COLUMN perm_namespace_path,
    DROP COLUMN perm_name;
ALTER TABLE warden_role_permissions ADD PRIMARY KEY (role_id, permission_id);

DROP INDEX IF EXISTS idx_warden_role_perms_perm;
CREATE INDEX idx_warden_role_perms_perm ON warden_role_permissions (permission_id);
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "namespaces",
			Version: "20260101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_roles            ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_permissions      ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_policies         ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_resource_types   ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_assignments      ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_relations        ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';
ALTER TABLE warden_check_logs       ADD COLUMN namespace_path TEXT NOT NULL DEFAULT '';

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
				_, err := exec.Exec(ctx, `
DROP INDEX IF EXISTS idx_warden_roles_ns;
DROP INDEX IF EXISTS idx_warden_perms_ns;
DROP INDEX IF EXISTS idx_warden_policies_ns;
DROP INDEX IF EXISTS idx_warden_rtypes_ns;
DROP INDEX IF EXISTS idx_warden_assign_ns;
DROP INDEX IF EXISTS idx_warden_rel_ns;

ALTER TABLE warden_roles            DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_permissions      DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_policies         DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_resource_types   DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_assignments      DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_relations        DROP COLUMN IF EXISTS namespace_path;
ALTER TABLE warden_check_logs       DROP COLUMN IF EXISTS namespace_path;
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "role_parent_slug",
			Version: "20260101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_roles ADD COLUMN parent_slug TEXT;

UPDATE warden_roles c
SET parent_slug = p.slug
FROM warden_roles p
WHERE c.parent_id = p.id AND c.tenant_id = p.tenant_id;

ALTER TABLE warden_roles DROP COLUMN parent_id;

ALTER TABLE warden_roles
    ADD CONSTRAINT warden_roles_parent_fk
    FOREIGN KEY (tenant_id, parent_slug)
    REFERENCES warden_roles(tenant_id, slug)
    ON DELETE SET NULL
    ON UPDATE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

DROP INDEX IF EXISTS idx_warden_roles_parent;
CREATE INDEX IF NOT EXISTS idx_warden_roles_parent_slug ON warden_roles (tenant_id, parent_slug)
    WHERE parent_slug IS NOT NULL;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_roles DROP CONSTRAINT IF EXISTS warden_roles_parent_fk;
DROP INDEX IF EXISTS idx_warden_roles_parent_slug;

ALTER TABLE warden_roles ADD COLUMN parent_id TEXT;

UPDATE warden_roles c
SET parent_id = p.id
FROM warden_roles p
WHERE c.parent_slug = p.slug AND c.tenant_id = p.tenant_id;

ALTER TABLE warden_roles DROP COLUMN parent_slug;

CREATE INDEX IF NOT EXISTS idx_warden_roles_parent ON warden_roles (parent_id);
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "policy_pbac",
			Version: "20260101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_policies
    ADD COLUMN not_before  TIMESTAMPTZ,
    ADD COLUMN not_after   TIMESTAMPTZ,
    ADD COLUMN obligations JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_warden_policies_window
    ON warden_policies (tenant_id, namespace_path)
    WHERE not_before IS NOT NULL OR not_after IS NOT NULL;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
DROP INDEX IF EXISTS idx_warden_policies_window;

ALTER TABLE warden_policies
    DROP COLUMN IF EXISTS not_before,
    DROP COLUMN IF EXISTS not_after,
    DROP COLUMN IF EXISTS obligations;
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
    eval_time_ns    BIGINT NOT NULL DEFAULT 0,
    request_ip      TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS warden_check_logs CASCADE`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "namespace_scoped_uniqueness",
			Version: "20260201000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
-- warden_roles: drop (tenant_id, slug); add (tenant_id, namespace_path, slug).
-- The old constraint was created without an explicit name, so its auto-name
-- follows Postgres's default <table>_<col>_..._<col>_key pattern.
--
-- The role_parent_slug migration (20260101000001) added a self-referencing
-- FK that targets the old (tenant_id, slug) unique. We drop the FK, swap
-- the unique constraint, then re-add the FK widened with namespace_path
-- (parent must live in the same namespace as the child — cross-namespace
-- inheritance isn't supported).
ALTER TABLE warden_roles
    DROP CONSTRAINT IF EXISTS warden_roles_parent_fk;

ALTER TABLE warden_roles
    DROP CONSTRAINT IF EXISTS warden_roles_tenant_id_slug_key;
ALTER TABLE warden_roles
    ADD CONSTRAINT warden_roles_scope_slug_key
    UNIQUE (tenant_id, namespace_path, slug);

ALTER TABLE warden_roles
    ADD CONSTRAINT warden_roles_parent_fk
    FOREIGN KEY (tenant_id, namespace_path, parent_slug)
    REFERENCES warden_roles(tenant_id, namespace_path, slug)
    ON DELETE SET NULL
    ON UPDATE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- warden_permissions: drop (tenant_id, name); add (tenant_id, namespace_path, name).
ALTER TABLE warden_permissions
    DROP CONSTRAINT IF EXISTS warden_permissions_tenant_id_name_key;
ALTER TABLE warden_permissions
    ADD CONSTRAINT warden_permissions_scope_name_key
    UNIQUE (tenant_id, namespace_path, name);

-- warden_policies: drop (tenant_id, name); add (tenant_id, namespace_path, name).
ALTER TABLE warden_policies
    DROP CONSTRAINT IF EXISTS warden_policies_tenant_id_name_key;
ALTER TABLE warden_policies
    ADD CONSTRAINT warden_policies_scope_name_key
    UNIQUE (tenant_id, namespace_path, name);

-- warden_resource_types: drop (tenant_id, name); add (tenant_id, namespace_path, name).
ALTER TABLE warden_resource_types
    DROP CONSTRAINT IF EXISTS warden_resource_types_tenant_id_name_key;
ALTER TABLE warden_resource_types
    ADD CONSTRAINT warden_resource_types_scope_name_key
    UNIQUE (tenant_id, namespace_path, name);

-- warden_assignments: drop the old (tenant_id, role_id, subject_kind, subject_id,
-- resource_type, resource_id) key; add namespace_path to it. Postgres truncates
-- auto-names to 63 bytes, hence the slightly cropped default name on the DROP.
ALTER TABLE warden_assignments
    DROP CONSTRAINT IF EXISTS warden_assignments_tenant_id_role_id_subject_kind_subject_i_key;
ALTER TABLE warden_assignments
    ADD CONSTRAINT warden_assignments_scope_key
    UNIQUE (tenant_id, namespace_path, role_id, subject_kind, subject_id, resource_type, resource_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE warden_roles            DROP CONSTRAINT IF EXISTS warden_roles_parent_fk;
ALTER TABLE warden_roles            DROP CONSTRAINT IF EXISTS warden_roles_scope_slug_key;
ALTER TABLE warden_roles            ADD  CONSTRAINT warden_roles_tenant_id_slug_key UNIQUE (tenant_id, slug);
ALTER TABLE warden_roles
    ADD CONSTRAINT warden_roles_parent_fk
    FOREIGN KEY (tenant_id, parent_slug)
    REFERENCES warden_roles(tenant_id, slug)
    ON DELETE SET NULL
    ON UPDATE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE warden_permissions      DROP CONSTRAINT IF EXISTS warden_permissions_scope_name_key;
ALTER TABLE warden_permissions      ADD  CONSTRAINT warden_permissions_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE warden_policies         DROP CONSTRAINT IF EXISTS warden_policies_scope_name_key;
ALTER TABLE warden_policies         ADD  CONSTRAINT warden_policies_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE warden_resource_types   DROP CONSTRAINT IF EXISTS warden_resource_types_scope_name_key;
ALTER TABLE warden_resource_types   ADD  CONSTRAINT warden_resource_types_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE warden_assignments      DROP CONSTRAINT IF EXISTS warden_assignments_scope_key;
ALTER TABLE warden_assignments      ADD  CONSTRAINT warden_assignments_tenant_id_role_id_subject_kind_subject_i_key
    UNIQUE (tenant_id, role_id, subject_kind, subject_id, resource_type, resource_id);
`)
				return err
			},
		},
	)
}
