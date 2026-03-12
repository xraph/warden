package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Warden mongo store.
var Migrations = migrate.NewGroup("warden")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_warden_roles",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*roleModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colRoles, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "slug", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "parent_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "is_system", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*roleModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_permissions",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*permissionModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colPermissions, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "resource", Value: 1}, {Key: "action", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*permissionModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_role_permissions",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*rolePermissionModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colRolePermissions, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "role_id", Value: 1}, {Key: "permission_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "role_id", Value: 1}}},
					{Keys: bson.D{{Key: "permission_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*rolePermissionModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_assignments",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*assignmentModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colAssignments, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "role_id", Value: 1}, {Key: "subject_kind", Value: 1}, {Key: "subject_id", Value: 1}, {Key: "resource_type", Value: 1}, {Key: "resource_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_kind", Value: 1}, {Key: "subject_id", Value: 1}}},
					{Keys: bson.D{{Key: "role_id", Value: 1}}},
					{Keys: bson.D{{Key: "expires_at", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*assignmentModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_relations",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*relationModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colRelations, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "object_type", Value: 1}, {Key: "object_id", Value: 1}, {Key: "relation", Value: 1}, {Key: "subject_type", Value: 1}, {Key: "subject_id", Value: 1}, {Key: "subject_relation", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "object_type", Value: 1}, {Key: "object_id", Value: 1}, {Key: "relation", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_type", Value: 1}, {Key: "subject_id", Value: 1}, {Key: "relation", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*relationModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_policies",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*policyModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colPolicies, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "is_active", Value: 1}, {Key: "priority", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*policyModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_resource_types",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*resourceTypeModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colResourceTypes, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*resourceTypeModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_warden_check_logs",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*checkLogModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colCheckLogs, []mongo.IndexModel{
					{Keys: bson.D{{Key: "tenant_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "subject_kind", Value: 1}, {Key: "subject_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "resource_type", Value: 1}, {Key: "resource_id", Value: 1}}},
					{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "decision", Value: 1}}},
					{Keys: bson.D{{Key: "created_at", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*checkLogModel)(nil))
			},
		},
	)
}
