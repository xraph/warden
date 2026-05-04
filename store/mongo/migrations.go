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
			Name:    "namespaces",
			Version: "20260101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				db := mexec.DB().Database()

				// Initialize namespace_path = "" on every doc that doesn't have it.
				for _, coll := range []string{
					colRoles, colPermissions, colPolicies, colResourceTypes,
					colAssignments, colRelations, colCheckLogs,
				} {
					_, err := db.Collection(coll).UpdateMany(ctx,
						bson.M{"namespace_path": bson.M{"$exists": false}},
						bson.M{"$set": bson.M{"namespace_path": ""}},
					)
					if err != nil {
						return fmt.Errorf("warden: backfill namespace_path on %s: %w", coll, err)
					}
				}

				// Create indexes on (tenant_id, namespace_path).
				for _, coll := range []string{
					colRoles, colPermissions, colPolicies, colResourceTypes,
				} {
					if _, err := db.Collection(coll).Indexes().CreateOne(ctx, mongo.IndexModel{
						Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "namespace_path", Value: 1}},
					}); err != nil {
						return fmt.Errorf("warden: create ns index on %s: %w", coll, err)
					}
				}
				if _, err := db.Collection(colAssignments).Indexes().CreateOne(ctx, mongo.IndexModel{
					Keys: bson.D{
						{Key: "tenant_id", Value: 1},
						{Key: "namespace_path", Value: 1},
						{Key: "subject_kind", Value: 1},
						{Key: "subject_id", Value: 1},
					},
				}); err != nil {
					return fmt.Errorf("warden: create ns index on %s: %w", colAssignments, err)
				}
				if _, err := db.Collection(colRelations).Indexes().CreateOne(ctx, mongo.IndexModel{
					Keys: bson.D{
						{Key: "tenant_id", Value: 1},
						{Key: "namespace_path", Value: 1},
						{Key: "object_type", Value: 1},
						{Key: "object_id", Value: 1},
					},
				}); err != nil {
					return fmt.Errorf("warden: create ns index on %s: %w", colRelations, err)
				}
				return nil
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				db := mexec.DB().Database()
				for _, coll := range []string{
					colRoles, colPermissions, colPolicies, colResourceTypes,
					colAssignments, colRelations, colCheckLogs,
				} {
					_, err := db.Collection(coll).UpdateMany(ctx, bson.M{}, bson.M{"$unset": bson.M{"namespace_path": ""}})
					if err != nil {
						return fmt.Errorf("warden: unset namespace_path on %s: %w", coll, err)
					}
				}
				return nil
			},
		},
		&migrate.Migration{
			Name:    "role_parent_slug",
			Version: "20260101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				coll := mexec.DB().Database().Collection(colRoles)

				cursor, err := coll.Find(ctx, bson.M{"parent_id": bson.M{"$exists": true}})
				if err != nil {
					return fmt.Errorf("warden: find roles with parent_id: %w", err)
				}
				defer func() { _ = cursor.Close(ctx) }()
				for cursor.Next(ctx) {
					var doc struct {
						ID       string `bson:"_id"`
						TenantID string `bson:"tenant_id"`
						ParentID string `bson:"parent_id"`
					}
					if err := cursor.Decode(&doc); err != nil {
						return fmt.Errorf("warden: decode role: %w", err)
					}
					var parent struct {
						Slug string `bson:"slug"`
					}
					if err := coll.FindOne(ctx, bson.M{"_id": doc.ParentID, "tenant_id": doc.TenantID}).Decode(&parent); err != nil {
						continue // orphan parent_id — leave parent_slug unset
					}
					if _, err := coll.UpdateOne(ctx, bson.M{"_id": doc.ID}, bson.M{"$set": bson.M{"parent_slug": parent.Slug}}); err != nil {
						return fmt.Errorf("warden: backfill parent_slug: %w", err)
					}
				}
				if err := cursor.Err(); err != nil {
					return fmt.Errorf("warden: iterate roles: %w", err)
				}

				if _, err := coll.UpdateMany(ctx, bson.M{}, bson.M{"$unset": bson.M{"parent_id": ""}}); err != nil {
					return fmt.Errorf("warden: drop parent_id field: %w", err)
				}

				_ = coll.Indexes().DropOne(ctx, "parent_id_1")

				_, err = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
					Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "parent_slug", Value: 1}},
				})
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				coll := mexec.DB().Database().Collection(colRoles)

				cursor, err := coll.Find(ctx, bson.M{"parent_slug": bson.M{"$exists": true}})
				if err != nil {
					return fmt.Errorf("warden: find roles with parent_slug: %w", err)
				}
				defer func() { _ = cursor.Close(ctx) }()
				for cursor.Next(ctx) {
					var doc struct {
						ID         string `bson:"_id"`
						TenantID   string `bson:"tenant_id"`
						ParentSlug string `bson:"parent_slug"`
					}
					if err := cursor.Decode(&doc); err != nil {
						return fmt.Errorf("warden: decode role: %w", err)
					}
					var parent struct {
						ID string `bson:"_id"`
					}
					if err := coll.FindOne(ctx, bson.M{"slug": doc.ParentSlug, "tenant_id": doc.TenantID}).Decode(&parent); err != nil {
						continue
					}
					if _, err := coll.UpdateOne(ctx, bson.M{"_id": doc.ID}, bson.M{"$set": bson.M{"parent_id": parent.ID}}); err != nil {
						return fmt.Errorf("warden: backfill parent_id: %w", err)
					}
				}
				if err := cursor.Err(); err != nil {
					return fmt.Errorf("warden: iterate roles: %w", err)
				}

				if _, err := coll.UpdateMany(ctx, bson.M{}, bson.M{"$unset": bson.M{"parent_slug": ""}}); err != nil {
					return fmt.Errorf("warden: drop parent_slug field: %w", err)
				}

				_ = coll.Indexes().DropOne(ctx, "tenant_id_1_parent_slug_1")

				_, err = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
					Keys: bson.D{{Key: "parent_id", Value: 1}},
				})
				return err
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
