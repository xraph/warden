// Quick diagnostic + data fix script for warden RBAC data.
// Usage: go run ./cmd/diagquery           (diagnostic mode)
//
//	go run ./cmd/diagquery --fix     (fix data)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	mongoURI = "mongodb://localhost:27017"
	dbName   = "twinos"
	userID   = "ausr_01kkc93awmfz49qs1hgaxyx3sj"
	appID    = "aapp_01kkc8zqbkfyard4xh8fbqhhqm"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("connect:", err)
	}
	defer client.Disconnect(ctx)

	db := client.Database(dbName)

	// 1. Find roles with slug platform_owner.
	fmt.Println("=== ROLES (platform_owner) ===")
	cur, err := db.Collection("warden_roles").Find(ctx, bson.M{"slug": "platform_owner"})
	if err != nil {
		log.Fatal("find roles:", err)
	}
	var roles []bson.M
	if err := cur.All(ctx, &roles); err != nil {
		log.Fatal("decode roles:", err)
	}
	dump("roles", roles)

	// 2. Find assignments for user.
	fmt.Println("\n=== ASSIGNMENTS (user) ===")
	cur, err = db.Collection("warden_assignments").Find(ctx, bson.M{
		"subject_id":   userID,
		"subject_kind": "user",
	})
	if err != nil {
		log.Fatal("find assignments:", err)
	}
	var assigns []bson.M
	if err := cur.All(ctx, &assigns); err != nil {
		log.Fatal("decode assigns:", err)
	}
	dump("assignments", assigns)

	// 3. For each role found, get permissions from junction table.
	roleIDs := make([]string, 0)
	for _, a := range assigns {
		if rid, ok := a["role_id"].(string); ok {
			roleIDs = append(roleIDs, rid)
		}
	}
	// Also add role IDs from step 1.
	for _, r := range roles {
		if rid, ok := r["_id"].(string); ok {
			roleIDs = append(roleIDs, rid)
		}
	}

	fmt.Println("\n=== ROLE-PERMISSION LINKS ===")
	for _, rid := range roleIDs {
		cur, err = db.Collection("warden_role_permissions").Find(ctx, bson.M{"role_id": rid})
		if err != nil {
			fmt.Printf("  role %s: error: %v\n", rid, err)
			continue
		}
		var links []bson.M
		if err := cur.All(ctx, &links); err != nil {
			fmt.Printf("  role %s: decode error: %v\n", rid, err)
			continue
		}
		fmt.Printf("  role %s: %d permissions linked\n", rid, len(links))
		for _, l := range links {
			permID := l["permission_id"]
			fmt.Printf("    -> perm_id: %v\n", permID)

			// Fetch the actual permission.
			var perm bson.M
			err := db.Collection("warden_permissions").FindOne(ctx, bson.M{"_id": permID}).Decode(&perm)
			if err != nil {
				fmt.Printf("       FETCH ERROR: %v\n", err)
				continue
			}
			fmt.Printf("       action=%v resource=%v name=%v tenant_id=%v\n",
				perm["action"], perm["resource"], perm["name"], perm["tenant_id"])
		}
	}

	// 4. List all roles and their permission counts.
	fmt.Println("\n=== ALL ROLES + PERMISSION COUNTS ===")
	cur, err = db.Collection("warden_roles").Find(ctx, bson.M{"tenant_id": appID})
	if err != nil {
		log.Fatal("find all roles:", err)
	}
	var allRoles []bson.M
	if err := cur.All(ctx, &allRoles); err != nil {
		log.Fatal("decode all roles:", err)
	}
	for _, r := range allRoles {
		rid := r["_id"].(string)
		cur2, _ := db.Collection("warden_role_permissions").Find(ctx, bson.M{"role_id": rid})
		var perms []bson.M
		cur2.All(ctx, &perms)
		fmt.Printf("  %v (slug=%v, parent_id=%v) → %d permissions\n", rid, r["slug"], r["parent_id"], len(perms))
	}

	// 5. Check if wildcard permissions exist anywhere.
	fmt.Println("\n=== WILDCARD PERMISSIONS (*) ===")
	cur, err = db.Collection("warden_permissions").Find(ctx, bson.M{
		"$or": []bson.M{
			{"action": "*"},
			{"resource": "*"},
		},
	})
	if err != nil {
		log.Fatal("find wildcard perms:", err)
	}
	var wildcardPerms []bson.M
	if err := cur.All(ctx, &wildcardPerms); err != nil {
		log.Fatal("decode wildcard perms:", err)
	}
	if len(wildcardPerms) == 0 {
		fmt.Println("  NONE FOUND - bootstrap never created wildcard permissions!")
	}
	for _, p := range wildcardPerms {
		fmt.Printf("  perm_id=%v action=%v resource=%v name=%v tenant_id=%v\n",
			p["_id"], p["action"], p["resource"], p["name"], p["tenant_id"])
	}

	// --fix mode: repair data.
	if len(os.Args) > 1 && os.Args[1] == "--fix" {
		fixData(ctx, db, allRoles, wildcardPerms)
	}
}

func fixData(ctx context.Context, db *mongo.Database, allRoles []bson.M, wildcardPerms []bson.M) {
	fmt.Println("\n========== FIXING DATA ==========")

	// Find the wildcard permission ID.
	if len(wildcardPerms) == 0 {
		log.Fatal("no wildcard permission found — cannot fix")
	}
	wildcardPermID := wildcardPerms[0]["_id"].(string)
	fmt.Printf("Using wildcard perm: %s\n", wildcardPermID)

	// Build slug → roleID map.
	slugToID := make(map[string]string)
	for _, r := range allRoles {
		slug := r["slug"].(string)
		roleID := r["_id"].(string)
		slugToID[slug] = roleID
	}

	// Fix 1: Attach wildcard permission to all roles that should have it.
	rolesNeedingWildcard := []string{"platform_owner", "platform_admin", "admin", "owner"}
	for _, slug := range rolesNeedingWildcard {
		roleID, ok := slugToID[slug]
		if !ok {
			fmt.Printf("  SKIP %s: role not found\n", slug)
			continue
		}

		// Check if already linked.
		count, err := db.Collection("warden_role_permissions").CountDocuments(ctx, bson.M{
			"role_id":       roleID,
			"permission_id": wildcardPermID,
		})
		if err != nil {
			fmt.Printf("  ERROR checking %s: %v\n", slug, err)
			continue
		}
		if count > 0 {
			fmt.Printf("  SKIP %s: wildcard already linked\n", slug)
			continue
		}

		// Insert junction table entry.
		_, err = db.Collection("warden_role_permissions").InsertOne(ctx, bson.M{
			"role_id":       roleID,
			"permission_id": wildcardPermID,
		})
		if err != nil {
			fmt.Printf("  ERROR linking %s: %v\n", slug, err)
		} else {
			fmt.Printf("  FIXED %s (%s): wildcard permission linked\n", slug, roleID)
		}
	}

	// Fix 2: Also attach platform_user's read permissions to app-scoped "user" role.
	platformUserID := slugToID["platform_user"]
	appUserID := slugToID["user"]
	if platformUserID != "" && appUserID != "" {
		// Get platform_user's permissions.
		cur, err := db.Collection("warden_role_permissions").Find(ctx, bson.M{"role_id": platformUserID})
		if err == nil {
			var links []bson.M
			cur.All(ctx, &links)
			for _, l := range links {
				permID := l["permission_id"].(string)
				count, _ := db.Collection("warden_role_permissions").CountDocuments(ctx, bson.M{
					"role_id":       appUserID,
					"permission_id": permID,
				})
				if count == 0 {
					db.Collection("warden_role_permissions").InsertOne(ctx, bson.M{
						"role_id":       appUserID,
						"permission_id": permID,
					})
					fmt.Printf("  FIXED user (%s): linked permission %s\n", appUserID, permID)
				}
			}
		}
	}

	// Fix 3: Assign platform_owner role to the user (in addition to platform_user).
	ownerRoleID := slugToID["platform_owner"]
	if ownerRoleID == "" {
		fmt.Println("  SKIP: no platform_owner role found")
		return
	}

	// Check if user already has platform_owner.
	count, err := db.Collection("warden_assignments").CountDocuments(ctx, bson.M{
		"subject_id":   userID,
		"subject_kind": "user",
		"role_id":      ownerRoleID,
		"tenant_id":    appID,
	})
	if err != nil {
		fmt.Printf("  ERROR checking owner assignment: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Println("  SKIP: user already has platform_owner role")
		return
	}

	// Create the assignment.
	now := time.Now()
	_, err = db.Collection("warden_assignments").InsertOne(ctx, bson.M{
		"_id":           fmt.Sprintf("asgn_fix_%d", now.UnixNano()),
		"tenant_id":     appID,
		"app_id":        appID,
		"role_id":       ownerRoleID,
		"subject_kind":  "user",
		"subject_id":    userID,
		"resource_type": "",
		"resource_id":   "",
		"granted_by":    "data_fix",
		"created_at":    now,
		"expires_at":    nil,
		"metadata":      nil,
	})
	if err != nil {
		fmt.Printf("  ERROR assigning platform_owner: %v\n", err)
	} else {
		fmt.Printf("  FIXED: user %s assigned platform_owner role (%s)\n", userID, ownerRoleID)
	}

	fmt.Println("\n========== DATA FIX COMPLETE ==========")
}

func dump(label string, docs []bson.M) {
	if len(docs) == 0 {
		fmt.Printf("  (none found)\n")
		return
	}
	for i, d := range docs {
		b, _ := json.MarshalIndent(d, "  ", "  ")
		fmt.Printf("  [%d] %s\n", i, string(b))
	}
}
