// resourcetype_empty_lists.go: a resource type with no relations and no
// permissions is stored and read back on every backend.
//
// ResourceType.Relations and Permissions are db:"-", and each backend
// persists them its own way. The REST create handler builds both lists by
// appending onto nil, so a create that sends neither reaches the store with
// nil slices, not empty ones. Postgres turned a nil slice into SQL NULL,
// which its NOT NULL jsonb columns refused.
package contract

import (
	"context"
	"testing"

	"github.com/xraph/warden/resourcetype"
)

const emptyListsTenant = "rt-empty-tenant"

// RunResourceTypeEmptyListsContract proves a resource type whose relation
// and permission lists are nil can be created, updated, and read back.
func RunResourceTypeEmptyListsContract(t *testing.T, mk MakeStore) {
	t.Run("create with nil lists then read through every path", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		rt := &resourcetype.ResourceType{
			TenantID:      emptyListsTenant,
			NamespacePath: "eng",
			Name:          "document",
			Relations:     nil,
			Permissions:   nil,
		}
		if err := s.CreateResourceType(ctx, rt); err != nil {
			t.Fatalf("CreateResourceType with nil lists: %v", err)
		}

		got, err := s.GetResourceType(ctx, emptyListsTenant, rt.ID)
		if err != nil {
			t.Fatalf("GetResourceType: %v", err)
		}
		requireEmptyLists(t, "GetResourceType", got)

		byName, err := s.GetResourceTypeByName(ctx, emptyListsTenant, "eng", "document")
		if err != nil {
			t.Fatalf("GetResourceTypeByName: %v", err)
		}
		requireEmptyLists(t, "GetResourceTypeByName", byName)

		listed, err := s.ListResourceTypes(ctx, &resourcetype.ListFilter{TenantID: emptyListsTenant})
		if err != nil || len(listed) != 1 {
			t.Fatalf("ListResourceTypes: %d rows, err %v", len(listed), err)
		}
		requireEmptyLists(t, "ListResourceTypes", listed[0])
	})

	t.Run("update to nil lists then read back", func(t *testing.T) {
		s, cleanup := mk(t)
		defer cleanup()
		ctx := context.Background()
		rt := &resourcetype.ResourceType{
			TenantID:      emptyListsTenant,
			NamespacePath: "eng",
			Name:          "folder",
			Relations:     []resourcetype.RelationDef{{Name: "viewer", AllowedSubjects: []string{"user"}}},
			Permissions:   []resourcetype.PermissionDef{{Name: "view", Expression: "viewer"}},
		}
		if err := s.CreateResourceType(ctx, rt); err != nil {
			t.Fatalf("CreateResourceType: %v", err)
		}
		rt.Relations, rt.Permissions = nil, nil
		if err := s.UpdateResourceType(ctx, rt); err != nil {
			t.Fatalf("UpdateResourceType with nil lists: %v", err)
		}
		got, err := s.GetResourceType(ctx, emptyListsTenant, rt.ID)
		if err != nil {
			t.Fatalf("GetResourceType: %v", err)
		}
		// An emptied list must read back empty, not as the old values.
		requireEmptyLists(t, "GetResourceType after UpdateResourceType", got)
	})
}

// requireEmptyLists asserts both lists read back with length 0. Whether a
// backend returns nil or [] is its own business; both mean "none".
func requireEmptyLists(t *testing.T, path string, got *resourcetype.ResourceType) {
	t.Helper()
	if len(got.Relations) != 0 {
		t.Errorf("%s: relations = %+v, want none", path, got.Relations)
	}
	if len(got.Permissions) != 0 {
		t.Errorf("%s: permissions = %+v, want none", path, got.Permissions)
	}
}
