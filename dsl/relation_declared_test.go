package dsl

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xraph/warden"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/store/memory"
)

// TestGoverningMatchesTheEvaluator holds the write check's resolution to
// the evaluator's findResourceType: the same resource type, from the same
// namespace, for every namespace a tuple can sit in.
func TestGoverningMatchesTheEvaluator(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	for _, ns := range []string{"", "eng", "eng/platform/sre", "sales"} {
		if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{TenantID: "t1", NamespacePath: ns, Name: "document"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{TenantID: "t1", NamespacePath: "eng", Name: "folder"}); err != nil {
		t.Fatal(err)
	}
	ee := NewEngineEvaluator(s)
	for _, name := range []string{"document", "folder", "nothing"} {
		for _, ns := range []string{"", "eng", "eng/platform", "eng/platform/sre", "eng/platform/sre/oncall", "sales", "sales/emea", "ops"} {
			wantRT, wantNS := ee.findResourceType(ctx, "t1", ns, name)
			gotRT, gotNS, err := resourcetype.Governing(ctx, s, "t1", ns, name)
			if err != nil {
				t.Fatalf("%s at %q: %v", name, ns, err)
			}
			if (wantRT == nil) != (gotRT == nil) || gotNS != wantNS || (gotRT != nil && gotRT.ID != wantRT.ID) {
				t.Errorf("%s at %q: Governing = (%v, %q), evaluator = (%v, %q)", name, ns, gotRT, gotNS, wantRT, wantNS)
			}
		}
	}
}

const docSchema = `
resource document {
    relation owner: user
    relation viewer: user | group#member
}
`

func relationCount(t *testing.T, s *memory.Store) int {
	t.Helper()
	rows, err := s.ListRelations(context.Background(), &relation.ListFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func engineOverStore(t *testing.T, s *memory.Store) *warden.Engine {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// applyBoth plans src and then applies it for real, and returns both
// errors. The real apply runs only when the plan passed or failed with a
// diagnostic, so a test sees what each would do.
func applyBoth(t *testing.T, s *memory.Store, src string, prune bool) (planErr, applyErr error) {
	t.Helper()
	eng := engineOverStore(t, s)
	prog := mustParse(t, src)
	_, planErr = Apply(context.Background(), eng, prog, ApplyOptions{TenantID: "t1", DryRun: true, Prune: prune})
	_, applyErr = Apply(context.Background(), eng, mustParse(t, src), ApplyOptions{TenantID: "t1", Prune: prune})
	return planErr, applyErr
}

func TestApply_TupleThatBreaksItsOwnDeclarationFailsAtPlan(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	src := "warden config 1\n" + docSchema + "\nrelation document:d1 owner = group:eng#member\n"
	planErr, applyErr := applyBoth(t, s, src, false)

	want := `test.warden:8:1: tuple document:d1#owner@group:eng#member in the tenant root is refused: relation "owner" of resource type "document" in the tenant root allows subjects "user", not "group#member"`
	for name, err := range map[string]error{"plan": planErr, "apply": applyErr} {
		var derr *DiagnosticError
		if !errors.As(err, &derr) {
			t.Fatalf("%s: err = %v, want a DiagnosticError", name, err)
		}
		if err.Error() != want {
			t.Errorf("%s:\n got %s\nwant %s", name, err.Error(), want)
		}
	}
	// Nothing was written: not the tuple, and not the resource type the
	// same source declares, because the check runs before any write.
	if n := relationCount(t, s); n != 0 {
		t.Errorf("stored %d tuples, want 0", n)
	}
	if _, err := s.GetResourceTypeByName(ctx, "t1", "", "document"); err == nil {
		t.Error("the refused apply wrote the resource type")
	}
}

func TestApply_TupleChecksAgainstTheSchemaTheApplyLeaves(t *testing.T) {
	ctx := context.Background()

	t.Run("a declaration in the same source allows the tuple the stored one refuses", func(t *testing.T) {
		s := memory.New()
		if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{
			TenantID: "t1", Name: "document",
			Relations: []resourcetype.RelationDef{{Name: "owner", AllowedSubjects: []string{"user"}}},
		}); err != nil {
			t.Fatal(err)
		}
		src := "warden config 1\n" + docSchema + "\nrelation document:d1 viewer = group:eng#member\n"
		planErr, applyErr := applyBoth(t, s, src, false)
		if planErr != nil || applyErr != nil {
			t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
		}
		if n := relationCount(t, s); n != 1 {
			t.Errorf("stored %d tuples, want 1", n)
		}
	})

	t.Run("a declaration in the same source refuses the tuple the stored one allows", func(t *testing.T) {
		s := memory.New()
		if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{
			TenantID: "t1", Name: "document",
			Relations: []resourcetype.RelationDef{{Name: "editor", AllowedSubjects: []string{"user"}}},
		}); err != nil {
			t.Fatal(err)
		}
		src := "warden config 1\n" + docSchema + "\nrelation document:d1 editor = user:alice\n"
		planErr, _ := applyBoth(t, s, src, false)
		if planErr == nil || !strings.Contains(planErr.Error(), `declares no relation "editor" (its relations are "owner", "viewer")`) {
			t.Fatalf("plan err = %v, want the source's own declaration to refuse it", planErr)
		}
		if n := relationCount(t, s); n != 0 {
			t.Errorf("stored %d tuples, want 0", n)
		}
	})

	t.Run("a resource type prune deletes no longer governs", func(t *testing.T) {
		s := memory.New()
		if err := s.CreateResourceType(ctx, &resourcetype.ResourceType{
			TenantID: "t1", Name: "document",
			Relations: []resourcetype.RelationDef{{Name: "owner", AllowedSubjects: []string{"user"}}},
		}); err != nil {
			t.Fatal(err)
		}
		src := "warden config 1\nrelation document:d1 editor = team:x\n"
		if planErr, _ := applyBoth(t, s, src, false); planErr == nil {
			t.Fatal("without prune the stored resource type stays and must refuse the tuple")
		}
		planErr, applyErr := applyBoth(t, s, src, true)
		if planErr != nil || applyErr != nil {
			t.Fatalf("with prune: plan %v, apply %v; want both clean", planErr, applyErr)
		}
		if n := relationCount(t, s); n != 1 {
			t.Errorf("stored %d tuples, want 1", n)
		}
	})
}

func TestApply_TupleCheckFollowsTheNamespaceChain(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		refused string // empty: applies
	}{
		{
			"undeclared object type writes",
			"warden config 1\n" + docSchema + "\nrelation folder:f anything = team:x\n",
			"",
		},
		{
			"declared relation and allowed subject write",
			"warden config 1\n" + docSchema + "\nrelation document:d1 viewer = group:eng#member\nrelation document:d1 owner = user:alice\n",
			"",
		},
		{
			"a relation that lists no subject types takes any subject",
			"warden config 1\nresource memo {\n    relation watcher:\n}\nrelation memo:m1 watcher = user:alice\nrelation memo:m1 watcher = group:eng#member\n",
			"",
		},
		{
			"undeclared relation is refused",
			"warden config 1\n" + docSchema + "\nrelation document:d1 editor = user:alice\n",
			`tuple document:d1#editor@user:alice in the tenant root is refused: resource type "document" in the tenant root declares no relation "editor" (its relations are "owner", "viewer")`,
		},
		{
			"an ancestor's declaration governs a child namespace",
			"warden config 1\n" + docSchema + "\nnamespace \"eng\" {\n    relation document:d1 viewer = group:eng\n}\n",
			`tuple document:d1#viewer@group:eng in namespace "eng" is refused: relation "viewer" of resource type "document" in the tenant root allows subjects "user", "group#member", not "group"`,
		},
		{
			"a sibling's declaration does not govern",
			"warden config 1\nnamespace \"sales\" {\n" + docSchema + "}\nnamespace \"eng\" {\n    relation document:d1 editor = team:x\n}\n",
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := memory.New()
			planErr, applyErr := applyBoth(t, s, c.src, false)
			if c.refused == "" {
				if planErr != nil || applyErr != nil {
					t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
				}
				return
			}
			if planErr == nil || !strings.Contains(planErr.Error(), c.refused) {
				t.Fatalf("plan err = %v\nwant %s", planErr, c.refused)
			}
			if n := relationCount(t, s); n != 0 {
				t.Errorf("stored %d tuples, want 0", n)
			}
		})
	}
}

func TestApply_AStoredTupleIsNotRechecked(t *testing.T) {
	// The check refuses writes. A tuple already stored is a no-op for the
	// apply, so a source that repeats it still plans, even when its
	// resource type would refuse it as a new write.
	ctx := context.Background()
	s := memory.New()
	if err := s.CreateRelation(ctx, &relation.Tuple{
		TenantID: "t1", ObjectType: "document", ObjectID: "d1",
		Relation: "editor", SubjectType: "user", SubjectID: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	src := "warden config 1\n" + docSchema + "\nrelation document:d1 editor = user:alice\n"
	planErr, applyErr := applyBoth(t, s, src, false)
	if planErr != nil || applyErr != nil {
		t.Fatalf("plan %v, apply %v; want both clean", planErr, applyErr)
	}
}
