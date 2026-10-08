package lsp

import (
	"encoding/json"
	"strings"
	"testing"
)

// completionAt opens the given .warden source as a single document and
// returns the items the LSP returns at the cursor position. The cursor
// is the (0-based) line + character. The doc URI is fixed.
func completionAt(t *testing.T, cli *rpcClient, uri, src string, line, char int) []completionItem {
	t.Helper()
	open := didOpenParams{}
	open.TextDocument.URI = uri
	open.TextDocument.LanguageID = "warden"
	open.TextDocument.Version = 1
	open.TextDocument.Text = src
	cli.notify("textDocument/didOpen", open)
	// Drain the diagnostics notification that follows didOpen.
	cli.expectNotification()

	cp := completionParams{}
	cp.TextDocument.URI = uri
	cp.Position = lspPosition{Line: line, Character: char}
	resp := cli.request("textDocument/completion", cp)
	if resp.Error != nil {
		t.Fatalf("completion error: %v", resp.Error)
	}
	var result completionList
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode completion: %v", err)
	}
	return result.Items
}

func labels(items []completionItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Label
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func TestCompletion_AdvertisesCapability(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	resp := cli.request("initialize", initializeParams{})
	var result initializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Capabilities.CompletionProvider == nil {
		t.Fatal("expected completion provider in capabilities")
	}
	if !contains(result.Capabilities.CompletionProvider.TriggerCharacters, ":") {
		t.Errorf("expected ':' as a completion trigger character, got %v",
			result.Capabilities.CompletionProvider.TriggerCharacters)
	}
}

func TestCompletion_TopLevelKeywords(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	src := `warden config 1
tenant t1

`
	// Cursor on the empty line at end (line index 3, char 0).
	items := completionAt(t, cli, "file:///top.warden", src, 3, 0)
	got := labels(items)
	for _, want := range []string{"resource", "permission", "role", "policy", "namespace"} {
		if !contains(got, want) {
			t.Errorf("expected top-level keyword %q in items, got %v", want, got)
		}
	}
}

func TestCompletion_RoleParentSlugCrossFile(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	// Open a file declaring some roles.
	rolesA := `warden config 1
tenant t1

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}

role auditor {
    name = "Auditor"
    grants = ["doc:read"]
}
`
	open := didOpenParams{}
	open.TextDocument.URI = "file:///roles.warden"
	open.TextDocument.LanguageID = "warden"
	open.TextDocument.Version = 1
	open.TextDocument.Text = rolesA
	cli.notify("textDocument/didOpen", open)
	cli.expectNotification()

	// Open a second file mid-typing `role admin :` and request completion.
	rolesB := `warden config 1
tenant t1

role admin : `
	items := completionAt(t, cli, "file:///admin.warden", rolesB, 3, len("role admin : "))
	got := labels(items)
	if !contains(got, "viewer") {
		t.Errorf("expected 'viewer' in cross-file parent suggestions, got %v", got)
	}
	if !contains(got, "auditor") {
		t.Errorf("expected 'auditor' in cross-file parent suggestions, got %v", got)
	}
}

func TestCompletion_RoleGrantsListsPermissions(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	src := `warden config 1
tenant t1

permission "doc:read" (document : read)
permission "doc:write" (document : edit)

role viewer {
    grants = [`
	// Cursor on the `[` line, just after the opening bracket.
	lines := strings.Split(src, "\n")
	cursorLine := len(lines) - 1
	cursorChar := len(lines[cursorLine])
	items := completionAt(t, cli, "file:///grants.warden", src, cursorLine, cursorChar)
	got := labels(items)
	if !contains(got, "doc:read") {
		t.Errorf("expected 'doc:read' in grants completion, got %v", got)
	}
	if !contains(got, "doc:write") {
		t.Errorf("expected 'doc:write' in grants completion, got %v", got)
	}
}

func TestCompletion_PolicyFieldsIncludePBAC(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	src := `warden config 1
tenant t1

policy "incident-freeze" {
    `
	lines := strings.Split(src, "\n")
	cursorLine := len(lines) - 1
	cursorChar := len(lines[cursorLine])
	items := completionAt(t, cli, "file:///pol.warden", src, cursorLine, cursorChar)
	got := labels(items)
	for _, want := range []string{"effect", "priority", "active", "not_before", "not_after", "obligations", "actions", "when"} {
		if !contains(got, want) {
			t.Errorf("expected policy field %q in items, got %v", want, got)
		}
	}
}

func TestCompletion_NoMatchOutsidePolicyOrRole(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	// Inside a resource block — top-level keywords should not surface,
	// and policy fields shouldn't either.
	src := `warden config 1
tenant t1

resource document {
    `
	lines := strings.Split(src, "\n")
	cursorLine := len(lines) - 1
	cursorChar := len(lines[cursorLine])
	items := completionAt(t, cli, "file:///rt.warden", src, cursorLine, cursorChar)
	got := labels(items)
	if contains(got, "policy") {
		t.Errorf("did not expect 'policy' top-level keyword inside resource block, got %v", got)
	}
	if contains(got, "not_before") {
		t.Errorf("did not expect PBAC field inside resource block, got %v", got)
	}
}

func TestCompletion_ResourceExpressionRefs(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()
	cli.request("initialize", initializeParams{})

	// Inside resource block, the `permission read = ` line should
	// surface declared relations.
	src := `warden config 1
tenant t1

resource document {
    relation viewer: user
    relation editor: user
    permission read = `
	lines := strings.Split(src, "\n")
	cursorLine := len(lines) - 1
	cursorChar := len(lines[cursorLine])
	items := completionAt(t, cli, "file:///expr.warden", src, cursorLine, cursorChar)
	got := labels(items)
	if !contains(got, "viewer") {
		t.Errorf("expected relation 'viewer' in expression completion, got %v", got)
	}
	if !contains(got, "editor") {
		t.Errorf("expected relation 'editor' in expression completion, got %v", got)
	}
	if !contains(got, "or") {
		t.Errorf("expected expression operator 'or', got %v", got)
	}
}

// The resolver refuses a role parent outside the role's own namespace,
// so parent completion offers only roles in that namespace: the bare slug,
// plus the absolute path into the namespace (`/viewer` at the root). The
// role being declared is never offered as its own parent.
func TestCompletion_RoleParentOnlyFromOwnNamespace(t *testing.T) {
	roles := `warden config 1
tenant t1

role viewer {
    name = "Root Viewer"
    grants = ["doc:read"]
}

namespace eng {
    role viewer {
        name = "Eng Viewer"
        grants = ["doc:read"]
    }
    role lead {
        name = "Eng Lead"
        grants = ["doc:read"]
    }
    namespace backend {
        role oncall {
            name = "Backend Oncall"
            grants = ["doc:read"]
        }
    }
}

namespace ops {
    role viewer {
        name = "Ops Viewer"
        grants = ["doc:read"]
    }
}
`
	cases := []struct {
		name    string
		src     string
		want    map[string]string // label -> role name its Detail starts with
		notWant []string
	}{
		{
			name: "root",
			src: `warden config 1
tenant t1

role admin : `,
			want:    map[string]string{"viewer": "Root Viewer", "/viewer": "Root Viewer"},
			notWant: []string{"admin", "/admin", "lead", "/eng/viewer", "/eng/lead", "/eng/backend/oncall", "oncall", "/ops/viewer"},
		},
		{
			name: "namespace",
			src: `warden config 1
tenant t1

namespace eng {
    role admin : `,
			want:    map[string]string{"viewer": "Eng Viewer", "/eng/viewer": "Eng Viewer", "lead": "Eng Lead", "/eng/lead": "Eng Lead"},
			notWant: []string{"admin", "/eng/admin", "/eng/backend/oncall", "oncall", "/ops/viewer"},
		},
		{
			name: "nested namespace",
			src: `warden config 1
tenant t1

namespace "eng" {
    role other {
        name = "Other"
    }
    namespace backend {
        role admin : `,
			want:    map[string]string{"oncall": "Backend Oncall", "/eng/backend/oncall": "Backend Oncall"},
			notWant: []string{"admin", "/eng/backend/admin", "other", "viewer", "lead", "/eng/viewer", "/eng/lead", "/ops/viewer"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, cleanup := newTestPair(t)
			defer cleanup()
			cli.request("initialize", initializeParams{})

			open := didOpenParams{}
			open.TextDocument.URI = "file:///roles.warden"
			open.TextDocument.LanguageID = "warden"
			open.TextDocument.Version = 1
			open.TextDocument.Text = roles
			cli.notify("textDocument/didOpen", open)
			cli.expectNotification()

			lines := strings.Split(tc.src, "\n")
			last := len(lines) - 1
			items := completionAt(t, cli, "file:///admin.warden", tc.src, last, len(lines[last]))

			byLabel := map[string][]completionItem{}
			for _, it := range items {
				byLabel[it.Label] = append(byLabel[it.Label], it)
			}
			for label, roleName := range tc.want {
				got := byLabel[label]
				if len(got) != 1 {
					t.Errorf("label %q offered %d times, want once; all labels %v", label, len(got), labels(items))
					continue
				}
				if !strings.HasPrefix(got[0].Detail, roleName) {
					t.Errorf("label %q detail = %q, want the role %q", label, got[0].Detail, roleName)
				}
			}
			for _, label := range tc.notWant {
				if _, ok := byLabel[label]; ok {
					t.Errorf("label %q offered, but it is outside the role's namespace; all labels %v", label, labels(items))
				}
			}
			if len(items) != len(tc.want) {
				t.Errorf("got %d items %v, want exactly %d", len(items), labels(items), len(tc.want))
			}
		})
	}
}
