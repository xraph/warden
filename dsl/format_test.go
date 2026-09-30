package dsl

import (
	"strings"
	"testing"
)

func TestFormat_RoundTrip(t *testing.T) {
	// Property: fmt(parse(fmt(parse(src)))) == fmt(parse(src)).
	// Real-world fixtures that exercise every grammar production.
	fixtures := []struct {
		name string
		src  string
	}{
		{
			name: "minimal",
			src:  "warden config 1\ntenant t1\n",
		},
		{
			name: "role with grants",
			src: `warden config 1
tenant t1

permission "doc:read"  (doc : read)
permission "doc:write" (doc : write)

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}

role editor : viewer {
    name = "Editor"
    grants += ["doc:write"]
}
`,
		},
		{
			name: "resource with expression",
			src: `warden config 1
tenant t1

resource document {
    relation owner: user
    relation viewer: user | group#member
    permission read = viewer or owner
}
`,
		},
		{
			name: "policy with conditions",
			src: `warden config 1
tenant t1

policy "biz-hours" {
    effect = allow
    priority = 100
    active = true
    actions = ["read"]
    when {
        context.time time_after "09:00:00Z"
        subject.attributes.dept == "engineering"
    }
}
`,
		},
		{
			name: "relations",
			src: `warden config 1
tenant t1

relation document:welcome owner = user:alice
relation document:welcome viewer = group:eng#member
`,
		},
		{
			name: "namespaces, nested and empty",
			src: `warden config 1
tenant t1

namespace "eng" {
    role lead {
        name = "Lead"
    }
    namespace "platform" {
        permission "svc:restart" (svc : restart)
    }
}
namespace "ops" {}
`,
		},
		{
			name: "policy with subjects and every value shape",
			src: `warden config 1
tenant "0f3a"

policy "Deny Contractors" {
    effect = deny
    subjects = [{ kind = "user", id = "bob" }, {}]
    actions = ["write"]
    when {
        context.risk > 0.75
        context.score <= -3
        subject.attributes.level in [1, 2]
        subject.name exists
        "subject.attributes[\"team name\"]" == "co\"re\\x"
        resource.owner != "x"
    }
}
`,
		},
		{
			name: "names that need quotes and qualified grants",
			src: `warden config 1
tenant t1

resource "role" {
    relation "name": "user:*" | group#member
    relation "on call":
}

permission "warden:*" {
    resource = "warden"
    action = "*"
    is_system = true
}

role "Auditor Team" {
    grants = ["warden:*", { namespace = "eng", name = "deploy:run" }]
}
role empty {
    grants = []
}

relation "role":"3f2a" "name" = user:"bob@example.com"
`,
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			prog1, errs := Parse("test", []byte(fx.src))
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			out1 := Format(prog1)

			prog2, errs := Parse("test", []byte(out1))
			if len(errs) > 0 {
				t.Fatalf("re-parse: %v\nfirst output:\n%s", errs, out1)
			}
			out2 := Format(prog2)

			if out1 != out2 {
				t.Fatalf("format not idempotent\nfirst:\n%s\n---\nsecond:\n%s", out1, out2)
			}
			// Sanity: output ends with newline.
			if !strings.HasSuffix(out1, "\n") {
				t.Errorf("output should end with newline")
			}
		})
	}
}

func TestFormat_DeterministicOrder(t *testing.T) {
	// Two source files with the same decls in different orders should
	// produce the same canonical output.
	src1 := `warden config 1
tenant t1
permission "b:y" (b : y)
permission "a:x" (a : x)
role beta { name = "B" }
role alpha { name = "A" }
`
	src2 := `warden config 1
tenant t1
permission "a:x" (a : x)
permission "b:y" (b : y)
role alpha { name = "A" }
role beta { name = "B" }
`
	p1, _ := Parse("a", []byte(src1))
	p2, _ := Parse("b", []byte(src2))
	o1 := Format(p1)
	o2 := Format(p2)
	if o1 != o2 {
		t.Errorf("formatter not order-stable:\n%s\n---\n%s", o1, o2)
	}
}

func TestFormat_StringListLayout(t *testing.T) {
	// ≤3 items inline; > 3 multi-line.
	short := []string{"a", "b", "c"}
	long := []string{"a", "b", "c", "d"}
	got := formatStringList(short)
	if !strings.Contains(got, "[\"a\", \"b\", \"c\"]") {
		t.Errorf("short list should be inline, got %q", got)
	}
	got = formatStringList(long)
	if !strings.Contains(got, "\n") {
		t.Errorf("long list should be multi-line, got %q", got)
	}
}

func TestFormat_WritesNamespaceBlocks(t *testing.T) {
	prog, errs := Parse("t", []byte(`warden config 1
role admin {
    name = "Admin"
}
namespace "eng" {
    role lead {
        name = "Lead"
    }
    namespace "platform" {
        role sre {
            name = "SRE"
        }
    }
}
namespace "ops" {}
`))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	out := Format(prog)
	for _, want := range []string{"namespace \"eng\" {\n    role lead {", "namespace \"eng/platform\" {\n    role sre {", "namespace \"ops\" {}\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("format lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "role admin") > strings.Index(out, "namespace") {
		t.Errorf("root entities should come before namespace blocks:\n%s", out)
	}
	back, errs := Parse("t", []byte(out))
	if len(errs) > 0 {
		t.Fatalf("re-parse: %v\n%s", errs, out)
	}
	paths := map[string]string{}
	for _, r := range back.Roles {
		paths[r.Slug] = r.NamespacePath
	}
	if paths["admin"] != "" || paths["lead"] != "eng" || paths["sre"] != "eng/platform" {
		t.Errorf("namespaces after a round trip = %v", paths)
	}
	if _, ok := coveredNamespaces(back)["ops"]; !ok {
		t.Error("the empty ops block was lost, so prune no longer covers ops")
	}
}

func TestFormat_QuotesNamesThatDoNotLex(t *testing.T) {
	for in, want := range map[string]string{
		"viewer":      "viewer",
		"billing-ops": "billing-ops",
		"Viewer":      "Viewer",
		"role":        `"role"`,
		"true":        `"true"`,
		"3f2a":        `"3f2a"`,
		"a b":         `"a b"`,
		"warden:role": `"warden:role"`,
		"*":           `"*"`,
		"":            `""`,
		"a.b":         `"a.b"`,
	} {
		if got := formatName(in); got != want {
			t.Errorf("formatName(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFormat_StringsReadBack(t *testing.T) {
	for _, s := range []string{"plain", `back\slash`, `quo"te`, "new\nline", "tab\there", "cr\rhere", `\x41 stays`, "caf\u00e9", "bell\x07"} {
		lit := quoteString(s)
		tok := NewLexer("t", []byte(lit)).Next()
		if tok.Kind != STRING || tok.Value != s {
			t.Errorf("quoteString(%q) = %s reads back as %s %q", s, lit, tok.Kind, tok.Value)
		}
	}
}

func TestFormat_NumbersReadBack(t *testing.T) {
	for _, v := range []any{0.75, -3.0, 1000000.0, 1e21, 0.000001, -0.5, 42, -7} {
		src := "warden config 1\npolicy \"p\" {\n    effect = allow\n    when {\n        context.n == " + formatLiteral(v) + "\n    }\n}\n"
		prog, errs := Parse("t", []byte(src))
		if len(errs) > 0 {
			t.Errorf("%v formats as %s, which does not parse: %v", v, formatLiteral(v), errs)
			continue
		}
		if got := prog.Policies[0].Conditions[0].Value; !valuesEqual(got, v) {
			t.Errorf("%v formats as %s and reads back as %#v", v, formatLiteral(v), got)
		}
	}
}
