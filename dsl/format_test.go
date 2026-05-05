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
