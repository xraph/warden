//go:build ignore

// Generates large.warden — a stress fixture for the DSL benchmarks.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	var b strings.Builder
	b.WriteString("warden config 1\ntenant t1\n\n")

	// 100 permissions
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "permission \"r%d:read\"  (r%d : read)\n", i, i)
		fmt.Fprintf(&b, "permission \"r%d:write\" (r%d : write)\n", i, i)
	}
	b.WriteString("\n")

	// 100 roles, each granting 2 perms; every 5th has a parent.
	for i := 0; i < 100; i++ {
		if i > 0 && i%5 == 0 {
			fmt.Fprintf(&b, "role role-%d : role-%d {\n", i, i-1)
		} else {
			fmt.Fprintf(&b, "role role-%d {\n", i)
		}
		fmt.Fprintf(&b, "  name = \"Role %d\"\n", i)
		fmt.Fprintf(&b, "  grants = [\"r%d:read\", \"r%d:write\"]\n", i, i)
		b.WriteString("}\n\n")
	}

	// 20 resource types with 4 relations each.
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "resource res_%d {\n", i)
		b.WriteString("  relation owner: user\n")
		b.WriteString("  relation editor: user\n")
		b.WriteString("  relation viewer: user\n")
		b.WriteString("  permission read = viewer or editor or owner\n")
		b.WriteString("  permission edit = editor or owner\n")
		b.WriteString("}\n\n")
	}

	// 30 policies.
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "policy \"pol-%d\" {\n", i)
		b.WriteString("  effect = allow\n")
		fmt.Fprintf(&b, "  priority = %d\n", i)
		b.WriteString("  active = true\n")
		b.WriteString("  actions = [\"read\"]\n")
		b.WriteString("  when {\n")
		fmt.Fprintf(&b, "    context.tenant == \"t-%d\"\n", i)
		b.WriteString("  }\n}\n\n")
	}

	if err := os.WriteFile("large.warden", []byte(b.String()), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote large.warden (%d bytes)\n", b.Len())
}
