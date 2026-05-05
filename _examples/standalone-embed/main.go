// Standalone-embed example — boots a Warden engine, applies an
// embedded .warden config tree, then runs a sample Check.
//
// Run:
//
//	go run ./_examples/standalone-embed
//	WARDEN_VAR_REGION=eu-west-1 go run ./_examples/standalone-embed
//
// The `all:config` //go:embed prefix is required so Go bundles the
// `_shared/` directory — the default //go:embed pattern strips
// leading-underscore directories.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"

	"github.com/xraph/warden"
	"github.com/xraph/warden/dsl"
	"github.com/xraph/warden/store/memory"
)

//go:embed all:config
var configFS embed.FS

func main() {
	ctx := context.Background()

	// 1. Construct the engine. Any store backend works; memory keeps the
	// example self-contained.
	eng, err := warden.NewEngine(warden.WithStore(memory.New()))
	if err != nil {
		fail("engine: %v", err)
	}

	// 2. Resolve template variables. Region is read from the env so the
	// same binary can serve multiple deployments. Tenant could come from
	// a CLI flag, K8s ConfigMap, or any other source — here we hard-code
	// it for clarity.
	region := os.Getenv("WARDEN_VAR_REGION")
	if region == "" {
		region = "us-east-1"
	}
	vars := dsl.Variables{
		"TENANT": "acme",
		"REGION": region,
	}

	// 3. Apply the embedded config. ApplyFS walks configFS rooted at
	// "config" (matching the //go:embed path), parses every .warden
	// file, runs name resolution + type checking, and writes to the
	// store. Idempotent — re-running with the same source is a no-op.
	res, err := dsl.ApplyFS(ctx, eng, configFS, "config",
		dsl.ApplyOptions{TenantID: "acme"},
		dsl.WithVariables(vars),
	)
	if err != nil {
		// dsl.DiagnosticError carries every parse + resolver diagnostic.
		// Print them line-by-line for CI-friendly output.
		var derr *dsl.DiagnosticError
		if errors.As(err, &derr) {
			for _, d := range derr.Diagnostics() {
				fmt.Fprintln(os.Stderr, d)
			}
			os.Exit(1)
		}
		fail("apply: %v", err)
	}

	fmt.Println("Applied embedded config:")
	for _, line := range res.Created {
		fmt.Println("  " + line)
	}
	if res.NoOps > 0 {
		fmt.Printf("  (%d unchanged)\n", res.NoOps)
	}

	// 4. Smoke-check: the admin role inherits doc:read transitively,
	// so a Check for read on a document — once we assign admin to a
	// user — should be allowed.
	//
	// Real systems would assign roles via store.CreateAssignment from
	// their own provisioning code; we skip that here since the focus is
	// the embed → apply round-trip.
	fmt.Println("\nLooking up the 'admin' role from the store ...")
	ctxTenant := warden.WithTenant(ctx, "", "acme")
	r, err := eng.Store().GetRoleBySlug(ctxTenant, "acme", "admin")
	if err != nil {
		fail("GetRoleBySlug: %v", err)
	}
	fmt.Printf("  ID:     %s\n", r.ID)
	fmt.Printf("  Name:   %s\n", r.Name)
	fmt.Printf("  Parent: %s\n", r.ParentSlug)

	fmt.Println("\nDone.")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
