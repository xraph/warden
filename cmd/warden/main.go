// Command warden is the CLI for the .warden DSL.
//
// Usage:
//
//	warden lint <path>                   — static checks; no DB required
//	warden apply -f <path> --store <DSN> — apply config to a tenant
//	warden diff  -f <path> --store <DSN> — alias for `apply --dry-run`
//
// Path may be a single .warden file, a directory (walked recursively for
// .warden files), or a glob pattern. Hidden directories are skipped;
// `_`-prefixed directories are kept by convention.
//
// Store DSNs:
//
//	memory:                              (testing only)
//	sqlite:<path>                        (single-file dev)
//	postgres://user:pass@host:port/db    (production)
//
// Exit codes:
//
//	0 — success
//	1 — diagnostics (lint, dry-run with errors)
//	2 — usage error
//	3 — store / runtime error
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xraph/warden"
	"github.com/xraph/warden/cmd/internal/cli"
	"github.com/xraph/warden/dsl"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "lint":
		os.Exit(runLint(os.Args[2:]))
	case "apply":
		os.Exit(runApply(os.Args[2:], false))
	case "diff":
		os.Exit(runApply(os.Args[2:], true))
	case "version", "--version", "-v":
		fmt.Println("warden CLI v1 (DSL)")
		os.Exit(0)
	case "help", "--help", "-h":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "warden: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `warden — declarative authorization config CLI

USAGE:
  warden lint <path>                   Static validate (no DB)
  warden apply -f <path> --store DSN   Apply to a tenant
  warden diff  -f <path> --store DSN   Show what apply would change

PATH formats:
  file.warden      single file
  ./config/        directory walked recursively
  'glob/*.warden'  filepath.Glob pattern

STORE DSNs:
  memory:                            (in-memory; tests only)
  sqlite:./warden.db                 (single-file dev)
  postgres://user:pass@host/db       (production)

FLAGS:
  --tenant ID      Override 'tenant' declared in source
  --app ID         Override 'app' declared in source
  --dry-run        Plan without writing
  --prune          Delete tenant entries not in config (apply only)
  --skip-migrate   Don't run store migrations on connect

EXIT CODES:
  0 success | 1 diagnostics | 2 usage | 3 store error`)
}

func runLint(args []string) int {
	fs := flag.NewFlagSet("warden lint", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: warden lint <path>") }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return 2
	}
	prog, errs, err := dsl.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden lint: %v\n", err)
		return 3
	}
	allErrs := append([]*dsl.Diagnostic{}, errs...)
	allErrs = append(allErrs, dsl.Resolve(prog)...)
	for _, d := range allErrs {
		fmt.Fprintln(os.Stderr, d.String())
	}
	if len(allErrs) > 0 {
		return 1
	}
	fmt.Printf("warden lint: %s — %d roles, %d permissions, %d resource types, %d policies, %d relations — OK\n",
		fs.Arg(0),
		len(prog.Roles), len(prog.Permissions), len(prog.ResourceTypes),
		len(prog.Policies), len(prog.Relations))
	return 0
}

func runApply(args []string, dryRunDefault bool) int {
	fs := flag.NewFlagSet("warden apply", flag.ExitOnError)
	var (
		path        = fs.String("f", "", "path to a .warden file, directory, or glob")
		storeDSN    = fs.String("store", "", "store DSN (memory:, sqlite:..., postgres://...)")
		tenantID    = fs.String("tenant", "", "override tenant ID")
		appID       = fs.String("app", "", "override app ID")
		dryRun      = fs.Bool("dry-run", dryRunDefault, "plan without writing")
		prune       = fs.Bool("prune", false, "delete tenant entries not in config")
		skipMigrate = fs.Bool("skip-migrate", false, "skip running store migrations on connect")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "warden: -f <path> is required")
		return 2
	}
	if *storeDSN == "" {
		fmt.Fprintln(os.Stderr, "warden: --store is required")
		return 2
	}

	prog, errs, err := dsl.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		return 3
	}
	allErrs := append([]*dsl.Diagnostic{}, errs...)
	allErrs = append(allErrs, dsl.Resolve(prog)...)
	if len(allErrs) > 0 {
		for _, d := range allErrs {
			fmt.Fprintln(os.Stderr, d.String())
		}
		return 1
	}

	ctx := context.Background()
	store, closeStore, err := cli.OpenStore(ctx, *storeDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		return 3
	}
	defer func() { _ = closeStore() }()
	if err := cli.MaybeMigrate(ctx, store, *skipMigrate); err != nil {
		fmt.Fprintf(os.Stderr, "warden: migrate: %v\n", err)
		return 3
	}

	ev := dsl.NewEngineEvaluator(store)
	eng, err := warden.NewEngine(warden.WithStore(store), warden.WithExpressionEvaluator(ev))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		return 3
	}

	result, err := dsl.Apply(ctx, eng, prog, dsl.ApplyOptions{
		TenantID: *tenantID,
		AppID:    *appID,
		DryRun:   *dryRun,
		Prune:    *prune,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		return 1
	}
	printApplyResult(*path, *dryRun, result)
	return 0
}

func printApplyResult(path string, dryRun bool, r *dsl.ApplyResult) {
	verb := "applied"
	if dryRun {
		verb = "planned"
	}
	fmt.Printf("warden: %s %s\n", verb, path)
	for _, line := range r.Created {
		fmt.Println(line)
	}
	for _, line := range r.Updated {
		fmt.Println(line)
	}
	for _, line := range r.Deleted {
		fmt.Println(line)
	}
	if r.NoOps > 0 {
		fmt.Printf("(%d unchanged)\n", r.NoOps)
	}
	total := len(r.Created) + len(r.Updated) + len(r.Deleted)
	fmt.Printf("%d %s, %d unchanged\n", total, joinChange(r), r.NoOps)
}

func joinChange(r *dsl.ApplyResult) string {
	parts := make([]string, 0, 3)
	if len(r.Created) > 0 {
		parts = append(parts, fmt.Sprintf("%d created", len(r.Created)))
	}
	if len(r.Updated) > 0 {
		parts = append(parts, fmt.Sprintf("%d updated", len(r.Updated)))
	}
	if len(r.Deleted) > 0 {
		parts = append(parts, fmt.Sprintf("%d deleted", len(r.Deleted)))
	}
	if len(parts) == 0 {
		return "0 changes"
	}
	return strings.Join(parts, ", ")
}
