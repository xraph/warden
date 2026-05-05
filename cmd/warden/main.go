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
	"path/filepath"
	"strings"

	"github.com/xraph/warden"
	"github.com/xraph/warden/cmd/internal/cli"
	"github.com/xraph/warden/dsl"
	"github.com/xraph/warden/lsp"
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
	case "fmt":
		os.Exit(runFmt(os.Args[2:]))
	case "export":
		os.Exit(runExport(os.Args[2:]))
	case "lsp":
		os.Exit(runLSP(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("warden CLI v1 (DSL)")
		os.Exit(0)
	case "help", "--help", "-h":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "warden: unknown subcommand %q\n", os.Args[1]) //nolint:gosec // %q escapes; stderr is not HTTP
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
  warden fmt   <path>                  Format file(s) in place
  warden fmt   -d <path>               Print canonical-form diff
  warden fmt   --check <path>          Exit 1 if reformatting needed
  warden export --tenant ID --store DSN -o <dir>  Dump tenant state to .warden
  warden lsp                           Start the language server (stdio)

PATH formats:
  file.warden      single file
  ./config/        directory walked recursively
  'glob/*.warden'  filepath.Glob pattern

STORE DSNs:
  memory:                            (in-memory; tests only)
  sqlite:./warden.db                 (single-file dev)
  postgres://user:pass@host/db       (production)

FLAGS:
  --tenant ID         Override 'tenant' declared in source
  --app ID            Override 'app' declared in source
  --var KEY=VALUE     Expand ${KEY} placeholders (repeatable; overrides WARDEN_VAR_*)
  --dry-run           Plan without writing
  --prune             Delete tenant entries not in config (apply only)
  --skip-migrate      Don't run store migrations on connect

ENVIRONMENT:
  WARDEN_VAR_<NAME>   Auto-bound to ${NAME} in source. CLI --var wins on conflict.

EXIT CODES:
  0 success | 1 diagnostics | 2 usage | 3 store error`)
}

// varList implements flag.Value for the repeatable `--var KEY=VALUE`
// flag. Multiple `--var` flags accumulate; the last value wins on
// duplicate keys (so callers can override env defaults from the CLI).
type varList struct{ vars dsl.Variables }

func (v *varList) String() string { return "" }
func (v *varList) Set(raw string) error {
	if v.vars == nil {
		v.vars = dsl.Variables{}
	}
	eq := strings.IndexByte(raw, '=')
	if eq < 0 {
		return fmt.Errorf("expected KEY=VALUE, got %q", raw)
	}
	v.vars[raw[:eq]] = raw[eq+1:]
	return nil
}

// resolveVariables merges (in order: env, CLI) into a single Variables
// map. CLI flags win over `WARDEN_VAR_*` env vars; env vars win over
// nothing. Returns nil when neither produced any entries — Load short-
// circuits substitution in that case.
func resolveVariables(flags *varList) dsl.Variables {
	merged := dsl.MergeVariables(dsl.EnvVariables(), flags.vars)
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func runLint(args []string) int {
	fs := flag.NewFlagSet("warden lint", flag.ExitOnError)
	cliVars := &varList{}
	fs.Var(cliVars, "var", "set DSL template variable, e.g. --var TENANT=acme (repeatable; overrides WARDEN_VAR_*)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: warden lint [--var KEY=VALUE]... <path>") }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return 2
	}
	vars := resolveVariables(cliVars)
	prog, errs, err := dsl.Load(fs.Arg(0), dsl.WithVariables(vars))
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
	cliVars := &varList{}
	var (
		path        = fs.String("f", "", "path to a .warden file, directory, or glob")
		storeDSN    = fs.String("store", "", "store DSN (memory:, sqlite:..., postgres://...)")
		tenantID    = fs.String("tenant", "", "override tenant ID")
		appID       = fs.String("app", "", "override app ID")
		dryRun      = fs.Bool("dry-run", dryRunDefault, "plan without writing")
		prune       = fs.Bool("prune", false, "delete tenant entries not in config")
		skipMigrate = fs.Bool("skip-migrate", false, "skip running store migrations on connect")
	)
	fs.Var(cliVars, "var", "set DSL template variable, e.g. --var TENANT=acme (repeatable; overrides WARDEN_VAR_*)")
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

	vars := resolveVariables(cliVars)
	prog, errs, err := dsl.Load(*path, dsl.WithVariables(vars))
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
	defer func() {
		if cerr := closeStore(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warden: close store: %v\n", cerr)
		}
	}()
	if mErr := cli.MaybeMigrate(ctx, store, *skipMigrate); mErr != nil {
		fmt.Fprintf(os.Stderr, "warden: migrate: %v\n", mErr)
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

// runFmt implements `warden fmt`.
//
// Without flags: rewrites each input file in place to canonical form.
// With -d:      prints a unified-style diff (canonical replaces input).
// With --check: exits 1 if any file would be modified (CI gate).
func runFmt(args []string) int {
	fs := flag.NewFlagSet("warden fmt", flag.ExitOnError)
	var (
		printDiff = fs.Bool("d", false, "print diff against canonical form (no writes)")
		check     = fs.Bool("check", false, "exit 1 if any file is not canonical")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: warden fmt [-d|--check] <path>...")
		return 2
	}

	// Collect every .warden file under each input path.
	var files []string
	for _, arg := range fs.Args() {
		fi, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warden fmt: %v\n", err)
			return 3
		}
		if fi.IsDir() {
			err := filepath.WalkDir(arg, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if !d.IsDir() && strings.HasSuffix(path, ".warden") {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warden fmt: %v\n", err)
				return 3
			}
			continue
		}
		files = append(files, arg)
	}

	anyChanged := false
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warden fmt: %v\n", err)
			return 3
		}
		prog, errs := dsl.Parse(path, src)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, e.String())
			}
			return 1
		}
		formatted := dsl.Format(prog)
		if string(src) == formatted {
			continue
		}
		anyChanged = true
		switch {
		case *check:
			fmt.Println(path)
		case *printDiff:
			fmt.Printf("--- %s (current)\n+++ %s (canonical)\n%s\n", path, path, formatted)
		default:
			if err := os.WriteFile(path, []byte(formatted), 0o644); err != nil { //nolint:gosec // source file rewrite
				fmt.Fprintf(os.Stderr, "warden fmt: %v\n", err)
				return 3
			}
		}
	}
	if *check && anyChanged {
		return 1
	}
	return 0
}

// runExport implements `warden export`.
//
// Reads tenant state from a store and writes canonical .warden files to
// --output (-o). Layout selects file organization: flat | sectional | domain.
func runExport(args []string) int {
	fs := flag.NewFlagSet("warden export", flag.ExitOnError)
	var (
		tenantID    = fs.String("tenant", "", "tenant ID (required)")
		appID       = fs.String("app", "", "optional app ID for the emitted header")
		storeDSN    = fs.String("store", "", "store DSN (required)")
		outDir      = fs.String("o", "", "output directory (required)")
		layoutStr   = fs.String("layout", "flat", "file layout: flat | sectional | domain")
		nsPrefix    = fs.String("namespace-prefix", "", "limit export to a namespace subtree")
		skipMigrate = fs.Bool("skip-migrate", true, "skip running store migrations on connect (export is read-only)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenantID == "" || *storeDSN == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "warden export: --tenant, --store, and -o are required")
		return 2
	}
	var layout dsl.Layout
	switch *layoutStr {
	case "flat":
		layout = dsl.FlatLayout
	case "sectional":
		layout = dsl.SectionalLayout
	case "domain":
		layout = dsl.DomainLayout
	default:
		fmt.Fprintf(os.Stderr, "warden export: unknown layout %q (flat|sectional|domain)\n", *layoutStr)
		return 2
	}

	ctx := context.Background()
	store, closeStore, err := cli.OpenStore(ctx, *storeDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden export: %v\n", err)
		return 3
	}
	defer func() {
		if cerr := closeStore(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warden export: close store: %v\n", cerr)
		}
	}()
	if mErr := cli.MaybeMigrate(ctx, store, *skipMigrate); mErr != nil {
		fmt.Fprintf(os.Stderr, "warden export: migrate: %v\n", mErr)
		return 3
	}

	eng, err := warden.NewEngine(warden.WithStore(store))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden export: %v\n", err)
		return 3
	}

	count, err := dsl.Export(ctx, eng, dsl.ExportOptions{
		TenantID:        *tenantID,
		AppID:           *appID,
		Layout:          layout,
		NamespacePrefix: *nsPrefix,
		OutputDir:       *outDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden export: %v\n", err)
		return 1
	}
	fmt.Printf("warden: exported %d file(s) to %s\n", count, *outDir)
	return 0
}

// runLSP starts the language server on stdio. Same wire protocol and
// capabilities as the standalone `warden-lsp` binary; both delegate to
// the lsp package. Editor configs can point at either entry point.
func runLSP(args []string) int {
	fs := flag.NewFlagSet("warden lsp", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: warden lsp

Starts the Warden Language Server Protocol server on stdio. Identical
to running the standalone warden-lsp binary; both share lsp.Run.

Editor wiring (Neovim):
    cmd = {'warden', 'lsp'}
or:
    cmd = {'warden-lsp'}

Capabilities advertised:
    textDocument/publishDiagnostics
    textDocument/hover
    textDocument/definition
    textDocument/formatting
    textDocument/completion`)
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := lsp.Run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "warden lsp: %v\n", err)
		return 3
	}
	return 0
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
