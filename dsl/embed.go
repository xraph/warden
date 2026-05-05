package dsl

import (
	"context"
	"io/fs"

	"github.com/xraph/warden"
)

// ApplyFile loads, validates, and applies a single .warden file against
// the engine. It is a convenience wrapper for the common Load → check
// → Apply sequence:
//
//	prog, parseErrs, err := dsl.LoadFile(path, loadOpts...)
//	// check err, parseErrs, then call dsl.Apply(ctx, eng, prog, opts)
//
// Parse-time diagnostics short-circuit Apply and are returned as
// *DiagnosticError. Resolver diagnostics surface the same way (Apply
// emits them itself). Use errors.As to inspect the diagnostics list.
//
// Pass dsl.WithVariables(...) via loadOpts to expand ${NAME}
// placeholders before parsing.
func ApplyFile(ctx context.Context, eng *warden.Engine, path string, opts ApplyOptions, loadOpts ...LoadOption) (*ApplyResult, error) {
	prog, parseErrs, err := LoadFile(path, loadOpts...)
	if err != nil {
		return nil, err
	}
	if len(parseErrs) > 0 {
		return nil, &DiagnosticError{Diags: parseErrs}
	}
	return Apply(ctx, eng, prog, opts)
}

// ApplyDir loads, validates, and applies every .warden file under dir.
// Hidden directories are skipped; underscore-prefixed directories
// (`_shared/`, etc.) are kept by convention.
//
// Cross-file conflicts (duplicate roles, mismatched tenant) are
// reported as parse-time diagnostics and short-circuit Apply.
func ApplyDir(ctx context.Context, eng *warden.Engine, dir string, opts ApplyOptions, loadOpts ...LoadOption) (*ApplyResult, error) {
	prog, parseErrs, err := LoadDir(dir, loadOpts...)
	if err != nil {
		return nil, err
	}
	if len(parseErrs) > 0 {
		return nil, &DiagnosticError{Diags: parseErrs}
	}
	return Apply(ctx, eng, prog, opts)
}

// ApplyFS loads, validates, and applies every .warden file under root
// in fsys. Designed for `//go:embed`: pass an embed.FS as fsys and the
// helper will walk it like a real filesystem.
//
//	//go:embed all:config
//	var configFS embed.FS
//
//	res, err := dsl.ApplyFS(ctx, eng, configFS, "config",
//	    dsl.ApplyOptions{TenantID: "acme"},
//	    dsl.WithVariables(dsl.Variables{"REGION": region}))
//
// Note: include the `all:` prefix in the //go:embed directive when your
// config tree contains directories beginning with `_` (like `_shared`)
// — the default //go:embed pattern strips those, but Warden's
// underscore-prefixed convention expects them.
func ApplyFS(ctx context.Context, eng *warden.Engine, fsys fs.FS, root string, opts ApplyOptions, loadOpts ...LoadOption) (*ApplyResult, error) {
	prog, parseErrs, err := LoadFS(fsys, root, loadOpts...)
	if err != nil {
		return nil, err
	}
	if len(parseErrs) > 0 {
		return nil, &DiagnosticError{Diags: parseErrs}
	}
	return Apply(ctx, eng, prog, opts)
}
