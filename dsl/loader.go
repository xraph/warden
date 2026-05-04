package dsl

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadFile reads and parses a single .warden file.
func LoadFile(path string) (*Program, []*Diagnostic, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	prog, errs := Parse(path, src)
	return prog, errs, nil
}

// LoadFiles reads, parses, and merges a fixed list of .warden files.
//
// Cross-file conflicts (same role/permission/policy/resource type declared
// in multiple files) produce diagnostics on the merged Program. The order
// of files determines tie-breaking only for the scope (tenant/app)
// fields — the first file with a non-empty value wins, and any later file
// declaring a conflicting non-empty value yields a diagnostic.
func LoadFiles(paths []string) (*Program, []*Diagnostic, error) {
	merged := &Program{}
	var allErrs []*Diagnostic

	// Stable order for deterministic diagnostics.
	files := append([]string{}, paths...)
	sort.Strings(files)

	for _, path := range files {
		prog, errs, err := LoadFile(path)
		if err != nil {
			return nil, allErrs, err
		}
		allErrs = append(allErrs, errs...)
		mergeInto(merged, prog, path, &allErrs)
	}
	if merged.File == "" && len(files) > 0 {
		merged.File = files[0]
	}
	return merged, allErrs, nil
}

// LoadDir walks a directory tree and loads every .warden file under it.
// Hidden directories (those starting with `.`) are skipped; underscore-
// prefixed directories like `_shared/` are kept by convention.
func LoadDir(dir string) (*Program, []*Diagnostic, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if isWardenFile(d.Name()) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("warden dsl: no .warden files found under %s", dir)
	}
	return LoadFiles(paths)
}

// LoadGlob loads every .warden file matching a glob pattern.
// Pattern semantics match filepath.Glob plus `**` for recursive matching
// (we don't expand `**` here — use LoadDir for that, or expand the pattern
// yourself with doublestar).
func LoadGlob(pattern string) (*Program, []*Diagnostic, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, err
	}
	if len(matches) == 0 {
		return nil, nil, fmt.Errorf("warden dsl: no files matched %q", pattern)
	}
	var paths []string
	for _, m := range matches {
		if isWardenFile(filepath.Base(m)) {
			paths = append(paths, m)
		}
	}
	return LoadFiles(paths)
}

// LoadFS reads .warden files from an fs.FS rooted at root. Useful for
// embedded configs (//go:embed).
func LoadFS(fsys fs.FS, root string) (*Program, []*Diagnostic, error) {
	var paths []string
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && isWardenFile(d.Name()) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	merged := &Program{}
	var allErrs []*Diagnostic
	sort.Strings(paths)
	for _, path := range paths {
		f, err := fsys.Open(path)
		if err != nil {
			return nil, allErrs, err
		}
		src, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, allErrs, err
		}
		prog, errs := Parse(path, src)
		allErrs = append(allErrs, errs...)
		mergeInto(merged, prog, path, &allErrs)
	}
	return merged, allErrs, nil
}

// Load auto-detects whether arg is a file, directory, or glob pattern.
func Load(arg string) (*Program, []*Diagnostic, error) {
	info, err := os.Stat(arg)
	if err == nil {
		if info.IsDir() {
			return LoadDir(arg)
		}
		return LoadFile(arg)
	}
	// Not a real path — try as a glob.
	return LoadGlob(arg)
}

func isWardenFile(name string) bool {
	return strings.HasSuffix(name, ".warden")
}

// mergeInto folds prog2 into prog1, recording cross-file conflicts as
// diagnostics on errs.
func mergeInto(prog1, prog2 *Program, path string, errs *[]*Diagnostic) {
	// Header — first non-empty value wins; conflicts reported.
	if prog1.Version == 0 {
		prog1.Version = prog2.Version
	} else if prog2.Version != 0 && prog1.Version != prog2.Version {
		*errs = append(*errs, &Diagnostic{
			Pos: prog2.HeaderPos,
			Msg: fmt.Sprintf("version %d in %s conflicts with version %d already loaded", prog2.Version, path, prog1.Version),
		})
	}
	if prog1.Tenant == "" {
		prog1.Tenant = prog2.Tenant
	} else if prog2.Tenant != "" && prog1.Tenant != prog2.Tenant {
		*errs = append(*errs, &Diagnostic{
			Pos: prog2.HeaderPos,
			Msg: fmt.Sprintf("tenant %q in %s conflicts with %q already loaded", prog2.Tenant, path, prog1.Tenant),
		})
	}
	if prog1.App == "" {
		prog1.App = prog2.App
	}

	prog1.ResourceTypes = append(prog1.ResourceTypes, prog2.ResourceTypes...)
	prog1.Permissions = append(prog1.Permissions, prog2.Permissions...)
	prog1.Roles = append(prog1.Roles, prog2.Roles...)
	prog1.Policies = append(prog1.Policies, prog2.Policies...)
	prog1.Relations = append(prog1.Relations, prog2.Relations...)
	prog1.Imports = append(prog1.Imports, prog2.Imports...)
	prog1.Namespaces = append(prog1.Namespaces, prog2.Namespaces...)
}
