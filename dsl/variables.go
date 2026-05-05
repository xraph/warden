package dsl

import (
	"fmt"
	"os"
	"strings"
)

// Variables is a name → value map of template variables expanded during
// loading. Names match the regex `[A-Za-z_][A-Za-z0-9_]*`. Values are
// inserted verbatim — substitution is purely textual, including inside
// string literals and comments.
//
// Use cases: per-environment tenant IDs, namespace prefixes, region
// tags, or any other field that varies between deployments without
// changing the rest of the config.
type Variables map[string]string

// MergeVariables returns a new Variables map composed of every layer.
// Later layers override earlier ones, so the typical call order is
// (defaults, env, cli) — CLI flags win over env, env wins over defaults.
// Nil layers are skipped. Empty-string values are treated as set.
func MergeVariables(layers ...Variables) Variables {
	out := Variables{}
	for _, layer := range layers {
		for k, v := range layer {
			out[k] = v
		}
	}
	return out
}

// EnvVariables collects every os.Environ() entry whose name starts with
// "WARDEN_VAR_" and exposes them under the suffix as a Variables map.
// Example: `WARDEN_VAR_TENANT=acme` becomes `${TENANT}` in source.
//
// Use this to thread CI-injected values through to the loader without
// per-flag plumbing. Returns an empty map (never nil) if nothing matches.
func EnvVariables() Variables {
	const prefix = "WARDEN_VAR_"
	out := Variables{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		name := kv[len(prefix):eq]
		if !isValidVarName(name) {
			continue
		}
		out[name] = kv[eq+1:]
	}
	return out
}

// SubstituteVariables expands `${NAME}` placeholders in src using vars.
// Each well-formed `${NAME}` reference is replaced with `vars[NAME]`.
//
// Escape: a literal `$$` in the source emits a single `$` and skips
// substitution at that byte. So `$${VAR}` produces `${VAR}` in the
// output (useful for documentation strings that mention the syntax).
//
// Diagnostics are produced for:
//   - unclosed `${...` (no matching `}` before EOL or EOF)
//   - invalid identifiers inside `${...}`
//   - undefined variables (name not in vars)
//
// Diagnostics carry the placeholder's source position so the LSP /
// `warden lint` can underline them precisely. The placeholder is left
// in the output untouched on diagnostic so downstream parsing still
// has bytes to work with — the parser's own errors then point at the
// resulting (still-broken) source.
//
// Substitution is purely textual: placeholders inside string literals
// and inside line/block comments are substituted just like everywhere
// else. This keeps the function simple and the rules predictable —
// users who genuinely want a literal `${...}` write `$$` to escape.
func SubstituteVariables(file string, src []byte, vars Variables) ([]byte, []*Diagnostic) {
	var out []byte
	var diags []*Diagnostic
	line, col := 1, 1
	for i := 0; i < len(src); {
		// `$$` → literal `$`
		if i+1 < len(src) && src[i] == '$' && src[i+1] == '$' {
			out = append(out, '$')
			line, col = advLineCol(line, col, '$')
			line, col = advLineCol(line, col, '$')
			i += 2
			continue
		}
		// `${NAME}` placeholder
		if i+1 < len(src) && src[i] == '$' && src[i+1] == '{' {
			startLine, startCol := line, col
			end := i + 2
			for end < len(src) && src[end] != '}' && src[end] != '\n' {
				end++
			}
			if end >= len(src) || src[end] != '}' {
				// Unclosed placeholder — emit diag, copy `$` literally,
				// continue at the next byte.
				diags = append(diags, &Diagnostic{
					Pos: Pos{File: file, Line: startLine, Col: startCol},
					Msg: "unclosed variable reference (expected `}`)",
				})
				out = append(out, src[i])
				line, col = advLineCol(line, col, src[i])
				i++
				continue
			}
			name := string(src[i+2 : end])
			if !isValidVarName(name) {
				diags = append(diags, &Diagnostic{
					Pos: Pos{File: file, Line: startLine, Col: startCol},
					Msg: fmt.Sprintf("invalid variable name %q (must match [A-Za-z_][A-Za-z0-9_]*)", name),
				})
				out = append(out, src[i:end+1]...)
				for k := i; k <= end; k++ {
					line, col = advLineCol(line, col, src[k])
				}
				i = end + 1
				continue
			}
			val, ok := vars[name]
			if !ok {
				diags = append(diags, &Diagnostic{
					Pos: Pos{File: file, Line: startLine, Col: startCol},
					Msg: fmt.Sprintf("undefined variable ${%s}", name),
				})
				out = append(out, src[i:end+1]...)
				for k := i; k <= end; k++ {
					line, col = advLineCol(line, col, src[k])
				}
				i = end + 1
				continue
			}
			out = append(out, val...)
			// Advance source line/col past the placeholder. Substituted
			// text doesn't shift line/col tracking — diagnostics in the
			// substituted region report the placeholder's position, which
			// is the most useful target for "fix the variable, not the
			// expansion".
			for k := i; k <= end; k++ {
				line, col = advLineCol(line, col, src[k])
			}
			i = end + 1
			continue
		}
		out = append(out, src[i])
		line, col = advLineCol(line, col, src[i])
		i++
	}
	return out, diags
}

func advLineCol(line, col int, b byte) (nextLine, nextCol int) {
	if b == '\n' {
		return line + 1, 1
	}
	return line, col + 1
}

// isValidVarName matches `[A-Za-z_][A-Za-z0-9_]*`.
func isValidVarName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
