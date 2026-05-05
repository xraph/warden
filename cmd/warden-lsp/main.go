// Command warden-lsp is a Language Server Protocol (LSP) server for the
// `.warden` DSL. Speaks JSON-RPC 2.0 over stdio with the LSP framing.
//
// This binary is a thin entry point — the real server lives in the
// importable `github.com/xraph/warden/lsp` package, which is also
// reachable as `warden lsp`. Editor configs can point at either:
//
//	# Standalone binary
//	go install github.com/xraph/warden/cmd/warden-lsp@latest
//	# (Neovim) cmd = {'warden-lsp'}
//
//	# Or via the unified CLI
//	go install github.com/xraph/warden/cmd/warden@latest
//	# (Neovim) cmd = {'warden', 'lsp'}
//
// Features (advertised via initialize):
//
//   - textDocument/publishDiagnostics  (parse + resolve errors)
//   - textDocument/hover               (role / permission / resource type / policy info)
//   - textDocument/definition          (jump to declaration)
//   - textDocument/formatting          (canonical form via dsl.Format)
//   - textDocument/completion          (context-aware, cross-file)
//   - lifecycle: initialize, initialized, shutdown, exit
package main

import (
	"fmt"
	"os"

	"github.com/xraph/warden/lsp"
)

func main() {
	if err := lsp.Run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "warden-lsp: %v\n", err)
		os.Exit(1)
	}
}
