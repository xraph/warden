package lsp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/xraph/warden/dsl"
)

// Run starts the LSP server, reading JSON-RPC framed messages from in
// and writing responses + notifications to out. It blocks until the
// client disconnects (EOF on in) or sends an `exit` notification.
//
// Both `cmd/warden-lsp` and `warden lsp` (subcommand) delegate here so
// the two entry points stay byte-for-byte equivalent. A nil return
// means "client disconnected cleanly"; callers typically convert that
// into a 0 exit code.
func Run(in io.Reader, out io.Writer) error {
	srv := newServer(in, out)
	if err := srv.run(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// server is the LSP server state. One instance per connection.
//
// All handler entry points must hold mu while reading/writing docs and the
// reverse: writes to the connection (out) are serialized via writeMu so
// notifications and responses don't interleave their framing.
type server struct {
	in  *bufio.Reader
	out io.Writer

	writeMu sync.Mutex // serializes Content-Length framed writes

	mu        sync.RWMutex
	docs      map[string]*document // keyed by URI
	workspace *workspaceIndex      // cross-file symbol cache (parallel to docs)
}

// document caches the most recent text + parsed AST for a URI.
type document struct {
	uri     string
	text    string
	prog    *dsl.Program
	diags   []*dsl.Diagnostic // parse + resolve diagnostics
	lineIdx []int             // byte offset of each line start; len = lineCount + 1
}

func newServer(in io.Reader, out io.Writer) *server {
	return &server{
		in:        bufio.NewReader(in),
		out:       out,
		docs:      make(map[string]*document),
		workspace: newWorkspaceIndex(),
	}
}

// run is the message loop. Reads framed JSON-RPC, dispatches to handlers,
// writes responses or notifications. Returns nil on graceful shutdown
// (`exit` notification) and io.EOF on stdin close.
func (s *server) run() error {
	for {
		msg, err := readMessage(s.in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := s.dispatch(msg); err != nil {
			// Handler errors are surfaced as JSON-RPC error responses;
			// only return at the protocol level (e.g. write failure).
			return err
		}
	}
}

// dispatch routes a single message to its handler.
//
// Requests (Method+ID set) get a response; notifications (Method only) do
// not. Responses (no Method, ID set) are ignored — we don't issue
// server-side requests in v1.
func (s *server) dispatch(msg *rpcMessage) error {
	if msg.Method == "" {
		return nil // response to a server-issued request; we don't make any.
	}
	isNotification := msg.ID == nil

	switch msg.Method {
	case "initialize":
		return s.respond(msg.ID, s.handleInitialize(msg.Params))
	case "initialized":
		return nil // no-op; client is announcing readiness.
	case "shutdown":
		return s.respond(msg.ID, nil)
	case "exit":
		return io.EOF // graceful exit signal.

	case "textDocument/didOpen":
		s.handleDidOpen(msg.Params)
		return nil
	case "textDocument/didChange":
		s.handleDidChange(msg.Params)
		return nil
	case "textDocument/didSave":
		s.handleDidSave(msg.Params)
		return nil
	case "textDocument/didClose":
		s.handleDidClose(msg.Params)
		return nil

	case "textDocument/hover":
		return s.respond(msg.ID, s.handleHover(msg.Params))
	case "textDocument/definition":
		return s.respond(msg.ID, s.handleDefinition(msg.Params))
	case "textDocument/formatting":
		return s.respond(msg.ID, s.handleFormatting(msg.Params))
	case "textDocument/completion":
		return s.respond(msg.ID, s.handleCompletion(msg.Params))
	}

	if isNotification {
		// Unknown notification — silently ignore per the spec.
		return nil
	}
	return s.write(makeError(msg.ID, errMethodNotFound, "method not found: "+msg.Method))
}

// respond writes a successful response (or a converted error if the
// handler returned a non-nil err result). Result may be nil for void
// methods like shutdown.
func (s *server) respond(id json.RawMessage, result any) error {
	if id == nil {
		return nil // request had no ID — can't reply
	}
	if errVal, ok := result.(error); ok && errVal != nil {
		return s.write(makeError(id, errInternalError, errVal.Error()))
	}
	resp, err := makeResponse(id, result)
	if err != nil {
		return s.write(makeError(id, errInternalError, err.Error()))
	}
	return s.write(resp)
}

// write serializes a single message to the connection.
func (s *server) write(msg *rpcMessage) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeMessage(s.out, msg)
}

// notify sends a server-initiated notification.
func (s *server) notify(method string, params any) error {
	n, err := makeNotification(method, params)
	if err != nil {
		return err
	}
	return s.write(n)
}

// ─────────────────────────────────────────────────────────────────────────
// Document tracking helpers.
// ─────────────────────────────────────────────────────────────────────────

func (s *server) setDoc(uri, text string) *document {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := &document{uri: uri, text: text, lineIdx: indexLines(text)}
	prog, errs := dsl.Parse(uri, []byte(text))
	d.prog = prog
	d.diags = append(d.diags, errs...)
	d.diags = append(d.diags, dsl.Resolve(prog)...)
	s.docs[uri] = d
	s.workspace.set(uri, prog)
	return d
}

func (s *server) getDoc(uri string) *document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.docs[uri]
}

func (s *server) deleteDoc(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, uri)
	s.workspace.remove(uri)
}

// indexLines returns the byte offset of each line start. Used for fast
// line/column ↔ byte-offset conversion in hover and diagnostic emission.
func indexLines(s string) []int {
	idx := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

// posToOffset converts a 0-based (line, char) into a byte offset within the
// document. Falls back to 0 on out-of-range input.
func (d *document) posToOffset(p lspPosition) int {
	if p.Line < 0 || p.Line >= len(d.lineIdx) {
		return 0
	}
	off := d.lineIdx[p.Line]
	// Walk `Character` runes forward (LSP says UTF-16 code units; for
	// ASCII-only DSL source this is equivalent to bytes, which is fine
	// for the editor positions we care about).
	for i := 0; i < p.Character && off < len(d.text) && d.text[off] != '\n'; i++ {
		off++
	}
	return off
}

// dslPosToLSP converts a dsl.Pos (1-based line and byte column) into an
// LSP position (0-based).
func dslPosToLSP(pos dsl.Pos) lspPosition {
	line := pos.Line - 1
	if line < 0 {
		line = 0
	}
	col := pos.Col - 1
	if col < 0 {
		col = 0
	}
	return lspPosition{Line: line, Character: col}
}

// dslRangeFromPos returns a single-character LSP range starting at the
// given dsl position. Used as a fallback when we don't know the exact span
// of the offending token.
func dslRangeFromPos(pos dsl.Pos) lspRange {
	start := dslPosToLSP(pos)
	end := lspPosition{Line: start.Line, Character: start.Character + 1}
	return lspRange{Start: start, End: end}
}

// identifierAt extracts a contiguous identifier-like token at the given
// document offset. Returns the text and the (start, end) byte offsets.
// Used by hover / definition to figure out what's under the cursor.
func identifierAt(text string, offset int) (ident string, start, end int) {
	if offset < 0 || offset > len(text) {
		return "", 0, 0
	}
	isIdentByte := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '/'
	}
	// Walk left.
	start = offset
	for start > 0 && isIdentByte(text[start-1]) {
		start--
	}
	end = offset
	for end < len(text) && isIdentByte(text[end]) {
		end++
	}
	if start == end {
		return "", offset, offset
	}
	return text[start:end], start, end
}

// formatErrorMsg trims the file/line prefix off a dsl.Diagnostic message
// for display in editor diagnostics — the LSP client already shows the
// position, so the duplicate prefix is noise.
func formatErrorMsg(msg string) string {
	// dsl.Diagnostic.Msg is the bare text (no prefix); but if a caller
	// stringified it via .Error() they'd get the prefixed form. Keep both.
	if i := strings.Index(msg, ": "); i >= 0 && i < 80 {
		// Only strip if the prefix is a position label (line:col) followed
		// by ": ".
		prefix := msg[:i]
		if strings.Count(prefix, ":") >= 2 {
			return msg[i+2:]
		}
	}
	return msg
}

// debugf is a placeholder for an LSP-window/logMessage notification;
// unused in v1.
var _ = fmt.Sprintf
