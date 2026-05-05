package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// rpcClient is a tiny in-process LSP client used by the tests. It writes
// requests to a pipe the server reads from, and reads server responses
// from a buffer the server writes to.
type rpcClient struct {
	t      *testing.T
	in     io.Writer
	out    *bufio.Reader
	nextID int

	pending map[int]chan *rpcMessage
	pendMu  sync.Mutex
	notifs  chan *rpcMessage
}

// newTestPair wires a server and client together over in-memory pipes.
// The server runs in a background goroutine until the input pipe closes.
func newTestPair(t *testing.T) (*rpcClient, func()) {
	t.Helper()

	clientToServer := newPipe()
	serverToClient := newPipe()

	srv := newServer(clientToServer.r, serverToClient.w)
	done := make(chan error, 1)
	go func() { done <- srv.run() }()

	cli := &rpcClient{
		t:       t,
		in:      clientToServer.w,
		out:     bufio.NewReader(serverToClient.r),
		pending: make(map[int]chan *rpcMessage),
		notifs:  make(chan *rpcMessage, 32),
	}
	// Drain server output: split notifications from responses by ID.
	go cli.readLoop()

	cleanup := func() {
		_ = clientToServer.Close()
		<-done
		_ = serverToClient.Close()
	}
	return cli, cleanup
}

func (c *rpcClient) readLoop() {
	for {
		msg, err := readMessage(c.out)
		if err != nil {
			return
		}
		if msg.ID == nil {
			// Notification — non-blocking enqueue.
			select {
			case c.notifs <- msg:
			default:
			}
			continue
		}
		var id int
		_ = json.Unmarshal(msg.ID, &id)
		c.pendMu.Lock()
		ch := c.pending[id]
		delete(c.pending, id)
		c.pendMu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

// request sends a request and blocks until the response arrives.
func (c *rpcClient) request(method string, params any) *rpcMessage {
	c.t.Helper()
	c.nextID++
	id := c.nextID
	idJSON, _ := json.Marshal(id)
	body, _ := json.Marshal(params)
	msg := &rpcMessage{
		JSONRPC: "2.0",
		ID:      idJSON,
		Method:  method,
		Params:  body,
	}
	ch := make(chan *rpcMessage, 1)
	c.pendMu.Lock()
	c.pending[id] = ch
	c.pendMu.Unlock()
	if err := writeMessage(c.in, msg); err != nil {
		c.t.Fatalf("write %s: %v", method, err)
	}
	return <-ch
}

// notify sends a notification (no response expected).
func (c *rpcClient) notify(method string, params any) {
	c.t.Helper()
	body, _ := json.Marshal(params)
	msg := &rpcMessage{JSONRPC: "2.0", Method: method, Params: body}
	if err := writeMessage(c.in, msg); err != nil {
		c.t.Fatalf("notify %s: %v", method, err)
	}
}

// expectNotification waits for the next textDocument/publishDiagnostics
// notification, ignoring any other notification kinds in the meantime.
func (c *rpcClient) expectNotification() *rpcMessage {
	c.t.Helper()
	const method = "textDocument/publishDiagnostics"
	for n := range c.notifs {
		if n.Method == method {
			return n
		}
	}
	c.t.Fatalf("did not receive notification %q", method)
	return nil
}

// pipe is an io.Reader/io.Writer pair backed by a bytes.Buffer + cond. Used
// instead of os.Pipe to keep tests deterministic and free of goroutine
// scheduling races on slow CI.
type pipe struct {
	r *pipeReader
	w *pipeWriter
}

func newPipe() *pipe {
	mu := &sync.Mutex{}
	cond := sync.NewCond(mu)
	buf := &bytes.Buffer{}
	state := &pipeState{cond: cond, buf: buf}
	return &pipe{
		r: &pipeReader{state: state},
		w: &pipeWriter{state: state},
	}
}

func (p *pipe) Close() error {
	p.r.state.cond.L.Lock()
	p.r.state.closed = true
	p.r.state.cond.Broadcast()
	p.r.state.cond.L.Unlock()
	return nil
}

type pipeState struct {
	cond   *sync.Cond
	buf    *bytes.Buffer
	closed bool
}

type pipeReader struct{ state *pipeState }
type pipeWriter struct{ state *pipeState }

func (r *pipeReader) Read(p []byte) (int, error) {
	r.state.cond.L.Lock()
	defer r.state.cond.L.Unlock()
	for r.state.buf.Len() == 0 {
		if r.state.closed {
			return 0, io.EOF
		}
		r.state.cond.Wait()
	}
	return r.state.buf.Read(p)
}

func (w *pipeWriter) Write(p []byte) (int, error) {
	w.state.cond.L.Lock()
	defer w.state.cond.L.Unlock()
	if w.state.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := w.state.buf.Write(p)
	w.state.cond.Broadcast()
	return n, err
}

// ─── Tests ───────────────────────────────────────────────────────────────

func TestLSP_InitializeAdvertisesCapabilities(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	resp := cli.request("initialize", initializeParams{ProcessID: 12345})
	if resp.Error != nil {
		t.Fatalf("initialize error: %v", resp.Error)
	}
	var result initializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	if !result.Capabilities.HoverProvider {
		t.Error("expected hover provider")
	}
	if !result.Capabilities.DefinitionProvider {
		t.Error("expected definition provider")
	}
	if !result.Capabilities.DocumentFormattingProvider {
		t.Error("expected formatting provider")
	}
	if result.Capabilities.TextDocumentSync != 1 {
		t.Errorf("expected TextDocumentSync=1 (full), got %d", result.Capabilities.TextDocumentSync)
	}
}

func TestLSP_DiagnosticsOnDidOpen(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	cli.request("initialize", initializeParams{})

	openParams := didOpenParams{}
	openParams.TextDocument.URI = "file:///x.warden"
	openParams.TextDocument.LanguageID = "warden"
	openParams.TextDocument.Version = 1
	openParams.TextDocument.Text = `warden config 1
tenant t1
role editor : ghost {
    name = "Editor"
}
`
	cli.notify("textDocument/didOpen", openParams)

	notif := cli.expectNotification()
	var p publishDiagnosticsParams
	if err := json.Unmarshal(notif.Params, &p); err != nil {
		t.Fatal(err)
	}
	if p.URI != "file:///x.warden" {
		t.Errorf("URI = %q", p.URI)
	}
	if len(p.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic for unknown parent")
	}
	saw := false
	for _, d := range p.Diagnostics {
		if strings.Contains(d.Message, "unknown parent") {
			saw = true
		}
		if d.Source != "warden" {
			t.Errorf("source = %q, want warden", d.Source)
		}
		if d.Severity != diagError {
			t.Errorf("severity = %d, want %d", d.Severity, diagError)
		}
	}
	if !saw {
		t.Errorf("expected `unknown parent` diagnostic, got %v",
			diagMessages(p.Diagnostics))
	}
}

func TestLSP_FormattingReturnsCanonicalDocument(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	cli.request("initialize", initializeParams{})

	// Slightly non-canonical input: extra whitespace, fields out of order.
	src := `warden config 1
tenant   t1

role  viewer  {
   grants = ["doc:read"]
   name   =   "Viewer"
}
`
	openParams := didOpenParams{}
	openParams.TextDocument.URI = "file:///fmt.warden"
	openParams.TextDocument.Text = src
	cli.notify("textDocument/didOpen", openParams)
	cli.expectNotification()

	fp := formattingParams{}
	fp.TextDocument.URI = "file:///fmt.warden"
	resp := cli.request("textDocument/formatting", fp)
	if resp.Error != nil {
		t.Fatalf("formatting error: %v", resp.Error)
	}
	var edits []lspTextEdit
	if err := json.Unmarshal(resp.Result, &edits); err != nil {
		t.Fatal(err)
	}
	if len(edits) != 1 {
		t.Fatalf("expected 1 edit, got %d", len(edits))
	}
	if !strings.Contains(edits[0].NewText, "name = \"Viewer\"") {
		t.Errorf("formatted text missing canonical name field:\n%s", edits[0].NewText)
	}
	if !strings.Contains(edits[0].NewText, "grants = [\"doc:read\"]") {
		t.Errorf("formatted text missing canonical grants:\n%s", edits[0].NewText)
	}
}

func TestLSP_DefinitionJumpsToDeclaration(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	cli.request("initialize", initializeParams{})

	src := `warden config 1
tenant t1

role viewer {
    name = "Viewer"
    grants = ["doc:read"]
}

role editor : viewer {
    name = "Editor"
}
`
	openParams := didOpenParams{}
	openParams.TextDocument.URI = "file:///def.warden"
	openParams.TextDocument.Text = src
	cli.notify("textDocument/didOpen", openParams)
	cli.expectNotification()

	// `editor : viewer` — the second `viewer` is on line 8 (0-based: 8),
	// at character position right after the colon. Position the cursor
	// inside the word "viewer" of the parent reference.
	parentRefLine := strings.Split(src, "\n")
	for i, line := range parentRefLine {
		if strings.Contains(line, "role editor") {
			// Cursor at position of 'v' in "viewer".
			col := strings.Index(line, ": viewer") + 2
			pp := textDocumentPositionParams{}
			pp.TextDocument.URI = "file:///def.warden"
			pp.Position = lspPosition{Line: i, Character: col + 1} // mid-word
			resp := cli.request("textDocument/definition", pp)
			if resp.Error != nil {
				t.Fatalf("definition error: %v", resp.Error)
			}
			var locs []lspLocation
			if err := json.Unmarshal(resp.Result, &locs); err != nil {
				t.Fatalf("decode definition: %v\nraw=%s", err, string(resp.Result))
			}
			if len(locs) == 0 {
				t.Fatal("expected at least one definition location")
			}
			// Should jump to the line where `role viewer {` is declared.
			declLine := -1
			for j, l := range parentRefLine {
				if strings.HasPrefix(l, "role viewer") {
					declLine = j
					break
				}
			}
			if locs[0].Range.Start.Line != declLine {
				t.Errorf("definition jumped to line %d, want %d",
					locs[0].Range.Start.Line, declLine)
			}
			return
		}
	}
	t.Fatal("setup error: did not find role editor line")
}

func TestLSP_HoverReturnsRoleInfo(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	cli.request("initialize", initializeParams{})

	src := `warden config 1
tenant t1

role viewer {
    name = "Viewer"
    description = "Read-only access"
    grants = ["doc:read"]
}
`
	openParams := didOpenParams{}
	openParams.TextDocument.URI = "file:///hover.warden"
	openParams.TextDocument.Text = src
	cli.notify("textDocument/didOpen", openParams)
	cli.expectNotification()

	// Cursor inside "viewer" on the role line.
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "role viewer") {
			continue
		}
		col := strings.Index(line, "viewer") + 2 // mid-word
		pp := textDocumentPositionParams{}
		pp.TextDocument.URI = "file:///hover.warden"
		pp.Position = lspPosition{Line: i, Character: col}
		resp := cli.request("textDocument/hover", pp)
		if resp.Error != nil {
			t.Fatalf("hover error: %v", resp.Error)
		}
		var h hoverResult
		if err := json.Unmarshal(resp.Result, &h); err != nil {
			t.Fatalf("decode hover: %v\nraw=%s", err, string(resp.Result))
		}
		if !strings.Contains(h.Contents.Value, "**role**") {
			t.Errorf("hover missing role label: %s", h.Contents.Value)
		}
		if !strings.Contains(h.Contents.Value, "Viewer") {
			t.Errorf("hover missing display name: %s", h.Contents.Value)
		}
		if !strings.Contains(h.Contents.Value, "Read-only access") {
			t.Errorf("hover missing description: %s", h.Contents.Value)
		}
		return
	}
	t.Fatal("setup error: did not find role viewer line")
}

func TestLSP_ShutdownExit(t *testing.T) {
	cli, cleanup := newTestPair(t)
	defer cleanup()

	cli.request("initialize", initializeParams{})
	resp := cli.request("shutdown", nil)
	if resp.Error != nil {
		t.Fatalf("shutdown error: %v", resp.Error)
	}
	cli.notify("exit", nil)
	// cleanup waits for run() to return.
}

// diagMessages helps test failure output stay readable.
func diagMessages(diags []lspDiagnostic) []string {
	out := make([]string, len(diags))
	for i, d := range diags {
		out[i] = fmt.Sprintf("%d:%d %s", d.Range.Start.Line, d.Range.Start.Character, d.Message)
	}
	return out
}
