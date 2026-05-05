// Package lsp implements the Warden Language Server Protocol server for
// the .warden DSL.
//
// Both binaries reach the same code: the standalone `cmd/warden-lsp` and
// the `warden lsp` subcommand both delegate to lsp.Run, so editor configs
// can point at either entry point interchangeably.
//
// Protocol layer: minimal hand-rolled JSON-RPC 2.0 with LSP framing
// (Content-Length headers). No external dependencies — reuses dsl/ for
// parsing, resolving, formatting, and AST queries.
package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// rpcMessage is the JSON-RPC 2.0 envelope. Either Method (request/notification)
// or Result/Error (response) is set; never both.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`     // omitted on notifications
	Method  string          `json:"method,omitempty"` // omitted on responses
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC error codes from the LSP spec.
const (
	errParseError     = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternalError  = -32603
)

// readMessage reads a single LSP-framed JSON-RPC message from r. The frame
// is `Content-Length: N\r\n\r\n` followed by N bytes of UTF-8 JSON.
//
// Returns io.EOF on clean end-of-stream.
func readMessage(r *bufio.Reader) (*rpcMessage, error) {
	var contentLength int
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // headers complete
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			return nil, fmt.Errorf("warden-lsp: malformed header %q", line)
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if strings.EqualFold(key, "Content-Length") {
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("warden-lsp: invalid Content-Length %q", val)
			}
			contentLength = n
		}
	}
	if contentLength <= 0 {
		return nil, fmt.Errorf("warden-lsp: missing or zero Content-Length")
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("warden-lsp: parse JSON-RPC: %w", err)
	}
	return &msg, nil
}

// writeMessage serializes msg with the LSP framing.
func writeMessage(w io.Writer, msg *rpcMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("warden-lsp: marshal JSON-RPC: %w", err)
	}
	if _, werr := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(body)); werr != nil {
		return werr
	}
	_, err = w.Write(body)
	return err
}

// makeResponse builds a successful JSON-RPC response for the given request ID.
func makeResponse(id json.RawMessage, result any) (*rpcMessage, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &rpcMessage{JSONRPC: "2.0", ID: id, Result: encoded}, nil
}

// makeError builds an error response for the given request ID.
func makeError(id json.RawMessage, code int, message string) *rpcMessage {
	return &rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
}

// makeNotification builds a server-initiated notification.
func makeNotification(method string, params any) (*rpcMessage, error) {
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &rpcMessage{JSONRPC: "2.0", Method: method, Params: encoded}, nil
}
