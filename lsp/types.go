package lsp

// Subset of the LSP types the warden-lsp server actually consumes or
// produces. The full protocol is enormous; we only declare what's wired up.

// LSP positions are 0-based line and UTF-16 code-unit column. The DSL
// uses 1-based byte columns. Conversion happens at the boundary in
// handlers — see toLSPRange / fromLSPPosition.
type lspPosition struct {
	Line      int `json:"line"`      // 0-based
	Character int `json:"character"` // 0-based UTF-16 code unit
}

type lspRange struct {
	Start lspPosition `json:"start"`
	End   lspPosition `json:"end"`
}

type lspLocation struct {
	URI   string   `json:"uri"`
	Range lspRange `json:"range"`
}

// initializeParams — minimal subset.
type initializeParams struct {
	ProcessID    int    `json:"processId,omitempty"`
	RootURI      string `json:"rootUri,omitempty"`
	Capabilities any    `json:"capabilities,omitempty"`
}

// initializeResult — server capabilities.
type initializeResult struct {
	Capabilities serverCapabilities `json:"capabilities"`
	ServerInfo   *serverInfo        `json:"serverInfo,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// serverCapabilities lists the LSP features warden-lsp supports.
//
// TextDocumentSync = 1 means "full text on every change" — we re-parse
// the whole document on each edit, which is cheap given the parser
// throughput (~110 MB/s).
type serverCapabilities struct {
	TextDocumentSync           int                `json:"textDocumentSync"`
	HoverProvider              bool               `json:"hoverProvider"`
	DefinitionProvider         bool               `json:"definitionProvider"`
	DocumentFormattingProvider bool               `json:"documentFormattingProvider,omitempty"`
	CompletionProvider         *completionOptions `json:"completionProvider,omitempty"`
}

// completionOptions advertises the LSP completion capability.
type completionOptions struct {
	TriggerCharacters []string `json:"triggerCharacters,omitempty"`
	ResolveProvider   bool     `json:"resolveProvider,omitempty"`
}

// completionParams — request from the client at a cursor position.
type completionParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
	Position lspPosition         `json:"position"`
	Context  *completionContext0 `json:"context,omitempty"`
}

// completionContext0 — when present, tells us why completion was triggered.
// The "0" suffix avoids collision with the parser's own context type.
type completionContext0 struct {
	TriggerKind      int    `json:"triggerKind"`
	TriggerCharacter string `json:"triggerCharacter,omitempty"`
}

// completionItemKind — LSP enum for the icon shown next to each item.
const (
	completionItemKeyword    = 14
	completionItemValue      = 12
	completionItemConstant   = 21
	completionItemEnum       = 13
	completionItemEnumMember = 20
	completionItemClass      = 7  // resource type
	completionItemInterface  = 8  // policy
	completionItemFunction   = 3  // permission
	completionItemVariable   = 6  // role
	completionItemField      = 5  // policy field / role field
	completionItemProperty   = 10 // relation
)

// completionList is the response shape — `IsIncomplete=false` means the
// editor can client-side filter the items as the user keeps typing.
type completionList struct {
	IsIncomplete bool             `json:"isIncomplete"`
	Items        []completionItem `json:"items"`
}

// completionItem is a single suggestion. Label is the displayed text,
// InsertText (optional) overrides what gets inserted.
type completionItem struct {
	Label         string `json:"label"`
	Kind          int    `json:"kind,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Documentation string `json:"documentation,omitempty"`
	InsertText    string `json:"insertText,omitempty"`
	SortText      string `json:"sortText,omitempty"`
}

// didOpenParams / didChangeParams / didCloseParams — document lifecycle.
type didOpenParams struct {
	TextDocument struct {
		URI        string `json:"uri"`
		LanguageID string `json:"languageId"`
		Version    int    `json:"version"`
		Text       string `json:"text"`
	} `json:"textDocument"`
}

type didChangeParams struct {
	TextDocument struct {
		URI     string `json:"uri"`
		Version int    `json:"version"`
	} `json:"textDocument"`
	ContentChanges []struct {
		Text string `json:"text"`
	} `json:"contentChanges"`
}

type didCloseParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
}

type didSaveParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
	Text string `json:"text,omitempty"`
}

// publishDiagnosticsParams — server → client notification.
type publishDiagnosticsParams struct {
	URI         string          `json:"uri"`
	Diagnostics []lspDiagnostic `json:"diagnostics"`
}

type lspDiagnostic struct {
	Range    lspRange `json:"range"`
	Severity int      `json:"severity"`
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

// Diagnostic severity (LSP enum).
const (
	diagError   = 1
	diagWarning = 2
	diagInfo    = 3
	diagHint    = 4
)

// hoverParams / hoverResult.
type textDocumentPositionParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
	Position lspPosition `json:"position"`
}

type hoverResult struct {
	Contents markupContent `json:"contents"`
	Range    *lspRange     `json:"range,omitempty"`
}

type markupContent struct {
	Kind  string `json:"kind"` // "plaintext" | "markdown"
	Value string `json:"value"`
}

// formatting — minimal.
type formattingParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
	Options any `json:"options,omitempty"`
}

type lspTextEdit struct {
	Range   lspRange `json:"range"`
	NewText string   `json:"newText"`
}
