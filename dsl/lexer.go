package dsl

import (
	"strings"
	"unicode/utf8"
)

// Lexer is a hand-written tokenizer for `.warden` source.
//
// Encoding is UTF-8; positions are tracked in 1-based line and byte column.
// The lexer never errors fatally — it returns ILLEGAL tokens for malformed
// input and lets the parser report richer diagnostics.
type Lexer struct {
	file string
	src  []byte

	// Cursor — byte offset.
	pos int

	// Position cursor advances with pos.
	curLine int
	curCol  int

	// pendingError holds an ILLEGAL token detected during trivia skipping
	// (most notably an unterminated block comment) so the next Next() call
	// can surface it.
	pendingError *Token
}

// NewLexer constructs a fresh Lexer over the given source bytes.
func NewLexer(file string, src []byte) *Lexer {
	return &Lexer{
		file:    file,
		src:     src,
		curLine: 1,
		curCol:  1,
	}
}

// Next returns the next token. After EOF is returned, every subsequent call
// keeps returning EOF.
func (l *Lexer) Next() Token {
	l.skipTrivia()
	if l.pendingError != nil {
		t := *l.pendingError
		l.pendingError = nil
		return t
	}
	startLine, startCol := l.curLine, l.curCol
	startPos := Pos{File: l.file, Line: startLine, Col: startCol}

	if l.pos >= len(l.src) {
		return Token{Kind: EOF, Pos: startPos}
	}

	ch := l.src[l.pos]
	switch {
	case ch == '"':
		return l.readString(startPos)
	case isIdentStart(ch):
		return l.readIdent(startPos)
	case isDigit(ch):
		return l.readInt(startPos)
	}

	// Punctuation / operators.
	switch ch {
	case '{':
		l.advance()
		return Token{Kind: LBRACE, Value: "{", Pos: startPos}
	case '}':
		l.advance()
		return Token{Kind: RBRACE, Value: "}", Pos: startPos}
	case '(':
		l.advance()
		return Token{Kind: LPAREN, Value: "(", Pos: startPos}
	case ')':
		l.advance()
		return Token{Kind: RPAREN, Value: ")", Pos: startPos}
	case '[':
		l.advance()
		return Token{Kind: LBRACKET, Value: "[", Pos: startPos}
	case ']':
		l.advance()
		return Token{Kind: RBRACKET, Value: "]", Pos: startPos}
	case ',':
		l.advance()
		return Token{Kind: COMMA, Value: ",", Pos: startPos}
	case ':':
		l.advance()
		return Token{Kind: COLON, Value: ":", Pos: startPos}
	case ';':
		l.advance()
		return Token{Kind: SEMI, Value: ";", Pos: startPos}
	case '.':
		l.advance()
		return Token{Kind: DOT, Value: ".", Pos: startPos}
	case '|':
		l.advance()
		return Token{Kind: PIPE, Value: "|", Pos: startPos}
	case '#':
		l.advance()
		return Token{Kind: HASH, Value: "#", Pos: startPos}
	case '&':
		l.advance()
		return Token{Kind: AMP, Value: "&", Pos: startPos}
	case '+':
		l.advance()
		if l.peek(0) == '=' {
			l.advance()
			return Token{Kind: APPEND, Value: "+=", Pos: startPos}
		}
		return Token{Kind: PLUS, Value: "+", Pos: startPos}
	case '-':
		l.advance()
		if l.peek(0) == '>' {
			l.advance()
			return Token{Kind: ARROW, Value: "->", Pos: startPos}
		}
		return Token{Kind: MINUS, Value: "-", Pos: startPos}
	case '=':
		l.advance()
		switch l.peek(0) {
		case '=':
			l.advance()
			return Token{Kind: EQ, Value: "==", Pos: startPos}
		case '~':
			l.advance()
			return Token{Kind: REGEX, Value: "=~", Pos: startPos}
		}
		return Token{Kind: ASSIGN, Value: "=", Pos: startPos}
	case '!':
		l.advance()
		if l.peek(0) == '=' {
			l.advance()
			return Token{Kind: NE, Value: "!=", Pos: startPos}
		}
		return Token{Kind: BANG, Value: "!", Pos: startPos}
	case '<':
		l.advance()
		if l.peek(0) == '=' {
			l.advance()
			return Token{Kind: LE, Value: "<=", Pos: startPos}
		}
		return Token{Kind: LT, Value: "<", Pos: startPos}
	case '>':
		l.advance()
		if l.peek(0) == '=' {
			l.advance()
			return Token{Kind: GE, Value: ">=", Pos: startPos}
		}
		return Token{Kind: GT, Value: ">", Pos: startPos}
	case '/':
		// Note: line/block comments are handled in skipTrivia. By the time we
		// reach this branch we're inside `Next` past trivia, so `/` is the
		// SLASH operator (used for absolute namespace paths).
		l.advance()
		return Token{Kind: SLASH, Value: "/", Pos: startPos}
	}

	// Anything else is an illegal character. Consume one rune so we don't loop.
	r, size := utf8.DecodeRune(l.src[l.pos:])
	for i := 0; i < size; i++ {
		l.advance()
	}
	return Token{Kind: ILLEGAL, Value: string(r), Pos: startPos}
}

// readString reads a double-quoted string literal, unescaping \\, \", \n, \t.
// A missing closing quote returns ILLEGAL.
func (l *Lexer) readString(startPos Pos) Token {
	l.advance() // consume opening "
	var b strings.Builder
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '"' {
			l.advance()
			return Token{Kind: STRING, Value: b.String(), Pos: startPos}
		}
		if ch == '\n' {
			return Token{Kind: ILLEGAL, Value: "unterminated string", Pos: startPos}
		}
		if ch == '\\' {
			l.advance()
			if l.pos >= len(l.src) {
				return Token{Kind: ILLEGAL, Value: "unterminated string escape", Pos: startPos}
			}
			esc := l.src[l.pos]
			l.advance()
			switch esc {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte('\\')
				b.WriteByte(esc)
			}
			continue
		}
		b.WriteByte(ch)
		l.advance()
	}
	return Token{Kind: ILLEGAL, Value: "unterminated string", Pos: startPos}
}

// readIdent reads an identifier or keyword.
//
// Identifiers may contain hyphens (kebab-case), but a hyphen immediately
// followed by `>` is the start of the `->` arrow operator and terminates
// the identifier. This lets us write `parent->read` without ambiguity
// while still supporting `billing-admin`.
func (l *Lexer) readIdent(startPos Pos) Token {
	start := l.pos
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '-' && l.peek(1) == '>' {
			break
		}
		if !isIdentPart(ch) {
			break
		}
		l.advance()
	}
	lex := string(l.src[start:l.pos])
	if kw, ok := keywords[lex]; ok {
		// Booleans keep their lexeme so the parser can distinguish true/false.
		if kw == BOOL {
			return Token{Kind: BOOL, Value: lex, Pos: startPos}
		}
		return Token{Kind: kw, Value: lex, Pos: startPos}
	}
	return Token{Kind: IDENT, Value: lex, Pos: startPos}
}

// readInt reads an unsigned integer literal.
func (l *Lexer) readInt(startPos Pos) Token {
	start := l.pos
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.advance()
	}
	return Token{Kind: INT, Value: string(l.src[start:l.pos]), Pos: startPos}
}

// skipTrivia skips whitespace, line comments (// ... \n), and block comments (/* ... */).
// Unterminated block comments cause a sentinel ILLEGAL token at the next Next() call.
func (l *Lexer) skipTrivia() {
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		switch {
		case ch == ' ', ch == '\t', ch == '\r', ch == '\n':
			l.advance()
		case ch == '/' && l.peek(1) == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance()
			}
		case ch == '/' && l.peek(1) == '*':
			startPos := Pos{File: l.file, Line: l.curLine, Col: l.curCol}
			l.advance()
			l.advance()
			closed := false
			for l.pos < len(l.src) {
				if l.src[l.pos] == '*' && l.peek(1) == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				l.pendingError = &Token{Kind: ILLEGAL, Value: "unterminated block comment", Pos: startPos}
				return
			}
		default:
			return
		}
	}
}

// peek returns the byte at offset n from the current position, or 0 at EOF.
func (l *Lexer) peek(n int) byte {
	if l.pos+n >= len(l.src) {
		return 0
	}
	return l.src[l.pos+n]
}

// advance moves the position forward by one byte and updates line/col.
func (l *Lexer) advance() {
	if l.pos >= len(l.src) {
		return
	}
	if l.src[l.pos] == '\n' {
		l.curLine++
		l.curCol = 1
	} else {
		l.curCol++
	}
	l.pos++
}

// isIdentStart accepts a permissive alphabet (a-z, A-Z, _) so that violations
// of the slug/name conventions (which require lowercase) are surfaced by the
// resolver as helpful diagnostics rather than as opaque lexer errors.
func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '-'
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
