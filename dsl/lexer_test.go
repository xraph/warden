package dsl

import (
	"reflect"
	"testing"
)

// tok is a compact constructor for expected tokens in tests.
func tok(k TokenKind, v string, line, col int) Token {
	return Token{Kind: k, Value: v, Pos: Pos{Line: line, Col: col}}
}

func TestLexer_HappyPath(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Token
	}{
		{
			name: "header",
			src:  "warden config 1",
			want: []Token{
				tok(WARDEN, "warden", 1, 1),
				tok(CONFIG, "config", 1, 8),
				tok(INT, "1", 1, 15),
				tok(EOF, "", 1, 16),
			},
		},
		{
			name: "tenant + app",
			src:  "tenant t1\napp app1",
			want: []Token{
				tok(TENANT, "tenant", 1, 1),
				tok(IDENT, "t1", 1, 8),
				tok(APP, "app", 2, 1),
				tok(IDENT, "app1", 2, 5),
				tok(EOF, "", 2, 9),
			},
		},
		{
			name: "string literal with escapes",
			src:  `name = "hello \"world\""`,
			want: []Token{
				tok(NAME, "name", 1, 1),
				tok(ASSIGN, "=", 1, 6),
				tok(STRING, `hello "world"`, 1, 8),
				tok(EOF, "", 1, 25),
			},
		},
		{
			name: "operators",
			src:  "= += -> == != <= >= < > + - & =~ |",
			want: []Token{
				tok(ASSIGN, "=", 1, 1),
				tok(APPEND, "+=", 1, 3),
				tok(ARROW, "->", 1, 6),
				tok(EQ, "==", 1, 9),
				tok(NE, "!=", 1, 12),
				tok(LE, "<=", 1, 15),
				tok(GE, ">=", 1, 18),
				tok(LT, "<", 1, 21),
				tok(GT, ">", 1, 23),
				tok(PLUS, "+", 1, 25),
				tok(MINUS, "-", 1, 27),
				tok(AMP, "&", 1, 29),
				tok(REGEX, "=~", 1, 31),
				tok(PIPE, "|", 1, 34),
				tok(EOF, "", 1, 35),
			},
		},
		{
			name: "punctuation",
			src:  "{ } ( ) [ ] , : ; . #",
			want: []Token{
				tok(LBRACE, "{", 1, 1),
				tok(RBRACE, "}", 1, 3),
				tok(LPAREN, "(", 1, 5),
				tok(RPAREN, ")", 1, 7),
				tok(LBRACKET, "[", 1, 9),
				tok(RBRACKET, "]", 1, 11),
				tok(COMMA, ",", 1, 13),
				tok(COLON, ":", 1, 15),
				tok(SEMI, ";", 1, 17),
				tok(DOT, ".", 1, 19),
				tok(HASH, "#", 1, 21),
				tok(EOF, "", 1, 22),
			},
		},
		{
			name: "keywords vs identifiers",
			src:  "role viewer permission edit",
			want: []Token{
				tok(ROLE, "role", 1, 1),
				tok(IDENT, "viewer", 1, 6),
				tok(PERMISSION, "permission", 1, 13),
				tok(IDENT, "edit", 1, 24),
				tok(EOF, "", 1, 28),
			},
		},
		{
			name: "boolean literals",
			src:  "is_system = true",
			want: []Token{
				tok(IS_SYSTEM, "is_system", 1, 1),
				tok(ASSIGN, "=", 1, 11),
				tok(BOOL, "true", 1, 13),
				tok(EOF, "", 1, 17),
			},
		},
		{
			name: "expression with traversal",
			src:  "viewer or parent->read",
			want: []Token{
				tok(IDENT, "viewer", 1, 1),
				tok(OR, "or", 1, 8),
				tok(IDENT, "parent", 1, 11),
				tok(ARROW, "->", 1, 17),
				tok(IDENT, "read", 1, 19),
				tok(EOF, "", 1, 23),
			},
		},
		{
			name: "line comment",
			src:  "// this is a comment\nrole viewer",
			want: []Token{
				tok(ROLE, "role", 2, 1),
				tok(IDENT, "viewer", 2, 6),
				tok(EOF, "", 2, 12),
			},
		},
		{
			name: "block comment",
			src:  "role /* a block\ncomment */ viewer",
			want: []Token{
				tok(ROLE, "role", 1, 1),
				tok(IDENT, "viewer", 2, 12),
				tok(EOF, "", 2, 18),
			},
		},
		{
			name: "kebab-case identifier",
			src:  "billing-admin",
			want: []Token{
				tok(IDENT, "billing-admin", 1, 1),
				tok(EOF, "", 1, 14),
			},
		},
		{
			name: "permission with colon-separated string",
			src:  `permission "document:read"`,
			want: []Token{
				tok(PERMISSION, "permission", 1, 1),
				tok(STRING, "document:read", 1, 12),
				tok(EOF, "", 1, 27),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lexAll(t, tt.src)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("token stream mismatch\nwant: %v\ngot:  %v", tt.want, got)
			}
		})
	}
}

func TestLexer_Errors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		// We don't pin exact error positions here, just that an ILLEGAL token appears.
	}{
		{"unterminated string", `"hello`},
		{"unterminated block comment", "/* unterminated"},
		{"unknown character", "@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lexAll(t, tt.src)
			sawIllegal := false
			for _, tok := range got {
				if tok.Kind == ILLEGAL {
					sawIllegal = true
					break
				}
			}
			if !sawIllegal {
				t.Fatalf("expected ILLEGAL token, got %v", got)
			}
		})
	}
}

func lexAll(t *testing.T, src string) []Token {
	t.Helper()
	l := NewLexer("test.warden", []byte(src))
	var toks []Token
	for {
		t := l.Next()
		// Strip filename from positions to keep tests concise.
		t.Pos.File = ""
		toks = append(toks, t)
		if t.Kind == EOF {
			break
		}
		if len(toks) > 1000 {
			break
		}
	}
	return toks
}
