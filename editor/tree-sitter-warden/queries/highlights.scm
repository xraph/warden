; Tree-sitter highlight queries for the Warden DSL.
; Maps grammar.js nodes to standard tree-sitter capture names.

; Header keywords.
(program "warden" @keyword)
(header "config" @keyword)
(header "tenant" @keyword)
(header "app" @keyword)

; Top-level declaration keywords.
"namespace" @keyword
"resource" @keyword
"relation" @keyword
"permission" @keyword
"role" @keyword
"policy" @keyword
"import" @keyword
"effect" @keyword
"when" @keyword
"all_of" @keyword
"any_of" @keyword
"grants" @keyword
"description" @keyword
"name" @keyword
"priority" @keyword
"active" @keyword
"actions" @keyword
"resources" @keyword
"subjects" @keyword
"is_system" @keyword
"is_default" @keyword
"max_members" @keyword
"metadata" @keyword
"negate" @keyword

; Logical / traversal operators.
"or" @keyword.operator
"and" @keyword.operator
"not" @keyword.operator
"->" @operator
"+=" @operator
"=" @operator
"==" @operator
"!=" @operator
"<=" @operator
">=" @operator
"<" @operator
">" @operator
"=~" @operator

; Condition operator keywords.
"in" @keyword.operator
"contains" @keyword.operator
"starts_with" @keyword.operator
"ends_with" @keyword.operator
"exists" @keyword.operator
"ip_in_cidr" @keyword.operator
"time_after" @keyword.operator
"time_before" @keyword.operator

; Entity-name captures.
(resource_decl name: (identifier) @type)
(role_decl slug: (identifier) @function)
(role_decl parent: (identifier) @function)
(permission_decl name: (string_literal) @function)
(resource_permission_decl name: (identifier) @function)
(relation_def name: (identifier) @property)

; Field keys.
(field_assign key: (identifier) @property)
(string_list_assign key: (identifier) @property)

; Literals.
"allow" @constant.builtin
"deny" @constant.builtin
(bool_literal) @constant.builtin
(int_literal) @number
(string_literal) @string

; Comments.
(line_comment) @comment
(block_comment) @comment
