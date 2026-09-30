// Tree-sitter grammar for the Warden DSL.
//
// This is the source-of-truth grammar definition. Build outputs (C source,
// WASM, npm packaging) belong in a standalone repo at github.com/xraph/
// tree-sitter-warden — fork this file there and run `tree-sitter generate`.
//
// Mirrors the EBNF in the project design doc. Keep this file in sync with
// dsl/parser.go when the grammar changes.

module.exports = grammar({
  name: 'warden',

  extras: $ => [
    /\s+/,
    $.line_comment,
    $.block_comment,
  ],

  word: $ => $.identifier,

  rules: {
    program: $ => seq(
      $.header,
      repeat($._stmt),
    ),

    header: $ => seq(
      'warden',
      'config',
      $.int_literal,
      optional(seq('tenant', $._name)),
      optional(seq('app', $._name)),
    ),

    _stmt: $ => choice(
      $.namespace_decl,
      $.resource_decl,
      $.permission_decl,
      $.role_decl,
      $.policy_decl,
      $.relation_decl,
      $.import_stmt,
    ),

    namespace_decl: $ => seq(
      'namespace',
      choice($.string_literal, $.identifier),
      '{',
      repeat($._stmt),
      '}',
    ),

    resource_decl: $ => seq(
      'resource',
      field('name', $._name),
      '{',
      repeat($._resource_member),
      '}',
    ),

    _resource_member: $ => choice(
      $.relation_def,
      $.resource_permission_decl,
      $.description_assign,
    ),

    // A relation may allow no subject type: `relation x:` with nothing after
    // the colon.
    relation_def: $ => seq(
      'relation',
      field('name', $._name),
      ':',
      optional($._subject_types),
    ),

    _subject_types: $ => seq(
      $._subject_type,
      repeat(seq('|', $._subject_type)),
    ),

    _subject_type: $ => seq(
      $._name,
      optional(seq('#', $._name)),
    ),

    resource_permission_decl: $ => seq(
      'permission',
      field('name', $._name),
      '=',
      field('expr', $._expr),
    ),

    permission_decl: $ => seq(
      'permission',
      field('name', $.string_literal),
      optional(choice(
        seq('(', $._name, ':', $._name, ')'),
        seq('{', repeat($._permission_member), '}'),
      )),
    ),

    _permission_member: $ => choice(
      seq('resource', '=', $._name),
      $._kv,
    ),

    role_decl: $ => seq(
      'role',
      field('slug', $._name),
      optional(seq(':', field('parent', $._role_parent))),
      '{',
      repeat($._role_member),
      '}',
    ),

    _role_parent: $ => choice(
      $._name,
      seq('/', $.identifier, repeat(seq('/', $.identifier))),
    ),

    _role_member: $ => choice(
      $.field_assign,
      $.grants_assign,
    ),

    // `grants = [...]`: permission names, and qualified grants
    // `{ namespace = "eng", name = "deploy:run" }` for a permission a name
    // alone cannot reach. `grants = []` revokes every grant.
    grants_assign: $ => seq(
      'grants',
      choice('=', '+='),
      $.grant_list,
    ),

    grant_list: $ => seq(
      '[',
      optional(seq(
        $._grant,
        repeat(seq(',', $._grant)),
        optional(','),
      )),
      ']',
    ),

    _grant: $ => choice($.string_literal, $.qualified_grant),

    qualified_grant: $ => seq(
      '{',
      repeat(seq(field('key', choice('namespace', 'name')), '=', $.string_literal, optional(','))),
      '}',
    ),

    policy_decl: $ => seq(
      'policy',
      field('name', $.string_literal),
      '{',
      repeat($._policy_member),
      '}',
    ),

    _policy_member: $ => choice(
      $.field_assign,
      $.string_list_assign,
      $.subjects_assign,
      $.when_block,
    ),

    // `subjects = [{ kind = "user" }, { id = "alice" }, { role = "admin" },
    // { kind = "user", id = "bob", role = "temp" }, {}]`. The fields of one
    // matcher are AND-ed; `{}` matches every subject.
    subjects_assign: $ => seq('subjects', '=', $.subject_list),

    subject_list: $ => seq(
      '[',
      optional(seq(
        $.subject_matcher,
        repeat(seq(',', $.subject_matcher)),
        optional(','),
      )),
      ']',
    ),

    subject_matcher: $ => seq(
      '{',
      repeat(seq(field('key', choice('kind', 'id', 'role')), '=', $.string_literal, optional(','))),
      '}',
    ),

    when_block: $ => seq('when', '{', repeat($._condition), '}'),

    _condition: $ => choice(
      $.condition_atom,
      $.condition_group,
    ),

    // A field a bare path cannot spell is a string literal. The value is
    // optional for exists / not exists (the Go parser reads one only on the
    // operator's own line, which this grammar does not model).
    condition_atom: $ => seq(
      choice($._field_path, $.string_literal),
      $._operator,
      optional($._value),
      optional('negate'),
    ),

    condition_group: $ => seq(
      choice('all_of', 'any_of'),
      '{',
      repeat($._condition),
      '}',
    ),

    // A path segment may be a keyword: resource.name, subject.role.
    _field_path: $ => seq(
      $._field_segment,
      repeat(choice(
        seq('.', $._field_segment),
        seq('.', '[', $.string_literal, ']'),
      )),
    ),

    _field_segment: $ => choice(
      $.identifier,
      alias(choice(
        'resource', 'role', 'name', 'description', 'subjects', 'actions',
        'resources', 'metadata', 'priority', 'active', 'effect', 'relation',
        'permission', 'policy', 'namespace', 'tenant', 'app',
      ), $.identifier),
    ),

    _operator: $ => choice(
      '==', '!=', '<=', '>=', '<', '>', '=~',
      'in', seq('not', 'in'),
      'contains', 'starts_with', 'ends_with',
      'exists', seq('not', 'exists'),
      'ip_in_cidr', 'time_after', 'time_before',
    ),

    relation_decl: $ => seq(
      'relation',
      $._name, ':', $._name,
      $._name,
      '=',
      $._name, ':', $._name,
      optional(seq('#', $._name)),
    ),

    import_stmt: $ => seq('import', $.string_literal),

    description_assign: $ => seq('description', '=', $.string_literal),

    field_assign: $ => seq(
      field('key', $.identifier),
      '=',
      field('value', $._literal),
    ),

    string_list_assign: $ => seq(
      field('key', $.identifier),
      '=',
      $.string_list,
    ),

    _kv: $ => $.field_assign,

    // Permission expressions — Pratt-style precedence.
    _expr: $ => $._or_expr,
    _or_expr: $ => choice($._and_expr, $.or_expr),
    or_expr: $ => prec.left(1, seq($._or_expr, choice('or', '+'), $._and_expr)),
    _and_expr: $ => choice($._not_expr, $.and_expr),
    and_expr: $ => prec.left(2, seq($._and_expr, choice('and', '&'), $._not_expr)),
    _not_expr: $ => choice($._primary, $.not_expr),
    not_expr: $ => prec(3, seq(choice('not', '!', '-'), $._not_expr)),
    _primary: $ => choice(
      seq('(', $._expr, ')'),
      $.traverse_expr,
      $.identifier,
    ),
    traverse_expr: $ => prec(4, seq($.identifier, repeat1(seq('->', $.identifier)))),

    // Lexical primitives.
    //
    // A name is a bare identifier, or a string literal for a name a bare
    // identifier cannot spell (a keyword, a leading digit, a space, a colon
    // such as warden:role, a glob such as *).
    _name: $ => choice($.identifier, $.string_literal),
    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_-]*/,
    int_literal: $ => /\d+/,
    float_literal: $ => /\d+\.\d+/,
    number_literal: $ => seq(optional('-'), choice($.float_literal, $.int_literal)),
    string_literal: $ => /"([^"\\]|\\.)*"/,
    string_list: $ => seq('[', optional(seq($.string_literal, repeat(seq(',', $.string_literal)), optional(','))), ']'),
    _literal: $ => choice($.string_literal, $.int_literal, $.bool_literal, $.string_list),
    // A condition value: a string, a number (a decimal, a sign), a bool, or
    // a list mixing them.
    _value: $ => choice($.string_literal, $.number_literal, $.bool_literal, $.value_list),
    value_list: $ => seq('[', optional(seq($._value_item, repeat(seq(',', $._value_item)), optional(','))), ']'),
    _value_item: $ => choice($.string_literal, $.number_literal, $.bool_literal),
    bool_literal: $ => choice('true', 'false'),

    line_comment: $ => token(seq('//', /[^\n]*/)),
    block_comment: $ => token(seq('/*', repeat(choice(/[^*]/, /\*[^/]/)), '*/')),
  },
});
