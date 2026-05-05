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
      optional(seq('tenant', $.identifier)),
      optional(seq('app', $.identifier)),
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
      field('name', $.identifier),
      '{',
      repeat($._resource_member),
      '}',
    ),

    _resource_member: $ => choice(
      $.relation_def,
      $.resource_permission_decl,
      $.description_assign,
    ),

    relation_def: $ => seq(
      'relation',
      field('name', $.identifier),
      ':',
      $._subject_types,
    ),

    _subject_types: $ => seq(
      $._subject_type,
      repeat(seq('|', $._subject_type)),
    ),

    _subject_type: $ => seq(
      $.identifier,
      optional(seq('#', $.identifier)),
    ),

    resource_permission_decl: $ => seq(
      'permission',
      field('name', $.identifier),
      '=',
      field('expr', $._expr),
    ),

    permission_decl: $ => seq(
      'permission',
      field('name', $.string_literal),
      optional(choice(
        seq('(', $.identifier, ':', $.identifier, ')'),
        seq('{', repeat($._kv), '}'),
      )),
    ),

    role_decl: $ => seq(
      'role',
      field('slug', $.identifier),
      optional(seq(':', field('parent', $._role_parent))),
      '{',
      repeat($._role_member),
      '}',
    ),

    _role_parent: $ => choice(
      $.identifier,
      seq('/', $.identifier, repeat(seq('/', $.identifier))),
    ),

    _role_member: $ => choice(
      $.field_assign,
      $.grants_assign,
    ),

    grants_assign: $ => seq(
      'grants',
      choice('=', '+='),
      $.string_list,
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
      $.when_block,
    ),

    when_block: $ => seq('when', '{', repeat($._condition), '}'),

    _condition: $ => choice(
      $.condition_atom,
      $.condition_group,
    ),

    condition_atom: $ => seq(
      $._field_path,
      $._operator,
      $._literal,
      optional('negate'),
    ),

    condition_group: $ => seq(
      choice('all_of', 'any_of'),
      '{',
      repeat($._condition),
      '}',
    ),

    _field_path: $ => seq(
      $.identifier,
      repeat(choice(
        seq('.', $.identifier),
        seq('[', $.string_literal, ']'),
      )),
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
      $.identifier, ':', $.identifier,
      $.identifier,
      '=',
      $.identifier, ':', $.identifier,
      optional(seq('#', $.identifier)),
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
    identifier: $ => /[a-z_][a-zA-Z0-9_-]*/,
    int_literal: $ => /\d+/,
    string_literal: $ => /"([^"\\]|\\.)*"/,
    string_list: $ => seq('[', optional(seq($.string_literal, repeat(seq(',', $.string_literal)), optional(','))), ']'),
    _literal: $ => choice($.string_literal, $.int_literal, $.bool_literal, $.string_list),
    bool_literal: $ => choice('true', 'false'),

    line_comment: $ => token(seq('//', /[^\n]*/)),
    block_comment: $ => token(seq('/*', repeat(choice(/[^*]/, /\*[^/]/)), '*/')),
  },
});
