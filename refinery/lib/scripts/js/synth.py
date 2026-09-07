from __future__ import annotations

from typing import Callable

from refinery.lib.scripts import Node, Synthesizer
from refinery.lib.scripts.js.deobfuscation.helpers import (
    escape_js_string,
    escape_js_template_text,
)
from refinery.lib.scripts.js.lexer import identifier_string_value
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBigIntLiteral,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassBody,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDebuggerStatement,
    JsDecorator,
    JsDoWhileStatement,
    JsEmptyStatement,
    JsErrorNode,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExportSpecifier,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsImportAttribute,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportExpression,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMemberExpression,
    JsMetaProperty,
    JsMethodDefinition,
    JsMethodKind,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsPrivateIdentifier,
    JsProperty,
    JsPropertyDefinition,
    JsPropertyKind,
    JsRegExpLiteral,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStaticBlock,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsTemplateElement,
    JsTemplateLiteral,
    JsThisExpression,
    JsThrowStatement,
    JsTryStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    JsWithStatement,
    JsYieldExpression,
    Statement,
)
from refinery.lib.scripts.js.numbers import exact_integer, is_negative_zero
from refinery.lib.scripts.js.precedence import (
    for_in_target_needs_parens,
    for_initializer_needs_parens,
    for_of_target_needs_parens,
    needs_parens,
    statement_needs_parens,
)
from refinery.lib.scripts.js.strict import promoted_use_strict, spelling_states
from refinery.lib.scripts.js.token import spells_only_a_name
from refinery.lib.scripts.js.utf16 import from_code_units
from refinery.lib.tools import RecursionDepth

_WORD_UNARY_OPS = frozenset({'typeof', 'void', 'delete'})

_BYTE_GRID_COLUMNS = 15


def _is_decorator_member(expr: Node) -> bool:
    """
    Whether *expr* is a `DecoratorMemberExpression`: a bare identifier or a dotted chain of
    non-computed member accesses bottoming out in one (`a`, `a.b.c`). A computed member (`a[b]`) or a
    member whose base is a call (`a().b`) is not, so it cannot follow `@` without parentheses.
    """
    if isinstance(expr, JsIdentifier):
        return True
    if isinstance(expr, JsMemberExpression) and not expr.computed and isinstance(expr.property, JsIdentifier):
        return expr.object is not None and _is_decorator_member(expr.object)
    return False


def _is_bare_decorator(expr: Node) -> bool:
    """
    Whether *expr* may follow `@` without parentheses. The decorator grammar admits only a
    `DecoratorMemberExpression` (`a`, `a.b`) or a `DecoratorCallExpression` — one such member chain
    applied to a single argument list (`a.b()`). Any other expression (a computed member, a chained or
    higher-order call, an arbitrary expression) must be wrapped in parentheses to round-trip.
    """
    if _is_decorator_member(expr):
        return True
    if isinstance(expr, JsCallExpression) and expr.callee is not None:
        return _is_decorator_member(expr.callee)
    return False


class JsSynthesizer(Synthesizer):

    def __init__(
        self,
        indent: str = '  ',
        line_length: int = 140,
        unescape_strings: bool = False,
        strip_comments: bool = False,
    ):
        super().__init__(indent, line_length)
        self._unescape_strings = unescape_strings
        self._strip_comments = strip_comments
        self._cut = False

    def convert(self, node: Node) -> str:
        self._cut = False
        with RecursionDepth(10000):
            return super().convert(node)

    def _write(self, text: str):
        """
        Nothing is written past the end of the file. A construct the file ended inside — a
        literal, a block — writes what it holds and then cuts the output, so that no closing
        bracket, quote or semicolon the file did not hold is written behind it.
        """
        if not self._cut:
            super()._write(text)

    def _newline(self):
        if not self._cut:
            super()._newline()

    def _emit_leading_comments(self, node: Node):
        if self._strip_comments or not node.leading_comments:
            return
        for comment in node.leading_comments:
            self._write(comment)
            self._newline()

    @staticmethod
    def _opens_html_close_comment(stmt: Node) -> bool:
        """
        Whether *stmt* is unread text opening with `-->`, which at the head of a line would open a
        comment and swallow the line: such text is written on the line of what precedes it, where
        the lexer read it as the decrement and the `>` it is.
        """
        return isinstance(stmt, JsErrorNode) and stmt.text.startswith('-->')

    def _separate(self, stmt: Node):
        if self._opens_html_close_comment(stmt):
            self._write(' ')
        else:
            self._newline()

    def _emit_block_node(self, block: JsBlockStatement, *, prologue: bool = False):
        self._emit_block(block.body, prologue=prologue, owner=block)

    def _emit_block(
        self,
        body: list[Statement],
        *,
        prologue: bool = False,
        owner: JsBlockStatement | JsStaticBlock | None = None,
    ):
        """
        Write *body* as a braced block. *prologue* says that this block is a body a Directive
        Prologue opens — a function body or a class static block — where a `'use strict'` standing
        at the head is read as a directive and makes the body strict. Every other block holds
        ordinary statements, and passing `True` for one of those would parenthesize a string that
        governs nothing.
        """
        self._write('{')
        self._depth += 1
        self._emit_statements(body, prologue=prologue)
        self._depth -= 1
        if owner is not None and not owner.terminated:
            self._cut = True
            return
        if body:
            self._newline()
        self._write('}')

    def _emit_statements(self, body: list[Statement], *, prologue: bool):
        promoted = promoted_use_strict(body) if prologue else []
        for stmt in body:
            self._separate(stmt)
            self._emit_leading_comments(stmt)
            self._emit_body_statement(stmt, promoted)

    def _emit_body_statement(self, stmt: Statement, promoted: list[JsExpressionStatement]):
        """
        Write one statement of a body, parenthesizing it when it is one of *promoted* — a
        `'use strict'` an edit moved into the Directive Prologue rather than the source having
        written it there.

        The parenthesis is what keeps the mode where the file left it. A directive is a statement
        whose expression *is* the literal, so `('use strict');` computes the same string and declares
        nothing, and the run it stood in ends at it. That last part is why only a string which would
        otherwise turn the body strict is worth writing this way: ending the run ejects every
        directive behind it, and for an inert string that is a cost paid for nothing.
        """
        if isinstance(stmt, JsExpressionStatement) and any(p is stmt for p in promoted):
            literal = stmt.expression
            if isinstance(literal, JsStringLiteral):
                self._write('(')
                self.visit(literal)
                self._write(');')
                return
        self.visit(stmt)

    def _emit_child(self, child: Node | None, parent: Node):
        """
        Emit *child* in the context of *parent*, wrapping it in parentheses when operator precedence
        requires it. This makes the printed output correct regardless of whether the tree carries
        an explicit `refinery.lib.scripts.js.model.JsParenthesizedExpression` node in that position.
        """
        if child is None:
            return
        if needs_parens(child, parent):
            self._write('(')
            self.visit(child)
            self._write(')')
        else:
            self.visit(child)

    def _emit_element(self, node, wrap_sequences: bool):
        if node is None:
            return
        if wrap_sequences and isinstance(node, JsSequenceExpression):
            self._write('(')
            self.visit(node)
            self._write(')')
        else:
            self.visit(node)

    def _comma_separated(
        self,
        nodes: list,
        lead_newline: bool = True,
        wrap_sequences: bool = False,
    ) -> bool:
        if not nodes:
            return False
        save_pos = self._parts.tell()
        save_col = self._col
        save_cut = self._cut
        overflow = False
        for i, node in enumerate(nodes):
            if i > 0:
                self._write(', ')
            self._emit_element(node, wrap_sequences)
            if self._col > self._line_length:
                overflow = True
                break
        if not overflow:
            return False
        self._parts.seek(save_pos)
        self._parts.truncate()
        self._col = save_col
        self._cut = save_cut
        self._depth += 1
        for i, node in enumerate(nodes):
            if i > 0 or lead_newline:
                self._newline()
            self._emit_element(node, wrap_sequences)
            if i < len(nodes) - 1:
                self._write(',')
        self._depth -= 1
        return True

    def _emit_params(self, params: list):
        self._write('(')
        if self._comma_separated(params):
            self._newline()
        self._write(')')

    def _emit_function_prefix(self, is_async: bool, generator: bool):
        if is_async:
            self._write('async ')
        self._write('function')
        if generator:
            self._write('*')

    def _emit_key(self, key: Node | None, computed: bool):
        """
        A computed key holds one operand and not a whole expression, so a sequence written as one
        keeps its brackets: without them the first comma ends the key rather than continuing it, and
        the text is not a program at all.
        """
        if computed:
            self._write('[')
            self._emit_element(key, True)
            self._write(']')
        elif key:
            self.visit(key)

    def visit_JsNumericLiteral(self, node: JsNumericLiteral):
        self._write(node.raw)

    def visit_JsBigIntLiteral(self, node: JsBigIntLiteral):
        self._write(node.raw)

    def visit_JsStringLiteral(self, node: JsStringLiteral):
        if self._unescape_strings and node.value is not None and node.terminated:
            self._write(self._encode_string(node.value, node.raw))
        else:
            self._write(node.raw)
        if not node.terminated:
            self._cut = True

    @staticmethod
    def _encode_string(value: str, raw: str) -> str:
        """
        Re-spell a literal from the text it denotes, unless the shorter spelling would state
        something the source did not. Whether a literal spells the Use Strict Directive, or an
        escape strict code refuses, is a fact about how it was written and not what it denotes:
        unescaping `'use\\x20strict'` to `'use strict'` writes a directive nobody wrote and turns
        the code behind it strict. Where either would move, the source spelling is kept, the same
        rule the folding pass holds.
        """
        quote = raw[0] if raw and raw[0] in ('"', "'") else "'"
        body = escape_js_string(value, quote)
        if raw and spelling_states(body) != spelling_states(raw[1:-1]):
            return raw
        return F'{quote}{body}{quote}'

    def visit_JsRegExpLiteral(self, node: JsRegExpLiteral):
        self._write(node.raw)

    def visit_JsBooleanLiteral(self, node: JsBooleanLiteral):
        self._write('true' if node.value else 'false')

    def visit_JsNullLiteral(self, node: JsNullLiteral):
        self._write('null')

    def visit_JsThisExpression(self, node: JsThisExpression):
        self._write('this')

    def visit_JsIdentifier(self, node: JsIdentifier):
        self._write(self._encode_identifier(node.name, node.raw))

    def visit_JsPrivateIdentifier(self, node: JsPrivateIdentifier):
        self._write('#')
        self._write(self._encode_identifier(node.name, node.raw))

    @staticmethod
    def _encode_identifier(name: str, raw: str) -> str:
        """
        Write a name as itself, unless the bare text would be read as something other than a name.
        `spells_only_a_name` says which words those are, and for one of them the source spelling is
        the only text that says which reading the file meant:

            var l\\u0065t = [0]; l\\u0065t[0] = 5;

        is a program, and the same file with the name written out is not.

        The spelling is trusted only for as long as it spells the name being printed, so a pass
        that renames a node has nothing to maintain here — what it left behind is a spelling of
        some other name, and the name itself is written instead. This is the rule
        `_encode_string` holds for a literal, asked of a name.
        """
        if raw and not spells_only_a_name(name) and identifier_string_value(raw) == name:
            return raw
        return from_code_units(name)

    def visit_JsErrorNode(self, node: JsErrorNode):
        self._write(node.text)

    def visit_JsTemplateLiteral(self, node: JsTemplateLiteral):
        self._write('`')
        expressions = iter(node.expressions)
        for index, quasi in enumerate(node.quasis):
            if not quasi.opened:
                self._cut = True
            self.visit(quasi)
            if not quasi.terminated:
                self._cut = True
            expression = next(expressions, None)
            if expression is not None:
                self._write('${')
                self.visit(expression)
                if index + 1 < len(node.quasis) and node.quasis[index + 1].opened:
                    self._write('}')
        self._write('`')

    def visit_JsTemplateElement(self, node: JsTemplateElement):
        """
        A run of template text is written the way the source wrote it, because `value` is what that
        spelling denotes: printing the cooked text back turns an escaped backtick into one that
        ends the literal and an escaped `${` into a hole. A run that was never written has no
        spelling to print and is escaped from its value instead.
        """
        self._write(node.raw or escape_js_template_text(node.value or ''))

    def _emit_array_like(self, node):
        """
        An array literal, or the pattern that matches one. A hole is an element that was left out,
        and what spells it is the comma that would have followed it, so a hole at the end needs a
        comma of its own: the separators between the elements spell one fewer than there are, and
        `[1, 2, ,]` written back as `[1, 2, ]` is an array of two.
        """
        self._write('[')
        elements = node.elements
        wrapped = self._byte_grid(elements) or self._comma_separated(elements, wrap_sequences=True)
        if elements and elements[-1] is None:
            self._write(',')
        if wrapped:
            self._newline()
        self._write(']')

    visit_JsArrayExpression = _emit_array_like
    visit_JsArrayPattern = _emit_array_like

    def _byte_grid(self, elements: list) -> bool:
        """
        Emit *elements* as a grid of fixed-width hex bytes, and report whether that was done. Declines
        unless every element is an integer literal in `0 .. 255` and there are enough of them to fill more
        than one row, and unless the array would overflow the line anyway — the grid is an alternative to
        the one-element-per-line fallback, so where that fallback does not apply the array is left exactly
        as it was written.

        Negative zero is excluded even though it is an integer in range, because the grid respells
        each element from its value and `0x00` denotes positive zero: the one Number whose sign this
        spelling cannot carry is the one Number whose sign is observable without reading it back,
        through `1 / -0`.

        A byte array printed one element per line costs a screen of vertical space to say very little, and
        decimal cannot be aligned: `15` and `216` differ in width, so the reader loses the column structure
        that makes a key or ciphertext block legible. Hex is what buys the alignment, which is why the
        radix change and the row width are one decision rather than two.
        """
        if len(elements) <= _BYTE_GRID_COLUMNS:
            return False
        byte_values: list[int] = []
        for element in elements:
            if not isinstance(element, JsNumericLiteral) or is_negative_zero(element.value):
                return False
            byte = exact_integer(element.value)
            if byte is None or not (0 <= byte <= 0xFF):
                return False
            byte_values.append(byte)
        if not self._overflows_inline(elements):
            return False
        self._depth += 1
        for start in range(0, len(byte_values), _BYTE_GRID_COLUMNS):
            row = byte_values[start:start + _BYTE_GRID_COLUMNS]
            self._newline()
            self._write(', '.join(F'0x{byte:02X}' for byte in row))
            if start + _BYTE_GRID_COLUMNS < len(byte_values):
                self._write(',')
        self._depth -= 1
        return True

    def _overflows_inline(self, elements: list) -> bool:
        """
        Whether emitting *elements* comma-separated on the current line would pass the line limit, and so
        be broken up. Measured from each element's own spelling, because that is what would be printed:
        deciding this from the hex form instead would grid an array of small values that fits as written,
        since `0x05` is wider than `5`.
        """
        width = sum(len(element.raw) for element in elements) + 2 * (len(elements) - 1)
        return self._col + width > self._line_length

    def visit_JsObjectExpression(self, node: JsObjectExpression):
        if not node.properties:
            self._write('{}')
            return
        self._write('{')
        breaking = False
        for i, prop in enumerate(node.properties):
            if i > 0:
                self._write(',')
            if not breaking and self._col >= self._line_length:
                breaking = True
                self._depth += 1
            if breaking:
                self._newline()
            else:
                self._write(' ')
            self.visit(prop)
        if breaking:
            self._depth -= 1
            self._newline()
            self._write('}')
        else:
            self._write(' }')

    def visit_JsProperty(self, node: JsProperty):
        if node.kind in (JsPropertyKind.GET, JsPropertyKind.SET):
            self._write(F'{node.kind.value} ')
        if node.method and node.value and isinstance(node.value, JsFunctionExpression):
            if node.value.is_async:
                self._write('async ')
            if node.value.generator:
                self._write('*')
        self._emit_key(node.key, node.computed)
        if node.method:
            if node.value and isinstance(node.value, JsFunctionExpression):
                self._emit_params(node.value.params)
                self._write(' ')
                if node.value.body:
                    self._emit_block_node(node.value.body, prologue=True)
            return
        if node.shorthand:
            if isinstance(node.value, JsAssignmentPattern):
                self._write(' = ')
                self._emit_element(node.value.right, True)
            return
        self._write(': ')
        self._emit_element(node.value, True)

    def _emit_spread_like(self, node):
        self._write('...')
        self._emit_element(node.argument, True)

    visit_JsSpreadElement = _emit_spread_like
    visit_JsRestElement = _emit_spread_like

    def visit_JsUnaryExpression(self, node: JsUnaryExpression):
        if node.prefix:
            self._write(node.operator)
            if node.operator in _WORD_UNARY_OPS:
                self._write(' ')
            self._emit_child(node.operand, node)
        else:
            self._emit_child(node.operand, node)
            self._write(node.operator)

    def visit_JsUpdateExpression(self, node: JsUpdateExpression):
        if node.prefix:
            self._write(node.operator)
            self._emit_child(node.argument, node)
        else:
            self._emit_child(node.argument, node)
            self._write(node.operator)

    def _emit_binary_like(self, node):
        self._emit_child(node.left, node)
        self._write(F' {node.operator} ')
        self._emit_child(node.right, node)

    visit_JsBinaryExpression = _emit_binary_like
    visit_JsLogicalExpression = _emit_binary_like
    visit_JsAssignmentExpression = _emit_binary_like

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self._emit_child(node.test, node)
        self._write(' ? ')
        self._emit_child(node.consequent, node)
        self._write(' : ')
        self._emit_child(node.alternate, node)

    def visit_JsMemberExpression(self, node: JsMemberExpression):
        self._emit_child(node.object, node)
        if node.computed:
            if node.optional:
                self._write('?.')
            self._write('[')
            if node.property:
                self.visit(node.property)
            self._write(']')
        elif node.optional:
            self._write('?.')
            if node.property:
                self.visit(node.property)
        else:
            self._write('.')
            if node.property:
                self.visit(node.property)

    def visit_JsCallExpression(self, node: JsCallExpression):
        self._emit_child(node.callee, node)
        if node.optional:
            self._write('?.')
        self._write('(')
        if self._comma_separated(node.arguments, wrap_sequences=True):
            self._newline()
        self._write(')')

    def visit_JsNewExpression(self, node: JsNewExpression):
        self._write('new ')
        self._emit_child(node.callee, node)
        self._write('(')
        if self._comma_separated(node.arguments, wrap_sequences=True):
            self._newline()
        self._write(')')

    def visit_JsSequenceExpression(self, node: JsSequenceExpression):
        """
        A sequence written inside a sequence keeps its brackets. The comma operator is flat in the
        text and nested in the tree, so `(a, b), c` and `a, (b, c)` are both spelled `a, b, c` once
        the brackets are gone, and reading that back gives one sequence of three where the tree held
        two of two. The value is the same either way, which is exactly why nothing downstream would
        report the shape being lost.
        """
        self._comma_separated(node.expressions, lead_newline=False, wrap_sequences=True)

    def visit_JsYieldExpression(self, node: JsYieldExpression):
        self._write('yield')
        if node.delegate:
            self._write('*')
        if node.argument:
            self._write(' ')
            self._emit_element(node.argument, True)

    def visit_JsAwaitExpression(self, node: JsAwaitExpression):
        self._write('await ')
        self._emit_child(node.argument, node)

    def visit_JsTaggedTemplateExpression(self, node: JsTaggedTemplateExpression):
        self._emit_child(node.tag, node)
        if node.quasi:
            self.visit(node.quasi)

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self._write('(')
        if node.expression:
            self.visit(node.expression)
        self._write(')')

    def _emit_function(self, node):
        self._emit_function_prefix(node.is_async, node.generator)
        if node.id:
            self._write(' ')
            self.visit(node.id)
        self._emit_params(node.params)
        self._write(' ')
        if node.body:
            self._emit_block_node(node.body, prologue=True)

    visit_JsFunctionExpression = _emit_function

    def visit_JsArrowFunctionExpression(self, node: JsArrowFunctionExpression):
        if node.is_async:
            self._write('async ')
        if len(node.params) == 1 and isinstance(node.params[0], JsIdentifier):
            self.visit(node.params[0])
        else:
            self._emit_params(node.params)
        self._write(' => ')
        if node.body:
            if isinstance(node.body, JsBlockStatement):
                self._emit_block_node(node.body, prologue=True)
            elif isinstance(node.body, JsSequenceExpression) or statement_needs_parens(node.body):
                self._write('(')
                self.visit(node.body)
                self._write(')')
            else:
                self.visit(node.body)

    def _emit_decorators(self, decorators: list[JsDecorator]):
        for decorator in decorators:
            self.visit(decorator)
            self._write(' ')

    def visit_JsDecorator(self, node: JsDecorator):
        self._write('@')
        expr = node.expression
        if expr is None:
            return
        if _is_bare_decorator(expr):
            self.visit(expr)
        else:
            self._write('(')
            self.visit(expr)
            self._write(')')

    def _emit_class(self, node: JsClassDeclaration | JsClassExpression):
        self._emit_decorators(node.decorators)
        self._write('class')
        if node.id:
            self._write(' ')
            self.visit(node.id)
        if node.super_class:
            self._write(' extends ')
            self._emit_child(node.super_class, node)
        self._write(' ')
        if node.body:
            self.visit(node.body)

    def visit_JsClassExpression(self, node: JsClassExpression):
        self._emit_class(node)

    def visit_JsObjectPattern(self, node: JsObjectPattern):
        self._write('{')
        for i, prop in enumerate(node.properties):
            if i > 0:
                self._write(', ')
            else:
                self._write(' ')
            self.visit(prop)
        if node.properties:
            self._write(' ')
        self._write('}')

    def visit_JsAssignmentPattern(self, node: JsAssignmentPattern):
        if node.left:
            self.visit(node.left)
        self._write(' = ')
        self._emit_element(node.right, True)

    def visit_JsClassBody(self, node: JsClassBody):
        self._write('{')
        self._depth += 1
        for member in node.body:
            self._separate(member)
            self._emit_leading_comments(member)
            self.visit(member)
        self._depth -= 1
        if not node.terminated:
            self._cut = True
            return
        if node.body:
            self._newline()
        self._write('}')

    def visit_JsMethodDefinition(self, node: JsMethodDefinition):
        self._emit_decorators(node.decorators)
        if node.is_static:
            self._write('static ')
        if node.kind in (JsMethodKind.GET, JsMethodKind.SET):
            self._write(F'{node.kind.value} ')
        if node.value and isinstance(node.value, JsFunctionExpression):
            if node.value.is_async:
                self._write('async ')
            if node.value.generator:
                self._write('*')
        self._emit_key(node.key, node.computed)
        if node.value and isinstance(node.value, JsFunctionExpression):
            self._emit_params(node.value.params)
            self._write(' ')
            if node.value.body:
                self._emit_block_node(node.value.body, prologue=True)

    def visit_JsPropertyDefinition(self, node: JsPropertyDefinition):
        self._emit_decorators(node.decorators)
        if node.is_static:
            self._write('static ')
        self._emit_key(node.key, node.computed)
        if node.value:
            self._write(' = ')
            self._emit_element(node.value, True)
        self._write(';')

    def visit_JsStaticBlock(self, node: JsStaticBlock):
        self._write('static ')
        self._emit_block(node.body, prologue=True, owner=node)

    def visit_JsExpressionStatement(self, node: JsExpressionStatement):
        expr = node.expression
        if expr is not None:
            if statement_needs_parens(expr):
                self._write('(')
                self.visit(expr)
                self._write(')')
            else:
                self.visit(expr)
        self._write(';')

    def visit_JsBlockStatement(self, node: JsBlockStatement):
        self._emit_block_node(node)

    def visit_JsEmptyStatement(self, node: JsEmptyStatement):
        self._write(';')

    def visit_JsVariableDeclaration(self, node: JsVariableDeclaration):
        self._write(F'{node.kind.value} ')
        self._comma_separated(node.declarations)
        self._write(';')

    def visit_JsVariableDeclarator(self, node: JsVariableDeclarator):
        if node.id:
            self.visit(node.id)
        if node.init:
            self._write(' = ')
            self._emit_element(node.init, True)

    def visit_JsIfStatement(self, node: JsIfStatement):
        self._write('if (')
        if node.test:
            self.visit(node.test)
        self._write(') ')
        if node.consequent:
            self._emit_statement_body(node.consequent)
        if node.alternate:
            self._write(' else ')
            self._emit_statement_body(node.alternate)

    def _emit_statement_body(self, stmt: Statement):
        """
        The body of a clause, written as a block. Text the parser could not read is written as it
        was written, with no block put around it: a brace inside such text would close or open the
        block the printer put there, and the file would read back with a different shape.
        """
        if isinstance(stmt, JsBlockStatement):
            self._emit_block_node(stmt)
        elif isinstance(stmt, JsErrorNode):
            self.visit(stmt)
        else:
            self._emit_block([stmt])

    def visit_JsWhileStatement(self, node: JsWhileStatement):
        self._write('while (')
        if node.test:
            self.visit(node.test)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsDoWhileStatement(self, node: JsDoWhileStatement):
        self._write('do ')
        if node.body:
            self._emit_statement_body(node.body)
        self._write(' while (')
        if node.test:
            self.visit(node.test)
        self._write(');')

    def _emit_bracketed_if(self, node: Node | None, refuses: Callable[[Node], bool]):
        if node is None:
            return
        if not refuses(node):
            self.visit(node)
            return
        self._write('(')
        self.visit(node)
        self._write(')')

    def _emit_for_binding(self, node: Statement | Node, refuses: Callable[[Node], bool]):
        """
        The binding or the assignment target in a loop head, bracketed where the head it stands in
        refuses what it says. Each of the three heads refuses something the others do not, so which
        rule applies is what the caller names; adding the next one is a rule beside them rather than
        another answer inside this.

        A declaration spells its own keyword and cannot be bracketed, so the rule reaches the value
        each declarator is given instead — which is where a `for` initializer can still read an
        `in` the head was not offering it.

        Nothing else is bracketed. The other shape a statement may not open with is an object
        literal, and a loop head is where one is a destructuring target: bracketing `for ({a} of x)`
        would make the target invalid rather than keep it whole.
        """
        if not isinstance(node, JsVariableDeclaration):
            return self._emit_bracketed_if(node, refuses)
        self._write(F'{node.kind.value} ')
        for i, decl in enumerate(node.declarations):
            if i > 0:
                self._write(', ')
            if decl.init is None or not refuses(decl.init):
                self.visit(decl)
                continue
            if decl.id:
                self.visit(decl.id)
            self._write(' = ')
            self._emit_bracketed_if(decl.init, refuses)

    def visit_JsForStatement(self, node: JsForStatement):
        self._write('for (')
        if node.init:
            self._emit_for_binding(node.init, for_initializer_needs_parens)
        self._write('; ')
        if node.test:
            self.visit(node.test)
        self._write('; ')
        if node.update:
            self.visit(node.update)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsForInStatement(self, node: JsForInStatement):
        self._write('for (')
        if node.left:
            self._emit_for_binding(node.left, for_in_target_needs_parens)
        self._write(' in ')
        if node.right:
            self.visit(node.right)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsForOfStatement(self, node: JsForOfStatement):
        self._write('for ')
        if node.is_await:
            self._write('await ')
        self._write('(')
        if node.left:
            self._emit_for_binding(node.left, for_of_target_needs_parens)
        self._write(' of ')
        if node.right:
            self._emit_element(node.right, True)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsSwitchStatement(self, node: JsSwitchStatement):
        self._write('switch (')
        if node.discriminant:
            self.visit(node.discriminant)
        self._write(') {')
        self._depth += 1
        for case in node.cases:
            self._separate(case)
            self._emit_leading_comments(case)
            self.visit(case)
        self._depth -= 1
        if not node.terminated:
            self._cut = True
            return
        if node.cases:
            self._newline()
        self._write('}')

    def visit_JsSwitchCase(self, node: JsSwitchCase):
        if node.test:
            self._write('case ')
            self.visit(node.test)
            self._write(':')
        else:
            self._write('default:')
        self._depth += 1
        for stmt in node.body:
            self._separate(stmt)
            self._emit_leading_comments(stmt)
            self.visit(stmt)
        self._depth -= 1

    def visit_JsTryStatement(self, node: JsTryStatement):
        self._write('try ')
        if node.block:
            self._emit_block_node(node.block)
        if node.handler:
            self._write(' ')
            self.visit(node.handler)
        if node.finalizer:
            self._write(' finally ')
            self._emit_block_node(node.finalizer)

    def visit_JsCatchClause(self, node: JsCatchClause):
        self._write('catch')
        if node.param:
            self._write(' (')
            self.visit(node.param)
            self._write(')')
        self._write(' ')
        if node.body:
            self._emit_block_node(node.body)

    def visit_JsThrowStatement(self, node: JsThrowStatement):
        self._write('throw ')
        if node.argument:
            self.visit(node.argument)
        self._write(';')

    def visit_JsReturnStatement(self, node: JsReturnStatement):
        self._write('return')
        if node.argument:
            self._write(' ')
            self.visit(node.argument)
        self._write(';')

    def visit_JsBreakStatement(self, node: JsBreakStatement):
        self._write('break')
        if node.label:
            self._write(' ')
            self.visit(node.label)
        self._write(';')

    def visit_JsContinueStatement(self, node: JsContinueStatement):
        self._write('continue')
        if node.label:
            self._write(' ')
            self.visit(node.label)
        self._write(';')

    def visit_JsLabeledStatement(self, node: JsLabeledStatement):
        if node.label:
            self.visit(node.label)
        self._write(': ')
        if node.body:
            self.visit(node.body)

    def visit_JsWithStatement(self, node: JsWithStatement):
        self._write('with (')
        if node.object:
            self.visit(node.object)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsDebuggerStatement(self, node: JsDebuggerStatement):
        self._write('debugger;')

    visit_JsFunctionDeclaration = _emit_function

    def visit_JsClassDeclaration(self, node: JsClassDeclaration):
        self._emit_class(node)

    def visit_JsImportDeclaration(self, node: JsImportDeclaration):
        self._write('import ')
        if not node.specifiers:
            if node.source:
                self.visit(node.source)
            self._emit_import_attributes(node)
            self._write(';')
            return
        default_spec = None
        namespace_spec = None
        named_specs: list = []
        for spec in node.specifiers:
            if isinstance(spec, JsImportDefaultSpecifier):
                default_spec = spec
            elif isinstance(spec, JsImportNamespaceSpecifier):
                namespace_spec = spec
            elif isinstance(spec, JsImportSpecifier):
                named_specs.append(spec)
        if default_spec:
            if default_spec.local:
                self.visit(default_spec.local)
            if namespace_spec or named_specs:
                self._write(', ')
        if namespace_spec:
            self._write('* as ')
            if namespace_spec.local:
                self.visit(namespace_spec.local)
        if named_specs:
            self._write('{ ')
            for i, spec in enumerate(named_specs):
                if i > 0:
                    self._write(', ')
                self.visit(spec)
            self._write(' }')
        self._write(' from ')
        if node.source:
            self.visit(node.source)
        self._emit_import_attributes(node)
        self._write(';')

    def _emit_import_attributes(
        self,
        node: JsImportDeclaration | JsExportNamedDeclaration | JsExportAllDeclaration,
    ):
        if not node.attributes_keyword:
            return
        self._write(F' {node.attributes_keyword} {{ ')
        for i, attr in enumerate(node.attributes):
            if i > 0:
                self._write(', ')
            self.visit(attr)
        self._write(' }')

    def visit_JsImportAttribute(self, node: JsImportAttribute):
        if node.key:
            self.visit(node.key)
        self._write(': ')
        if node.value:
            self.visit(node.value)

    def visit_JsImportExpression(self, node: JsImportExpression):
        self._write('import(')
        if node.source is not None:
            self._emit_element(node.source, True)
        if node.options is not None:
            self._write(', ')
            self._emit_element(node.options, True)
        self._write(')')

    def visit_JsMetaProperty(self, node: JsMetaProperty):
        self._write(node.meta)
        self._write('.')
        self._write(node.property)

    @staticmethod
    def _renames(written: Node | None, other: Node | None) -> bool:
        """
        Whether a specifier writes two names rather than the one a shorthand writes once. `import
        { a }` holds a single node in both of its slots and `{ a as a }` holds two spelling one
        name, and neither is written with an `as`; anything else is, whatever kind of node stands
        there. A module export name written as a string is not a name node at all, and a position
        the parser could not read is an error node, so deciding this by node class rather than by
        what the two nodes say would drop the half that carries the meaning.
        """
        if written is None or other is None or written is other:
            return False
        if isinstance(written, JsIdentifier) and isinstance(other, JsIdentifier):
            return written.name != other.name
        return True

    def visit_JsImportSpecifier(self, node: JsImportSpecifier):
        if node.imported:
            self.visit(node.imported)
        local = node.local
        if local is not None and self._renames(local, node.imported):
            self._write(' as ')
            self.visit(local)

    def visit_JsImportDefaultSpecifier(self, node: JsImportDefaultSpecifier):
        if node.local:
            self.visit(node.local)

    def visit_JsImportNamespaceSpecifier(self, node: JsImportNamespaceSpecifier):
        self._write('* as ')
        if node.local:
            self.visit(node.local)

    def visit_JsExportNamedDeclaration(self, node: JsExportNamedDeclaration):
        self._write('export ')
        if node.declaration:
            self.visit(node.declaration)
            return
        self._write('{ ')
        for i, spec in enumerate(node.specifiers):
            if i > 0:
                self._write(', ')
            self.visit(spec)
        self._write(' }')
        if node.source:
            self._write(' from ')
            self.visit(node.source)
            self._emit_import_attributes(node)
        self._write(';')

    def visit_JsExportDefaultDeclaration(self, node: JsExportDefaultDeclaration):
        self._write('export default ')
        if node.declaration:
            self._emit_element(node.declaration, True)
            if not isinstance(node.declaration, (
                JsFunctionDeclaration, JsClassDeclaration,
            )):
                self._write(';')

    def visit_JsExportAllDeclaration(self, node: JsExportAllDeclaration):
        self._write('export *')
        if node.exported:
            self._write(' as ')
            self.visit(node.exported)
        self._write(' from ')
        if node.source:
            self.visit(node.source)
            self._emit_import_attributes(node)
        self._write(';')

    def visit_JsExportSpecifier(self, node: JsExportSpecifier):
        if node.local:
            self.visit(node.local)
        exported = node.exported
        if exported is not None and self._renames(exported, node.local):
            self._write(' as ')
            self.visit(exported)

    def visit_JsScript(self, node: JsScript):
        promoted = promoted_use_strict(node.body)
        for i, stmt in enumerate(node.body):
            if i > 0:
                self._separate(stmt)
            self._emit_leading_comments(stmt)
            self._emit_body_statement(stmt, promoted)
