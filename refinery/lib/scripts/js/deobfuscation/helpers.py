"""
Shared utilities for JavaScript deobfuscation transforms.
"""
from __future__ import annotations

import operator
import re

from typing import Callable, Sequence, TYPE_CHECKING

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    Transformer,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsNullLiteral,
    JsNumericLiteral,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS

if TYPE_CHECKING:
    from typing import TypeGuard

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : operator.mul,
    '/'  : operator.truediv,
    '%'  : operator.mod,
    '**' : operator.pow,
    '|'  : operator.or_,
    '&'  : operator.and_,
    '^'  : operator.xor,
    '<<' : operator.lshift,
    '>>' : operator.rshift,
}

RELATIONAL_OPS: dict[str, Callable] = {
    '<' : operator.lt,
    '>' : operator.gt,
    '<=': operator.le,
    '>=': operator.ge,
}


def escape_js_string(value: str, quote: str = "'") -> str:
    """
    Escape a string for use in a JavaScript string literal. Returns the escaped body without
    surrounding quotes. Backslash is escaped first to avoid double-escaping. Control characters
    not covered by named escapes are emitted as `\\xHH`.
    """
    def _residue(m: re.Match[str]):
        return F'\\x{ord(m.group()):02x}'
    value = value.replace('\\', r'\\')
    value = value.replace('\n', r'\n')
    value = value.replace('\r', r'\r')
    value = value.replace('\t', r'\t')
    value = value.replace('\0', r'\0')
    value = value.replace(quote, F'\\{quote}')
    return re.sub(r'[\x01-\x1f]', _residue, value)


def string_value(node: Expression | None) -> str | None:
    if isinstance(node, JsStringLiteral):
        return node.value
    return None


def property_key(prop: JsProperty) -> str | None:
    """
    Extract the string key from a property node. Handles both string-literal keys and plain
    identifier keys. Returns `None` for computed keys.
    """
    if prop.computed:
        return None
    if isinstance(prop.key, JsStringLiteral):
        return prop.key.value
    if isinstance(prop.key, JsIdentifier):
        return prop.key.name
    return None


def make_string_literal(value: str) -> JsStringLiteral:
    escaped = escape_js_string(value)
    raw = F"'{escaped}'"
    return JsStringLiteral(value=value, raw=raw)


def numeric_value(node: Expression) -> int | float | None:
    if isinstance(node, JsNumericLiteral):
        return node.value
    return None


def make_numeric_literal(value: int | float) -> JsNumericLiteral:
    if isinstance(value, float):
        if value == int(value) and not (value == 0.0 and str(value).startswith('-')):
            raw = str(int(value))
        else:
            raw = str(value)
    else:
        raw = str(value)
    return JsNumericLiteral(value=value, raw=raw)


def is_literal(node: Node) -> TypeGuard[JsStringLiteral | JsNumericLiteral | JsBooleanLiteral | JsNullLiteral]:
    return isinstance(node, (
        JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral,
    ))


def is_valid_identifier(name: str) -> bool:
    return bool(SIMPLE_IDENTIFIER.match(name)) and name not in JS_RESERVED


def is_simple_expression(node: Node) -> bool:
    """
    Check whether a node is a side-effect-free leaf expression: a literal value, an identifier, or
    a unary operator applied to a literal (e.g. `-42`).
    """
    if is_literal(node) or isinstance(node, JsIdentifier):
        return True
    if isinstance(node, JsUnaryExpression) and node.operand is not None:
        return is_literal(node.operand)
    return False


def is_truthy(node: Node) -> bool | None:
    """
    Return the JavaScript truthiness of a literal node, or `None` when the value cannot be
    determined statically.
    """
    if isinstance(node, JsBooleanLiteral):
        return node.value
    if isinstance(node, JsNumericLiteral):
        # return correct value for NaN
        return (v := node.value) != 0 and v == v
    if isinstance(node, JsStringLiteral):
        return bool(node.value)
    if isinstance(node, JsNullLiteral):
        return False
    if isinstance(node, JsIdentifier) and node.name == 'undefined':
        return False
    if isinstance(node, JsArrayExpression):
        return True
    return None


def is_statically_evaluable(node: Node) -> bool:
    """
    Return whether the node can be evaluated to a known truthiness at transform time. This
    includes all literal types and the `undefined` identifier.
    """
    return (
        is_literal(node)
        or (isinstance(node, JsIdentifier) and node.name == 'undefined')
        or isinstance(node, JsArrayExpression)
    )


def is_nullish(node: Node) -> bool:
    """
    Return whether the node is statically known to be `null` or `undefined`.
    """
    if isinstance(node, JsNullLiteral):
        return True
    if isinstance(node, JsIdentifier) and node.name == 'undefined':
        return True
    return False


def js_parse_int(s: str, radix: int = 10) -> int | None:
    """
    Replicate the semantics of JavaScript's `parseInt(string, radix)`. Strips leading whitespace,
    handles an optional `+`/`-` sign, and for radix 16 skips a leading `0x`/`0X` prefix. Parses
    leading characters valid for the given radix (2-36) and stops at the first invalid one. Returns
    `None` when no valid digits are found (JS would return `NaN`).
    """
    if radix == 0:
        radix = 10
    if not (2 <= radix <= 36):
        return None
    s = s.strip()
    if not s:
        return None
    sign = 1
    if s[0] in '+-':
        if s[0] == '-':
            sign = -1
        s = s[1:]
    if radix == 16 and len(s) >= 2 and s[0] == '0' and s[1] in 'xX':
        s = s[2:]
    digits: list[str] = []
    for ch in s:
        if '0' <= ch <= '9':
            if ord(ch) - ord('0') >= radix:
                break
            digits.append(ch)
        elif 'a' <= ch <= 'z' or 'A' <= ch <= 'Z':
            if ord(ch.lower()) - ord('a') + 10 >= radix:
                break
            digits.append(ch)
        else:
            break
    if not digits:
        return None
    return sign * int(''.join(digits), radix)


def get_body(node: Node) -> list | None:
    """
    Return the statement body list of a node if it has one (JsScript or JsBlockStatement).
    """
    if isinstance(node, (JsScript, JsBlockStatement)):
        return node.body
    return None


def remove_declarator(declarator: JsVariableDeclarator) -> None:
    """
    Remove a `JsVariableDeclarator` from its parent `JsVariableDeclaration`. If the declaration
    has no remaining declarators afterward, remove it from the body as well.
    """
    var_decl = declarator.parent
    _remove_from_parent(declarator)
    if isinstance(var_decl, JsVariableDeclaration) and not var_decl.declarations:
        _remove_from_parent(var_decl)


def extract_identifier_params(params: list) -> list[str] | None:
    """
    Extract plain identifier names from a function's parameter list. Returns `None` if any parameter
    is not a simple `JsIdentifier` (e.g. destructuring or rest patterns).
    """
    names: list[str] = []
    for p in params:
        if not isinstance(p, JsIdentifier):
            return None
        names.append(p.name)
    return names


def is_closed_expression(node: Node, allowed_names: set[str]) -> bool:
    """
    Check whether every leaf in the expression tree is either a literal or an identifier whose
    name is in *allowed_names*. This ensures the expression has no free variables.
    """
    children = list(node.children())
    if not children:
        if isinstance(node, JsIdentifier):
            return node.name in allowed_names
        return is_simple_expression(node)
    return all(is_closed_expression(child, allowed_names) for child in children)


def substitute_params(
    expression: Node,
    param_names: Sequence[str],
    arguments: Sequence[Node],
) -> Node:
    """
    Deep-clone *expression* and replace every `JsIdentifier` whose name appears in *param_names*
    with a clone of the positionally corresponding node from *arguments*.
    """
    cloned = _clone_node(expression)
    mapping = dict(zip(param_names, arguments))
    for node in list(cloned.walk()):
        if isinstance(node, JsIdentifier) and node.name in mapping:
            _replace_in_parent(node, _clone_node(mapping[node.name]))
    return cloned


def try_inline_trivial_function(
    func: JsFunctionExpression,
    call_args: list,
) -> Node | None:
    """
    If *func* is a trivial wrapper (single return whose expression uses only the function's
    parameters), substitute call-site arguments into a clone of the return expression. Returns the
    inlined expression or `None` if the function is not a simple wrapper.
    """
    if func.body is None or not isinstance(func.body, JsBlockStatement):
        return None
    body = func.body.body
    if len(body) != 1:
        return None
    stmt = body[0]
    if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
        return None
    param_names = extract_identifier_params(func.params)
    if param_names is None:
        return None
    if len(call_args) != len(param_names):
        return None
    expr = stmt.argument
    if not is_closed_expression(expr, set(param_names)):
        return None
    return substitute_params(expr, param_names, call_args)


def walk_outer_scope(root: Node):
    """
    Walk the AST like `root.walk()` but skip the bodies of function definitions and expressions.
    The function node itself is yielded so that it can still be inspected or removed; only its
    subtree is suppressed.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            continue
        for child in node.children():
            stack.append(child)


class BodyProcessingTransformer(Transformer):
    """
    Intermediate base for JS deobfuscation transformers that process the statement list (body) of
    `JsScript` and `JsBlockStatement` nodes after visiting children. Subclasses override
    `_process_body`.
    """

    def visit_JsScript(self, node: JsScript):
        self.generic_visit(node)
        self._process_body(node, node.body)
        return None

    def visit_JsBlockStatement(self, node: JsBlockStatement):
        self.generic_visit(node)
        self._process_body(node, node.body)
        return None

    def _process_body(self, parent: Node, body: list[Statement]) -> None:
        raise NotImplementedError

    def _replace_body(
        self,
        parent: Node,
        body: list[Statement],
        replacement: list[Statement],
    ) -> None:
        """
        Replace the contents of *body* with *replacement*, fix parent pointers, and mark the
        transformer as changed.
        """
        body.clear()
        body.extend(replacement)
        for stmt in body:
            stmt.parent = parent
        self.mark_changed()


class ScopeProcessingTransformer(Transformer):
    """
    Base for transforms that process at function-scope boundaries. Visits `JsScript` and each
    function body (`JsFunctionDeclaration`, `JsFunctionExpression`, `JsArrowFunctionExpression`).
    Subclasses override `_process_scope`.
    """

    def visit_JsScript(self, node: JsScript):
        self.generic_visit(node)
        self._process_scope(node)
        return None

    def visit_JsFunctionDeclaration(self, node: JsFunctionDeclaration):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def visit_JsFunctionExpression(self, node: JsFunctionExpression):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def visit_JsArrowFunctionExpression(self, node: JsArrowFunctionExpression):
        self.generic_visit(node)
        if isinstance(node.body, JsBlockStatement):
            self._process_scope(node.body)
        return None

    def _process_scope(self, scope: Node) -> None:
        raise NotImplementedError
