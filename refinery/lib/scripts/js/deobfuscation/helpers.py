"""
Shared utilities for JavaScript deobfuscation transforms.
"""
from __future__ import annotations

import math
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
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsVarKind,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS

if TYPE_CHECKING:
    from typing import TypeGuard

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})


def _to_int32(v: int | float) -> int:
    v = int(v) & 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : operator.mul,
    '/'  : operator.truediv,
    '%'  : math.fmod,
    '**' : operator.pow,
    '|'  : lambda a, b: _to_int32(int(a) | int(b)),
    '&'  : lambda a, b: _to_int32(int(a) & int(b)),
    '^'  : lambda a, b: _to_int32(int(a) ^ int(b)),
    '<<' : lambda a, b: _to_int32(int(a) << (int(b) & 0x1F)),
    '>>' : lambda a, b: _to_int32(_to_int32(int(a)) >> (int(b) & 0x1F)),
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
    not covered by named escapes are emitted as `\\xHH`; surrogates as `\\uXXXX`.
    """
    def _residue(m: re.Match[str]):
        cp = ord(m.group())
        if cp > 0xFF:
            return F'\\u{cp:04X}'
        return F'\\x{cp:02x}'
    value = value.replace('\\', r'\\')
    value = value.replace('\n', r'\n')
    value = value.replace('\r', r'\r')
    value = value.replace('\t', r'\t')
    value = value.replace('\0', r'\0')
    value = value.replace(quote, F'\\{quote}')
    return re.sub(r'[\x01-\x1f\ud800-\udfff]', _residue, value)


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


def access_key(node: JsMemberExpression) -> str | None:
    """
    Extract the string key from a member-access expression. Handles both computed (`obj['key']`)
    and dot (`obj.key`) accesses.
    """
    if node.computed:
        return string_value(node.property)
    if isinstance(node.property, JsIdentifier):
        return node.property.name
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
        if value == 0.0 and str(value).startswith('-'):
            raw = '-0'
        elif value == int(value):
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


def is_while_true(node: JsWhileStatement) -> bool:
    """
    Check whether the while-loop condition is `true`, `!![]`, or `!0` — the forms the
    obfuscator uses for infinite loops.
    """
    test = node.test
    if isinstance(test, JsBooleanLiteral) and test.value is True:
        return True
    if not isinstance(test, JsUnaryExpression) or test.operator != '!':
        return False
    inner = test.operand
    if isinstance(inner, JsNumericLiteral) and inner.value == 0:
        return True
    if isinstance(inner, JsUnaryExpression) and inner.operator == '!':
        return True
    return False


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


def walk_scope(root: Node, *, include_root_body: bool = False):
    """
    Walk the AST under *root* without descending into nested function bodies. Function boundary
    nodes are yielded (so their identifiers can be inspected) but their subtrees are suppressed.
    Children are visited in source order.

    When *include_root_body* is True and *root* is itself a function, its body IS traversed (only
    inner functions are skipped). This is useful when *root* represents the scope being analyzed.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            if not (include_root_body and node is root):
                continue
        children = list(node.children())
        children.reverse()
        for child in children:
            stack.append(child)


def collect_identifier_names(node: Node) -> set[str]:
    """
    Collect the names of all `JsIdentifier` nodes in the subtree rooted at *node*.
    """
    return {n.name for n in node.walk() if isinstance(n, JsIdentifier)}


def find_enclosing_body(node: Node) -> list | None:
    """
    Walk up parent pointers from *node* to find the body list that directly contains it. Returns
    the `body` attribute of the nearest `JsBlockStatement` or `JsScript` ancestor whose body
    list includes *node* (or an ancestor of *node*).
    """
    child = node
    parent = node.parent
    while parent is not None:
        if isinstance(parent, (JsBlockStatement, JsScript)):
            if child in parent.body:
                return parent.body
        child = parent
        parent = parent.parent
    return None


def _body_declares_var(body: list, name: str) -> bool:
    """
    Check whether a function body's statement list contains a `var` declaration that includes a
    declarator with the given *name*.
    """
    for stmt in body:
        if not isinstance(stmt, JsVariableDeclaration):
            continue
        if stmt.kind != JsVarKind.VAR:
            continue
        for decl in stmt.declarations:
            if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                if decl.id.name == name:
                    return True
    return False


def _is_shadowed(node: Node, name: str) -> bool:
    """
    Walk up from *node* through all enclosing function boundaries and check whether any of them
    shadows *name* via a `var` declaration or a function parameter.
    """
    parent = node.parent
    while parent is not None:
        if isinstance(parent, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
            for param in getattr(parent, 'params', ()):
                if isinstance(param, JsIdentifier) and param.name == name:
                    return True
            body = getattr(parent, 'body', None)
            if isinstance(body, JsBlockStatement):
                if _body_declares_var(body.body, name):
                    return True
        parent = parent.parent
    return False


def has_remaining_references(
    root: Node,
    name: str,
    exclude: Node | None = None,
    exclude_ids: set[int] | None = None,
    check_shadowing: bool = False,
) -> bool:
    """
    Check whether *name* is referenced anywhere in the subtree of *root*, excluding nodes that
    belong to *exclude* (by identity) or whose `id()` is in *exclude_ids*. When *check_shadowing*
    is True, identifiers inside function bodies that shadow *name* via `var`/param are skipped.
    Bare hoisted declarations (`var NAME;` with no initializer) are never counted.
    """
    if exclude is not None:
        if exclude_ids is None:
            exclude_ids = set()
        exclude_ids = exclude_ids | {id(n) for n in exclude.walk()}
    for node in root.walk():
        if exclude_ids and id(node) in exclude_ids:
            continue
        parent = node.parent
        if exclude_ids and parent is not None and id(parent) in exclude_ids:
            continue
        if not isinstance(node, JsIdentifier) or node.name != name:
            continue
        if (
            isinstance(parent, JsVariableDeclarator)
            and parent.id is node
            and parent.init is None
        ):
            continue
        if check_shadowing and _is_shadowed(node, name):
            continue
        return True
    return False


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
    Subclasses may override either `_process_scope` or `_process_scope_body`.
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
        """
        Receives the raw scope node (`JsScript` or `JsBlockStatement`).
        """
        body = get_body(scope)
        if body is not None:
            self._process_scope_body(scope, body)

    def _process_scope_body(self, scope: Node, body: list) -> None:
        """
        Receives the scope node and its `body` list. The `_process_scope` method extracts the body
        and delegates here.
        """
        raise NotImplementedError


class ScriptLevelTransformer(Transformer):
    """
    Base for transforms that process the entire script manually rather than using the recursive
    visitor. Subclasses override `_process_script`.
    """

    def visit_JsScript(self, node: JsScript):
        self._process_script(node)
        return None

    def generic_visit(self, node: Node):
        pass

    def _process_script(self, node: JsScript) -> None:
        raise NotImplementedError
