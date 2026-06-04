"""
Shared utilities for JavaScript deobfuscation transforms.
"""
from __future__ import annotations

import math
import operator
import re

from collections import Counter
from typing import TYPE_CHECKING, Callable, Iterator, Sequence

if TYPE_CHECKING:
    from typing import TypeAlias
    LiteralValue: TypeAlias = str | int | float | bool | list | dict | None

from refinery.lib.scripts import (
    Expression,
    Node,
    Statement,
    Transformer,
    _clone_node,
    _compute_children,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsConditionalExpression,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
)
from refinery.lib.scripts.js.token import FUTURE_RESERVED, KEYWORDS

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$')

JS_RESERVED = frozenset(set(KEYWORDS) | FUTURE_RESERVED | {'undefined'})

FUNCTION_NODE_TYPES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)
GLOBAL_OBJECT_ALIASES: frozenset[str] = frozenset({'globalThis', 'global', 'window', 'self'})
VOID_LITERAL_OPERANDS = (JsNumericLiteral, JsStringLiteral, JsBooleanLiteral, JsNullLiteral)


def _to_int32(v: int | float) -> int:
    """
    Replicate the ECMA-262 ToInt32 abstract operation: `NaN`, `+Infinity`, and `-Infinity` all
    coerce to `0`, finite floats truncate towards zero, the result is taken mod 2^32 and
    sign-extended to the int32 range.
    """
    if isinstance(v, float):
        if v != v or v == float('inf') or v == float('-inf'):
            return 0
        v = int(v) if v >= 0 else -int(-v)
    v = v & 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def _js_div(a: int | float, b: int | float) -> int | float:
    if b == 0:
        if a == 0 or a != a:
            return float('nan')
        return float('inf') if a > 0 else float('-inf')
    return a / b


def _js_mod(a: int | float, b: int | float) -> int | float:
    if b == 0 or a != a or b != b:
        return float('nan')
    if a == float('inf') or a == float('-inf'):
        return float('nan')
    if b == float('inf') or b == float('-inf'):
        return a
    return math.fmod(a, b)


BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : operator.mul,
    '/'  : _js_div,
    '%'  : _js_mod,
    '**' : operator.pow,
    '|'  : lambda a, b: _to_int32(a) | _to_int32(b),
    '&'  : lambda a, b: _to_int32(a) & _to_int32(b),
    '^'  : lambda a, b: _to_int32(a) ^ _to_int32(b),
    '<<' : lambda a, b: _to_int32(_to_int32(a) << (_to_int32(b) & 0x1F)),
    '>>' : lambda a, b: _to_int32(a) >> (_to_int32(b) & 0x1F),
}

RELATIONAL_OPS: dict[str, Callable] = {
    '<' : operator.lt,
    '>' : operator.gt,
    '<=': operator.le,
    '>=': operator.ge,
}


def eval_binary_op(op: str, left: int | float, right: int | float) -> int | float | bool | None:
    """
    Evaluate a JavaScript binary operator on two numeric operands. Returns the result value, or
    `None` when the operator is unknown or the computation overflows/divides by zero. Handles
    arithmetic, bitwise, relational, equality, and the unsigned right shift `>>>`.
    """
    if op in ('===', '=='):
        return left == right
    if op in ('!==', '!='):
        return left != right
    rel = RELATIONAL_OPS.get(op)
    if rel is not None:
        return rel(left, right)
    if op == '>>>':
        a = int(left) & 0xFFFFFFFF
        b = int(right) & 0x1F
        return (a >> b) & 0xFFFFFFFF
    fn = BINARY_OPS.get(op)
    if fn is None:
        return None
    try:
        return fn(left, right)
    except (ZeroDivisionError, OverflowError, ValueError):
        return None


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


def extract_literal_value(node: Node) -> tuple[bool, LiteralValue]:
    """
    Extract a Python value from a literal AST node. Returns `(True, value)` on success or
    `(False, None)` when the node is not a recognized literal form. Handles string, numeric,
    boolean, null literals, `void expr`, negative numerics, `!0`/`!1`, and array expressions
    where all elements are themselves literals.
    """
    if isinstance(node, JsStringLiteral):
        return True, node.value
    if isinstance(node, JsNumericLiteral):
        return True, node.value
    if isinstance(node, JsBooleanLiteral):
        return True, node.value
    if isinstance(node, JsNullLiteral):
        return True, None
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'void' and isinstance(node.operand, VOID_LITERAL_OPERANDS):
            return True, None
        if node.operator == '-' and isinstance(node.operand, JsNumericLiteral):
            return True, -node.operand.value
        if node.operator == '+' and isinstance(node.operand, JsNumericLiteral):
            return True, node.operand.value
        if node.operator == '!' and isinstance(node.operand, JsNumericLiteral):
            return True, not bool(node.operand.value)
    if isinstance(node, JsArrayExpression):
        items: list[LiteralValue] = []
        for el in node.elements:
            if el is None:
                return False, None
            ok, val = extract_literal_value(el)
            if not ok:
                return False, None
            items.append(val)
        return True, items
    return False, None


def value_to_node(value: object) -> Expression | None:
    """
    Convert a Python value to the corresponding AST literal node. Returns `None` when the value
    type is not representable as a literal expression.
    """
    if isinstance(value, str):
        return make_string_literal(value)
    if isinstance(value, bool):
        return JsBooleanLiteral(value=value)
    if isinstance(value, int):
        if value < 0:
            return JsUnaryExpression(operator='-', operand=make_numeric_literal(-value))
        return make_numeric_literal(value)
    if isinstance(value, float):
        if value != value:
            return JsIdentifier(name='NaN')
        if value == float('inf'):
            return JsIdentifier(name='Infinity')
        if value == float('-inf'):
            return JsUnaryExpression(operator='-', operand=JsIdentifier(name='Infinity'))
        if value < 0:
            return JsUnaryExpression(operator='-', operand=make_numeric_literal(-value))
        return make_numeric_literal(value)
    if isinstance(value, list):
        elements: list[Expression | None] = []
        for item in value:
            el = value_to_node(item)
            if el is None:
                return None
            elements.append(el)
        return JsArrayExpression(elements=elements)
    if isinstance(value, dict):
        properties = []
        for k, v in value.items():
            if not isinstance(k, str):
                return None
            val_node = value_to_node(v)
            if val_node is None:
                return None
            properties.append(JsProperty(key=make_string_literal(k), value=val_node))
        return JsObjectExpression(properties=properties)
    if value is None:
        return JsUnaryExpression(
            operator='void',
            operand=JsNumericLiteral(value=0, raw='0'),
        )
    return None


def is_literal(node: Node) -> bool:
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'void' and isinstance(node.operand, VOID_LITERAL_OPERANDS):
            return True
        if node.operator == '-' and isinstance(node.operand, JsNumericLiteral):
            return True
    return False


def member_key(node: JsMemberExpression) -> str | None:
    """
    Flatten a chain of property accesses into a dot-separated key string. Handles both dot
    notation and computed access with string-literal keys. Returns `None` if the chain contains
    a dynamic computed access that cannot be resolved to a static key.
    """
    parts: list[str] = []
    cursor: Expression | None = node
    while isinstance(cursor, JsMemberExpression):
        key = access_key(cursor)
        if key is None:
            return None
        parts.append(key)
        cursor = cursor.object
    if not isinstance(cursor, JsIdentifier):
        return None
    parts.append(cursor.name)
    parts.reverse()
    return '.'.join(parts)


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


def is_write_target(node: JsIdentifier) -> bool:
    """
    Return whether this identifier is a write target: the left-hand side of an assignment
    expression, or the iteration variable of a `for-in` / `for-of` statement.
    """
    p = node.parent
    if isinstance(p, JsAssignmentExpression) and p.left is node:
        return True
    if isinstance(p, (JsForInStatement, JsForOfStatement)) and p.left is node:
        return True
    return False


def is_binding_site(node: JsIdentifier) -> bool:
    """
    Return whether this identifier is in a binding position (variable declarator id or function
    declaration name) rather than a reference/read position.
    """
    p = node.parent
    if isinstance(p, JsVariableDeclarator) and p.id is node:
        return True
    if isinstance(p, JsFunctionDeclaration) and p.id is node:
        return True
    return False


def is_reference(node: JsIdentifier) -> bool:
    """
    Return whether this identifier is in a true variable reference position: not a binding site,
    not a non-computed member property, and not a non-computed object-literal key.
    """
    p = node.parent
    if p is None:
        return False
    if isinstance(p, JsVariableDeclarator) and p.id is node:
        return False
    if isinstance(p, JsFunctionDeclaration) and p.id is node:
        return False
    if isinstance(p, JsMemberExpression) and p.property is node and not p.computed:
        return False
    if isinstance(p, JsProperty) and p.key is node and not p.computed:
        return False
    return True


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


def _is_safe_property_base(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Check whether property access on *node* is guaranteed to be side-effect-free. Returns `True`
    when the object is a value that cannot have custom getters: literals, fresh
    object/array/function expressions, or identifiers in the *defunct* set (being removed, so
    their getters are irrelevant to live code). Chained member expressions are safe when their
    root base is safe.
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, (JsObjectExpression, JsArrayExpression, JsFunctionExpression)):
        return True
    if isinstance(node, JsIdentifier):
        return bool(defunct) and node.name in defunct
    if isinstance(node, JsMemberExpression) and node.object is not None:
        return _is_safe_property_base(node.object, defunct)
    return False


def is_side_effect_free(node: Node, defunct: set[str] | None = None) -> bool:
    """
    Conservative check for whether an expression can be removed without observable side effects.
    When *defunct* is provided, calls to identifiers in that set are treated as side-effect-free
    (the function no longer exists in scope).
    """
    if isinstance(node, (JsStringLiteral, JsNumericLiteral, JsBooleanLiteral, JsNullLiteral)):
        return True
    if isinstance(node, JsIdentifier):
        return True
    if isinstance(node, JsFunctionExpression):
        return True
    if isinstance(node, JsUnaryExpression):
        if node.operator == 'delete':
            return False
        return node.operand is not None and is_side_effect_free(node.operand, defunct)
    if isinstance(node, JsMemberExpression):
        if node.object is None:
            return False
        if not is_side_effect_free(node.object, defunct):
            return False
        if node.property is not None and not is_side_effect_free(node.property, defunct):
            return False
        return _is_safe_property_base(node.object, defunct)
    if isinstance(node, (JsBinaryExpression, JsLogicalExpression)):
        return (
            node.left is not None
            and is_side_effect_free(node.left, defunct)
            and node.right is not None
            and is_side_effect_free(node.right, defunct)
        )
    if isinstance(node, JsConditionalExpression):
        return (
            node.test is not None
            and is_side_effect_free(node.test, defunct)
            and node.consequent is not None
            and is_side_effect_free(node.consequent, defunct)
            and node.alternate is not None
            and is_side_effect_free(node.alternate, defunct)
        )
    if isinstance(node, JsObjectExpression):
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                return False
            if prop.value is not None and not is_side_effect_free(prop.value, defunct):
                return False
        return True
    if isinstance(node, JsArrayExpression):
        return all(
            elem is None or is_side_effect_free(elem, defunct) for elem in node.elements
        )
    if isinstance(node, JsSequenceExpression):
        return all(is_side_effect_free(e, defunct) for e in node.expressions)
    if isinstance(node, JsCallExpression):
        if defunct and isinstance(node.callee, JsIdentifier) and node.callee.name in defunct:
            return all(is_side_effect_free(arg, defunct) for arg in node.arguments)
        if isinstance(node.callee, JsFunctionExpression):
            return all(is_side_effect_free(arg, defunct) for arg in node.arguments)
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


def get_body(node: Node) -> list[Statement] | None:
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


def _collect_unconditional_identifiers(expr: Node) -> list[str]:
    """
    Walk *expr* in evaluation order, descending only into children that are unconditionally
    evaluated (not short-circuit branches or ternary arms). Return the identifier names encountered
    in evaluation order.
    """
    names: list[str] = []
    stack: list[Node] = [expr]
    while stack:
        node = stack.pop()
        if isinstance(node, JsIdentifier):
            names.append(node.name)
            continue
        if isinstance(node, (JsBinaryExpression, JsAssignmentExpression)):
            children: list[Node] = [c for c in (node.left, node.right) if c is not None]
        elif isinstance(node, JsUnaryExpression):
            children = [node.operand] if node.operand is not None else []
        elif isinstance(node, JsLogicalExpression):
            children = [node.left] if node.left is not None else []
        elif isinstance(node, JsConditionalExpression):
            children = [node.test] if node.test is not None else []
        elif isinstance(node, JsSequenceExpression):
            children = list(node.expressions)
        elif isinstance(node, JsMemberExpression):
            children = [node.object] if node.object is not None else []
            if node.computed and node.property is not None:
                children.append(node.property)
        else:
            continue
        for child in reversed(children):
            stack.append(child)
    return names


def is_safe_iife_inline(
    expr: Node,
    param_names: Sequence[str],
    call_args: Sequence[Node],
) -> bool:
    """
    Verify that substituting IIFE arguments into the body expression preserves evaluation
    semantics. An argument that is side-effect-free can be freely moved or omitted. An effectful
    argument must be used exactly once, in an unconditionally-evaluated position, and in
    declaration order relative to other effectful arguments.
    """
    effectful_indices = [
        i for i, arg in enumerate(call_args)
        if not is_side_effect_free(arg)
    ]
    if not effectful_indices:
        return True
    use_counts = Counter(
        n.name for n in expr.walk()
        if isinstance(n, JsIdentifier)
    )
    for i in effectful_indices:
        if use_counts[param_names[i]] != 1:
            return False
    unconditional = _collect_unconditional_identifiers(expr)
    effectful_names = {param_names[i] for i in effectful_indices}
    effectful_in_eval = [n for n in unconditional if n in effectful_names]
    if len(effectful_in_eval) != len(effectful_indices):
        return False
    param_order = {name: i for i, name in enumerate(param_names)}
    prev = -1
    for name in effectful_in_eval:
        idx = param_order[name]
        if idx <= prev:
            return False
        prev = idx
    return True


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
    *,
    relaxed: bool = False,
) -> Node | None:
    """
    If *func* is a trivial wrapper (single return whose expression uses only the function's
    parameters), substitute call-site arguments into a clone of the return expression. Returns the
    inlined expression or `None` if the function is not a simple wrapper.

    When *relaxed* is False (default), all arguments must be side-effect-free simple expressions.
    When *relaxed* is True, only arguments used more than once in the return expression need to be
    simple (prevents duplicating side effects while allowing complex single-use arguments).
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
    if relaxed:
        for i, name in enumerate(param_names):
            uses = sum(1 for n in expr.walk() if isinstance(n, JsIdentifier) and n.name == name)
            if uses > 1 and not is_simple_expression(call_args[i]):
                return None
    return substitute_params(expr, param_names, call_args)


def walk_scope(root: Node, *, include_root_body: bool = False) -> Iterator[Node]:
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
        cc = _compute_children(node)
        stack.extend(reversed(cc))


def collect_identifier_names(node: Node) -> set[str]:
    """
    Collect the names of all `JsIdentifier` nodes in the subtree rooted at *node*.
    """
    return {n.name for n in node.walk() if isinstance(n, JsIdentifier)}


def find_enclosing_body(node: Node) -> list[Statement] | None:
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


def function_binds_name(func: Node, name: str) -> bool:
    """
    Check if a function creates a local binding for `name` (parameter, function name, or var
    declaration anywhere in its body — excluding nested functions).
    """
    if isinstance(func, JsFunctionDeclaration) and func.id is not None and func.id.name == name:
        return True
    for p in (getattr(func, 'params', None) or []):
        if isinstance(p, JsIdentifier) and p.name == name:
            return True
    body = getattr(func, 'body', None)
    if not isinstance(body, JsBlockStatement):
        return False
    stack: list[Node] = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, FUNCTION_NODE_TYPES):
            continue
        if isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.VAR:
            for decl in node.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    if decl.id.name == name:
                        return True
        for child in node.children():
            stack.append(child)
    return False


def _is_shadowed(node: Node, name: str) -> bool:
    """
    Walk up from *node* through all enclosing function boundaries and check whether any of them
    shadows *name* via a `var` declaration or a function parameter.

    This intentionally checks only function boundaries, NOT block/script-level declarations.
    `has_remaining_references` relies on this: a script-level `var x = expr` must not be considered
    "shadowed" at its own declaration site, or the function will incorrectly conclude no references
    remain.
    """
    parent = node.parent
    while parent is not None:
        if isinstance(parent, FUNCTION_NODE_TYPES):
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
