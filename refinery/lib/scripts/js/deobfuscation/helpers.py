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
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import side_effect_free
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    Role,
    SemanticModel,
    build_semantic_model,
    is_use_position,
    reference_role,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsClassDeclaration,
    JsClassExpression,
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
    JsThisExpression,
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

OBJECT_PROTOTYPE_MEMBERS = frozenset({
    '__defineGetter__',
    '__defineSetter__',
    '__lookupGetter__',
    '__lookupSetter__',
    '__proto__',
    'constructor',
    'hasOwnProperty',
    'isPrototypeOf',
    'propertyIsEnumerable',
    'toLocaleString',
    'toString',
    'valueOf',
})
"""
The members every plain object inherits from `Object.prototype`. An access of one of these names on
an object that does not own it resolves through the prototype rather than to `undefined`, so a fold
that treats an absent own-property as `undefined` must leave these intact.
"""


class _JsNull:
    """
    Singleton sentinel for the JavaScript `null` value. The interpreter uses Python `None` for
    `undefined` (the value of missing/absent things), so a distinct object is required to keep `null`
    and `undefined` apart where JavaScript treats them differently: `Number(null)` is `0` but
    `Number(undefined)` is `NaN`, `typeof null` is `'object'`, `null === undefined` is `false`, and
    `String(null)` is `'null'`.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return 'JS_NULL'


JS_NULL = _JsNull()


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


def _to_uint32(v: int | float) -> int:
    """
    Replicate the ECMA-262 ToUint32 abstract operation.
    """
    if isinstance(v, float):
        if v != v or v == float('inf') or v == float('-inf'):
            return 0
        v = int(v) if v >= 0 else -int(-v)
    return v & 0xFFFFFFFF


def _js_div(a: int | float, b: int | float) -> int | float:
    if b == 0:
        if a == 0 or a != a:
            return float('nan')
        return float('inf') if a > 0 else float('-inf')
    return a / b


def _js_mul(a: int | float, b: int | float) -> int | float:
    """
    Multiply two JavaScript numbers, preserving the IEEE-754 sign of a zero product: a product of
    magnitude zero is negative zero exactly when the operands have opposite signs. Python integer
    multiplication cannot represent `-0`, so `0 * -5` would otherwise silently lose the sign.
    """
    result = a * b
    if result == 0 and (math.copysign(1.0, a) < 0) != (math.copysign(1.0, b) < 0):
        return -0.0
    return result


def _js_mod(a: int | float, b: int | float) -> int | float:
    if b == 0 or a != a or b != b:
        return float('nan')
    if a == float('inf') or a == float('-inf'):
        return float('nan')
    if b == float('inf') or b == float('-inf'):
        return a
    return math.fmod(a, b)


def _js_pow(base: int | float, exp: int | float) -> int | float:
    """
    Replicate JavaScript exponentiation (`**` / `Math.pow`). JavaScript numbers are IEEE-754 doubles,
    so this diverges from Python in cases that matter: `anything ** 0` is `1` (even `NaN ** 0`); a base
    of `1` or `-1` with an infinite exponent is `NaN` (Python: `1.0`); a negative base with a
    non-integer exponent is a complex number in Python (JS: `NaN`); a zero base with a negative
    exponent is `Infinity` (with the sign rule for `-0`); and a magnitude beyond the double range is
    `Infinity`, whereas Python's arbitrary-precision `int ** int` returns an exact bignum.
    """
    inf = float('inf')
    if exp == 0:
        return 1
    if base != base or exp != exp:
        return float('nan')
    if (base == 1 or base == -1) and exp in (inf, -inf):
        return float('nan')
    if base == 0 and exp < 0:
        if (
            exp not in (inf, -inf)
            and exp == int(exp)
            and int(exp) % 2 != 0
            and math.copysign(1.0, base) < 0
        ):
            return -inf
        return inf
    is_int_exp = exp not in (inf, -inf) and exp == int(exp)
    if base < 0 and not is_int_exp:
        return float('nan')
    try:
        result = base ** exp
    except OverflowError:
        return -inf if (base < 0 and is_int_exp and int(exp) % 2 != 0) else inf
    except (ValueError, ZeroDivisionError):
        return float('nan')
    if isinstance(result, complex):
        return float('nan')
    if isinstance(result, int):
        try:
            float(result)
        except OverflowError:
            return -inf if result < 0 else inf
    return result


BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : _js_mul,
    '/'  : _js_div,
    '%'  : _js_mod,
    '**' : _js_pow,
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
        a = _to_uint32(left)
        b = _to_uint32(right) & 0x1F
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
        return True, JS_NULL
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
    if value is JS_NULL:
        return JsNullLiteral()
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


def is_valid_property_key(name: str) -> bool:
    return bool(SIMPLE_IDENTIFIER.match(name))


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
    determined statically. This is the AST-node counterpart of the runtime `interpreter._truthy`;
    the two must agree on which values are falsy (`undefined`, `null`, `0`, `NaN`, `''`).
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


def get_body(node: Node) -> list[Statement] | None:
    """
    Return the statement body list of a node if it has one (JsScript or JsBlockStatement).
    """
    if isinstance(node, (JsScript, JsBlockStatement)):
        return node.body
    return None


def remove_declarator(declarator: JsVariableDeclarator) -> None:
    """
    Remove a `refinery.lib.scripts.js.model.JsVariableDeclarator` from its parent
    `refinery.lib.scripts.js.model.JsVariableDeclaration`. If the declaration has no remaining
    declarators afterward, remove it from the body as well.
    """
    var_decl = declarator.parent
    _remove_from_parent(declarator)
    if isinstance(var_decl, JsVariableDeclaration) and not var_decl.declarations:
        _remove_from_parent(var_decl)


def extract_identifier_params(params: list) -> list[str] | None:
    """
    Extract plain identifier names from a function's parameter list. Returns `None` if any parameter
    is not a simple `refinery.lib.scripts.js.model.JsIdentifier` (e.g. destructuring or rest
    patterns).
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


def _param_written(expr: Node, param_names: set[str]) -> bool:
    """
    Whether any of *param_names* occurs at a write position — an assignment, compound-assignment, or
    update target — within *expr*. Such a parameter is not read-only, so substituting the call
    argument for it would place the argument at a write target: assigning to a value (`(11 = 'x')`)
    or, for an lvalue argument, mutating the caller's binding. A wrapper with a written parameter is
    therefore not a pure function of its arguments and must not be inlined by substitution.
    """
    return any(
        isinstance(node, JsIdentifier)
        and node.name in param_names
        and reference_role(node) is not Role.READ
        for node in expr.walk()
    )


def is_safe_iife_inline(
    expr: Node,
    param_names: Sequence[str],
    call_args: Sequence[Node],
    call_pure: Callable[..., bool] | None = None,
) -> bool:
    """
    Verify that substituting IIFE arguments into the body expression preserves evaluation semantics.
    An argument used more than once must be a simple, identity-stable expression — a literal or a bare
    identifier: duplicating a fresh array/object/function literal (or a call) would split one value into
    distinct copies and break an identity comparison such as `x === x`. An effectful argument must
    additionally be used exactly once, in an unconditionally-evaluated position, and in declaration
    order relative to other effectful arguments, so its side effect is neither dropped, duplicated, nor
    reordered. When *call_pure* is given (an
    `refinery.lib.scripts.js.analysis.effects.EffectModel.is_pure_call`), a call argument it proves pure
    counts as side-effect-free for the ordering rules — but, being a call, is not simple, so it is still
    not duplicated.
    """
    if _param_written(expr, set(param_names)):
        return False
    use_counts = Counter(
        n.name for n in expr.walk()
        if isinstance(n, JsIdentifier) and is_use_position(n)
    )
    for i, arg in enumerate(call_args):
        if use_counts[param_names[i]] > 1 and not is_simple_expression(arg):
            return False
    effectful_indices = [
        i for i, arg in enumerate(call_args)
        if not side_effect_free(arg, call_pure=call_pure)
    ]
    if not effectful_indices:
        return True
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
    params: Sequence[Node],
    arguments: Sequence[Node],
    transformer: Transformer | None = None,
) -> Node:
    """
    Deep-clone *expression* and replace every reference to one of the function parameters *params* with
    a clone of the positionally corresponding node from *arguments*. Only identifiers the parameter
    actually binds are replaced: a non-computed property key (the `a` in `b.a`) names a property, and a
    function or class nested in *expression* that reintroduces a parameter's name keeps its own
    identifiers rather than the outer parameter's. When *expression* nests no scope, no name under it
    can be rebound, so a parameter's references are exactly the use-position identifiers carrying its
    name and are substituted directly; only when it does nest a scope is a semantic model built to
    resolve each occurrence against the binding it reads. When *transformer* is given, that model is
    taken from its shared analysis cache; otherwise it is built standalone.
    """
    cloned = _clone_node(expression)
    mapping = {
        param.name: argument
        for param, argument in zip(params, arguments)
        if isinstance(param, JsIdentifier)
    }
    if isinstance(expression, JsIdentifier):
        if expression.name in mapping and is_use_position(expression):
            return _clone_node(mapping[expression.name])
        return cloned
    if not _introduces_nested_scope(expression):
        for node in list(cloned.walk()):
            if isinstance(node, JsIdentifier) and node.name in mapping and is_use_position(node):
                _substitute_use_position(node, _clone_node(mapping[node.name]))
        return cloned
    root = expression
    while root.parent is not None:
        root = root.parent
    assert isinstance(root, JsScript)
    if transformer is None:
        model = build_semantic_model(root)
    else:
        model = model_cache(transformer, root).model
    bindings = {
        param.name: model.binding_of(param)
        for param in params
        if isinstance(param, JsIdentifier)
    }
    for original, clone in zip(list(expression.walk()), list(cloned.walk())):
        if not isinstance(original, JsIdentifier) or original.name not in mapping:
            continue
        binding = bindings.get(original.name)
        if binding is None or model.resolve(original) is not binding:
            continue
        if isinstance(clone, JsIdentifier) and clone.name == original.name:
            _substitute_use_position(clone, _clone_node(mapping[original.name]))
    return cloned


def _introduces_nested_scope(node: Node) -> bool:
    """
    Whether the subtree at *node* contains a function or class — a scope in which an enclosing
    function's parameter name could be rebound. When it does not, no identifier under *node* can shadow
    such a parameter, so the parameter's references are exactly the use-position identifiers that carry
    its name.
    """
    return any(
        isinstance(child, (
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsFunctionDeclaration,
            JsClassExpression,
            JsClassDeclaration,
        ))
        for child in node.walk()
    )


def _substitute_use_position(node: JsIdentifier, replacement: Node) -> None:
    """
    Replace use-position identifier *node* with *replacement*. In an object-literal shorthand (`{a}`),
    one identifier serves as both the property name and the read of the variable, so a plain replacement
    would rename the property — or emit invalid syntax for a non-identifier argument. Keep the name in
    that case: never substitute a non-computed property key, and clear the shorthand flag when replacing
    its value so the property is written out in full. Guarding the key makes the result independent of
    which of the two cloned occurrences is visited first.
    """
    parent = node.parent
    if isinstance(parent, JsProperty) and not parent.computed:
        if parent.key is node:
            return
        if parent.shorthand and parent.value is node:
            parent.shorthand = False
    _replace_in_parent(node, replacement)


def try_inline_trivial_function(
    func: JsFunctionExpression,
    call_args: list,
    *,
    relaxed: bool = False,
    transformer: Transformer | None = None,
) -> Node | None:
    """
    If *func* is a trivial wrapper (single return whose expression uses only the function's
    parameters), substitute call-site arguments into a clone of the return expression. Returns the
    inlined expression or `None` if the function is not a simple wrapper.

    When *relaxed* is False (default), all arguments must be side-effect-free simple expressions.
    When *relaxed* is True, only arguments used more than once in the return expression need to be
    simple (prevents duplicating side effects while allowing complex single-use arguments).

    An async or generator function is never inlined: calling it produces a promise or an iterator, not
    the bare value of its return expression, so substituting the expression in for the call would drop
    that wrapping and change the value's type.
    """
    if func.is_async or func.generator:
        return None
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
    if _param_written(expr, set(param_names)):
        return None
    if relaxed:
        for i, name in enumerate(param_names):
            uses = sum(
                1 for n in expr.walk()
                if isinstance(n, JsIdentifier) and n.name == name and is_use_position(n)
            )
            if uses > 1 and not is_simple_expression(call_args[i]):
                return None
    return substitute_params(expr, func.params, call_args, transformer=transformer)


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
    Collect the names of all `refinery.lib.scripts.js.model.JsIdentifier` nodes in the subtree
    rooted at *node*.
    """
    return {n.name for n in node.walk() if isinstance(n, JsIdentifier)}


def find_enclosing_body(node: Node) -> list[Statement] | None:
    """
    Walk up parent pointers from *node* to find the body list that directly contains it. Returns the
    `body` attribute of the nearest `refinery.lib.scripts.js.model.JsBlockStatement` or
    `refinery.lib.scripts.js.model.JsScript` ancestor whose body list includes *node* (or an
    ancestor of *node*).
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


def references_receiver_this(root: Node) -> bool:
    """
    Return whether relocating *root* would change the meaning of a `this` or `super` reference bound
    to its current receiver. Both are receiver-bound: `this` to the call's receiver and `super` to the
    method's home object, and `super` is a syntax error outside a method, so a value that uses either
    cannot be detached from its containing method. Arrow functions inherit both lexically, so they are
    traversed; regular and generator functions nested below *root* rebind `this` (and cannot name the
    outer `super`) and are not descended into. A class also rebinds `this` for its method bodies and
    field initializers, but its `extends` clause and any computed member keys are evaluated in the
    enclosing `this` context, so only those parts of a class are traversed. *root* itself is always
    traversed, so a method whose body reads `this` or `super` (directly or through an arrow) counts.
    An identifier `super` that merely names a property (`x.super`) or an object-literal key is not a
    receiver-bound reference, so it is gated on `is_use_position` and does not count.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, JsThisExpression):
            return True
        if isinstance(node, JsIdentifier) and node.name == 'super' and is_use_position(node):
            return True
        if isinstance(node, (JsFunctionExpression, JsFunctionDeclaration)) and node is not root:
            continue
        if isinstance(node, (JsClassDeclaration, JsClassExpression)):
            if node.super_class is not None:
                stack.append(node.super_class)
            if node.body is not None:
                for member in node.body.body:
                    if member.computed and member.key is not None:
                        stack.append(member.key)
            continue
        stack.extend(node.children())
    return False


def binding_has_references(
    model: SemanticModel,
    binding: Binding | None,
    *,
    exclude: Node | None = None,
    exclude_ids: set[int] | None = None,
) -> bool:
    """
    Whether *binding* is still read or written outside an excluded region. Resolution is
    binding-precise: only references that actually resolve to *binding* count, so a same-named
    variable in another scope never keeps it alive — this subsumes the name-based shadow check that
    `has_remaining_references` performs textually. A `None` binding (a name the model cannot resolve
    to a declaration) is conservatively reported as still referenced. References within the subtree
    of *exclude*, or whose node identity is in *exclude_ids*, are not counted.
    """
    if binding is None:
        return True
    for ref in model.references(binding, exclude=exclude):
        if exclude_ids and id(ref) in exclude_ids:
            continue
        return True
    return False


class BodyProcessingTransformer(Transformer):
    """
    Intermediate base for JS deobfuscation transformers that process the statement list (body) of
    `refinery.lib.scripts.js.model.JsScript` and `refinery.lib.scripts.js.model.JsBlockStatement`
    nodes after visiting children. Subclasses override `_process_body`.
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
    Base for transforms that process at function-scope boundaries. Visits
    `refinery.lib.scripts.js.model.JsScript` and each function body
    (`refinery.lib.scripts.js.model.JsFunctionDeclaration`,
    `refinery.lib.scripts.js.model.JsFunctionExpression`,
    `refinery.lib.scripts.js.model.JsArrowFunctionExpression`). Subclasses may override either
    `_process_scope` or `_process_scope_body`.
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
        Receives the raw scope node (`refinery.lib.scripts.js.model.JsScript` or
        `refinery.lib.scripts.js.model.JsBlockStatement`).
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
