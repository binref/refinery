"""
The JavaScript value domain: what a value is (`Value`, `JS_NULL`, `JS_HOLE`, `JsBuffer`), the
ECMA-262 conversions between values (`to_number`, `to_string`, `to_boolean`, `to_primitive`,
`js_typeof`), and the operators over them (`UNARY_OPS`, `BINARY_OPS`).

This module sits beside `refinery.lib.scripts.js.numbers` because what an operator computes from two
values is a property of the language rather than of any one pass over a program. Every layer that
asks it, the analysis included, can import it from here.
"""
from __future__ import annotations

import math
import operator

from typing import TYPE_CHECKING, Callable

from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrowFunctionExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
)
from refinery.lib.scripts.js.numbers import js_number_to_string, js_string_to_number, to_js_number

if TYPE_CHECKING:
    from typing import TypeAlias

    from refinery.lib.scripts.js.model import JsFunctionNode

    Value: TypeAlias = (
        str | float | bool | list | dict | JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression | None
    )


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


class _JsHole:
    """
    Singleton sentinel for an array hole: a position an array holds no element at, which is not
    an element holding `undefined`. A program cannot produce one as a value — reading a hole
    yields `undefined` (`refinery.lib.scripts.js.deobfuscation.helpers.read_data_property` answers
    `ABSENT` for the slot) — so the sentinel never reaches a folded result. It exists so that a
    store growing an array past its end can grow the array in place, where a copy could not:
    `var v = u; u[87] = 5` leaves `v.length` at 88, so the positions the store skipped over have to
    live in the one array both names hold, as slots no read treats as elements.
    """
    __slots__ = ()

    def __repr__(self) -> str:
        return 'JS_HOLE'


JS_HOLE = _JsHole()


GLOBAL_VALUE_NAMES: dict[str, Value] = {
    'undefined': None,
    'NaN': float('nan'),
    'Infinity': float('inf'),
}
"""
The three global names that carry a value no literal spells, so that an operand written with one of
them holds a value `refinery.lib.scripts.js.deobfuscation.helpers.extract_literal_value` cannot
report and a caller that wants it looks here.

What makes reading them safe is *not* the specification. ES5 made them non-writable and
non-configurable, but ES3 did not — its own Annex E lists the change as an intentional
incompatibility — and ES3 is what Windows Script Host runs, which is the dialect of the `.js`, `.wsf`
and `.hta` droppers this tool exists for. Measured under `cscript`, JScript 11.0: `undefined =
'CLOBBERED'` sticks, and `typeof undefined` becomes `'string'` afterwards. Clobbering `undefined` is
a live obfuscation technique precisely because it breaks a naive `=== undefined` check.

What makes reading them safe is the binding analysis. A program that assigns one of these names at
top level creates an `IMPLICIT_GLOBAL` binding the model records, and
`refinery.lib.scripts.js.deobfuscation.helpers.denoted_value` — the only reader that may consult
this table — refuses any name the model resolves. All three are also ordinary identifiers as far as
scoping goes: a parameter, a `let` or a `var` of the same name shadows them, and that is the same
refusal. Reading the table without asking the model is a bug.
"""


class JsBuffer(list):
    """
    Thin wrapper around `list` to distinguish a Node.js Buffer (byte array) from a plain JS Array in
    the interpreter's type-based method dispatch. It lives beside `JS_NULL` because both are members
    of the interpreter's value domain that a plain Python type cannot express, and every consumer of
    that domain — most importantly `refinery.lib.scripts.js.deobfuscation.helpers.value_to_node`,
    which must not render a Buffer as an array literal — has to be able to tell them apart.
    """
    pass


def converts_uninterceptably(value: Value) -> bool:
    """
    Whether converting *value* to a string — or to the key of a property access, which converts it
    the same way — is an internal operation no program can replace. Every primitive is: `String(1)`
    and `o[1]` answer what the specification says whatever the file did to the prototypes. A hole
    is too: it renders as the empty string, and whether an array's chain supplies an element at the
    position the hole stands at is a question about the array, which the caller holding the array
    asks of it. An array and an object are not, because their conversion runs `Array.prototype.join`
    and `Object.prototype.toString`, so a file that replaces either decides what `o[[1]]` reads.
    A fold that converts a value without asking this computes a key or an operand the engine never
    would.
    """
    return (
        value is None or value is JS_NULL or value is JS_HOLE
        or isinstance(value, (str, int, float, bool))
    )


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


def to_boolean(value: Value) -> bool:
    """
    Apply the ECMA-262 ToBoolean abstract operation. This is the value-domain counterpart of the
    AST-node `refinery.lib.scripts.js.deobfuscation.helpers.is_truthy`; the two must agree on which
    values are falsy (`undefined`, `null`, `0`, `NaN`, `''`) so that interpreted and statically
    folded conditionals stay consistent.
    """
    if value is None or value is JS_NULL:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0 and value == value
    if isinstance(value, str):
        return len(value) > 0
    if isinstance(value, list):
        return True
    if isinstance(value, dict):
        return True
    if isinstance(value, FUNCTION_NODES):
        return True
    return False


def to_number(value: Value) -> float:
    """
    Apply the ECMA-262 ToNumber abstract operation, which is a dispatch on the type of a value. The
    string case is the only one with a grammar behind it, and that grammar is `js_string_to_number`
    in the Number domain, where the reading of a Number belongs; asking Python's `float` here
    instead would answer a different question, its own grammar being wider than the language's in
    several places at once.
    """
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return to_js_number(value)
    if isinstance(value, str):
        return js_string_to_number(value)
    if value is JS_NULL:
        return 0.0
    if isinstance(value, list):
        return to_number(to_string(value))
    return float('nan')


def function_source(func: JsFunctionNode) -> str:
    """
    The text `Function.prototype.toString` answers for *func*. A function the parser read carries
    the source it was written with; one a transform built carries none, and is written back the way
    the synthesizer would write it, which is what running that program would then read for it.
    """
    if func.source_text is not None:
        return func.source_text
    from refinery.lib.scripts.js.synth import JsSynthesizer
    return JsSynthesizer().convert(func)


def to_string(value: Value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return 'undefined'
    if value is JS_NULL:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return js_number_to_string(value)
    if isinstance(value, list):
        return ','.join(_array_element_string(v) for v in value)
    if isinstance(value, FUNCTION_NODES):
        return function_source(value)
    return '[object Object]'


def _array_element_string(value: Value) -> str:
    """
    Stringify an array element for `Array.prototype.toString` / `join` / the string coercion of
    the whole array. JavaScript renders `null`, `undefined` and hole elements as the empty string
    (e.g. `[1, null, 2].toString()` is `'1,,2'`), unlike a top-level `String(null)` which is
    `'null'`.
    """
    if value is None or value is JS_NULL or value is JS_HOLE:
        return ''
    return to_string(value)


def _to_int(value: Value) -> int:
    n = to_number(value)
    if n != n or math.isinf(n):
        return 0
    return int(n)


def js_typeof(value: Value) -> str:
    """
    Apply the `typeof` operator to a value. Total over the domain, and the reason `typeof null` is
    `'object'` falls out of the ordering rather than being stated: `JS_NULL` is not any of the
    primitive types tested for, so it reaches the same answer every object does.
    """
    if value is None:
        return 'undefined'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, FUNCTION_NODES):
        return 'function'
    return 'object'


def _js_div(a: int | float, b: int | float) -> int | float:
    if b == 0:
        if a == 0 or a != a:
            return float('nan')
        negative = (a < 0) != (math.copysign(1.0, b) < 0)
        return float('-inf') if negative else float('inf')
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


def _js_pow(base: int | float, exp: int | float) -> float:
    """
    Replicate JavaScript exponentiation (`**` / `Math.pow`). JavaScript numbers are IEEE-754 doubles,
    so this diverges from Python in cases that matter: `anything ** 0` is `1` (even `NaN ** 0`); a base
    of `1` or `-1` with an infinite exponent is `NaN` (Python: `1.0`); a negative base with a
    non-integer exponent is a complex number in Python (JS: `NaN`); a zero base with a negative
    exponent is `Infinity` (with the sign rule for `-0`); and a magnitude beyond the double range is
    `Infinity`, whereas Python's arbitrary-precision `int ** int` returns an exact bignum.

    An infinite exponent is decided from the base's *magnitude* alone and never from its sign, which
    is why it is answered before the negative-base rule rather than folded into it. Raising `-2` to
    `Infinity` is `Infinity` and raising `-0.5` to it is `0`, where reading an infinite exponent as
    a non-integer one would call both `NaN`.

    Both operands are coerced here and not only at `eval_binary_op`, because this is the one
    operator that answers an unbounded amount of work when handed Python integers, and it is
    reachable through `BINARY_OPS` without passing that function.
    """
    base = to_js_number(base)
    exp = to_js_number(exp)
    inf = float('inf')
    if exp == 0:
        return 1.0
    if base != base or exp != exp:
        return float('nan')
    if exp in (inf, -inf):
        magnitude = abs(base)
        if magnitude == 1:
            return float('nan')
        return inf if (magnitude > 1) == (exp == inf) else 0.0
    is_int_exp = exp == int(exp)
    if base == 0 and exp < 0:
        if is_int_exp and int(exp) % 2 != 0 and math.copysign(1.0, base) < 0:
            return -inf
        return inf
    if base < 0 and base != -inf and not is_int_exp:
        return float('nan')
    try:
        result = base ** exp
    except OverflowError:
        return -inf if (base < 0 and is_int_exp and int(exp) % 2 != 0) else inf
    except (ValueError, ZeroDivisionError):
        return float('nan')
    return result


BINARY_OPS: dict[str, Callable] = {
    '+'  : operator.add,
    '-'  : operator.sub,
    '*'  : _js_mul,
    '/'  : _js_div,
    '%'  : _js_mod,
    '**' : _js_pow,
    '|'  : lambda a, b: float(_to_int32(a) | _to_int32(b)),
    '&'  : lambda a, b: float(_to_int32(a) & _to_int32(b)),
    '^'  : lambda a, b: float(_to_int32(a) ^ _to_int32(b)),
    '<<' : lambda a, b: float(_to_int32(_to_int32(a) << (_to_int32(b) & 0x1F))),
    '>>' : lambda a, b: float(_to_int32(a) >> (_to_int32(b) & 0x1F)),
}
"""
JavaScript's binary operators over two *numbers*. Every entry assumes both operands have already
been coerced, which is why `+` is `operator.add` here: on numbers that is what `+` means, but on a
value that may be a string or an object `+` is a different operator entirely — it applies
ToPrimitive to both sides and concatenates when either is a string. A caller holding uncoerced
values must not reach this table for `+`; the interpreter routes every operator through
`refinery.lib.scripts.js.deobfuscation.interpreter.JsInterpreter._apply_binary`, which resolves the
string cases before delegating here.
"""

UNARY_OPS: dict[str, Callable[[Value], Value]] = {
    '-'     : lambda v: -to_number(v),
    '+'     : to_number,
    '~'     : lambda v: float(_to_int32(~_to_int(v))),
    '!'     : lambda v: not to_boolean(v),
    'void'  : lambda v: None,
    'typeof': js_typeof,
}
"""
JavaScript's unary operators that are functions of their operand's *value* alone. Each is total over
the value domain — the coercions answer for every value rather than refusing any — so a caller holding
a value needs no per-operator guard, and a caller holding a syntax tree needs only to obtain the value.

`delete` is absent because it is not one of these: its result depends on the operand's *reference*
rather than its value, and evaluating it changes the object it names. A pass that wants to fold a
`delete` has to reason about that object, which is a question about the program and not about a value,
so the absence is what keeps this table from being asked it.

`void` is a member despite discarding its operand, because discarding a value is still a function of
it. The caller remains responsible for evaluating the operand: `void f()` is `undefined` and calls `f`,
and this table only supplies the first half.
"""

RELATIONAL_OPS: dict[str, Callable] = {
    '<' : operator.lt,
    '>' : operator.gt,
    '<=': operator.le,
    '>=': operator.ge,
}


def eval_binary_op(op: str, left: float, right: float) -> float | bool | None:
    """
    Evaluate a JavaScript binary operator on two numeric operands. Returns the result value, or
    `None` when the operator is unknown or the computation overflows/divides by zero. Handles
    arithmetic, bitwise, relational, equality, and the unsigned right shift `>>>`.

    Both operands are coerced here so that every operator below sees the Number the caller meant and
    not whichever Python type happened to carry it. That is a normalization and not the bound on the
    work: `refinery.lib.scripts.js.deobfuscation.stringarray` reaches `BINARY_OPS` without passing
    through this function, so the operator that can be asked for unbounded work — `**`, where Python
    integers build a number of half a billion digits for what a double answers in one operation —
    coerces for itself as well.
    """
    left = to_js_number(left)
    right = to_js_number(right)
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
        return float((a >> b) & 0xFFFFFFFF)
    fn = BINARY_OPS.get(op)
    if fn is None:
        return None
    try:
        return fn(left, right)
    except (ZeroDivisionError, OverflowError, ValueError):
        return None


#: The value-domain types that model a JavaScript object: an array, a plain object, and a function.
#: They share the two behaviours the primitives do not: a ToPrimitive that runs a conversion, and an
#: equality by reference rather than by value.
OBJECT_VALUE_TYPES = (
    list,
    dict,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsArrowFunctionExpression,
)


def to_primitive(value: Value) -> Value:
    """
    Apply the ECMA-262 ToPrimitive abstract operation. An array, a plain object and a function have
    no `valueOf` that answers a primitive, so each converts to its string form under either hint;
    every other value already is one. Whether the program replaced the conversion is the caller's
    question (`refinery.lib.scripts.js.deobfuscation.helpers.coerces_uninterceptably`).
    """
    if isinstance(value, OBJECT_VALUE_TYPES):
        return to_string(value)
    return value


def js_strict_equal(a: Value, b: Value) -> bool:
    """
    Compare two values using JavaScript strict-equality (`===`) semantics. Unlike Python equality
    this does not conflate booleans with the numbers `1` and `0`.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, str):
        return a == b
    return a is b


def js_loose_equal(a: Value, b: Value) -> bool:
    """
    Replicate the ECMA-262 abstract-equality (`==`) algorithm. `null` and `undefined` are equal to
    each other and to nothing else; a boolean coerces to a number; two objects compare by
    reference, while an object compared with a primitive coerces to a primitive first; a number
    compared with a string compares by numeric value.
    """
    a_nullish = a is None or a is JS_NULL
    b_nullish = b is None or b is JS_NULL
    if a_nullish or b_nullish:
        return a_nullish and b_nullish
    if isinstance(a, bool):
        a = 1 if a else 0
    if isinstance(b, bool):
        b = 1 if b else 0
    a_object = isinstance(a, OBJECT_VALUE_TYPES)
    b_object = isinstance(b, OBJECT_VALUE_TYPES)
    if a_object and b_object:
        return js_strict_equal(a, b)
    if a_object:
        a = to_primitive(a)
    elif b_object:
        b = to_primitive(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    a_num = isinstance(a, (int, float))
    b_num = isinstance(b, (int, float))
    if a_num and b_num:
        return a == b
    if (a_num and isinstance(b, str)) or (isinstance(a, str) and b_num):
        return to_number(a) == to_number(b)
    return js_strict_equal(a, b)


def js_add(a: Value, b: Value) -> Value:
    """
    Replicate the JavaScript `+` operator: apply ToPrimitive to both operands, then concatenate as
    strings if either is a string, otherwise add numerically.
    """
    a = to_primitive(a)
    b = to_primitive(b)
    if isinstance(a, str) or isinstance(b, str):
        return to_string(a) + to_string(b)
    return to_number(a) + to_number(b)
