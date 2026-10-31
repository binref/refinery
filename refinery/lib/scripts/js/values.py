"""
The JavaScript value domain: what a value is (`Value`, `JS_NULL`, `JS_HOLE`, `JsBuffer`), the
ECMA-262 conversions between values (`to_number`, `to_string`, `to_boolean`, `to_primitive`,
`js_typeof`), and the operators over them (`UNARY_OPS`, `BINARY_OPS`).

This module sits beside `refinery.lib.scripts.js.numbers` because what an operator computes from two
values is a property of the language rather than of any one pass over a program. The analysis that
decides whether an operator may run code (`COERCING_BINARY_OPERATORS`), the static fold, and the
interpreter all read it here, so none of them states a second answer.
"""
from __future__ import annotations

import math
import operator

from typing import TYPE_CHECKING, Any, Callable

from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrowFunctionExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
)
from refinery.lib.scripts.js.numbers import js_number_to_string, js_string_to_number, to_js_number
from refinery.lib.scripts.js.utf16 import to_code_units


class BuiltinFunction:
    """
    A function the language installs, as a fold holds one: the one instance
    `refinery.lib.scripts.js.builtins` keeps for each such function, so that two reads of one
    function are one value and reads of two functions are two. *name* is the `name` the function
    owns, and *is_constructor* marks one of the constructors a global name holds.

    It is an object whose `typeof` is `'function'`. Converting it to a primitive gives the text the
    host's engine writes for it, which no value of this domain knows, so `to_string` raises
    `HostApproximated` and a fold asks the host instead
    (`refinery.lib.scripts.js.analysis.environment.HostEnvironment.native_function_text`); every
    host writes that text in the syntax of a function, which reads as no number.
    """
    __slots__ = 'name', 'is_constructor'

    def __init__(self, name: str, is_constructor: bool):
        self.name = name
        self.is_constructor = is_constructor

    def __repr__(self) -> str:
        return F'BuiltinFunction({self.name!r})'


if TYPE_CHECKING:
    from typing import TypeAlias

    from refinery.lib.scripts.js.model import JsFunctionNode

    Value: TypeAlias = (
        str | float | bool | list | dict | JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression
        | BuiltinFunction | None
    )


class HostApproximated(ArithmeticError):
    """
    Raised for a value the language leaves to the engine to approximate, so that engines differ in
    it. A caller that would write the value into the program, or compute on with it, refuses.
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
    if isinstance(value, BuiltinFunction):
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
    """
    Apply the ECMA-262 ToString abstract operation. A Buffer converts through its own `toString`,
    which decodes its bytes as UTF-8 and writes U+FFFD for each sequence that is not, as Node does;
    any other array joins its elements.
    """
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
    if isinstance(value, JsBuffer):
        return utf8_text(bytes(_to_int(v) & 0xFF for v in value))
    if isinstance(value, list):
        return ','.join(_array_element_string(v) for v in value)
    if isinstance(value, FUNCTION_NODES):
        return function_source(value)
    if isinstance(value, BuiltinFunction):
        raise HostApproximated
    return '[object Object]'


def utf8_text(data: bytes) -> str:
    """
    The string a Buffer holding *data* decodes to as UTF-8, as Node decodes it: U+FFFD for each
    sequence that is not UTF-8, and every character spelled in UTF-16 code units.
    """
    return to_code_units(data.decode('utf-8', 'replace'))


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
    if isinstance(value, BuiltinFunction):
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

    The specification fixes the result only in those cases and for a zero or infinite base. For any
    other pair it asks for a value the implementation approximates, and engines differ in the last
    digit: V8 answers `9 ** 17` with `16677181699666570`, where the nearest double to the power is
    `16677181699666568`. A result is therefore given only where every engine agrees on it: a base
    raised to an integer exponent whose power is a double, or so large that it is an infinity. Any
    other pair raises `HostApproximated`.

    Both operands are coerced here and not only at `BINARY_OPS`, because this is the one operator
    that answers an unbounded amount of work when handed Python integers, and `Math.pow` reaches it
    without passing that table.
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
    odd = exp == int(exp) and int(exp) % 2 != 0
    if base == 0 or base in (inf, -inf):
        magnitude = inf if (base != 0) == (exp > 0) else 0.0
        return -magnitude if odd and math.copysign(1.0, base) < 0 else magnitude
    if base < 0 and exp != int(exp):
        return float('nan')
    if exp == int(exp):
        power = _exact_power(base, int(exp))
        if power is not None:
            return power
    raise HostApproximated


def _exact_power(base: float, exp: int) -> float | None:
    """
    The finite nonzero *base* raised to the nonzero *exp* where every engine computes the same
    double, or `None`: the power itself where it is a double, and an infinity of its sign where it
    is at least `2 ** 1024`, which is past the largest double by more than any engine errs.

    The base is an odd integer times a power of two, and its power is a double exactly where the
    power of the odd integer is an integer of at most 53 bits and the power of two lies in the range
    of a double. Below a negative exponent only the odd integer `1` stays an integer, so `2 ** -1`
    is the double `0.5` and `10 ** -2` is no double at all. The odd integer is raised only where the
    bound can hold, and an infinity is otherwise read from the logarithm only where it is clear of
    `2 ** 1024`, so the work stays bounded.
    """
    numerator, denominator = abs(base).as_integer_ratio()
    twos = (numerator & -numerator).bit_length() - 1
    odd = numerator >> twos
    scale = (twos - denominator.bit_length() + 1) * exp
    sign = -1.0 if base < 0 and exp % 2 else 1.0
    power = _odd_power(odd, exp)
    if power is not None:
        if power.bit_length() + scale > 1024:
            return math.copysign(float('inf'), sign)
        if scale < -1074:
            return None
        return math.copysign(math.ldexp(power, scale), sign)
    if exp * math.log2(abs(base)) >= 1025:
        return math.copysign(float('inf'), sign)
    return None


def _odd_power(odd: int, exp: int) -> int | None:
    """
    The odd integer *odd* raised to *exp* where that is an integer of at most 53 bits, or `None`.
    """
    if odd == 1:
        return 1
    if exp < 0 or exp * (odd.bit_length() - 1) >= 53:
        return None
    power = odd ** exp
    return power if power >> 53 == 0 else None


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

COERCING_UNARY_OPERATORS = frozenset({'+', '-', '~'})
"""
The unary operators that convert their operand, each to a number. Converting an object runs its
`valueOf`, `toString` or `Symbol.toPrimitive`, so an operand of one of these runs code wherever it
may be an object. `!`, `typeof` and `void` take the operand to a truth value, a type name or
nothing without asking it anything.
"""

#: The value-domain types that model a JavaScript object: an array, a plain object, a function,
#: and a function the language installs. They share the two behaviours the primitives do not: a
#: ToPrimitive that runs a conversion, and an equality by reference rather than by value.
OBJECT_VALUE_TYPES = (
    list,
    dict,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsArrowFunctionExpression,
    BuiltinFunction,
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


def _on_numbers(apply: Callable[[float, float], float]) -> Callable[[Value, Value], Value]:
    """
    The operator that applies *apply* to the numbers its two operands convert to.
    """
    return lambda a, b: apply(to_number(a), to_number(b))


def _comparing(compare: Callable[[Any, Any], bool]) -> Callable[[Value, Value], Value]:
    """
    The relational operator that answers *compare*: two strings compare by their code units, and
    any other pair of primitives by the numbers they convert to, where `NaN` answers `false`.
    """
    def apply(a: Value, b: Value) -> Value:
        a = to_primitive(a)
        b = to_primitive(b)
        if isinstance(a, str) and isinstance(b, str):
            return compare(a, b)
        return compare(to_number(a), to_number(b))
    return apply


BINARY_OPS: dict[str, Callable[[Value, Value], Value]] = {
    '+'   : js_add,
    '-'   : _on_numbers(operator.sub),
    '*'   : _on_numbers(_js_mul),
    '/'   : _on_numbers(_js_div),
    '%'   : _on_numbers(_js_mod),
    '**'  : _on_numbers(_js_pow),
    '|'   : _on_numbers(lambda a, b: float(_to_int32(a) | _to_int32(b))),
    '&'   : _on_numbers(lambda a, b: float(_to_int32(a) & _to_int32(b))),
    '^'   : _on_numbers(lambda a, b: float(_to_int32(a) ^ _to_int32(b))),
    '<<'  : _on_numbers(lambda a, b: float(_to_int32(_to_int32(a) << (_to_int32(b) & 0x1F)))),
    '>>'  : _on_numbers(lambda a, b: float(_to_int32(a) >> (_to_int32(b) & 0x1F))),
    '>>>' : _on_numbers(lambda a, b: float(_to_uint32(a) >> (_to_uint32(b) & 0x1F))),
    '<'   : _comparing(operator.lt),
    '>'   : _comparing(operator.gt),
    '<='  : _comparing(operator.le),
    '>='  : _comparing(operator.ge),
    '=='  : js_loose_equal,
    '!='  : lambda a, b: not js_loose_equal(a, b),
    '===' : js_strict_equal,
    '!==' : lambda a, b: not js_strict_equal(a, b),
}
"""
JavaScript's binary operators that are functions of their two operands' *values*, the counterpart of
`UNARY_OPS`. Each entry applies the conversions its operator performs, so each is total over the
value domain: a caller holding two values needs no per-operator guard, and a caller holding a syntax
tree needs only to obtain the values. Whether converting an object runs code the program installed
is not a question about the value, and the caller asks it before applying an entry
(`refinery.lib.scripts.js.deobfuscation.helpers.coerces_uninterceptably`).

`**` raises `HostApproximated` where the language leaves its result to the engine (`_js_pow`).

`in` and `instanceof` are absent for the reason `delete` is absent from `UNARY_OPS`: each asks the
object its right operand names, for a property or for its prototype, which the value does not say.
"""

COERCING_BINARY_OPERATORS = frozenset(BINARY_OPS) - {'===', '!=='}
"""
The binary operators that convert an operand: every one in `BINARY_OPS` but strict equality, which
compares the values as they are. Converting an object runs its `valueOf`, `toString` or
`Symbol.toPrimitive`, so an operand of one of these runs code wherever it may be an object.
"""


def converted_operands(operator: str, a: Value, b: Value) -> tuple[bool, bool]:
    """
    Whether the binary *operator* in `BINARY_OPS` converts the object *a* and the object *b* to
    primitives when applied to them; a primitive is never converted. Loose equality converts
    neither operand where both are objects, which it compares by reference, or where one is `null`
    or `undefined`, which it compares with nothing else; it converts the object of an object and a
    primitive, as every other coercing operator converts every object operand.
    """
    if operator not in COERCING_BINARY_OPERATORS:
        return False, False
    a_object = isinstance(a, OBJECT_VALUE_TYPES)
    b_object = isinstance(b, OBJECT_VALUE_TYPES)
    if operator in ('==', '!='):
        if a_object and b_object:
            return False, False
        if a is None or a is JS_NULL or b is None or b is JS_NULL:
            return False, False
    return a_object, b_object
