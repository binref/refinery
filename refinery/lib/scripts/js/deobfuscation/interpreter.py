"""
Mini-interpreter for executing pure JavaScript functions with concrete arguments.
"""
from __future__ import annotations

import base64
import json
import math
import re
import sys
import urllib.parse

from decimal import Decimal

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Mapping, TypeAlias

    from refinery.lib.scripts.js.analysis.effects import EffectModel
    from refinery.lib.scripts.js.model import JsArrowFunctionExpression as _Arrow
    from refinery.lib.scripts.js.model import JsFunctionDeclaration as _FuncDecl
    from refinery.lib.scripts.js.model import JsFunctionExpression as _FuncExpr

    Value: TypeAlias = str | int | float | bool | list | dict | _FuncDecl | _FuncExpr | _Arrow | None
    _FuncNode: TypeAlias = _FuncDecl | _FuncExpr | _Arrow

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.deobfuscation.helpers import (
    JS_NULL,
    RELATIONAL_OPS,
    _js_pow,
    _to_int32,
    _to_uint32,
    eval_binary_op,
    js_parse_int,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDoWhileStatement,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
    JsReturnStatement,
    JsSequenceExpression,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTemplateLiteral,
    JsThrowStatement,
    JsTryStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
)

MAX_ITERATIONS = 100_000
MAX_STRING_LEN = 1_000_000
_MAX_RECURSION = 10


class InterpreterError(Exception):
    pass


class IrreducibleExpression(Exception):
    def __init__(self, node: Node):
        self.node = node


class _ReturnSignal(Exception):
    def __init__(self, value: Value):
        self.value = value


class _BreakSignal(Exception):
    pass


class _ContinueSignal(Exception):
    pass


class _ThrowSignal(Exception):
    def __init__(self, value: Value):
        self.value = value


def _js_throw(name: str, message: str = '') -> None:
    """
    Signal a genuine JavaScript runtime exception (e.g. a `TypeError` or `RangeError`) that an
    emulated `try/catch` must be able to catch. The thrown value is a plain object carrying `name`
    and `message`, so `typeof e` is `'object'` and `e.name` / `e.message` are usable. This is
    distinct from `InterpreterError`, which means "abort interpretation" and is never caught.
    """
    raise _ThrowSignal({'name': name, 'message': message})


class _ReturnIrreducible(Exception):
    """
    Raised when a function's return value (or an arrow's tail expression) is an irreducible
    expression. This is distinct from a bare `IrreducibleExpression`, which may surface from a
    non-return position (a variable initializer, an expression statement, a loop) and therefore does
    NOT represent the function's value. Only a `_ReturnIrreducible` is converted back into an
    `IrreducibleExpression` for the evaluator to substitute at the call site.
    """
    def __init__(self, node: Node):
        self.node = node


class JsBuffer(list):
    """
    Thin wrapper around `list` to distinguish a Node.js Buffer (byte array) from a plain JS Array
    in the interpreter's type-based method dispatch.
    """
    pass


def _contains_jsbuffer(value: Value) -> bool:
    """
    Recursively determine whether *value* is, or contains, a `JsBuffer`. A Buffer (even nested
    inside an array or object) must never be emitted as a plain array literal, which would silently
    change its type and method dispatch (e.g. `.toString('hex')` would no longer work).
    """
    if isinstance(value, JsBuffer):
        return True
    if isinstance(value, list):
        return any(_contains_jsbuffer(v) for v in value)
    if isinstance(value, dict):
        return any(_contains_jsbuffer(v) for v in value.values())
    return False


def _deep_copy_value(value):
    if isinstance(value, list):
        return type(value)(_deep_copy_value(item) for item in value)
    if isinstance(value, dict):
        return {k: _deep_copy_value(v) for k, v in value.items()}
    return value


def _truthy(value: Value) -> bool:
    """
    Return the JavaScript truthiness of a runtime value. This is the runtime counterpart of the
    AST-node `refinery.lib.scripts.js.deobfuscation.helpers.is_truthy`; the two must agree on which
    values are falsy (`undefined`, `null`, `0`, `NaN`, `''`) so that interpreted and
    statically-folded conditionals stay consistent.
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
    if isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return True
    return False


def _to_int(value: Value) -> int:
    n = to_number(value)
    if n != n or math.isinf(n):
        return 0
    return int(n)


def _to_index(value: Value) -> int:
    n = to_number(value)
    if n != n:
        return 0
    if n == float('inf'):
        return sys.maxsize
    if n == float('-inf'):
        return -sys.maxsize
    return int(n)


def _to_array_length(value: Value) -> int:
    """
    Coerce a value to a valid array length. Per ECMA-262 ArraySetLength, `ToUint32(v)` must equal
    `ToNumber(v)`; otherwise the length is invalid and a JavaScript `RangeError` is signalled. This
    rejects NaN, +/-Infinity, negative, and non-integer lengths, each of which a real engine
    (verified against Node and Chrome) reports as `Invalid array length`.
    """
    number_len = to_number(value)
    length = _to_uint32(number_len)
    if length != number_len:
        _js_throw('RangeError', 'Invalid array length')
    return length


def to_number(value: Value) -> int | float:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        if '_' in s:
            return float('nan')
        if s[0] in '+-' and len(s) > 2 and s[1] == '0' and s[2] in 'xXoObB':
            return float('nan')
        try:
            return int(s, 0)
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            return float('nan')
    if value is JS_NULL:
        return 0
    if isinstance(value, list):
        return to_number(to_string(value))
    return float('nan')


def _js_float_to_string(value: float) -> str:
    """
    Format a finite, non-zero float as JavaScript's `Number.prototype.toString` (the ECMA-262
    Number::toString algorithm) would: this controls the decimal/exponential cutoff (exponential at
    magnitudes >= 1e21 or < 1e-6) and the exponent format (`1e-7`, not Python's `1e-07`).
    """
    neg = value < 0
    d = Decimal(repr(abs(value)))
    s = ''.join(str(digit) for digit in d.as_tuple().digits).rstrip('0') or '0'
    k = len(s)
    n = d.adjusted() + 1
    if k <= n <= 21:
        result = s + '0' * (n - k)
    elif 0 < n <= 21:
        result = s[:n] + '.' + s[n:]
    elif -6 < n <= 0:
        result = '0.' + '0' * -n + s
    else:
        mantissa = s if k == 1 else s[0] + '.' + s[1:]
        exponent = n - 1
        result = F"{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"
    return '-' + result if neg else result


def to_string(value: Value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return 'undefined'
    if value is JS_NULL:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:
            return 'NaN'
        if value == float('inf'):
            return 'Infinity'
        if value == float('-inf'):
            return '-Infinity'
        if value == 0:
            return '0'
        if value == int(value) and abs(value) < 1e21:
            return str(int(value))
        return _js_float_to_string(value)
    if isinstance(value, list):
        return ','.join(_array_element_string(v) for v in value)
    return '[object Object]'


def _array_element_string(value: Value) -> str:
    """
    Stringify an array element for `Array.prototype.toString` / `join`. JavaScript renders `null` and
    `undefined` elements as the empty string (e.g. `[1, null, 2].toString()` is `'1,,2'`), unlike a
    top-level `String(null)` which is `'null'`.
    """
    if value is None or value is JS_NULL:
        return ''
    return to_string(value)


def _to_primitive(value: Value) -> Value:
    """
    Replicate the ECMA-262 ToPrimitive abstract operation with the default hint, as used by `+`.
    Arrays and plain objects have no useful `valueOf`, so they coerce to their string form; all other
    values are already primitive.
    """
    if isinstance(value, (list, dict)):
        return to_string(value)
    return value


def _js_typeof(value: Value) -> str:
    if value is None:
        return 'undefined'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
        return 'function'
    return 'object'


def js_strict_equal(a: Value, b: Value) -> bool:
    """
    Compare two interpreter values using JavaScript strict-equality (`===`) semantics. Unlike
    Python equality this does not conflate booleans with the numbers `1` and `0`.
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


BUILTIN_REGISTRY: dict[tuple, Callable] = {}


def _register(key: tuple):
    def _decorator(fn: Callable):
        BUILTIN_REGISTRY[key] = fn
        return fn
    return _decorator


@_register((str, 'length'))
def _str_length(s: str, args: list[Value]) -> Value:
    return len(s)


@_register((str, 'charAt'))
def _str_char_at(s: str, args: list[Value]) -> Value:
    idx = _to_index(args[0]) if args else 0
    if 0 <= idx < len(s):
        return s[idx]
    return ''


@_register((str, 'charCodeAt'))
def _str_char_code_at(s: str, args: list[Value]) -> Value:
    idx = _to_index(args[0]) if args else 0
    if 0 <= idx < len(s):
        return ord(s[idx])
    return float('nan')


@_register((str, 'indexOf'))
def _str_index_of(s: str, args: list[Value]) -> Value:
    if not args:
        return -1
    search = to_string(args[0])
    start = _to_index(args[1]) if len(args) > 1 else 0
    return s.find(search, max(0, start))


@_register((str, 'lastIndexOf'))
def _str_last_index_of(s: str, args: list[Value]) -> Value:
    if not args:
        return -1
    search = to_string(args[0])
    n = len(s)
    if len(args) > 1:
        pos = to_number(args[1])
        start = n if pos != pos else max(0, min(_to_index(args[1]), n))
    else:
        start = n
    return s.rfind(search, 0, start + len(search))


@_register((str, 'includes'))
def _str_includes(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    search = to_string(args[0])
    start = _to_index(args[1]) if len(args) > 1 else 0
    return s.find(search, max(0, start)) != -1


@_register((str, 'startsWith'))
def _str_starts_with(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    prefix = to_string(args[0])
    start = max(0, _to_index(args[1])) if len(args) > 1 else 0
    return s[start:].startswith(prefix)


@_register((str, 'endsWith'))
def _str_ends_with(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    suffix = to_string(args[0])
    end = max(0, min(_to_index(args[1]), len(s))) if len(args) > 1 else len(s)
    return s[:end].endswith(suffix)


@_register((str, 'slice'))
def _str_slice(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = _to_index(args[0]) if args else 0
    end = _to_index(args[1]) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    if end < 0:
        end = max(n + end, 0)
    return s[start:end]


@_register((str, 'substring'))
def _str_substring(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = _to_index(args[0]) if args else 0
    end = _to_index(args[1]) if len(args) > 1 else n
    start = max(0, min(start, n))
    end = max(0, min(end, n))
    if start > end:
        start, end = end, start
    return s[start:end]


@_register((str, 'substr'))
def _str_substr(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = _to_index(args[0]) if args else 0
    length = _to_index(args[1]) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    return s[start:start + max(0, length)]


@_register((str, 'split'))
def _str_split(s: str, args: list[Value]) -> Value:
    if not args or args[0] is None:
        if len(args) > 1 and args[1] is not None:
            if _to_index(args[1]) == 0:
                return []
        return [s]
    sep = to_string(args[0])
    if not sep:
        result = list(s)
    else:
        result = s.split(sep)
    if len(args) > 1 and args[1] is not None:
        limit = _to_uint32(to_number(args[1]))
        result = result[:limit]
    return result


def _expand_replacement(replacement: str, s: str, start: int, matched: str) -> str:
    """
    Expand the JavaScript replacement-string patterns ($$, $&, $`, $') for a literal-string match
    of `matched` at index `start` in `s`. Capture-group patterns ($1..) have no meaning for a
    string search and are emitted verbatim, as JavaScript does.
    """
    out: list[str] = []
    i = 0
    n = len(replacement)
    while i < n:
        c = replacement[i]
        if c == '$' and i + 1 < n:
            nxt = replacement[i + 1]
            if nxt == '$':
                out.append('$')
            elif nxt == '&':
                out.append(matched)
            elif nxt == '`':
                out.append(s[:start])
            elif nxt == "'":
                out.append(s[start + len(matched):])
            else:
                out.append('$')
                out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


@_register((str, 'replace'))
def _str_replace(s: str, args: list[Value]) -> Value:
    if len(args) < 2:
        return s
    search = to_string(args[0])
    replacement = to_string(args[1])
    index = s.find(search)
    if index < 0:
        return s
    expanded = _expand_replacement(replacement, s, index, search)
    return s[:index] + expanded + s[index + len(search):]


@_register((str, 'replaceAll'))
def _str_replace_all(s: str, args: list[Value]) -> Value:
    if len(args) < 2:
        return s
    search = to_string(args[0])
    replacement = to_string(args[1])
    if not search:
        raise InterpreterError
    out: list[str] = []
    pos = 0
    while True:
        index = s.find(search, pos)
        if index < 0:
            out.append(s[pos:])
            break
        out.append(s[pos:index])
        out.append(_expand_replacement(replacement, s, index, search))
        pos = index + len(search)
    return ''.join(out)


@_register((str, 'toLowerCase'))
def _str_to_lower(s: str, args: list[Value]) -> Value:
    return s.lower()


@_register((str, 'toUpperCase'))
def _str_to_upper(s: str, args: list[Value]) -> Value:
    return s.upper()


@_register((str, 'trim'))
def _str_trim(s: str, args: list[Value]) -> Value:
    return s.strip()


@_register((str, 'trimStart'))
def _str_trim_start(s: str, args: list[Value]) -> Value:
    return s.lstrip()


@_register((str, 'trimEnd'))
def _str_trim_end(s: str, args: list[Value]) -> Value:
    return s.rstrip()


@_register((str, 'repeat'))
def _str_repeat(s: str, args: list[Value]) -> Value:
    count = _to_index(args[0]) if args else 0
    if count < 0 or count > 0x10000000:
        _js_throw('RangeError', 'Invalid count value')
    return s * count


def _str_pad(s: str, args: list[Value], prepend: bool) -> Value:
    target_len = _to_index(args[0]) if args else 0
    if target_len > 0x10000000:
        _js_throw('RangeError', 'Invalid string length')
    fill = to_string(args[1]) if len(args) > 1 else ' '
    needed = target_len - len(s)
    if needed <= 0 or not fill:
        return s
    pad = (fill * (needed // len(fill) + 1))[:needed]
    return pad + s if prepend else s + pad


@_register((str, 'padStart'))
def _str_pad_start(s: str, args: list[Value]) -> Value:
    return _str_pad(s, args, prepend=True)


@_register((str, 'padEnd'))
def _str_pad_end(s: str, args: list[Value]) -> Value:
    return _str_pad(s, args, prepend=False)


@_register((str, 'at'))
def _str_at(s: str, args: list[Value]) -> Value:
    idx = _to_index(args[0]) if args else 0
    if idx < 0:
        idx += len(s)
    if 0 <= idx < len(s):
        return s[idx]
    return None


@_register(('String', 'fromCharCode'))
def _string_from_char_code(args: list[Value]) -> Value:
    return ''.join(chr(_to_int(a) & 0xFFFF) for a in args)


def _json_nulls_to_jsnull(value):
    """
    Replace every decoded JSON `null` (Python `None`) with the `JS_NULL` sentinel, recursively, so
    parsed JSON uses the interpreter's `null` representation rather than `undefined`.
    """
    if value is None:
        return JS_NULL
    if isinstance(value, list):
        return [_json_nulls_to_jsnull(v) for v in value]
    if isinstance(value, dict):
        return {k: _json_nulls_to_jsnull(v) for k, v in value.items()}
    return value


@_register(('JSON', 'parse'))
def _json_parse(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError

    def _reject_constant(_: str) -> Value:
        raise InterpreterError
    s = to_string(args[0])
    try:
        parsed = json.loads(s, parse_int=float, parse_constant=_reject_constant)
    except Exception:
        raise InterpreterError
    return _json_nulls_to_jsnull(parsed)


@_register((list, 'length'))
def _arr_length(arr: list, args: list[Value]) -> Value:
    return len(arr)


@_register((list, 'push'))
def _arr_push(arr: list, args: list[Value]) -> Value:
    arr.extend(args)
    return len(arr)


@_register((list, 'pop'))
def _arr_pop(arr: list, args: list[Value]) -> Value:
    if arr:
        return arr.pop()
    return None


@_register((list, 'shift'))
def _arr_shift(arr: list, args: list[Value]) -> Value:
    if arr:
        return arr.pop(0)
    return None


@_register((list, 'unshift'))
def _arr_unshift(arr: list, args: list[Value]) -> Value:
    for i, a in enumerate(args):
        arr.insert(i, a)
    return len(arr)


@_register((list, 'reverse'))
def _arr_reverse(arr: list, args: list[Value]) -> Value:
    arr.reverse()
    return arr


@_register((list, 'concat'))
def _arr_concat(arr: list, args: list[Value]) -> Value:
    result = list(arr)
    for a in args:
        if isinstance(a, list):
            result.extend(a)
        else:
            result.append(a)
    return result


@_register((list, 'slice'))
def _arr_slice(arr: list, args: list[Value]) -> Value:
    n = len(arr)
    start = _to_index(args[0]) if args else 0
    end = _to_index(args[1]) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    if end < 0:
        end = max(n + end, 0)
    return arr[start:end]


@_register((list, 'splice'))
def _arr_splice(arr: list, args: list[Value]) -> Value:
    if not args:
        return []
    start = _to_index(args[0])
    n = len(arr)
    if start < 0:
        start = max(n + start, 0)
    else:
        start = min(start, n)
    delete_count = _to_index(args[1]) if len(args) > 1 else n - start
    delete_count = max(0, min(delete_count, n - start))
    removed = arr[start:start + delete_count]
    new_items = list(args[2:])
    arr[start:start + delete_count] = new_items
    return removed


@_register((list, 'join'))
def _arr_join(arr: list, args: list[Value]) -> Value:
    sep = ',' if not args or args[0] is None else to_string(args[0])
    return sep.join(_array_element_string(v) for v in arr)


@_register((list, 'toString'))
def _arr_to_string(arr: list, args: list[Value]) -> Value:
    return to_string(arr)


@_register((int, 'toString'))
@_register((float, 'toString'))
def _number_to_string(num: int | float, args: list[Value]) -> Value:
    radix = _to_int(args[0]) if args and args[0] is not None else 10
    if radix == 10:
        return to_string(num)
    if not 2 <= radix <= 36:
        _js_throw('RangeError', 'toString() radix must be between 2 and 36')
    value = to_number(num)
    if value != value or math.isinf(value):
        return to_string(value)
    if value != int(value):
        raise InterpreterError
    integer = abs(int(value))
    if integer == 0:
        return '0'
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    out: list[str] = []
    while integer:
        out.append(digits[integer % radix])
        integer //= radix
    text = ''.join(reversed(out))
    return '-' + text if value < 0 else text


@_register((list, 'indexOf'))
def _arr_index_of(arr: list, args: list[Value]) -> Value:
    if not args:
        return -1
    target = args[0]
    start = _to_index(args[1]) if len(args) > 1 else 0
    if start < 0:
        start = max(0, len(arr) + start)
    for i in range(start, len(arr)):
        if js_strict_equal(arr[i], target):
            return i
    return -1


@_register((list, 'includes'))
def _arr_includes(arr: list, args: list[Value]) -> Value:
    if not args:
        return False
    return any(js_strict_equal(item, args[0]) for item in arr)


@_register((list, 'flat'))
def _arr_flat(arr: list, args: list[Value]) -> Value:
    depth = _to_index(args[0]) if args else 1

    def _flatten(lst: list, d: int) -> list:
        result: list = []
        for item in lst:
            if isinstance(item, list) and d > 0:
                result.extend(_flatten(item, d - 1))
            else:
                result.append(item)
        return result
    return _flatten(arr, depth)


@_register((list, 'at'))
def _arr_at(arr: list, args: list[Value]) -> Value:
    idx = _to_index(args[0]) if args else 0
    if idx < 0:
        idx += len(arr)
    if 0 <= idx < len(arr):
        return arr[idx]
    return None


@_register((list, 'fill'))
def _arr_fill(arr: list, args: list[Value]) -> Value:
    if not args:
        return arr
    value = args[0]
    n = len(arr)
    start = _to_index(args[1]) if len(args) > 1 else 0
    end = _to_index(args[2]) if len(args) > 2 else n
    if start < 0:
        start = max(n + start, 0)
    if end < 0:
        end = max(n + end, 0)
    for i in range(start, min(end, n)):
        arr[i] = value
    return arr


_ARRAY_HOF_METHODS = frozenset({
    'every', 'some', 'map', 'filter', 'reduce', 'forEach', 'find', 'findIndex',
})

_BUFFER_PRESERVING_HOFS = frozenset({'map', 'filter'})


def _to_js_integer(args: list[Value], round_to_integer) -> Value:
    """
    Shared implementation for the integer-valued `Math` roundings (floor/ceil/round/trunc). Passes NaN
    and the infinities through unchanged and preserves the sign of a negative-zero result, which JS
    requires (e.g. `Math.round(-0)` is `-0`, observable as `1 / Math.round(-0) === -Infinity`).
    """
    v = to_number(args[0]) if args else float('nan')
    if v != v:
        return float('nan')
    if math.isinf(v):
        return v
    result = int(round_to_integer(v))
    if result == 0 and math.copysign(1.0, v) < 0:
        return -0.0
    return result


@_register(('Math', 'floor'))
def _math_floor(args: list[Value]) -> Value:
    return _to_js_integer(args, math.floor)


@_register(('Math', 'ceil'))
def _math_ceil(args: list[Value]) -> Value:
    return _to_js_integer(args, math.ceil)


def _round_half_up(v: float) -> float:
    """
    Round *v* to the nearest integer, ties toward positive infinity, matching JS `Math.round`. The
    result is taken from the fractional distance to the floor rather than `floor(v + 0.5)`, whose
    addition rounds the largest double below `0.5` up to `1.0` and would yield `1` instead of `0`.
    """
    lower = math.floor(v)
    return lower if v - lower < 0.5 else lower + 1


@_register(('Math', 'round'))
def _math_round(args: list[Value]) -> Value:
    return _to_js_integer(args, _round_half_up)


@_register(('Math', 'abs'))
def _math_abs(args: list[Value]) -> Value:
    return abs(to_number(args[0])) if args else float('nan')


@_register(('Math', 'pow'))
def _math_pow(args: list[Value]) -> Value:
    if len(args) < 2:
        return float('nan')
    return _js_pow(to_number(args[0]), to_number(args[1]))


@_register(('Math', 'sqrt'))
def _math_sqrt(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else float('nan')
    if v < 0:
        return float('nan')
    return math.sqrt(v)


@_register(('Math', 'min'))
def _math_min(args: list[Value]) -> Value:
    if not args:
        return float('inf')
    values = [to_number(a) for a in args]
    if any(v != v for v in values):
        return float('nan')
    result = min(values)
    if result == 0 and any(math.copysign(1.0, v) < 0 for v in values):
        return -0.0
    return result


@_register(('Math', 'max'))
def _math_max(args: list[Value]) -> Value:
    if not args:
        return float('-inf')
    values = [to_number(a) for a in args]
    if any(v != v for v in values):
        return float('nan')
    result = max(values)
    if result == 0 and any(math.copysign(1.0, v) > 0 for v in values):
        return 0.0
    return result


@_register(('Math', 'trunc'))
def _math_trunc(args: list[Value]) -> Value:
    return _to_js_integer(args, math.trunc)


@_register(('Math', 'sign'))
def _math_sign(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else float('nan')
    if v != v:
        return v
    if v > 0:
        return 1
    if v < 0:
        return -1
    return v


def _math_log_impl(args: list[Value], fn) -> Value:
    v = to_number(args[0]) if args else float('nan')
    if v <= 0:
        return float('-inf') if v == 0 else float('nan')
    return fn(v)


@_register(('Math', 'log'))
def _math_log(args: list[Value]) -> Value:
    return _math_log_impl(args, math.log)


@_register(('Math', 'log2'))
def _math_log2(args: list[Value]) -> Value:
    return _math_log_impl(args, math.log2)


@_register((None, 'parseInt'))
def _global_parse_int(args: list[Value]) -> Value:
    if not args:
        return float('nan')
    s = to_string(args[0])
    radix = _to_int(args[1]) if len(args) > 1 else 10
    result = js_parse_int(s, radix)
    if result is None:
        return float('nan')
    return result


@_register((None, 'parseFloat'))
def _global_parse_float(args: list[Value]) -> Value:
    if not args:
        return float('nan')
    s = to_string(args[0]).strip()
    if not s:
        return float('nan')
    digits: list[str] = []
    i = 0
    if i < len(s) and s[i] in '+-':
        digits.append(s[i])
        i += 1
    has_dot = False
    while i < len(s):
        if s[i].isdigit():
            digits.append(s[i])
        elif s[i] == '.' and not has_dot:
            digits.append(s[i])
            has_dot = True
        else:
            break
        i += 1
    if not digits or digits == ['+'] or digits == ['-']:
        return float('nan')
    try:
        return float(''.join(digits))
    except ValueError:
        return float('nan')


@_register((None, 'isNaN'))
def _global_is_nan(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else float('nan')
    return v != v


@_register((None, 'isFinite'))
def _global_is_finite(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else float('nan')
    return math.isfinite(v)


@_register((None, 'Number'))
def _global_number(args: list[Value]) -> Value:
    if not args:
        return 0
    return to_number(args[0])


@_register((None, 'String'))
def _global_string(args: list[Value]) -> Value:
    if not args:
        return ''
    return to_string(args[0])


@_register((None, 'atob'))
def _global_atob(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError
    s = to_string(args[0])
    try:
        cleaned = _RE_WHITESPACE.sub('', s)
        padded = cleaned + '=' * (-len(cleaned) % 4)
        return base64.b64decode(padded, validate=True).decode('latin-1')
    except Exception:
        raise InterpreterError


@_register((None, 'btoa'))
def _global_btoa(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError
    s = to_string(args[0])
    try:
        return base64.b64encode(s.encode('latin-1')).decode('ascii')
    except Exception:
        raise InterpreterError


_UNESCAPE_PATTERN = re.compile(r'%u([0-9A-Fa-f]{4})|%([0-9A-Fa-f]{2})')
_RE_WHITESPACE = re.compile(r'\s')
_RE_NON_BASE64 = re.compile(r'[^A-Za-z0-9+/=]')


@_register((None, 'unescape'))
def _global_unescape(args: list[Value]) -> Value:
    if not args:
        return 'undefined'
    s = to_string(args[0])
    return _UNESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), s)


@_register((None, 'decodeURIComponent'))
def _global_decode_uri_component(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError
    s = to_string(args[0])
    try:
        result = urllib.parse.unquote(s, encoding='utf-8', errors='surrogatepass')
        if any('\uD800' <= c <= '\uDFFF' for c in result):
            raise InterpreterError
        return result
    except Exception:
        raise InterpreterError


@_register((None, 'encodeURIComponent'))
def _global_encode_uri_component(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError
    s = to_string(args[0])
    try:
        return urllib.parse.quote(s, safe="!'()*~-._")
    except Exception:
        raise InterpreterError


@_register(('Object', 'keys'))
def _object_keys(args: list[Value]) -> Value:
    if args and isinstance(args[0], dict):
        return list(args[0].keys())
    raise InterpreterError


@_register(('Object', 'values'))
def _object_values(args: list[Value]) -> Value:
    if args and isinstance(args[0], dict):
        return list(args[0].values())
    raise InterpreterError


@_register(('Object', 'entries'))
def _object_entries(args: list[Value]) -> Value:
    if args and isinstance(args[0], dict):
        return [[k, v] for k, v in args[0].items()]
    raise InterpreterError


@_register(('Array', 'from'))
def _array_from(args: list[Value]) -> Value:
    if not args:
        return []
    src = args[0]
    if isinstance(src, (str, list)):
        return list(src)
    raise InterpreterError


@_register(('Array', 'isArray'))
def _array_is_array(args: list[Value]) -> Value:
    return isinstance(args[0], list) and not isinstance(args[0], JsBuffer) if args else False


@_register(('Buffer', 'from'))
def _buffer_from(args: list[Value]) -> Value:
    if not args:
        raise InterpreterError
    data = args[0]
    if isinstance(data, list):
        return JsBuffer(_to_int(v) & 0xFF for v in data)
    if not isinstance(data, str):
        raise InterpreterError
    encoding = args[1] if len(args) > 1 else 'utf8'
    if not isinstance(encoding, str):
        raise InterpreterError
    try:
        if encoding == 'base64':
            normalized = data.replace('-', '+').replace('_', '/')
            stripped = _RE_NON_BASE64.sub('', normalized)
            padded = stripped.rstrip('=')
            padded = padded + '=' * (-len(padded) % 4)
            return JsBuffer(base64.b64decode(padded))
        if encoding in ('utf8', 'utf-8'):
            return JsBuffer(data.encode('utf-8'))
        if encoding in ('latin1', 'binary'):
            return JsBuffer(data.encode('latin-1'))
        if encoding == 'hex':
            return JsBuffer(bytes.fromhex(data))
    except Exception:
        raise InterpreterError
    raise InterpreterError


@_register((JsBuffer, 'toString'))
def _list_to_string(buf: list, args: list[Value]) -> Value:
    encoding = args[0] if args else 'utf8'
    if not isinstance(encoding, str):
        raise InterpreterError
    try:
        raw = bytes(_to_int(v) & 0xFF for v in buf)
    except (TypeError, ValueError, OverflowError):
        raise InterpreterError
    try:
        if encoding in ('utf8', 'utf-8'):
            return raw.decode('utf-8')
        if encoding in ('latin1', 'binary'):
            return raw.decode('latin-1')
        if encoding == 'base64':
            return base64.b64encode(raw).decode('ascii')
        if encoding == 'hex':
            return raw.hex()
        if encoding == 'ascii':
            return raw.decode('ascii')
    except Exception:
        raise InterpreterError
    raise InterpreterError


STATIC_OBJECTS = frozenset({'Math', 'String', 'Object', 'Array', 'Number', 'JSON', 'Buffer'})

_TYPEOF_FUNCTION_GLOBALS = frozenset({
    'String',
    'Number',
    'Boolean',
    'Array',
    'Object',
    'Function',
    'Symbol',
    'BigInt',
    'Date',
    'RegExp',
    'Error',
    'EvalError',
    'RangeError',
    'ReferenceError',
    'SyntaxError',
    'TypeError',
    'URIError',
    'AggregateError',
    'Promise',
    'Map',
    'Set',
    'WeakMap',
    'WeakSet',
    'WeakRef',
    'Proxy',
    'ArrayBuffer',
    'SharedArrayBuffer',
    'DataView',
    'Int8Array',
    'Uint8Array',
    'Uint8ClampedArray',
    'Int16Array',
    'Uint16Array',
    'Int32Array',
    'Uint32Array',
    'Float32Array',
    'Float64Array',
    'BigInt64Array',
    'BigUint64Array',
    'Buffer',
    'parseInt',
    'parseFloat',
    'isNaN',
    'isFinite',
    'encodeURIComponent',
    'decodeURIComponent',
    'encodeURI',
    'decodeURI',
    'eval',
    'escape',
    'unescape',
    'btoa',
    'atob',
    'setTimeout',
    'setInterval',
    'clearTimeout',
    'clearInterval',
    'setImmediate',
    'queueMicrotask',
})

_TYPEOF_OBJECT_GLOBALS = frozenset({'Math', 'JSON', 'Reflect', 'Atomics', 'globalThis', 'console'})


def _global_typeof(name: str) -> str | None:
    """
    The `typeof` result for a well-known global *name* — a constructor or built-in function is
    `'function'`, a namespace object is `'object'`, `NaN`/`Infinity` are `'number'` and `undefined` is
    `'undefined'` — or `None` when the interpreter does not model *name* and so cannot tell a declared
    global (whose `typeof` is not `'undefined'`) from a genuinely absent one.
    """
    if name in _TYPEOF_FUNCTION_GLOBALS or (None, name) in BUILTIN_REGISTRY:
        return 'function'
    if name in _TYPEOF_OBJECT_GLOBALS:
        return 'object'
    if name in ('NaN', 'Infinity'):
        return 'number'
    if name == 'undefined':
        return 'undefined'
    return None


def is_runtime_name(name: str) -> bool:
    """
    Return True if `name` is a known JavaScript runtime symbol — either a static object namespace
    (e.g. `Math`, `String`) or a global function registered in the builtin registry (e.g.
    `parseInt`, `parseFloat`).
    """
    return name in STATIC_OBJECTS or (None, name) in BUILTIN_REGISTRY


class JsInterpreter:
    """
    Execute a JavaScript function body with concrete argument values. Returns a Python value or
    raises `IrreducibleExpression` when the return value cannot be reduced to a simple value.
    """

    def __init__(
        self, *,
        max_iterations: int = MAX_ITERATIONS,
        max_string_len: int = MAX_STRING_LEN,
        max_recursion: int = _MAX_RECURSION,
        effects: EffectModel | None = None,
        closure: Mapping[str, Value] | None = None,
        closure_env: Mapping[int, Mapping[str, Value]] | None = None,
        depth: int = 0,
    ):
        self.max_iterations = max_iterations
        self.max_string_len = max_string_len
        self.max_recursion = max_recursion
        self._effects = effects
        self._closure: Mapping[str, Value] = closure or {}
        self._closure_env: Mapping[int, Mapping[str, Value]] = closure_env or {}
        self._env: dict[str, Value] = {}
        self._iterations = 0
        self._depth = depth

    def execute(
        self,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        arguments: list[Value],
    ) -> Value:
        params = func.params
        param_names: list[str] = []
        for p in params:
            if not isinstance(p, JsIdentifier):
                raise InterpreterError
            param_names.append(p.name)
        self._env = {}
        for i, name in enumerate(param_names):
            self._env[name] = arguments[i] if i < len(arguments) else None
        body = func.body
        for name in self._collect_hoisted_var_names(body):
            self._env.setdefault(name, None)
        for name, value in self._closure.items():
            if name not in self._env:
                self._env[name] = _deep_copy_value(value)
        self._iterations = 0
        if isinstance(body, JsBlockStatement):
            try:
                self._exec_statements(body.body)
            except _ReturnSignal as r:
                return r.value
            except _ReturnIrreducible as r:
                raise IrreducibleExpression(r.node)
            except IrreducibleExpression:
                raise InterpreterError
            except _ThrowSignal:
                if self._depth == 0:
                    raise InterpreterError
                raise
            return None
        if body is not None:
            try:
                return self._eval(body)
            except IrreducibleExpression:
                raise IrreducibleExpression(body)
            except _ThrowSignal:
                if self._depth == 0:
                    raise InterpreterError
                raise
        return None

    @staticmethod
    def _collect_hoisted_var_names(body) -> list[str]:
        """
        Collect the names of all `var` declarations in *body*, which JavaScript hoists to the top of
        the function scope (initialized to `undefined`). Nested function bodies are not traversed.
        Reading a hoisted name before its initializer must yield `undefined`, not an unresolved free
        identifier.
        """
        if not isinstance(body, JsBlockStatement):
            return []
        names: list[str] = []
        for node in walk_scope(body, include_root_body=True):
            if isinstance(node, JsVariableDeclaration) and node.kind == JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                        names.append(decl.id.name)
        return names

    def _exec_statements(self, stmts: list) -> None:
        for stmt in stmts:
            self._exec_statement(stmt)

    def _exec_statement(self, stmt) -> None:
        if isinstance(stmt, JsVariableDeclaration):
            self._exec_var_decl(stmt)
        elif isinstance(stmt, JsExpressionStatement):
            self._eval(stmt.expression)
        elif isinstance(stmt, JsIfStatement):
            self._exec_if(stmt)
        elif isinstance(stmt, JsSwitchStatement):
            self._exec_switch(stmt)
        elif isinstance(stmt, JsForStatement):
            self._exec_for(stmt)
        elif isinstance(stmt, JsWhileStatement):
            self._exec_while(stmt)
        elif isinstance(stmt, JsDoWhileStatement):
            self._exec_do_while(stmt)
        elif isinstance(stmt, JsForInStatement):
            self._exec_for_in(stmt)
        elif isinstance(stmt, JsForOfStatement):
            self._exec_for_of(stmt)
        elif isinstance(stmt, JsReturnStatement):
            if stmt.argument is None:
                raise _ReturnSignal(None)
            try:
                value = self._eval(stmt.argument)
            except IrreducibleExpression:
                raise _ReturnIrreducible(stmt.argument)
            raise _ReturnSignal(value)
        elif isinstance(stmt, JsBreakStatement):
            raise _BreakSignal
        elif isinstance(stmt, JsContinueStatement):
            raise _ContinueSignal
        elif isinstance(stmt, JsBlockStatement):
            self._exec_statements(stmt.body)
        elif isinstance(stmt, JsTryStatement):
            self._exec_try(stmt)
        elif isinstance(stmt, JsThrowStatement):
            value = self._eval(stmt.argument) if stmt.argument else None
            raise _ThrowSignal(value)
        elif isinstance(stmt, JsFunctionDeclaration):
            if isinstance(stmt.id, JsIdentifier):
                self._env[stmt.id.name] = stmt
        else:
            raise InterpreterError

    def _exec_var_decl(self, node: JsVariableDeclaration) -> None:
        for decl in node.declarations:
            if not isinstance(decl, JsVariableDeclarator):
                raise InterpreterError
            if not isinstance(decl.id, JsIdentifier):
                raise InterpreterError
            name = decl.id.name
            if decl.init is not None:
                self._env[name] = self._eval(decl.init)
            elif node.kind == JsVarKind.VAR:
                self._env.setdefault(name, None)
            else:
                self._env[name] = None

    def _exec_if(self, node: JsIfStatement) -> None:
        if _truthy(self._eval(node.test)):
            if node.consequent:
                self._exec_statement(node.consequent)
        elif node.alternate:
            self._exec_statement(node.alternate)

    def _exec_switch(self, node: JsSwitchStatement) -> None:
        discriminant = self._eval(node.discriminant)
        matched = False
        for case in node.cases:
            if not isinstance(case, JsSwitchCase):
                raise InterpreterError
            if not matched:
                matched = case.test is None or self._strict_equal(discriminant, self._eval(case.test))
            if matched:
                try:
                    self._exec_statements(case.body)
                except _BreakSignal:
                    return

    def _exec_loop_body(self, body) -> bool:
        if not body:
            return False
        try:
            self._exec_statement(body)
        except _BreakSignal:
            return True
        except _ContinueSignal:
            pass
        return False

    def _exec_for(self, node: JsForStatement) -> None:
        if node.init:
            if isinstance(node.init, JsVariableDeclaration):
                self._exec_var_decl(node.init)
            else:
                self._eval(node.init)
        while True:
            self._tick()
            if node.test and not _truthy(self._eval(node.test)):
                break
            if self._exec_loop_body(node.body):
                break
            if node.update:
                self._eval(node.update)

    def _exec_while(self, node: JsWhileStatement) -> None:
        while True:
            self._tick()
            if not _truthy(self._eval(node.test)):
                break
            if self._exec_loop_body(node.body):
                break

    def _exec_do_while(self, node: JsDoWhileStatement) -> None:
        while True:
            self._tick()
            if self._exec_loop_body(node.body):
                break
            if not _truthy(self._eval(node.test)):
                break

    def _exec_for_in(self, node: JsForInStatement) -> None:
        right = self._eval(node.right)
        if right is None or right is JS_NULL:
            return
        if isinstance(right, dict):
            keys: list = list(right.keys())
        elif isinstance(right, list):
            keys = [str(i) for i in range(len(right))]
        else:
            raise InterpreterError
        var_name = self._get_loop_var(node.left)
        for key in keys:
            self._tick()
            self._env[var_name] = key
            if self._exec_loop_body(node.body):
                break

    def _exec_for_of(self, node: JsForOfStatement) -> None:
        right = self._eval(node.right)
        if right is None or right is JS_NULL:
            _js_throw('TypeError', F'{to_string(right)} is not iterable')
        if isinstance(right, list):
            items = right
        elif isinstance(right, str):
            items = list(right)
        else:
            raise InterpreterError
        var_name = self._get_loop_var(node.left)
        for item in items:
            self._tick()
            self._env[var_name] = item
            if self._exec_loop_body(node.body):
                break

    def _exec_try(self, node: JsTryStatement) -> None:
        thrown: _ThrowSignal | None = None
        propagate: Exception | None = None
        try:
            if node.block:
                self._exec_statements(node.block.body)
        except _ThrowSignal as exc:
            thrown = exc
        except (
            IrreducibleExpression,
            InterpreterError,
            _ReturnSignal,
            _BreakSignal,
            _ContinueSignal,
            _ReturnIrreducible,
        ) as exc:
            propagate = exc
        if propagate is not None:
            if node.finalizer:
                self._exec_statements(node.finalizer.body)
            raise propagate
        if thrown is not None:
            if node.handler and node.handler.body:
                param_name: str | None = None
                had_param: bool = False
                prev_param: Value = None
                if isinstance(node.handler.param, JsIdentifier):
                    param_name = node.handler.param.name
                    had_param = param_name in self._env
                    prev_param = self._env.get(param_name)
                    self._env[param_name] = thrown.value
                handler_outcome: Exception | None = None
                try:
                    self._exec_statements(node.handler.body.body)
                except (
                    _ThrowSignal,
                    IrreducibleExpression,
                    InterpreterError,
                    _ReturnSignal,
                    _BreakSignal,
                    _ContinueSignal,
                    _ReturnIrreducible,
                ) as exc:
                    handler_outcome = exc
                finally:
                    if param_name is not None:
                        if had_param:
                            self._env[param_name] = prev_param
                        else:
                            self._env.pop(param_name, None)
                if node.finalizer:
                    self._exec_statements(node.finalizer.body)
                if handler_outcome is not None:
                    raise handler_outcome
                return
            if node.finalizer:
                self._exec_statements(node.finalizer.body)
            raise thrown
        if node.finalizer:
            self._exec_statements(node.finalizer.body)

    def _get_loop_var(self, left) -> str:
        if isinstance(left, JsVariableDeclaration):
            if len(left.declarations) == 1:
                decl = left.declarations[0]
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    return decl.id.name
        if isinstance(left, JsIdentifier):
            return left.name
        raise InterpreterError

    def _tick(self) -> None:
        self._iterations += 1
        if self._iterations > self.max_iterations:
            raise InterpreterError

    def _eval(self, expr) -> Value:
        if expr is None:
            return None
        if isinstance(expr, JsStringLiteral):
            return expr.value
        if isinstance(expr, JsNumericLiteral):
            return expr.value
        if isinstance(expr, JsBooleanLiteral):
            return expr.value
        if isinstance(expr, JsNullLiteral):
            return JS_NULL
        if isinstance(expr, JsIdentifier):
            return self._eval_identifier(expr)
        if isinstance(expr, JsBinaryExpression):
            return self._eval_binary(expr)
        if isinstance(expr, JsUnaryExpression):
            return self._eval_unary(expr)
        if isinstance(expr, JsUpdateExpression):
            return self._eval_update(expr)
        if isinstance(expr, JsLogicalExpression):
            return self._eval_logical(expr)
        if isinstance(expr, JsAssignmentExpression):
            return self._eval_assignment(expr)
        if isinstance(expr, JsCallExpression):
            return self._eval_call(expr)
        if isinstance(expr, JsMemberExpression):
            return self._eval_member(expr)
        if isinstance(expr, JsConditionalExpression):
            test = self._eval(expr.test)
            return self._eval(expr.consequent) if _truthy(test) else self._eval(expr.alternate)
        if isinstance(expr, JsArrayExpression):
            return [self._eval(e) if e else None for e in expr.elements]
        if isinstance(expr, JsSequenceExpression):
            result: Value = None
            for e in expr.expressions:
                result = self._eval(e)
            return result
        if isinstance(expr, JsTemplateLiteral):
            return self._eval_template(expr)
        if isinstance(expr, JsObjectExpression):
            return self._eval_object(expr)
        if isinstance(expr, (JsFunctionExpression, JsArrowFunctionExpression)):
            return expr
        if isinstance(expr, JsParenthesizedExpression):
            return self._eval(expr.expression)
        raise InterpreterError

    def _resolve_function_node(self, node: JsIdentifier) -> _FuncNode | None:
        """
        The single function *node* names that this interpreter may resolve without ordering information,
        or `None`. Delegates to `EffectModel.unambiguous_function`: a function declaration or a
        bare-assignment (`var f; f = function(){}`) resolves, but a name reassigned away from a value it
        already held stays unresolved — the ordering-free view the evaluator's old visible-functions map
        enforced before interpretation routed resolution through the model.
        """
        effects = self._effects
        if effects is None:
            return None
        return effects.unambiguous_function(effects.model.resolve(node))

    def _eval_identifier(self, node: JsIdentifier) -> Value:
        name = node.name
        if name == 'undefined':
            return None
        if name == 'NaN':
            return float('nan')
        if name == 'Infinity':
            return float('inf')
        if name in self._env:
            return self._env[name]
        func = self._resolve_function_node(node)
        if func is not None:
            return func
        raise IrreducibleExpression(node)

    def _js_add(self, left: Value, right: Value) -> Value:
        """
        Replicate the JavaScript `+` operator: apply ToPrimitive to both operands, then concatenate
        as strings if either is a string, otherwise add numerically.
        """
        left = _to_primitive(left)
        right = _to_primitive(right)
        if isinstance(left, str) or isinstance(right, str):
            result = to_string(left) + to_string(right)
            if len(result) > self.max_string_len:
                raise InterpreterError
            return result
        return to_number(left) + to_number(right)

    def _eval_binary(self, node: JsBinaryExpression) -> Value:
        op = node.operator
        left = self._eval(node.left)
        right = self._eval(node.right)
        if op == '===':
            return self._strict_equal(left, right)
        if op == '!==':
            return not self._strict_equal(left, right)
        if op == '==':
            return self._loose_equal(left, right)
        if op == '!=':
            return not self._loose_equal(left, right)
        if op == '+':
            return self._js_add(left, right)
        if op == 'in':
            if isinstance(right, dict):
                return to_string(left) in right
            if isinstance(right, list):
                key = to_string(left)
                if key == 'length':
                    return True
                if (type(right), key) in BUILTIN_REGISTRY or (list, key) in BUILTIN_REGISTRY:
                    return True
                if key in _ARRAY_HOF_METHODS:
                    return True
                try:
                    idx = int(key)
                except (ValueError, OverflowError):
                    return False
                return str(idx) == key and 0 <= idx < len(right)
            raise InterpreterError
        if op == 'instanceof':
            raise InterpreterError
        if op in RELATIONAL_OPS:
            left = _to_primitive(left)
            right = _to_primitive(right)
            if isinstance(left, str) and isinstance(right, str):
                return RELATIONAL_OPS[op](left, right)
        result = eval_binary_op(op, to_number(left), to_number(right))
        if result is None:
            raise InterpreterError
        return result

    def _eval_unary(self, node: JsUnaryExpression) -> Value:
        op = node.operator
        if op == 'typeof':
            if isinstance(node.operand, JsIdentifier):
                operand = node.operand
                name = operand.name
                if name in self._env:
                    return _js_typeof(self._env[name])
                if self._resolve_function_node(operand) is not None:
                    return 'function'
                result = _global_typeof(name)
                if result is None:
                    raise IrreducibleExpression(node)
                return result
            return _js_typeof(self._eval(node.operand))
        if op == 'void':
            self._eval(node.operand)
            return None
        operand = self._eval(node.operand)
        if op == '-':
            v = to_number(operand)
            return -v if v != 0 else -float(v)
        if op == '+':
            return to_number(operand)
        if op == '~':
            return _to_int32(~_to_int(operand))
        if op == '!':
            return not _truthy(operand)
        raise InterpreterError

    def _eval_update(self, node: JsUpdateExpression) -> Value:
        if not isinstance(node.argument, JsIdentifier):
            raise InterpreterError
        name = node.argument.name
        if name not in self._env:
            raise InterpreterError
        current = to_number(self._env[name])
        if node.operator == '++':
            new_val = current + 1
        elif node.operator == '--':
            new_val = current - 1
        else:
            raise InterpreterError
        self._env[name] = new_val
        return new_val if node.prefix else current

    def _eval_logical(self, node: JsLogicalExpression) -> Value:
        left = self._eval(node.left)
        if node.operator == '&&':
            return self._eval(node.right) if _truthy(left) else left
        if node.operator == '||':
            return left if _truthy(left) else self._eval(node.right)
        if node.operator == '??':
            if left is None or left is JS_NULL:
                return self._eval(node.right)
            return left
        raise InterpreterError

    def _eval_assignment(self, node: JsAssignmentExpression) -> Value:
        if isinstance(node.left, JsMemberExpression):
            return self._eval_member_assignment(node)
        if not isinstance(node.left, JsIdentifier):
            raise InterpreterError
        name = node.left.name
        op = node.operator
        if op == '=':
            value = self._eval(node.right)
            self._env[name] = value
            return value
        current = self._env.get(name)
        value = self._eval(node.right)
        if op == '+=':
            self._env[name] = self._js_add(current, value)
        elif op == '-=':
            self._env[name] = to_number(current) - to_number(value)
        elif op == '*=':
            self._env[name] = to_number(current) * to_number(value)
        elif op == '/=':
            divisor = to_number(value)
            if divisor == 0:
                raise InterpreterError
            self._env[name] = to_number(current) / divisor
        elif op == '%=':
            divisor = to_number(value)
            if divisor == 0:
                raise InterpreterError
            self._env[name] = math.fmod(to_number(current), divisor)
        elif op == '|=':
            self._env[name] = _to_int32(_to_int(current) | _to_int(value))
        elif op == '&=':
            self._env[name] = _to_int32(_to_int(current) & _to_int(value))
        elif op == '^=':
            self._env[name] = _to_int32(_to_int(current) ^ _to_int(value))
        elif op == '<<=':
            self._env[name] = _to_int32(_to_int32(_to_int(current)) << (_to_int(value) & 0x1F))
        elif op == '>>=':
            self._env[name] = _to_int32(
                _to_int32(_to_int(current)) >> (_to_int(value) & 0x1F)
            )
        else:
            raise InterpreterError
        return self._env[name]

    def _eval_member_assignment(self, node: JsAssignmentExpression) -> Value:
        member = node.left
        if not isinstance(member, JsMemberExpression):
            raise InterpreterError
        obj = self._eval(member.object)
        key = self._member_key(member)
        if node.operator == '=':
            value = self._eval(node.right)
        else:
            old = self._get_property(obj, key)
            rhs = self._eval(node.right)
            if node.operator == '+=':
                value = self._js_add(old, rhs)
            elif node.operator == '-=':
                value = to_number(old) - to_number(rhs)
            elif node.operator == '*=':
                value = to_number(old) * to_number(rhs)
            else:
                raise InterpreterError
        self._set_property(obj, key, value)
        return value

    def _eval_call(self, node: JsCallExpression) -> Value:
        if isinstance(node.callee, JsMemberExpression):
            return self._eval_method_call(node)
        if isinstance(node.callee, JsIdentifier):
            return self._eval_function_call(node)
        if isinstance(node.callee, (JsFunctionExpression, JsArrowFunctionExpression)):
            return self._eval_inline_call(node.callee, node.arguments)
        raise InterpreterError

    def _eval_function_call(self, node: JsCallExpression) -> Value:
        callee = node.callee
        if not isinstance(callee, JsIdentifier):
            raise InterpreterError
        name = callee.name
        args = [self._eval(a) for a in node.arguments]
        builtin = BUILTIN_REGISTRY.get((None, name))
        if builtin is not None:
            return builtin(args)
        if name in self._env:
            target = self._env[name]
            if isinstance(target, (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)):
                return self._call_function(target, args)
            if node.optional and (target is None or target is JS_NULL):
                return None
            _js_throw('TypeError', F'{name} is not a function')
        func = self._resolve_function_node(callee)
        if func is not None:
            return self._call_function(func, args)
        raise InterpreterError

    def _eval_method_call(self, node: JsCallExpression) -> Value:
        member = node.callee
        if not isinstance(member, JsMemberExpression):
            raise InterpreterError
        if (
            isinstance(member.object, JsIdentifier)
            and member.object.name in STATIC_OBJECTS
        ):
            static_name = member.object.name
            method_name = self._member_key(member)
            args = [self._eval(a) for a in node.arguments]
            builtin = BUILTIN_REGISTRY.get((static_name, method_name))
            if builtin is not None:
                return builtin(args)
            raise InterpreterError
        obj = self._eval(member.object)
        if obj is None or obj is JS_NULL:
            if member.optional:
                return None
            _js_throw('TypeError', F"Cannot read properties of {to_string(obj)} (reading a method)")
        method_name = self._member_key(member)
        args = [self._eval(a) for a in node.arguments]
        obj_type = type(obj)
        builtin = BUILTIN_REGISTRY.get((obj_type, method_name))
        if builtin is None and obj_type is not list and isinstance(obj, list):
            builtin = BUILTIN_REGISTRY.get((list, method_name))
        if builtin is not None:
            result = builtin(obj, args)
            if isinstance(obj, JsBuffer) and isinstance(result, list) and not isinstance(result, JsBuffer):
                result = JsBuffer(result)
            return result
        if isinstance(obj, list) and method_name in _ARRAY_HOF_METHODS:
            result = self._eval_array_hof(obj, method_name, args)
            if isinstance(obj, JsBuffer) and method_name in _BUFFER_PRESERVING_HOFS:
                if isinstance(result, list) and not isinstance(result, JsBuffer):
                    result = JsBuffer(result)
            return result
        if isinstance(obj, (JsFunctionExpression, JsArrowFunctionExpression)):
            if method_name == 'call':
                return self._call_function(obj, args[1:] if len(args) > 1 else [])
            if method_name == 'apply':
                actual_args = args[1] if len(args) > 1 and isinstance(args[1], list) else []
                return self._call_function(obj, actual_args)
        raise InterpreterError

    def _eval_array_hof(self, arr: list, method: str, args: list[Value]) -> Value:
        if not args:
            raise InterpreterError
        callback = args[0]
        if not isinstance(
            callback,
            (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)
        ):
            raise InterpreterError
        if method == 'every':
            for i, item in enumerate(arr):
                self._tick()
                if not _truthy(self._call_function(callback, [item, i, arr])):
                    return False
            return True
        if method == 'some':
            for i, item in enumerate(arr):
                self._tick()
                if _truthy(self._call_function(callback, [item, i, arr])):
                    return True
            return False
        if method == 'map':
            mapped: list[Value] = []
            for i, item in enumerate(arr):
                self._tick()
                mapped.append(self._call_function(callback, [item, i, arr]))
            return mapped
        if method == 'filter':
            filtered: list[Value] = []
            for i, item in enumerate(arr):
                self._tick()
                if _truthy(self._call_function(callback, [item, i, arr])):
                    filtered.append(item)
            return filtered
        if method == 'find':
            for i, item in enumerate(arr):
                self._tick()
                if _truthy(self._call_function(callback, [item, i, arr])):
                    return item
            return None
        if method == 'findIndex':
            for i, item in enumerate(arr):
                self._tick()
                if _truthy(self._call_function(callback, [item, i, arr])):
                    return i
            return -1
        if method == 'forEach':
            for i, item in enumerate(arr):
                self._tick()
                self._call_function(callback, [item, i, arr])
            return None
        if method == 'reduce':
            if len(arr) == 0 and len(args) < 2:
                raise InterpreterError
            if len(args) >= 2:
                acc: Value = args[1]
                start = 0
            else:
                acc = arr[0]
                start = 1
            for i in range(start, len(arr)):
                self._tick()
                acc = self._call_function(callback, [acc, arr[i], i, arr])
            return acc
        raise InterpreterError

    def _eval_inline_call(self, func, arguments: list) -> Value:
        args = [self._eval(a) for a in arguments]
        return self._call_function(func, args)

    def _mutates_captured_binding(self, func) -> bool:
        """
        Whether *func* assigns to a name that the calling environment binds but that *func* does not
        declare locally — a write through a closure into a captured outer variable. A nested call runs
        in an isolated child interpreter with only a snapshot of captured values and no write-back, so
        the mutation would be silently lost. Refusing to evaluate leaves the call in place for a real
        engine to run and keeps the fold sound rather than producing a wrong constant.
        """
        body = func.body
        if not isinstance(body, JsBlockStatement):
            return False
        local_names: set[str] = {p.name for p in func.params if isinstance(p, JsIdentifier)}
        if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
            local_names.add(func.id.name)
        for node in walk_scope(body):
            if isinstance(node, JsVariableDeclaration):
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                        local_names.add(decl.id.name)
            elif isinstance(node, JsFunctionDeclaration) and isinstance(node.id, JsIdentifier):
                local_names.add(node.id.name)
        for node in walk_scope(body):
            if isinstance(node, JsAssignmentExpression) and isinstance(node.left, JsIdentifier):
                name = node.left.name
            elif isinstance(node, JsUpdateExpression) and isinstance(node.argument, JsIdentifier):
                name = node.argument.name
            else:
                continue
            if name not in local_names and name in self._env:
                return True
        return False

    def _call_function(self, func, args: list[Value]) -> Value:
        if self._depth >= self.max_recursion:
            raise InterpreterError
        if self._mutates_captured_binding(func):
            raise InterpreterError
        callee_closure = self._closure_env.get(id(func)) or {}
        child = JsInterpreter(
            max_iterations=max(1, self.max_iterations - self._iterations),
            max_string_len=self.max_string_len,
            max_recursion=self.max_recursion,
            effects=self._effects,
            closure=callee_closure,
            closure_env=self._closure_env,
            depth=self._depth + 1,
        )
        try:
            result = child.execute(func, args)
        finally:
            self._iterations += child._iterations
        return result

    def _eval_member(self, node: JsMemberExpression) -> Value:
        if isinstance(node.object, JsIdentifier) and node.object.name in STATIC_OBJECTS:
            raise InterpreterError
        obj = self._eval(node.object)
        if node.optional and (obj is None or obj is JS_NULL):
            return None
        key = self._member_key(node)
        return self._get_property(obj, key)

    def _eval_template(self, node: JsTemplateLiteral) -> Value:
        parts: list[str] = []
        for i, quasi in enumerate(node.quasis):
            parts.append(quasi.value)
            if i < len(node.expressions):
                parts.append(to_string(self._eval(node.expressions[i])))
        result = ''.join(parts)
        if len(result) > self.max_string_len:
            raise InterpreterError
        return result

    def _eval_object(self, node: JsObjectExpression) -> Value:
        result: dict[str, Value] = {}
        for prop in node.properties:
            if not isinstance(prop, JsProperty):
                raise InterpreterError
            if prop.kind != JsPropertyKind.INIT:
                raise InterpreterError
            key: str
            if prop.computed:
                key = to_string(self._eval(prop.key))
            elif isinstance(prop.key, JsIdentifier):
                key = prop.key.name
            elif isinstance(prop.key, JsStringLiteral):
                key = prop.key.value
            elif isinstance(prop.key, JsNumericLiteral):
                key = to_string(prop.key.value)
            else:
                raise InterpreterError
            result[key] = self._eval(prop.value)
        return result

    def _member_key(self, node: JsMemberExpression) -> str:
        if node.computed:
            val = self._eval(node.property)
            return to_string(val)
        if isinstance(node.property, JsIdentifier):
            return node.property.name
        raise InterpreterError

    def _get_property(self, obj: Value, key: str) -> Value:
        if obj is None or obj is JS_NULL:
            _js_throw('TypeError', F"Cannot read properties of {to_string(obj)} (reading '{key}')")
        if isinstance(obj, dict):
            return obj.get(key)
        if isinstance(obj, list):
            if key == 'length':
                return len(obj)
            try:
                idx = int(key)
                if 0 <= idx < len(obj):
                    return obj[idx]
                return None
            except (ValueError, TypeError):
                pass
            obj_type = type(obj)
            builtin = BUILTIN_REGISTRY.get((obj_type, key))
            if builtin is None and obj_type is not list:
                builtin = BUILTIN_REGISTRY.get((list, key))
            if builtin is not None:
                raise InterpreterError
            return None
        if isinstance(obj, str):
            builtin = BUILTIN_REGISTRY.get((str, key))
            if builtin is not None:
                return builtin(obj, [])
            try:
                idx = int(key)
                if 0 <= idx < len(obj):
                    return obj[idx]
                return None
            except (ValueError, TypeError):
                pass
            return None
        raise InterpreterError

    def _set_property(self, obj: Value, key: str, value: Value) -> None:
        if isinstance(obj, dict):
            obj[key] = value
            return
        if isinstance(obj, list):
            if key == 'length':
                new_len = _to_array_length(value)
                if new_len < len(obj):
                    del obj[new_len:]
                else:
                    obj.extend([None] * (new_len - len(obj)))
                return
            try:
                idx = int(key)
                if idx < 0:
                    raise InterpreterError
                while len(obj) <= idx:
                    obj.append(None)
                obj[idx] = value
                return
            except (ValueError, TypeError):
                pass
        raise InterpreterError

    @staticmethod
    def _strict_equal(a: Value, b: Value) -> bool:
        return js_strict_equal(a, b)

    @staticmethod
    def _loose_equal(a: Value, b: Value) -> bool:
        """
        Replicate the ECMA-262 abstract-equality (`==`) algorithm. `null` and `undefined` are equal to
        each other and to nothing else; booleans and objects coerce to numbers/primitives; a number
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
        if isinstance(a, (list, dict)):
            a = _to_primitive(a)
        if isinstance(b, (list, dict)):
            b = _to_primitive(b)
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        a_num = isinstance(a, (int, float))
        b_num = isinstance(b, (int, float))
        if a_num and b_num:
            return a == b
        if (a_num and isinstance(b, str)) or (isinstance(a, str) and b_num):
            return to_number(a) == to_number(b)
        return js_strict_equal(a, b)

    def eval_expression(self, expr) -> Value:
        """
        Evaluate a single expression AST node and return a Python value.
        """
        return self._eval(expr)
