"""
Mini-interpreter for executing pure JavaScript functions with concrete arguments.
"""
from __future__ import annotations

import math

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import TypeAlias

    from refinery.lib.scripts.js.model import JsArrowFunctionExpression as _Arrow
    from refinery.lib.scripts.js.model import JsFunctionDeclaration as _FuncDecl
    from refinery.lib.scripts.js.model import JsFunctionExpression as _FuncExpr

    Value: TypeAlias = str | int | float | bool | list | dict | _FuncDecl | _FuncExpr | _Arrow | None

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.deobfuscation.helpers import (
    RELATIONAL_OPS,
    _to_int32,
    eval_binary_op,
    js_parse_int,
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


def _truthy(value: Value) -> bool:
    if value is None:
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
    return False


def to_number(value: Value) -> int | float:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        try:
            return int(s, 0)
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            return float('nan')
    if value is None:
        return 0
    return float('nan')


def to_string(value: Value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return 'undefined'
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
        if value == int(value):
            return str(int(value))
        return str(value)
    if isinstance(value, list):
        return ','.join(to_string(v) for v in value)
    return '[object Object]'


def _js_typeof(value: Value) -> str:
    if value is None:
        return 'undefined'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, (int, float)):
        return 'number'
    if isinstance(value, str):
        return 'string'
    return 'object'


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
    idx = int(to_number(args[0])) if args else 0
    if 0 <= idx < len(s):
        return s[idx]
    return ''


@_register((str, 'charCodeAt'))
def _str_char_code_at(s: str, args: list[Value]) -> Value:
    idx = int(to_number(args[0])) if args else 0
    if 0 <= idx < len(s):
        return ord(s[idx])
    return float('nan')


@_register((str, 'indexOf'))
def _str_index_of(s: str, args: list[Value]) -> Value:
    if not args:
        return -1
    search = to_string(args[0])
    start = int(to_number(args[1])) if len(args) > 1 else 0
    return s.find(search, max(0, start))


@_register((str, 'lastIndexOf'))
def _str_last_index_of(s: str, args: list[Value]) -> Value:
    if not args:
        return -1
    search = to_string(args[0])
    end = int(to_number(args[1])) + 1 if len(args) > 1 else len(s)
    return s.rfind(search, 0, end)


@_register((str, 'includes'))
def _str_includes(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    search = to_string(args[0])
    start = int(to_number(args[1])) if len(args) > 1 else 0
    return s.find(search, max(0, start)) != -1


@_register((str, 'startsWith'))
def _str_starts_with(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    prefix = to_string(args[0])
    start = int(to_number(args[1])) if len(args) > 1 else 0
    return s[start:].startswith(prefix)


@_register((str, 'endsWith'))
def _str_ends_with(s: str, args: list[Value]) -> Value:
    if not args:
        return False
    suffix = to_string(args[0])
    end = int(to_number(args[1])) if len(args) > 1 else len(s)
    return s[:end].endswith(suffix)


@_register((str, 'slice'))
def _str_slice(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = int(to_number(args[0])) if args else 0
    end = int(to_number(args[1])) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    if end < 0:
        end = max(n + end, 0)
    return s[start:end]


@_register((str, 'substring'))
def _str_substring(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = int(to_number(args[0])) if args else 0
    end = int(to_number(args[1])) if len(args) > 1 else n
    start = max(0, min(start, n))
    end = max(0, min(end, n))
    if start > end:
        start, end = end, start
    return s[start:end]


@_register((str, 'substr'))
def _str_substr(s: str, args: list[Value]) -> Value:
    n = len(s)
    start = int(to_number(args[0])) if args else 0
    length = int(to_number(args[1])) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    return s[start:start + max(0, length)]


@_register((str, 'split'))
def _str_split(s: str, args: list[Value]) -> Value:
    if not args:
        return [s]
    sep = to_string(args[0])
    if not sep:
        result = list(s)
    else:
        result = s.split(sep)
    if len(args) > 1:
        limit = int(to_number(args[1]))
        result = result[:limit]
    return result


@_register((str, 'replace'))
def _str_replace(s: str, args: list[Value]) -> Value:
    if len(args) < 2:
        return s
    search = to_string(args[0])
    replacement = to_string(args[1])
    return s.replace(search, replacement, 1)


@_register((str, 'replaceAll'))
def _str_replace_all(s: str, args: list[Value]) -> Value:
    if len(args) < 2:
        return s
    search = to_string(args[0])
    replacement = to_string(args[1])
    return s.replace(search, replacement)


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
    count = int(to_number(args[0])) if args else 0
    if count < 0:
        raise InterpreterError
    return s * count


def _str_pad(s: str, args: list[Value], prepend: bool) -> Value:
    target_len = int(to_number(args[0])) if args else 0
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
    idx = int(to_number(args[0])) if args else 0
    if idx < 0:
        idx += len(s)
    if 0 <= idx < len(s):
        return s[idx]
    return None


@_register(('String', 'fromCharCode'))
def _string_from_char_code(args: list[Value]) -> Value:
    return ''.join(chr(int(to_number(a)) & 0xFFFF) for a in args)


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
    start = int(to_number(args[0])) if args else 0
    end = int(to_number(args[1])) if len(args) > 1 else n
    if start < 0:
        start = max(n + start, 0)
    if end < 0:
        end = max(n + end, 0)
    return arr[start:end]


@_register((list, 'splice'))
def _arr_splice(arr: list, args: list[Value]) -> Value:
    if not args:
        return []
    start = int(to_number(args[0]))
    n = len(arr)
    if start < 0:
        start = max(n + start, 0)
    else:
        start = min(start, n)
    delete_count = int(to_number(args[1])) if len(args) > 1 else n - start
    delete_count = max(0, min(delete_count, n - start))
    removed = arr[start:start + delete_count]
    new_items = list(args[2:])
    arr[start:start + delete_count] = new_items
    return removed


@_register((list, 'join'))
def _arr_join(arr: list, args: list[Value]) -> Value:
    sep = to_string(args[0]) if args else ','
    return sep.join(to_string(v) for v in arr)


@_register((list, 'indexOf'))
def _arr_index_of(arr: list, args: list[Value]) -> Value:
    if not args:
        return -1
    target = args[0]
    start = int(to_number(args[1])) if len(args) > 1 else 0
    for i in range(max(0, start), len(arr)):
        if arr[i] == target:
            return i
    return -1


@_register((list, 'includes'))
def _arr_includes(arr: list, args: list[Value]) -> Value:
    if not args:
        return False
    return args[0] in arr


@_register((list, 'flat'))
def _arr_flat(arr: list, args: list[Value]) -> Value:
    depth = int(to_number(args[0])) if args else 1

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
    idx = int(to_number(args[0])) if args else 0
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
    start = int(to_number(args[1])) if len(args) > 1 else 0
    end = int(to_number(args[2])) if len(args) > 2 else n
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


@_register(('Math', 'floor'))
def _math_floor(args: list[Value]) -> Value:
    return int(math.floor(to_number(args[0]))) if args else 0


@_register(('Math', 'ceil'))
def _math_ceil(args: list[Value]) -> Value:
    return int(math.ceil(to_number(args[0]))) if args else 0


@_register(('Math', 'round'))
def _math_round(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else 0
    return int(math.floor(v + 0.5))


@_register(('Math', 'abs'))
def _math_abs(args: list[Value]) -> Value:
    return abs(to_number(args[0])) if args else 0


@_register(('Math', 'pow'))
def _math_pow(args: list[Value]) -> Value:
    if len(args) < 2:
        return float('nan')
    base = to_number(args[0])
    exp = to_number(args[1])
    try:
        return base ** exp
    except (OverflowError, ValueError):
        return float('nan')


@_register(('Math', 'sqrt'))
def _math_sqrt(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else 0
    if v < 0:
        return float('nan')
    return math.sqrt(v)


@_register(('Math', 'min'))
def _math_min(args: list[Value]) -> Value:
    if not args:
        return float('inf')
    return min(to_number(a) for a in args)


@_register(('Math', 'max'))
def _math_max(args: list[Value]) -> Value:
    if not args:
        return float('-inf')
    return max(to_number(a) for a in args)


@_register(('Math', 'trunc'))
def _math_trunc(args: list[Value]) -> Value:
    return int(math.trunc(to_number(args[0]))) if args else 0


@_register(('Math', 'sign'))
def _math_sign(args: list[Value]) -> Value:
    v = to_number(args[0]) if args else 0
    if v > 0:
        return 1
    if v < 0:
        return -1
    return 0


def _math_log_impl(args: list[Value], fn) -> Value:
    v = to_number(args[0]) if args else 0
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
    radix = int(to_number(args[1])) if len(args) > 1 else 10
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
    return isinstance(args[0], list) if args else False


STATIC_OBJECTS = frozenset({'Math', 'String', 'Object', 'Array', 'Number'})


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
        functions: Mapping[str, JsFunctionDeclaration] | None = None,
        depth: int = 0,
    ):
        self.max_iterations = max_iterations
        self.max_string_len = max_string_len
        self.max_recursion = max_recursion
        self._functions: Mapping[str, JsFunctionDeclaration] = functions or {}
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
        self._iterations = 0
        body = func.body
        if isinstance(body, JsBlockStatement):
            try:
                self._exec_statements(body.body)
            except _ReturnSignal as r:
                return r.value
            return None
        if body is not None:
            return self._eval(body)
        return None

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
            except InterpreterError:
                raise IrreducibleExpression(stmt.argument)
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
            raise InterpreterError
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
            value = self._eval(decl.init) if decl.init else None
            self._env[name] = value

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
        try:
            if node.block:
                self._exec_statements(node.block.body)
        except InterpreterError:
            if node.handler and node.handler.body:
                self._exec_statements(node.handler.body.body)
            else:
                raise

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
            return None
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
        raise InterpreterError

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
        raise InterpreterError

    def _eval_binary(self, node: JsBinaryExpression) -> Value:
        op = node.operator
        left = self._eval(node.left)
        right = self._eval(node.right)
        if op in ('===', '=='):
            return self._strict_equal(left, right)
        if op in ('!==', '!='):
            return not self._strict_equal(left, right)
        if op == '+':
            if isinstance(left, str) or isinstance(right, str):
                result = to_string(left) + to_string(right)
                if len(result) > self.max_string_len:
                    raise InterpreterError
                return result
            return to_number(left) + to_number(right)
        if op == 'in':
            if isinstance(right, dict):
                return to_string(left) in right
            if isinstance(right, list):
                idx = int(to_number(left))
                return 0 <= idx < len(right)
            raise InterpreterError
        if op == 'instanceof':
            raise InterpreterError
        if op in RELATIONAL_OPS and isinstance(left, str) and isinstance(right, str):
            return RELATIONAL_OPS[op](left, right)
        result = eval_binary_op(op, to_number(left), to_number(right))
        if result is None:
            raise InterpreterError
        return result

    def _eval_unary(self, node: JsUnaryExpression) -> Value:
        op = node.operator
        if op == 'typeof':
            if isinstance(node.operand, JsIdentifier):
                name = node.operand.name
                if name in self._env:
                    return _js_typeof(self._env[name])
                return 'undefined'
            return _js_typeof(self._eval(node.operand))
        if op == 'void':
            self._eval(node.operand)
            return None
        operand = self._eval(node.operand)
        if op == '-':
            v = to_number(operand)
            return -v if v != 0 else (-0.0 if isinstance(v, float) else 0)
        if op == '+':
            return to_number(operand)
        if op == '~':
            return _to_int32(~int(to_number(operand)))
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
            return left if left is not None else self._eval(node.right)
        raise InterpreterError

    def _eval_assignment(self, node: JsAssignmentExpression) -> Value:
        if isinstance(node.left, JsMemberExpression):
            return self._eval_member_assignment(node)
        if not isinstance(node.left, JsIdentifier):
            raise InterpreterError
        name = node.left.name
        value = self._eval(node.right)
        op = node.operator
        if op == '=':
            self._env[name] = value
            return value
        current = self._env.get(name)
        if op == '+=':
            if isinstance(current, str) or isinstance(value, str):
                result = to_string(current) + to_string(value)
                if len(result) > self.max_string_len:
                    raise InterpreterError
                self._env[name] = result
            else:
                self._env[name] = to_number(current) + to_number(value)
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
            self._env[name] = _to_int32(int(to_number(current)) | int(to_number(value)))
        elif op == '&=':
            self._env[name] = _to_int32(int(to_number(current)) & int(to_number(value)))
        elif op == '^=':
            self._env[name] = _to_int32(int(to_number(current)) ^ int(to_number(value)))
        elif op == '<<=':
            self._env[name] = _to_int32(_to_int32(int(to_number(current))) << (int(to_number(value)) & 0x1F))
        elif op == '>>=':
            self._env[name] = _to_int32(
                _to_int32(int(to_number(current))) >> (int(to_number(value)) & 0x1F)
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
        value = self._eval(node.right)
        if node.operator != '=':
            old = self._get_property(obj, key)
            if node.operator == '+=':
                if isinstance(old, str) or isinstance(value, str):
                    value = to_string(old) + to_string(value)
                else:
                    value = to_number(old) + to_number(value)
            elif node.operator == '-=':
                value = to_number(old) - to_number(value)
            elif node.operator == '*=':
                value = to_number(old) * to_number(value)
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
        func = self._functions.get(name)
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
        method_name = self._member_key(member)
        args = [self._eval(a) for a in node.arguments]
        obj_type = type(obj)
        builtin = BUILTIN_REGISTRY.get((obj_type, method_name))
        if builtin is not None:
            return builtin(obj, args)
        if isinstance(obj, list) and method_name in _ARRAY_HOF_METHODS:
            return self._eval_array_hof(obj, method_name, args)
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

    def _call_function(self, func, args: list[Value]) -> Value:
        if self._depth >= self.max_recursion:
            raise InterpreterError
        child = JsInterpreter(
            max_iterations=self.max_iterations - self._iterations,
            max_string_len=self.max_string_len,
            max_recursion=self.max_recursion,
            functions=self._functions,
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
                new_len = int(to_number(value))
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
        if a is None and b is None:
            return True
        if a is None or b is None:
            return False
        if type(a) is not type(b):
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return a == b
            return False
        return a == b
