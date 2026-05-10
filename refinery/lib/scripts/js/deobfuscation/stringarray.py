"""
Resolve the string-array rotation pattern produced by popular JavaScript obfuscators.

The obfuscator extracts all string literals into a single array, wraps access through an accessor
function and scrambles the array via a rotation IIFE that push/shifts until a checksum computed
from parseInt of the array's own elements matches a target constant. This transformer detects that
three-part pattern, simulates the rotation in Python, resolves every accessor call to its string
literal, and removes the dead definitions.
"""
from __future__ import annotations

import base64
import enum
import functools

from refinery.lib.scripts import (
    Node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BINARY_OPS,
    ScriptLevelTransformer,
    js_parse_int,
    make_string_literal,
    property_key,
    remove_declarator,
    string_value,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsMemberExpression,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
)

from typing import NamedTuple, Sequence


class Encoding(enum.Enum):
    NONE = 'none'
    B64 = 'base64'
    RC4 = 'rc4'


class ArrayFunction(NamedTuple):
    """
    Result of detecting the array-holder function pattern.
    """
    node: JsFunctionDeclaration
    name: str
    strings: list[str]


class AccessorFunction(NamedTuple):
    """
    Result of detecting the accessor function pattern.
    """
    node: JsFunctionDeclaration
    name: str
    base_offset: int


class RotationIIFE(NamedTuple):
    """
    Result of detecting the rotation IIFE pattern.
    """
    node: JsExpressionStatement
    target: int
    body: Sequence[Node]


class ChecksumInfo(NamedTuple):
    """
    Result of extracting the checksum expression from the rotation IIFE.
    """
    node: Node
    local_accessors: frozenset[str]
    wrappers: dict[str, 'AccessorWrapperInfo']
    prop_maps: dict[str, dict[str, int | str]]


def _find_array_function(body: Sequence[Node]) -> ArrayFunction | None:
    """
    Detect the array-holder function pattern:

        function NAME() {
          var x = ['str0', 'str1', ...];
          NAME = function() { return x; };
          return NAME();
        }

    Returns (node, function_name, initial_string_list) or None.
    """
    for statement in body:
        if not isinstance(statement, JsFunctionDeclaration):
            continue
        if statement.id is None or statement.body is None:
            continue
        name = statement.id.name
        statements = statement.body.body
        if len(statements) < 2:
            continue
        array_literal: list[str] | None = None
        has_self_reassignment = False
        for s in statements:
            if isinstance(s, JsVariableDeclaration):
                for decl in s.declarations:
                    if (
                        isinstance(decl, JsVariableDeclarator)
                        and isinstance(decl.init, JsArrayExpression)
                    ):
                        elements = []
                        for element in decl.init.elements:
                            if (sv := string_value(element)) is None:
                                break
                            elements.append(sv)
                        else:
                            if elements:
                                array_literal = elements
            elif (
                isinstance(s, JsExpressionStatement)
                and isinstance(assign := s.expression, JsAssignmentExpression)
                and isinstance(assign.left, JsIdentifier)
                and assign.left.name == name
            ):
                has_self_reassignment = True
        if array_literal is not None and has_self_reassignment:
            return ArrayFunction(statement, name, array_literal)
    return None


def _find_accessor_function(
    body: Sequence[Node],
    array_fn_name: str,
) -> AccessorFunction | None:
    """
    Detect the accessor function pattern:

        function NAME(param, _unused) {
          param = param - BASE_OFFSET;
          var v = ARRAY_FN();
          var r = v[param];
          return r;
        }

    Returns (node, function_name, base_offset) or None.
    """
    for stmt in body:
        if not isinstance(stmt, JsFunctionDeclaration):
            continue
        if stmt.id is None or stmt.body is None:
            continue
        if len(stmt.params) != 2:
            continue
        fn_name = stmt.id.name
        first_param = stmt.params[0]
        if not isinstance(first_param, JsIdentifier):
            continue
        param_name = first_param.name
        base_offset: int | None = None
        calls_array_fn = False
        for s in stmt.body.body:
            if isinstance(s, JsExpressionStatement) and isinstance(s.expression, JsAssignmentExpression):
                assign = s.expression
                if (
                    isinstance(assign.left, JsIdentifier)
                    and assign.left.name == param_name
                    and isinstance(assign.right, JsBinaryExpression)
                    and assign.right.operator == '-'
                    and isinstance(assign.right.left, JsIdentifier)
                    and assign.right.left.name == param_name
                    and assign.right.right is not None
                ):
                    try:
                        base_offset = int(_eval_arithmetic(assign.right.right))
                    except _EvalError:
                        pass
            elif isinstance(s, JsVariableDeclaration):
                for decl in s.declarations:
                    if isinstance(decl, JsVariableDeclarator) and isinstance(decl.init, JsCallExpression):
                        if isinstance(decl.init.callee, JsIdentifier) and decl.init.callee.name == array_fn_name:
                            calls_array_fn = True
        if base_offset is not None and calls_array_fn:
            return AccessorFunction(stmt, fn_name, base_offset)
    return None


def _find_rotation_iife(
    body: Sequence[Node],
    array_fn_name: str,
) -> RotationIIFE | None:
    """
    Detect the rotation IIFE pattern:

        (function(getArray, target) {
          var arr = getArray();
          while (true) { try { ... parseInt ... push(shift) } catch { push(shift) } }
        })(ARRAY_FN, TARGET_NUMBER);

    Returns (statement_node, target_checksum, iife_body_statements) or None.
    """
    for stmt in body:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if isinstance(expr, JsParenthesizedExpression):
            expr = expr.expression
        call = expr
        if not isinstance(call, JsCallExpression):
            continue
        if not isinstance(call.callee, JsFunctionExpression):
            continue
        if len(call.arguments) != 2:
            continue
        first_arg = call.arguments[0]
        second_arg = call.arguments[1]
        if not (isinstance(first_arg, JsIdentifier) and first_arg.name == array_fn_name):
            continue
        try:
            target = int(_eval_arithmetic(second_arg))
        except _EvalError:
            continue
        fn_body = call.callee.body
        if fn_body is None:
            continue
        has_while = False
        for s in fn_body.body:
            if isinstance(s, JsWhileStatement):
                has_while = True
                break
        if has_while:
            return RotationIIFE(stmt, target, fn_body.body)
    return None


class _EvalError(Exception):
    pass


class AccessorWrapperInfo(NamedTuple):
    """
    Describes an inner wrapper function inside the rotation IIFE that forwards to the main
    accessor with reordered arguments and an additional offset subtraction.
    """
    target: str
    offset: int
    idx_param_pos: int
    key_param_pos: int


def _resolve_member_access(
    node: JsMemberExpression,
    prop_maps: dict[str, dict[str, int | str]],
) -> int | str | None:
    """
    Resolve a member expression `OBJ.KEY` against a set of known property maps collected from
    object literals in the IIFE body. Returns the resolved value or None.
    """
    if not isinstance(node.object, JsIdentifier):
        return None
    obj_name = node.object.name
    if obj_name not in prop_maps:
        return None
    prop = node.property
    if isinstance(prop, JsIdentifier):
        key = prop.name
    elif isinstance(prop, JsStringLiteral):
        key = prop.value
    else:
        return None
    return prop_maps[obj_name].get(key)


def _resolve_constant(
    node: Node,
    prop_maps: dict[str, dict[str, int | str]],
) -> int | None:
    """
    Resolve a node to an integer constant, handling numeric literals, member accesses against known
    property maps, unary negation, and parenthesized expressions. Returns None on failure.
    """
    if isinstance(node, JsNumericLiteral):
        return int(node.value)
    if isinstance(node, JsParenthesizedExpression) and node.expression:
        return _resolve_constant(node.expression, prop_maps)
    if isinstance(node, JsMemberExpression):
        resolved = _resolve_member_access(node, prop_maps)
        return resolved if isinstance(resolved, int) else None
    if isinstance(node, JsUnaryExpression) and node.operator == '-' and node.operand:
        inner = _resolve_constant(node.operand, prop_maps)
        return -inner if inner is not None else None
    try:
        return int(_eval_arithmetic(node))
    except _EvalError:
        return None


def _extract_wrapper_offset(
    idx_arg: Node,
    prop_maps: dict[str, dict[str, int | str]],
) -> tuple[str, int] | None:
    """
    Analyze the index argument of a wrapper's forwarding call and extract `(param_name, offset)`
    where offset is the constant subtracted from the call-site argument. The effective accessor
    index is `call_arg - offset`. Handles these patterns:

        param             => (param, 0)
        param -   CONST   => (param, CONST)
        param -  -CONST   => (param, -CONST)
        param - (-CONST)  => (param, -CONST)
        param +   CONST   => (param, -CONST)
    """
    if isinstance(idx_arg, JsIdentifier):
        return idx_arg.name, 0
    if isinstance(idx_arg, JsBinaryExpression) and isinstance(idx_arg.left, JsIdentifier):
        if idx_arg.right is None:
            return None
        right_val = _resolve_constant(idx_arg.right, prop_maps)
        if right_val is None:
            return None
        if idx_arg.operator == '-':
            return idx_arg.left.name, right_val
        if idx_arg.operator == '+':
            return idx_arg.left.name, -right_val
    return None


def _parse_object_props(
    obj: JsObjectExpression,
    allow_strings: bool = False,
) -> dict[str, int | str]:
    """
    Extract `{key: value}` pairs from an object expression. Keys are identifier names or string
    literal values. Values are integers (via `_eval_arithmetic`) and optionally strings (via
    `string_value`) when `allow_strings` is True.
    """
    props: dict[str, int | str] = {}
    for prop in obj.properties:
        if not isinstance(prop, JsProperty) or prop.value is None:
            continue
        key = property_key(prop)
        if key is None:
            continue
        if allow_strings:
            sv = string_value(prop.value)
            if sv is not None:
                props[key] = sv
                continue
        try:
            props[key] = int(_eval_arithmetic(prop.value))
        except _EvalError:
            pass
    return props


def _collect_local_prop_maps(
    body: Sequence[Node],
) -> dict[str, dict[str, int | str]]:
    """
    Scan the leading variable declarations in a function body for object literals and return a
    mapping from variable name to its `{key: int}` property map. Stops at the first non-variable
    declaration statement.
    """
    local_props: dict[str, dict[str, int | str]] = {}
    for s in body:
        if not isinstance(s, JsVariableDeclaration):
            break
        for decl in s.declarations:
            if (
                isinstance(decl, JsVariableDeclarator)
                and isinstance(decl.id, JsIdentifier)
                and isinstance(decl.init, JsObjectExpression)
                and (lp := _parse_object_props(decl.init))
            ):
                local_props[decl.id.name] = lp
    return local_props


def _match_wrapper(
    fn: JsFunctionDeclaration,
    accessor_name: str,
    prop_maps: dict[str, dict[str, int | str]],
) -> AccessorWrapperInfo | None:
    """
    Check whether a function declaration is a wrapper that forwards to *accessor_name* with
    reordered arguments and a constant offset. Returns a `AccessorWrapperInfo` on match, else None.
    """
    if fn.id is None or fn.body is None:
        return None
    if len(fn.body.body) < 1 or len(fn.params) < 2:
        return None
    ret = fn.body.body[-1]
    if not isinstance(ret, JsReturnStatement) or ret.argument is None:
        return None
    call = ret.argument
    if not isinstance(call, JsCallExpression) or not isinstance(call.callee, JsIdentifier):
        return None
    if call.callee.name != accessor_name:
        return None
    if len(call.arguments) != 2:
        return None
    local_props = dict(prop_maps)
    local_props.update(_collect_local_prop_maps(fn.body.body[:-1]))
    idx_arg = call.arguments[0]
    key_arg = call.arguments[1]
    if not isinstance(key_arg, JsIdentifier):
        return None
    offset = _extract_wrapper_offset(idx_arg, local_props)
    if offset is None:
        return None
    idx_param_name, offset_value = offset
    param_names = [p.name for p in fn.params if isinstance(p, JsIdentifier)]
    if idx_param_name not in param_names or key_arg.name not in param_names:
        return None
    return AccessorWrapperInfo(
        target=accessor_name,
        offset=offset_value,
        idx_param_pos=param_names.index(idx_param_name),
        key_param_pos=param_names.index(key_arg.name),
    )


def _collect_iife_wrappers(
    iife_body: Sequence[Node],
    accessor_name: str,
) -> tuple[dict[str, AccessorWrapperInfo], dict[str, dict[str, int | str]]]:
    """
    Scan the rotation IIFE body for inner wrapper functions and their associated offset objects.
    Returns `(wrappers, prop_maps)` where `wrappers` maps wrapper function names to their
    `AccessorWrapperInfo` and `prop_maps` maps object variable names to their `{key: value}`
    dicts.

    Inner wrappers follow the pattern::

        var a = { p: 0x4 };
        function f(x, y) {
          return g(y - a.p, x);
        }

    The wrapper swaps argument order and subtracts a constant offset from the index parameter.
    """
    prop_maps: dict[str, dict[str, int | str]] = {}
    wrappers: dict[str, AccessorWrapperInfo] = {}
    for s in iife_body:
        if isinstance(s, JsVariableDeclaration):
            for decl in s.declarations:
                if (
                    isinstance(decl, JsVariableDeclarator)
                    and isinstance(decl.id, JsIdentifier)
                    and isinstance(decl.init, JsObjectExpression)
                ):
                    props = _parse_object_props(decl.init, allow_strings=True)
                    if props:
                        prop_maps[decl.id.name] = props
        if isinstance(s, JsFunctionDeclaration):
            info = _match_wrapper(s, accessor_name, prop_maps)
            if info is not None and s.id is not None:
                wrappers[s.id.name] = info
    return wrappers, prop_maps


def _collect_all_wrappers(
    root: Node,
    accessor_name: str,
) -> dict[str, AccessorWrapperInfo]:
    """
    Walk the entire AST to find all function declarations that forward to the accessor with a
    constant offset. Unlike `_collect_iife_wrappers`, this finds wrappers at any nesting level
    and handles local offset objects declared inside the wrapper body.
    """
    wrappers: dict[str, AccessorWrapperInfo] = {}
    for s in root.walk():
        if isinstance(s, JsFunctionDeclaration):
            info = _match_wrapper(s, accessor_name, {})
            if info is not None and s.id is not None:
                wrappers[s.id.name] = info
    return wrappers


def _extract_checksum_expression(
    iife_body: Sequence[Node],
    accessor_name: str,
) -> ChecksumInfo | None:
    """
    Extract the checksum expression AST node, local accessor aliases, and inner wrapper resolution
    data from the rotation IIFE body. The wrapper and property-map data allows `_eval_checksum` to
    evaluate wrapper calls on the fly without mutating the AST.
    """
    local_accessors: set[str] = {accessor_name}
    for s in iife_body:
        if isinstance(s, JsVariableDeclaration):
            for decl in s.declarations:
                if (
                    isinstance(decl, JsVariableDeclarator)
                    and isinstance(decl.id, JsIdentifier)
                    and isinstance(decl.init, JsIdentifier)
                    and decl.init.name == accessor_name
                ):
                    local_accessors.add(decl.id.name)
    checksum_node: Node | None = None
    for s in iife_body:
        if isinstance(s, JsWhileStatement) and s.body is not None:
            for ws in s.walk():
                if isinstance(ws, JsVariableDeclaration):
                    for decl in ws.declarations:
                        if isinstance(decl, JsVariableDeclarator) and decl.init is not None:
                            checksum_node = decl.init
                            break
                    if checksum_node is not None:
                        break
            break
    if checksum_node is None:
        return None
    wrappers, prop_maps = _collect_iife_wrappers(iife_body, accessor_name)
    return ChecksumInfo(
        checksum_node,
        frozenset(local_accessors),
        wrappers,
        prop_maps,
    )


def _decode_string(raw: str, encoding: Encoding, key: str | None = None) -> str:
    """
    Decode a raw string from the array according to the encoding mode. For RC4, a key must be
    supplied. Raises _EvalError when decoding is not possible.
    """
    if encoding == Encoding.NONE:
        return raw
    try:
        if encoding == Encoding.B64:
            return _decode_base64(raw)
        if encoding == Encoding.RC4:
            if key is None:
                raise _EvalError
            return _decrypt_rc4(raw, key)
    except _EvalError:
        raise
    except (UnicodeDecodeError, ValueError):
        raise _EvalError
    raise _EvalError


def _eval_arithmetic(node: Node) -> float:
    """
    Evaluate a pure arithmetic expression AST to a float. Handles numeric literals, unary `+`/`-`,
    binary operators, and parenthesized expressions. Raises `_EvalError` on any node that is not
    statically computable.
    """
    if isinstance(node, JsNumericLiteral):
        return float(node.value)
    if isinstance(node, JsParenthesizedExpression) and node.expression:
        return _eval_arithmetic(node.expression)
    if isinstance(node, JsUnaryExpression) and node.operand:
        if node.operator == '-':
            return -_eval_arithmetic(node.operand)
        if node.operator == '+':
            return _eval_arithmetic(node.operand)
    if isinstance(node, JsBinaryExpression) and node.left and node.right:
        left = _eval_arithmetic(node.left)
        right = _eval_arithmetic(node.right)
        fn = BINARY_OPS.get(node.operator)
        if fn is not None:
            if node.operator == '/' and right == 0:
                raise _EvalError
            return fn(left, right)
    raise _EvalError


def _eval_checksum(
    node: Node,
    local_accessors: frozenset[str],
    strings: list[str],
    base_offset: int,
    encoding: Encoding = Encoding.NONE,
    wrappers: dict[str, AccessorWrapperInfo] | None = None,
    prop_maps: dict[str, dict[str, int | str]] | None = None,
) -> float:
    """
    Evaluate a checksum expression against the current array state. Handles the arithmetic
    operators (`+`, `-`, `*`, `/`), unary negation, parentheses, `parseInt` calls on accessor
    lookups, and numeric literals. When inner wrapper functions are present, wrapper calls are
    resolved to direct accessor calls on the fly without modifying the AST.

    Raises `_EvalError` on any unrecognized pattern.
    """
    recurse = functools.partial(
        _eval_checksum,
        local_accessors=local_accessors,
        strings=strings,
        base_offset=base_offset,
        encoding=encoding,
        wrappers=wrappers,
        prop_maps=prop_maps,
    )
    if isinstance(node, JsNumericLiteral):
        return float(node.value)
    if isinstance(node, JsParenthesizedExpression) and node.expression:
        return recurse(node.expression)
    if isinstance(node, JsUnaryExpression) and node.operand:
        if node.operator == '-':
            return -recurse(node.operand)
        if node.operator == '+':
            return recurse(node.operand)
    if isinstance(node, JsBinaryExpression) and node.left and node.right:
        lhs = recurse(node.left)
        rhs = recurse(node.right)
        fn = BINARY_OPS.get(node.operator)
        if fn is not None:
            if node.operator == '/' and rhs == 0:
                raise _EvalError
            return fn(lhs, rhs)
    if isinstance(node, JsCallExpression) and isinstance(node.callee, JsIdentifier):
        if node.callee.name == 'parseInt' and len(node.arguments) >= 1:
            inner = node.arguments[0]
            if isinstance(inner, JsStringLiteral):
                result = js_parse_int(inner.value)
                if result is None:
                    raise _EvalError
                return float(result)
            if isinstance(inner, JsCallExpression) and isinstance(inner.callee, JsIdentifier):
                idx, key = _resolve_accessor_call(
                    inner, local_accessors, wrappers, prop_maps,
                )
                if 0 <= (i := idx - base_offset) < len(strings):
                    raw = strings[i]
                    decoded = _decode_string(raw, encoding, key)
                    if (result := js_parse_int(decoded)) is None:
                        raise _EvalError
                    return float(result)
            raise _EvalError
    raise _EvalError


def _resolve_accessor_call(
    call: JsCallExpression,
    local_accessors: frozenset[str],
    wrappers: dict[str, AccessorWrapperInfo] | None,
    prop_maps: dict[str, dict[str, int | str]] | None,
) -> tuple[int, str | None]:
    """
    Resolve an accessor or wrapper call to `(index, rc4_key)`. Handles both direct accessor calls
    (`accessor(idx, key)`) and inner wrapper calls (`wrapper(obj.key, obj.idx)`). Raises
    `_EvalError` when the call cannot be resolved.
    """
    callee_name = call.callee.name if isinstance(call.callee, JsIdentifier) else None
    if callee_name is not None and callee_name in local_accessors and len(call.arguments) >= 1:
        idx = int(_eval_arithmetic(call.arguments[0]))
        key: str | None = None
        if len(call.arguments) >= 2 and isinstance(call.arguments[1], JsStringLiteral):
            key = call.arguments[1].value
        return idx, key
    if wrappers and callee_name is not None:
        wrapper = wrappers.get(callee_name)
        if wrapper is not None:
            n_args = max(wrapper.idx_param_pos, wrapper.key_param_pos) + 1
            if len(call.arguments) >= n_args:
                raw_idx = call.arguments[wrapper.idx_param_pos]
                raw_key = call.arguments[wrapper.key_param_pos]
                pm = prop_maps or {}
                idx_value = _resolve_constant(raw_idx, pm)
                if idx_value is None:
                    raise _EvalError
                idx_value -= wrapper.offset
                key_value = _resolve_string_arg(raw_key, pm)
                return idx_value, key_value
    raise _EvalError


def _resolve_string_arg(
    node: Node,
    prop_maps: dict[str, dict[str, int | str]],
) -> str | None:
    """
    Resolve an argument node to a string, handling member access against known property maps.
    Returns None when the argument is not a string (non-RC4 case).
    """
    if isinstance(node, JsStringLiteral):
        return node.value
    if isinstance(node, JsMemberExpression):
        resolved = _resolve_member_access(node, prop_maps)
        if isinstance(resolved, str):
            return resolved
    return None


def _simulate_rotation(
    strings: list[str],
    base_offset: int,
    checksum_node: Node,
    local_accessors: frozenset[str],
    target: int,
    encoding: Encoding = Encoding.NONE,
    wrappers: dict[str, AccessorWrapperInfo] | None = None,
    prop_maps: dict[str, dict[str, int | str]] | None = None,
) -> list[str] | None:
    """
    Simulate the array rotation loop. For each rotation position, evaluate the checksum
    expression against the current array state. Stop when the checksum matches the target,
    or bail after len(strings) attempts.
    """
    array = list(strings)
    n = len(array)
    for _ in range(n):
        try:
            if int(_eval_checksum(
                checksum_node, local_accessors, array, base_offset, encoding, wrappers, prop_maps,
            )) == target:
                return array
        except _EvalError:
            pass
        array.append(array.pop(0))
    return None


def _collect_accessor_aliases(body: Sequence[Node], accessor_name: str) -> set[str]:
    """
    Collect all variable names that are directly assigned the accessor function identifier,
    walking the entire AST. These aliases are used at the top level (e.g. var _0xcbb5cc = _0x4914)
    and inside function bodies (e.g. var _0x4bad70 = _0x4914).
    """
    aliases: set[str] = set()
    for stmt in body:
        for node in stmt.walk():
            if (
                isinstance(node, JsVariableDeclarator)
                and isinstance(node.id, JsIdentifier)
                and isinstance(node.init, JsIdentifier)
                and node.init.name == accessor_name
            ):
                aliases.add(node.id.name)
    return aliases


_B64_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
_B64_STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
_B64_TRANSLATE = str.maketrans(_B64_ALPHABET, _B64_STANDARD)


def _detect_encoding(accessor_node: JsFunctionDeclaration) -> Encoding:
    """
    Detect the string encoding mode by inspecting the accessor function body. The base64 and RC4
    variants inject an init guard:

        if (NAME['...'] === undefined)

    that contains the base64 alphabet string and one (base64) or two (RC4) inner function
    definitions.
    """
    if accessor_node.body is None:
        return Encoding.NONE
    for stmt in accessor_node.body.body:
        if not isinstance(stmt, JsIfStatement):
            continue
        inner_functions = 0
        has_alphabet = False
        for child in stmt.walk():
            if isinstance(child, JsStringLiteral) and child.value == _B64_ALPHABET:
                has_alphabet = True
            if (
                isinstance(child, JsVariableDeclarator)
                and isinstance(child.init, JsFunctionExpression)
            ):
                inner_functions += 1
        if has_alphabet:
            return Encoding.RC4 if inner_functions >= 2 else Encoding.B64
    return Encoding.NONE


def _custom_b64decode(s: str) -> bytes:
    """
    Decode a string using the obfuscator's custom base64 alphabet (lowercase letters first)
    and tolerate missing padding.
    """
    translated = s.translate(_B64_TRANSLATE)
    pad = len(translated) % 4
    if pad:
        translated += '=' * (4 - pad)
    return base64.b64decode(translated)


def _decode_base64(s: str) -> str:
    """
    Decode a base64-encoded string as produced by the obfuscator.
    """
    return _custom_b64decode(s).decode('utf-8')


def _decrypt_rc4(s: str, key: str) -> str:
    """
    Base64-decode, UTF-8-decode, then RC4-decrypt a string using the given key. The obfuscator's
    RC4 operates on Unicode character codes (after UTF-8 decode), not raw bytes, because its
    inline atob uses `decodeURIComponent` which interprets the base64 output as UTF-8.
    """
    data = _decode_base64(s)
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + ord(key[i % len(key)])) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    i = j = 0
    out: list[str] = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out.append(chr(ord(ch) ^ sbox[(sbox[i] + sbox[j]) % 256]))
    return ''.join(out)


def _replace_accessor_calls(
    root: Node,
    aliases: set[str],
    raw_lookup: dict[int, str],
    encoding: Encoding,
    wrappers: dict[str, AccessorWrapperInfo] | None = None,
    prop_maps: dict[str, dict[str, int | str]] | None = None,
) -> int:
    """
    Walk the entire AST and replace accessor calls with decoded string literals. Handles direct
    accessor calls where the first argument is a pure arithmetic expression, and also wrapper calls
    that forward to the accessor with reordered arguments and an offset subtraction. For RC4, the
    decryption key is taken from the second argument (or resolved from the wrapper's key parameter).
    Returns the number of replaced calls.
    """
    count = 0
    local_accessors = frozenset(aliases)
    wrapper_names = set(wrappers) if wrappers else set()
    for node in list(root.walk()):
        if not isinstance(node, JsCallExpression):
            continue
        if not isinstance(node.callee, JsIdentifier):
            continue
        if node.callee.name not in aliases and node.callee.name not in wrapper_names:
            continue
        try:
            idx, key = _resolve_accessor_call(node, local_accessors, wrappers, prop_maps)
        except _EvalError:
            continue
        raw = raw_lookup.get(idx)
        if raw is None:
            continue
        try:
            value = _decode_string(raw, encoding, key)
        except _EvalError:
            continue
        _replace_in_parent(node, make_string_literal(value))
        count += 1
    return count


def _find_remaining_calls(
    root: JsScript,
    aliases: set[str],
    wrapper_names: set[str],
) -> tuple[bool, set[int]]:
    """
    Determine whether unresolved accessor or wrapper calls remain in the AST, excluding calls that
    are inside dead wrapper function bodies (which will be removed). Returns a `(bool, set)` pair:
    whether any outstanding calls exist, and the set of dead-node ids for reuse during cleanup.
    """
    dead_nodes: set[int] = set()
    for n in root.walk():
        if isinstance(n, JsFunctionDeclaration) and n.id is not None and n.id.name in wrapper_names:
            dead_nodes.add(id(n))
        elif (
            isinstance(n, JsCallExpression)
            and isinstance(n.callee, JsIdentifier)
            and (n.callee.name in aliases or n.callee.name in wrapper_names)
        ):
            p = n.parent
            while p is not None:
                if id(p) in dead_nodes:
                    break
                p = p.parent
            else:
                return True, dead_nodes
    return False, dead_nodes


def _cleanup_infrastructure(
    root: JsScript,
    body: Sequence[Node],
    array: ArrayFunction,
    accessor: AccessorFunction,
    dead_nodes: set[int],
    aliases: set[str],
) -> None:
    """
    Remove the string-array infrastructure (array function, accessor function, rotation IIFE, dead
    wrapper declarations, and accessor alias declarators) once all calls have been resolved.
    """
    _remove_from_parent(array.node)
    _remove_from_parent(accessor.node)
    rotation = _find_rotation_iife(body, array.name)
    if rotation is not None:
        _remove_from_parent(rotation.node)
    for n in list(root.walk()):
        if id(n) in dead_nodes:
            _remove_from_parent(n)
        elif (
            isinstance(n, JsVariableDeclarator)
            and isinstance(n.id, JsIdentifier)
            and n.id.name in aliases
            and isinstance(n.init, JsIdentifier)
            and n.init.name in aliases
        ):
            remove_declarator(n)


class _CachedResolution(NamedTuple):
    """
    Cached result of a successful array rotation simulation, stored on the JsScript node to
    survive across pipeline iterations. This prevents re-simulation failures when the simplifier
    modifies the checksum expression in the rotation IIFE between string array passes.
    """
    resolved: list[str]
    base_offset: int
    encoding: Encoding


_CACHE_ATTR = '_stringarray_cache'


class JsStringArrayResolver(ScriptLevelTransformer):

    def _process_script(self, node: JsScript):
        body = node.body
        array = _find_array_function(body)
        if array is None:
            return
        accessor = _find_accessor_function(body, array.name)
        if accessor is None:
            return
        encoding = _detect_encoding(accessor.node)
        cache: _CachedResolution | None = getattr(node, _CACHE_ATTR, None)
        if (
            cache is not None
            and cache.base_offset == accessor.base_offset
            and cache.encoding == encoding
        ):
            resolved = cache.resolved
        else:
            rotation = _find_rotation_iife(body, array.name)
            if rotation is None:
                return
            checksum = _extract_checksum_expression(rotation.body, accessor.name)
            if checksum is None:
                return
            resolved = _simulate_rotation(
                array.strings,
                accessor.base_offset,
                checksum.node,
                checksum.local_accessors,
                rotation.target,
                encoding,
                checksum.wrappers or None,
                checksum.prop_maps or None,
            )
            if resolved is None:
                return
            setattr(node, _CACHE_ATTR, _CachedResolution(resolved, accessor.base_offset, encoding))
        aliases = _collect_accessor_aliases(body, accessor.name)
        aliases.add(accessor.name)
        raw_lookup = {i + accessor.base_offset: s for i, s in enumerate(resolved)}
        all_wrappers = _collect_all_wrappers(node, accessor.name)
        if _replace_accessor_calls(
            node, aliases, raw_lookup, encoding, all_wrappers,
        ) == 0:
            return
        wrapper_names = set(all_wrappers)
        has_remaining, dead_nodes = _find_remaining_calls(node, aliases, wrapper_names)
        if not has_remaining:
            _cleanup_infrastructure(node, body, array, accessor, dead_nodes, aliases)
        self.mark_changed()
