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
import math

from typing import Callable, NamedTuple, Sequence

from refinery.lib.scripts import (
    Node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import Binding, Role, SemanticModel, reference_role
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    make_string_literal,
    nothing_still_names,
    remove_declarator,
    string_value,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBreakStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    Statement,
    is_generator_function,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.numbers import exact_integer, js_parse_int, js_string_to_number
from refinery.lib.scripts.js.values import BINARY_OPS, HostApproximated


class Encoding(enum.Enum):
    NONE = 'none'
    B64 = 'base64'
    RC4 = 'rc4'


class ArrayFunction(NamedTuple):
    node: JsFunctionDeclaration
    name: str
    strings: list[str]


class AccessorFunction(NamedTuple):
    node: JsFunctionDeclaration
    name: str
    base_offset: int
    encoding: Encoding


class RotationIIFE(NamedTuple):
    node: Node
    target: int
    body: Sequence[Node]
    target_param: str | None


def _answers_a_wrapper(node: Node | None) -> bool:
    """
    Whether *node* denotes a function a call to which answers a promise or a generator object.

    A recognizer here reads the function it can see, but what the program calls is often the one a
    self-replacing shape installs in its place. The replacement is read through this, so that the
    keyword is asked of the function whose answer the pass goes on to substitute for.
    """
    node = strip_parens(node)
    return isinstance(node, FUNCTION_NODES) and wraps_return(node)


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
        if wraps_return(statement):
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
                has_self_reassignment = not _answers_a_wrapper(assign.right)
        if array_literal is not None and has_self_reassignment:
            return ArrayFunction(statement, name, array_literal)
    return None


def _find_all_accessor_functions(
    model: SemanticModel,
    body: Sequence[Node],
    array_fn_name: str,
) -> list[AccessorFunction]:
    """
    Detect all accessor functions for a given array. An obfuscator can produce multiple accessors
    sharing the same array (e.g. one base64 and one RC4). Two structural variants are recognized:

    Simple pattern::

        function NAME(param, _unused) {
          param = param - BASE_OFFSET;
          var v = ARRAY_FN();
          var r = v[param];
          return r;
        }

    Self-overwriting (memoization) pattern::

        function NAME(B, I) {
          const Y = ARRAY_FN();
          NAME = function(Z, o) {
            Z = Z - BASE_OFFSET;
            ...
          };
          return NAME(B, I);
        }

    In both, subtracting the offset is the first thing the function does with its index, so the
    position a call asks for is the Number the subtraction reads from its argument, which is what
    `_decoder_index` computes. An accessor that does anything else with its index first is not
    recognized.
    """
    results: list[AccessorFunction] = []
    for stmt in body:
        if not isinstance(stmt, JsFunctionDeclaration):
            continue
        if wraps_return(stmt):
            continue
        if stmt.id is None or stmt.body is None:
            continue
        if len(stmt.params) != 2:
            continue
        fn_name = stmt.id.name
        first_param = stmt.params[0]
        if not isinstance(first_param, JsIdentifier):
            continue
        statements = stmt.body.body
        calls_array_fn = any(
            isinstance(decl, JsVariableDeclarator)
            and isinstance(decl.init, JsCallExpression)
            and isinstance(decl.init.callee, JsIdentifier)
            and decl.init.callee.name == array_fn_name
            for s in statements if isinstance(s, JsVariableDeclaration)
            for decl in s.declarations
        )
        if not calls_array_fn:
            continue
        base_offset = _index_shift(statements, first_param.name)
        if base_offset is None:
            base_offset = _extract_self_overwriting_offset(model, statements, fn_name, first_param)
        if base_offset is not None:
            results.append(AccessorFunction(stmt, fn_name, base_offset, _detect_encoding(stmt)))
    return results


def _index_shift(statements: Sequence[Node], param_name: str) -> int | None:
    """
    The offset the first of *statements* subtracts from the index parameter, when it is the plain
    assignment `param = param - OFFSET`, or `None`.
    """
    if not statements:
        return None
    first = statements[0]
    if not isinstance(first, JsExpressionStatement):
        return None
    assign = first.expression
    if not (
        isinstance(assign, JsAssignmentExpression)
        and assign.operator == '='
        and isinstance(assign.left, JsIdentifier)
        and assign.left.name == param_name
        and isinstance(assign.right, JsBinaryExpression)
        and assign.right.operator == '-'
        and isinstance(assign.right.left, JsIdentifier)
        and assign.right.left.name == param_name
        and assign.right.right is not None
    ):
        return None
    try:
        return exact_integer(_eval_arithmetic(assign.right.right))
    except _EvalError:
        return None


def _extract_self_overwriting_offset(
    model: SemanticModel,
    body: Sequence[Node],
    fn_name: str,
    param: JsIdentifier,
) -> int | None:
    """
    Detect the self-overwriting accessor variant where the function reassigns itself to an inner
    function expression containing the offset subtraction. Returns the base offset or None. The
    outer function hands its index on untouched: the only reference to its index parameter is the
    first argument of the call to its replacement that it returns. The replacement may declare a
    parameter of the same name, as a minifier spells it, and that is another binding.
    """
    if not body:
        return None
    forward = body[-1]
    if not (
        isinstance(forward, JsReturnStatement)
        and isinstance(call := forward.argument, JsCallExpression)
        and isinstance(call.callee, JsIdentifier)
        and call.callee.name == fn_name
        and call.arguments
        and isinstance(index := call.arguments[0], JsIdentifier)
        and (binding := model.binding_of(param)) is not None
    ):
        return None
    references = model.references(binding)
    if (
        len(references) != 1
        or references[0] is not index
        or model.dynamic_references(binding)
        or model.binding_maybe_reassigned_dynamically(binding)
    ):
        return None
    for s in body[:-1]:
        if not isinstance(s, JsExpressionStatement):
            continue
        if not isinstance(s.expression, JsAssignmentExpression):
            continue
        assign = s.expression
        if not isinstance(assign.left, JsIdentifier) or assign.left.name != fn_name:
            continue
        if not isinstance(assign.right, JsFunctionExpression):
            continue
        if wraps_return(assign.right):
            continue
        inner_fn = assign.right
        if inner_fn.body is None or len(inner_fn.params) < 2:
            continue
        inner_param = inner_fn.params[0]
        if not isinstance(inner_param, JsIdentifier):
            continue
        return _index_shift(inner_fn.body.body, inner_param.name)
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

    A generator is refused and an `async` function is not, which is where the two kinds a call wraps
    the answer of part company: this IIFE is read for its effect on the array and never for what the
    call answered, and calling a generator runs no body at all, where an `async` body with no
    `await` in it runs to completion before the call returns.

    Returns (statement_node, target_checksum, iife_body_statements) or None. Also handles the case
    where the rotation call is an element of a comma-separated sequence expression.
    """
    for stmt in body:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if isinstance(expr, JsParenthesizedExpression):
            expr = expr.expression
        candidates: list[tuple[Node, JsCallExpression]] = []
        if isinstance(expr, JsCallExpression):
            candidates.append((stmt, expr))
        elif isinstance(expr, JsSequenceExpression):
            for sub in expr.expressions:
                if isinstance(sub, JsCallExpression):
                    candidates.append((sub, sub))
        for removable, call in candidates:
            fn = call.callee
            if isinstance(fn, JsParenthesizedExpression):
                fn = fn.expression
            if not isinstance(fn, JsFunctionExpression):
                continue
            if is_generator_function(fn):
                continue
            if len(call.arguments) != 2:
                continue
            first_arg = call.arguments[0]
            second_arg = call.arguments[1]
            if not (isinstance(first_arg, JsIdentifier) and first_arg.name == array_fn_name):
                continue
            try:
                target = _as_position(_eval_arithmetic(second_arg))
            except _EvalError:
                continue
            fn_body = fn.body
            if fn_body is None:
                continue
            if not any(isinstance(s, JsWhileStatement) for s in fn_body.body):
                continue
            target_param = None
            if len(fn.params) >= 2 and isinstance(fn.params[1], JsIdentifier):
                target_param = fn.params[1].name
            return RotationIIFE(removable, target, fn_body.body, target_param)
    return None


class _EvalError(Exception):
    pass


def _array_order_is_literal(
    model: SemanticModel,
    array: ArrayFunction,
    accessors: Sequence[AccessorFunction],
) -> bool:
    """
    Whether the strings are in the order the array literal spells them. The model names every way
    the program reaches the array function — a reference, a write through an alias, a `with`-body
    name, an export, a global handed to a call — and the literal order is the order the accessors
    read only when each of those ways belongs to the array function itself or to an accessor. A
    rotation has to reach the array function before it can reorder the array, so a reference
    anywhere else is a hand this resolver cannot see the moves of.
    """
    binding = model.binding_of(array.node.id)
    if binding is None:
        return False
    if binding.exported or binding.reachable_through_a_handed_object:
        return False
    inside = {
        id(node)
        for root in (array.node, *(accessor.node for accessor in accessors))
        for node in root.walk()
    }
    references = [
        *model.references(binding),
        *model.dynamic_references(binding),
        *binding.indefinite_writes,
    ]
    return all(id(reference) in inside for reference in references)


def _as_position(value: float) -> int:
    """
    Read an evaluated Number as the whole number a pattern can use — an index, an offset, a rotation
    target, a checksum — truncated toward zero. `NaN` and the infinities name no position, and `int`
    raises on them rather than answering, so they are refused the way every other unusable
    expression in this module is refused: an uncaught `OverflowError` would abort the whole run
    instead.
    """
    if not math.isfinite(value):
        raise _EvalError
    return int(value)


def _extract_checksum_expression(
    iife_body: Sequence[Node],
    target_param: str | None = None,
) -> Node | None:
    """
    Extract the checksum expression AST node from the rotation IIFE body. Handles two structural
    variants:

    1. Variable declaration: `var x = CHECKSUM; if (x === target) break;`
    2. Inline if-condition: `if (CHECKSUM === target) break;`

    Variant 2 occurs when earlier passes eliminate the intermediate variable or constant-fold the
    checksum expression to a value equal to the rotation target.
    """
    checksum_node: Node | None = None
    for s in iife_body:
        if not isinstance(s, JsWhileStatement) or s.body is None:
            continue
        for ws in s.walk():
            if isinstance(ws, JsVariableDeclaration):
                for decl in ws.declarations:
                    if isinstance(decl, JsVariableDeclarator) and decl.init is not None:
                        checksum_node = decl.init
                        break
                if checksum_node is not None:
                    break
        if checksum_node is None and target_param is not None:
            for ws in s.walk():
                if (
                    isinstance(ws, JsIfStatement)
                    and isinstance(ws.test, JsBinaryExpression)
                    and ws.test.operator == '==='
                    and isinstance(ws.consequent, JsBreakStatement)
                ):
                    left, right = ws.test.left, ws.test.right
                    if isinstance(right, JsIdentifier) and right.name == target_param:
                        checksum_node = left
                    elif isinstance(left, JsIdentifier) and left.name == target_param:
                        checksum_node = right
                    if checksum_node is not None:
                        break
        break
    return checksum_node


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


def _arithmetic(operator: str, left: float, right: float) -> float:
    """
    The number *operator* computes from two numbers, refusing an operator whose result is no number,
    a power the engine approximates, and a division by zero.
    """
    apply = BINARY_OPS.get(operator)
    if apply is None or operator == '/' and right == 0:
        raise _EvalError
    try:
        result = apply(left, right)
    except HostApproximated:
        raise _EvalError
    if not isinstance(result, float):
        raise _EvalError
    return result


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
        return _arithmetic(node.operator, left, right)
    raise _EvalError


def _eval_checksum(
    node: Node,
    strings: list[str],
    decoder_calls: dict[int, AccessorFunction],
) -> float:
    """
    Evaluate a checksum expression against the current array state. Handles the arithmetic
    operators (`+`, `-`, `*`, `/`), unary negation, parentheses, `parseInt` calls on accessor
    lookups, and numeric literals. The accessor lookups are the calls in *decoder_calls*, which
    maps the `id` of each to the accessor it reaches.

    Raises `_EvalError` on any unrecognized pattern.
    """
    recurse = functools.partial(
        _eval_checksum,
        strings=strings,
        decoder_calls=decoder_calls,
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
        return _arithmetic(node.operator, lhs, rhs)
    if isinstance(node, JsCallExpression) and isinstance(node.callee, JsIdentifier):
        if node.callee.name == 'parseInt' and len(node.arguments) >= 1:
            radix = _checksum_radix(node.arguments[1:], recurse)
            inner = node.arguments[0]
            if isinstance(inner, JsStringLiteral):
                if inner.value is None:
                    raise _EvalError
                result = js_parse_int(inner.value, radix)
                if result is None:
                    raise _EvalError
                return result
            if (accessor := decoder_calls.get(id(inner))) is not None:
                assert isinstance(inner, JsCallExpression)
                decoded = _decode_call(inner, accessor, strings)
                if (result := js_parse_int(decoded, radix)) is None:
                    raise _EvalError
                return result
            raise _EvalError
    raise _EvalError


def _checksum_radix(
    rest: Sequence[Node],
    recurse: Callable[[Node], float],
) -> int:
    """
    The radix a `parseInt` call in a checksum expression names, or `0` for the language's "not
    supplied". Reading it is what keeps the simulated checksum equal to the one the engine computes:
    an unsupplied radix takes a `0x` prefix as base 16, so ignoring a written `10` would read
    `'0x1F'` as `31` where the engine reads `0`. A radix that does not evaluate to an integer is not
    a checksum this module can simulate.
    """
    if not rest:
        return 0
    radix = exact_integer(recurse(rest[0]))
    if radix is None:
        raise _EvalError
    return radix


def _decoder_index(node: Node) -> int | None:
    """
    The position a call to the decoder asks for, as the decoder's subtraction reads it from the
    argument: the Number the argument evaluates to, where it is a whole number. The obfuscator
    spells an index as a numeric string as often as a number, and the subtraction reads a string
    through StringToNumber, so `'0x13d'` asks for 317 where `'1_72'` asks for no position at all.
    """
    if isinstance(node, JsStringLiteral) and (text := string_value(node)) is not None:
        return exact_integer(js_string_to_number(text))
    try:
        return exact_integer(_eval_arithmetic(node))
    except _EvalError:
        return None


def _read_decoder_call(call: JsCallExpression) -> tuple[int, str | None]:
    """
    The position and the RC4 key a call to the decoder passes. The key is `None` where the call
    passes none, which the encodings without one never read. Raises `_EvalError` when the position
    is not one `_decoder_index` can read.
    """
    if not call.arguments:
        raise _EvalError
    index = _decoder_index(call.arguments[0])
    if index is None:
        raise _EvalError
    key = string_value(call.arguments[1]) if len(call.arguments) >= 2 else None
    return index, key


def _decode_call(call: JsCallExpression, accessor: AccessorFunction, strings: Sequence[str]) -> str:
    """
    The string *call*, a call to *accessor*, answers when the accessor reads *strings*: the element
    at the position the call asks for less the accessor's own offset, decoded the way the accessor
    decodes it. Raises `_EvalError` when the call asks for no position this module can read, the
    position names no element, or the element does not decode.
    """
    index, key = _read_decoder_call(call)
    position = index - accessor.base_offset
    if not 0 <= position < len(strings):
        raise _EvalError
    return _decode_string(strings[position], accessor.encoding, key)


def _simulate_rotation(
    strings: list[str],
    checksum_node: Node,
    decoder_calls: dict[int, AccessorFunction],
    target: int,
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
            if _as_position(_eval_checksum(checksum_node, array, decoder_calls)) == target:
                return array
        except _EvalError:
            pass
        array.append(array.pop(0))
    return None


class _Decoders(NamedTuple):
    """
    The bindings a call names an accessor through, each mapped to the accessor it denotes, and the
    declarators that make the aliases among them.
    """
    accessors: dict[Binding, AccessorFunction]
    alias_declarators: list[JsVariableDeclarator]

    def called_by(self, model: SemanticModel, node: Node) -> AccessorFunction | None:
        """
        The accessor *node* calls, where it is a call whose callee resolves to one of these
        bindings, or `None`.
        """
        if not isinstance(node, JsCallExpression) or not isinstance(node.callee, JsIdentifier):
            return None
        if (binding := model.resolve(node.callee)) is None:
            return None
        return self.accessors.get(binding)


def _is_written_only_by_itself(
    model: SemanticModel,
    binding: Binding,
    function: JsFunctionDeclaration,
) -> bool:
    """
    Whether every store into *binding* happens inside *function*, the one it declares. The
    self-overwriting decoder replaces itself with the function that does the work, and a store
    anywhere else means a call may reach some other function under the same name. A second
    declaration of the name is such a store: a later function declaration of it is the one the
    name holds, and a `var` of it with a value replaces the decoder where it runs.
    """
    if binding.exported or binding.reachable_through_a_handed_object:
        return False
    if len(binding.declarations) != 1 or binding.declarations[0] is not function.id:
        return False
    writes = [
        *binding.writes,
        *binding.indefinite_writes,
        *(ref for ref in model.dynamic_references(binding) if reference_role(ref) is not Role.READ),
    ]
    return all(write.is_descendant_of(function) for write in writes)


def _find_decoders(
    model: SemanticModel,
    scope: Node,
    accessors: Sequence[AccessorFunction],
) -> _Decoders:
    """
    Every binding through which a call reaches one of the *accessors*: the binding each declares,
    where nothing else stores into it, and every name declared with one of those as its only value,
    such as `const a0x = a0d` and the chains an obfuscator builds from it. A call is read as a call
    to the decoder when its callee resolves to one of these bindings, never by spelling alone: a
    parameter or a local of the same name inside some function is another binding.
    """
    found: dict[Binding, AccessorFunction] = {}
    for accessor in accessors:
        assert accessor.node.id is not None
        binding = model.binding_of(accessor.node.id)
        if binding is not None and _is_written_only_by_itself(model, binding, accessor.node):
            found[binding] = accessor
    copies: dict[Binding, list[tuple[Binding, JsVariableDeclarator]]] = {}
    for node in scope.walk():
        if (
            isinstance(node, JsVariableDeclarator)
            and isinstance(node.id, JsIdentifier)
            and isinstance(node.init, JsIdentifier)
            and (alias := model.binding_of(node.id)) is not None
            and (source := model.resolve(node.init)) is not None
        ):
            copies.setdefault(source, []).append((alias, node))
    aliases: list[JsVariableDeclarator] = []
    pending = list(found)
    while pending:
        source = pending.pop()
        for alias, declarator in copies.get(source, ()):
            if alias in found or model.singular_value(alias) is not declarator.init:
                continue
            found[alias] = found[source]
            aliases.append(declarator)
            pending.append(alias)
    return _Decoders(found, aliases)


_B64_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
_B64_STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
_B64_TRANSLATE = str.maketrans(_B64_ALPHABET, _B64_STANDARD)


def _detect_encoding(accessor_node: JsFunctionDeclaration) -> Encoding:
    """
    Detect the string encoding mode by inspecting the accessor function body. The base64 and RC4
    variants inject an init guard:

        if (NAME['...'] === undefined)

    that contains the base64 alphabet string and one (base64) or two (RC4) inner function
    definitions. For the self-overwriting variant, the guard is inside the inner function expression.
    """
    if accessor_node.body is None:
        return Encoding.NONE
    search_bodies: list[Sequence[Node]] = [accessor_node.body.body]
    if accessor_node.id is not None:
        fn_name = accessor_node.id.name
        for stmt in accessor_node.body.body:
            if (
                isinstance(stmt, JsExpressionStatement)
                and isinstance(stmt.expression, JsAssignmentExpression)
                and isinstance(stmt.expression.left, JsIdentifier)
                and stmt.expression.left.name == fn_name
                and isinstance(stmt.expression.right, JsFunctionExpression)
                and stmt.expression.right.body is not None
            ):
                search_bodies.append(stmt.expression.right.body.body)
    for body in search_bodies:
        for stmt in body:
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
    model: SemanticModel,
    decoders: _Decoders,
    strings: Sequence[str],
    infrastructure: Sequence[Node],
) -> int:
    """
    Replace every call to a decoder below *root* with the string `_decode_call` reads for it from
    *strings*, the table in the order the accessors read it. A call is one to a decoder when its
    callee resolves to a binding of *decoders*. A call inside the *infrastructure* stays: the
    rotation reads the array it is still turning, and answering those reads with the strings the
    turning ends on stops the loop before it turns, so a call the pass leaves standing would read
    the array unturned. Returns the number of replaced calls.
    """
    machinery = {id(node) for part in infrastructure for node in part.walk()}
    calls: list[tuple[JsCallExpression, AccessorFunction]] = []
    for node in root.walk():
        if id(node) in machinery:
            continue
        if (accessor := decoders.called_by(model, node)) is not None:
            assert isinstance(node, JsCallExpression)
            calls.append((node, accessor))
    count = 0
    for call, accessor in calls:
        try:
            value = _decode_call(call, accessor, strings)
        except _EvalError:
            continue
        _replace_in_parent(call, make_string_literal(value))
        count += 1
    return count


def _infrastructure_nodes(
    array: ArrayFunction,
    accessors: list[AccessorFunction],
    rotation: RotationIIFE | None,
    decoders: _Decoders,
) -> list[Node]:
    """
    Every node the string-array infrastructure occupies: the array function, the accessor functions,
    the rotation IIFE that puts the strings in order, and the declarators that alias an accessor.
    They are collected before anything is removed, so that the names they declare can be asked about
    together — a reference from one of them into another goes with the removal, and only a reference
    from outside all of them keeps the infrastructure alive.
    """
    nodes: list[Node] = [array.node]
    nodes.extend(accessor.node for accessor in accessors)
    if rotation is not None:
        nodes.append(rotation.node)
    nodes.extend(decoders.alias_declarators)
    return nodes


def _remove_infrastructure(nodes: Sequence[Node]) -> None:
    """
    Delete the nodes `_infrastructure_nodes` collected, each the way its kind is deleted: a
    declarator through `refinery.lib.scripts.js.deobfuscation.helpers.remove_declarator`, so that the
    declaration holding it goes too once it holds nothing else, and every other node out of the
    statement list it sits in.
    """
    for node in nodes:
        if isinstance(node, JsVariableDeclarator):
            remove_declarator(node)
        else:
            _remove_from_parent(node)


class _CachedResolution(NamedTuple):
    """
    Cached result of a successful array rotation simulation, stored on the scope root node to
    survive across pipeline iterations. This prevents re-simulation failures when the simplifier
    modifies the checksum expression in the rotation IIFE between string array passes. The result
    holds for the accessors `_accessor_signature` describes.
    """
    resolved: list[str]
    accessors: list[tuple[str, int, Encoding]]


def _accessor_signature(accessors: Sequence[AccessorFunction]) -> list[tuple[str, int, Encoding]]:
    """
    The name, offset and encoding of each of the *accessors*, which is what a cached rotation was
    simulated with.
    """
    return [(accessor.name, accessor.base_offset, accessor.encoding) for accessor in accessors]


_CACHE_ATTR = '_stringarray_cache'


class JsStringArrayResolver(ScopeProcessingTransformer):

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _strings_in_read_order(
        self,
        scope: Node,
        model: SemanticModel,
        array: ArrayFunction,
        accessors: Sequence[AccessorFunction],
        decoders: _Decoders,
        rotation: RotationIIFE | None,
    ) -> list[str] | None:
        """
        The string table in the order the accessors read it, or `None` when that order cannot be
        established. A rotation reorders the table until a checksum matches, so a found one is
        simulated and its result cached on the scope — a later pass may simplify the checksum
        expression into something this resolver can no longer read. The checksum reads the table
        through the calls in it that *decoders* says reach an accessor. Where no rotation is found,
        the literal already spells the order the accessors read, unless the model can name a hand
        that reaches the array besides them.
        """
        if rotation is None:
            if not _array_order_is_literal(model, array, accessors):
                return None
            return array.strings
        signature = _accessor_signature(accessors)
        cache: _CachedResolution | None = getattr(scope, _CACHE_ATTR, None)
        if cache is not None and cache.accessors == signature:
            return cache.resolved
        checksum = _extract_checksum_expression(rotation.body, rotation.target_param)
        if checksum is None:
            return None
        decoder_calls = {
            id(node): accessor for node in checksum.walk()
            if (accessor := decoders.called_by(model, node)) is not None
        }
        resolved = _simulate_rotation(array.strings, checksum, decoder_calls, rotation.target)
        if resolved is None:
            return None
        setattr(scope, _CACHE_ATTR, _CachedResolution(resolved, signature))
        return resolved

    def _process_scope_body(self, scope: Node, body: list[Statement]) -> None:
        array = _find_array_function(body)
        if array is None:
            return
        assert self._root is not None
        model = model_cache(self, self._root).model
        accessors = _find_all_accessor_functions(model, body, array.name)
        if not accessors:
            return
        decoders = _find_decoders(model, scope, accessors)
        rotation = _find_rotation_iife(body, array.name)
        resolved = self._strings_in_read_order(scope, model, array, accessors, decoders, rotation)
        if resolved is None:
            return
        infrastructure = _infrastructure_nodes(array, accessors, rotation, decoders)
        replaced = _replace_accessor_calls(scope, model, decoders, resolved, infrastructure)
        if nothing_still_names(model_cache(self, self._root).model, infrastructure):
            _remove_infrastructure(infrastructure)
            self.mark_changed()
        elif replaced > 0:
            self.mark_changed()
