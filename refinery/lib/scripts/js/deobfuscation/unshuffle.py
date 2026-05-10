"""
Resolve statically-evaluable array rotation calls.

Some obfuscators wrap array literals in a rotation function call:

    fn([...elements...], shift)

The function rotates the array left by `shift` positions at runtime using `arr.push(arr.shift())`
repeated `shift` times. This transformer detects such calls and replaces them with the statically
unrotated array literal.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    is_literal,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsReturnStatement,
    JsScript,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)


def _is_push_shift_rotation(func: JsFunctionDeclaration | JsFunctionExpression) -> bool:
    """
    Check if a function is a push/shift rotation: takes 2 params and its body contains a for-loop
    that calls

        param1.push(param1.shift())

    and returns `param1`.
    """
    if len(func.params) != 2:
        return False
    p0, p1 = func.params
    if not isinstance(p0, JsIdentifier) or not isinstance(p1, JsIdentifier):
        return False
    if func.body is None or not isinstance(func.body, JsBlockStatement):
        return False
    arr_param = p0.name
    shift_param = p1.name
    has_for_loop = False
    has_return = False
    for stmt in func.body.body:
        if isinstance(stmt, JsForStatement) and _is_rotation_loop(stmt, arr_param, shift_param):
            has_for_loop = True
        if isinstance(stmt, JsReturnStatement) and stmt.argument is not None:
            if isinstance(stmt.argument, JsIdentifier) and stmt.argument.name == arr_param:
                has_return = True
    return has_for_loop and has_return


def _is_rotation_loop(node: JsForStatement, arr_param: str, shift_param: str) -> bool:
    """
    Check if a for-statement matches the rotation loop pattern:

        for (var i = 0; i < shift; i++) arr.push(arr.shift())
    """
    if node.init is None or node.test is None or node.update is None or node.body is None:
        return False
    loop_var = _extract_loop_init_var(node.init)
    if loop_var is None:
        return False
    if not _is_loop_test(node.test, loop_var, shift_param):
        return False
    if not _is_increment(node.update, loop_var):
        return False
    return _body_is_push_shift(node.body, arr_param)


def _extract_loop_init_var(init: Node) -> str | None:
    """
    Extract the loop variable name from `var i = 0` or `i = 0`.
    """
    if isinstance(init, JsVariableDeclaration):
        if len(init.declarations) == 1:
            decl = init.declarations[0]
            if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                if isinstance(decl.init, JsNumericLiteral) and decl.init.value == 0:
                    return decl.id.name
    elif isinstance(init, JsAssignmentExpression):
        if isinstance(init.left, JsIdentifier) and init.operator == '=':
            if isinstance(init.right, JsNumericLiteral) and init.right.value == 0:
                return init.left.name
    return None


def _is_loop_test(test: Node, loop_var: str, shift_param: str) -> bool:
    if not isinstance(test, JsBinaryExpression):
        return False
    if test.operator != '<':
        return False
    if not isinstance(test.left, JsIdentifier) or test.left.name != loop_var:
        return False
    if not isinstance(test.right, JsIdentifier) or test.right.name != shift_param:
        return False
    return True


def _is_increment(update: Node, loop_var: str) -> bool:
    if isinstance(update, JsUpdateExpression) and update.operator == '++':
        if isinstance(update.argument, JsIdentifier) and update.argument.name == loop_var:
            return True
    return False


def _body_is_push_shift(body: Node, arr_param: str) -> bool:
    """
    Check if the loop body is (or contains) `arr.push(arr.shift())`.
    """
    stmts: list[Node] = []
    if isinstance(body, JsBlockStatement):
        stmts = list(body.body)
    else:
        stmts = [body]
    for stmt in stmts:
        target = stmt
        if isinstance(target, JsExpressionStatement):
            target = target.expression
        if not isinstance(target, JsCallExpression):
            continue
        if not isinstance(target.callee, JsMemberExpression):
            continue
        callee = target.callee
        if callee.computed:
            continue
        if not isinstance(callee.property, JsIdentifier) or callee.property.name != 'push':
            continue
        if not isinstance(callee.object, JsIdentifier) or callee.object.name != arr_param:
            continue
        if len(target.arguments) != 1:
            continue
        arg = target.arguments[0]
        if not isinstance(arg, JsCallExpression):
            continue
        if not isinstance(arg.callee, JsMemberExpression):
            continue
        if arg.callee.computed:
            continue
        if not isinstance(arg.callee.property, JsIdentifier) or arg.callee.property.name != 'shift':
            continue
        if not isinstance(arg.callee.object, JsIdentifier) or arg.callee.object.name != arr_param:
            continue
        return True
    return False


def _is_all_literal_array(node: JsArrayExpression) -> bool:
    return len(node.elements) >= 10 and all(
        e is not None and is_literal(e) for e in node.elements
    )


def _unrotate(elements: list, shift: int) -> list:
    """
    Reverse a left-rotation of `shift` positions. The obfuscator stored the array rotated right by
    `shift`, and the runtime function rotates left by `shift` to restore. We apply the same left
    rotation statically:

        elements[shift:] + elements[:shift]
    """
    return elements[shift:] + elements[:shift]


def _find_rotation_functions(root: JsScript) -> set[str]:
    """
    Find all function declarations/expressions that are push/shift rotation functions.
    """
    names: set[str] = set()
    for node in root.walk():
        if isinstance(node, JsFunctionDeclaration) and node.id is not None:
            if _is_push_shift_rotation(node):
                names.add(node.id.name)
    return names


class JsArrayUnshuffle(ScriptLevelTransformer):
    """
    Resolve array rotation calls where a function rotates an array by N positions using
    `push`/`shift`. Detects rotation functions structurally and replaces call sites with the
    statically un-rotated array literal.
    """

    def _process_script(self, node: JsScript):
        rotation_names = _find_rotation_functions(node)
        count = 0
        for call in node.walk():
            if not isinstance(call, JsCallExpression):
                continue
            if len(call.arguments) != 2:
                continue
            arr_arg = call.arguments[0]
            shift_arg = call.arguments[1]
            if not isinstance(arr_arg, JsArrayExpression):
                continue
            if not isinstance(shift_arg, JsNumericLiteral):
                continue
            shift = int(shift_arg.value)
            if shift <= 0 or shift >= len(arr_arg.elements):
                continue
            if not _is_all_literal_array(arr_arg):
                continue
            if not isinstance(call.callee, JsIdentifier):
                continue
            if call.callee.name not in rotation_names:
                continue
            unrotated = _unrotate(arr_arg.elements, shift)
            replacement = JsArrayExpression(elements=unrotated)
            _replace_in_parent(call, replacement)
            count += 1
        if count > 0:
            self.mark_changed()
