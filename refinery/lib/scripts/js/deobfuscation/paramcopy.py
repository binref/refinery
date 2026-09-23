"""
Fold a parameter into the local its function copies it to before anything else runs.

A function whose body opens by copying a parameter into a local of its own and never reads the
parameter again,

    function (a_1) { var a; a = a_1; ... a ... }

has the local hold the argument from the first statement on, which is what a parameter of that name
holds. Giving the parameter the local's name and dropping the copy leaves the same function:

    function (a) { ... a ... }

Recovering a function the obfuscator flattened into a state machine leaves this shape behind: the
machine stores the arguments into a scope object, and flattening that object turns each store into
a copy from the parameter the recovery gives the function.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    Binding,
    BindingKind,
    SemanticModel,
    references_own_arguments,
)
from refinery.lib.scripts.js.deobfuscation.helpers import ScriptLevelTransformer, remove_declarator
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBlockStatement,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsIdentifier,
    JsRestElement,
    JsScript,
    JsSequenceExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.strict import directive_prologue, strict_mode_at


class _Copy(NamedTuple):
    assignment: JsAssignmentExpression
    param: JsIdentifier
    local: Binding


def _entry_copies(function: JsFunctionNode) -> list[JsAssignmentExpression]:
    """
    The assignments `x = p` between two identifiers that run first in *function*, before any
    other statement of its body: those in the statements that open the body, where the only
    statements before them are directives, `var` declarations without an initializer and function
    declarations, none of which runs anything at its position. A statement joining several such
    assignments with commas contributes each of them.
    """
    body = function.body
    if not isinstance(body, JsBlockStatement):
        return []
    statements = body.body[len(directive_prologue(body)):]
    copies: list[JsAssignmentExpression] = []
    for statement in statements:
        if isinstance(statement, JsFunctionDeclaration):
            continue
        if isinstance(statement, JsVariableDeclaration):
            if all(
                isinstance(declarator, JsVariableDeclarator) and declarator.init is None
                for declarator in statement.declarations
            ):
                continue
            break
        if not isinstance(statement, JsExpressionStatement):
            break
        expression = statement.expression
        parts = [expression]
        if isinstance(expression, JsSequenceExpression):
            parts = expression.expressions
        assignments = [
            part for part in parts
            if isinstance(part, JsAssignmentExpression)
            and part.operator == '='
            and isinstance(part.left, JsIdentifier)
            and isinstance(part.right, JsIdentifier)
        ]
        if len(assignments) != len(parts):
            break
        copies.extend(assignments)
    return copies


def _is_sole_access(binding: Binding | None, reference: Node, model: SemanticModel) -> bool:
    """
    Whether *reference* is the one access to *binding* the program can make: the binding records it
    and nothing else, and no name the model cannot attribute can reach it.
    """
    return (
        binding is not None
        and [*binding.reads, *binding.writes] == [reference]
        and not binding.dynamic_refs
        and not binding.indefinite_writes
        and not binding.exported
        and not model.reflection_can_reach(binding)
    )


def _coalescible(function: JsFunctionNode, model: SemanticModel) -> list[_Copy]:
    """
    The entry copies of *function* whose parameter can take the local's place. The parameter is a
    plain or rest one of *function*'s own, read by the copy and by nothing else; the local is a
    `var` of *function* the copy writes and nothing else writes, so it holds the argument wherever
    it is read. A sloppy body that reads its own `arguments` sees the parameters through it, and
    moving an argument from one name to another would change what a write through either one
    reaches.
    """
    if not strict_mode_at(function) and references_own_arguments(function):
        return []
    params: dict[int, JsIdentifier] = {}
    for param in function.params:
        if isinstance(param, JsRestElement):
            param = param.argument
        if isinstance(param, JsIdentifier):
            params[id(param)] = param
    names = {param.name for param in params.values()}
    body_scope = model.function_scope(function)
    copies: list[_Copy] = []
    for assignment in _entry_copies(function):
        left = assignment.left
        right = assignment.right
        assert isinstance(left, JsIdentifier) and isinstance(right, JsIdentifier)
        source = model.resolve(right)
        if source is None or source.kind is not BindingKind.PARAM:
            continue
        declared = [ident for ident in source.declarations if id(ident) in params]
        if len(declared) != 1 or not _is_sole_access(source, right, model):
            continue
        local = model.resolve(left)
        if (
            local is None
            or local.kind is not BindingKind.VAR
            or local.scope is not body_scope
            or local.name in names
            or local.reads == []
            or local.writes != [left]
            or local.dynamic_refs
            or local.exported
            or model.reflection_can_reach(local)
            or not all(
                isinstance(declarator := declaration.parent, JsVariableDeclarator)
                and declarator.id is declaration
                and declarator.init is None
                for declaration in local.declarations
            )
        ):
            continue
        names.add(local.name)
        copies.append(_Copy(assignment, declared[0], local))
    return copies


def _drop(assignment: JsAssignmentExpression) -> None:
    """
    Remove an entry copy from the statement that holds it, and the statement with its last copy.
    """
    parent = assignment.parent
    if isinstance(parent, JsSequenceExpression):
        _remove_from_parent(assignment)
        if len(parent.expressions) == 1:
            _replace_in_parent(parent, parent.expressions[0])
        return
    assert isinstance(parent, JsExpressionStatement)
    _remove_from_parent(parent)


class JsParameterCopyCoalescing(ScriptLevelTransformer):
    """
    Give a parameter the name of the local its function copies it to on entry, and drop the copy.
    """

    def _process_script(self, node: JsScript) -> None:
        model = model_cache(self, node).model
        decided: list[_Copy] = []
        for function in node.walk():
            if isinstance(function, FUNCTION_NODES):
                decided.extend(_coalescible(function, model))
        for copy in decided:
            for declaration in copy.local.declarations:
                declarator = declaration.parent
                assert isinstance(declarator, JsVariableDeclarator)
                remove_declarator(declarator)
            _replace_in_parent(copy.param, JsIdentifier(name=copy.local.name))
            _drop(copy.assignment)
            self.mark_changed()
