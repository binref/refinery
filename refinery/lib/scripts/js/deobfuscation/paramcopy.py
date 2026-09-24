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
    Scope,
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
    JsSwitchCase,
    JsVariableDeclaration,
    JsVariableDeclarator,
)
from refinery.lib.scripts.js.strict import directive_prologue, strict_mode_at


class _Copy(NamedTuple):
    assignment: JsAssignmentExpression
    param: JsIdentifier
    local: Binding


def _parameters(function: JsFunctionNode) -> dict[int, JsIdentifier]:
    """
    The plain and rest parameters of *function*, by the id of the identifier each one declares.
    """
    params: dict[int, JsIdentifier] = {}
    for param in function.params:
        if isinstance(param, JsRestElement):
            param = param.argument
        if isinstance(param, JsIdentifier):
            params[id(param)] = param
    return params


def _entry_copies(function: JsFunctionNode, model: SemanticModel) -> list[JsAssignmentExpression]:
    """
    The assignments that run first in *function*, before any other statement of its body, and copy
    one of its parameters into a `var` of its body (`_copies_a_parameter`): those in the statements
    that open the body, where the only statements before them are directives, `var` declarations
    without an initializer and function declarations, none of which runs anything at its position.
    A statement joining several such assignments with commas contributes each of them. The run ends
    at the first assignment of any other kind, so no assignment before a copy reads a local or can
    throw.
    """
    body = function.body
    if not isinstance(body, JsBlockStatement):
        return []
    params = _parameters(function)
    body_scope = model.function_scope(function)
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
        for part in parts:
            if not _copies_a_parameter(part, params, body_scope, model):
                return copies
            assert isinstance(part, JsAssignmentExpression)
            copies.append(part)
    return copies


def _copies_a_parameter(
    part: Node | None,
    params: dict[int, JsIdentifier],
    body_scope: Scope | None,
    model: SemanticModel,
) -> bool:
    """
    Whether *part* is `x = p` for one of the parameters *params* and a `var` `x` of the function
    whose body scope is *body_scope*.
    """
    if not isinstance(part, JsAssignmentExpression) or part.operator != '=':
        return False
    left = part.left
    right = part.right
    if not isinstance(left, JsIdentifier) or not isinstance(right, JsIdentifier):
        return False
    source = model.resolve(right)
    local = model.resolve(left)
    return (
        source is not None
        and source.kind is BindingKind.PARAM
        and any(id(declaration) in params for declaration in source.declarations)
        and local is not None
        and local.kind is BindingKind.VAR
        and local.scope is body_scope
    )


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


def _names_in_the_parameter_list(function: JsFunctionNode) -> set[str]:
    """
    Every name spelled in the parameter list of *function*: the parameters it binds, and the names
    its default values read, which are resolved in a scope of their own that does not see the body.
    A parameter renamed to one of them would clash with a binding of the list or capture the read.
    """
    return {
        node.name
        for param in function.params
        for node in param.walk()
        if isinstance(node, JsIdentifier)
    }


def _declared_in_a_statement(declaration: Node) -> bool:
    """
    Whether *declaration* is the name of a declarator without an initializer whose `var` statement
    stands directly in a statement list, from which `remove_declarator` takes it without a gap.
    """
    declarator = declaration.parent
    if not isinstance(declarator, JsVariableDeclarator) or declarator.id is not declaration:
        return False
    statement = declarator.parent
    return (
        declarator.init is None
        and isinstance(statement, JsVariableDeclaration)
        and isinstance(statement.parent, (JsBlockStatement, JsScript, JsSwitchCase))
    )


def _coalescible(function: JsFunctionNode, model: SemanticModel) -> list[_Copy]:
    """
    The entry copies of *function* whose parameter can take the local's place. The parameter is a
    plain or rest one of *function*'s own, declared by nothing else, and read by the copy and by
    nothing else. The local holds the copied value and no other (`SemanticModel.singular_value`),
    is declared only by declarators `remove_declarator` can take out, and its name is spelled
    nowhere in the parameter list (`_names_in_the_parameter_list`). A sloppy body that reads its own
    `arguments` sees the parameters through it, and moving an argument from one name to another
    would change what a write through either one reaches.
    """
    if not strict_mode_at(function) and references_own_arguments(function):
        return []
    params = _parameters(function)
    spelled = _names_in_the_parameter_list(function)
    copies: list[_Copy] = []
    for assignment in _entry_copies(function, model):
        left = assignment.left
        right = assignment.right
        assert isinstance(left, JsIdentifier) and isinstance(right, JsIdentifier)
        source = model.resolve(right)
        if (
            source is None
            or len(source.declarations) != 1
            or id(source.declarations[0]) not in params
            or not _is_sole_access(source, right, model)
        ):
            continue
        local = model.resolve(left)
        if (
            local is None
            or local.name in spelled
            or not local.reads
            or model.singular_value(local) is not right
            or local.dynamic_refs
            or local.exported
            or model.reflection_can_reach(local)
            or not all(map(_declared_in_a_statement, local.declarations))
        ):
            continue
        spelled.add(local.name)
        copies.append(_Copy(assignment, params[id(source.declarations[0])], local))
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
