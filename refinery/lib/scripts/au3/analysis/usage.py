"""
The usage model: what the script does with its names. The dead-code elimination in
`refinery.lib.scripts.au3.deobfuscation.eliminate` asks it what a direct call names, which names
a string or a directive spells, which calls may consume a computed name, which storage every
variable occurrence binds, and which expressions are effect-free — each fact owned by the module
that pinned it: the bindings by `refinery.lib.scripts.au3.analysis.scopes`, the may-write
summaries by `refinery.lib.scripts.au3.analysis.propagation`, the builtin knowledge by
`refinery.lib.scripts.au3.analysis.builtins`.

An expression is effect-free when evaluating it writes nothing observable and cannot terminate
the script. Termination is what the arithmetic refuses: a division by zero ends the script
(pinned by the probe corpus), an out-of-range subscript ends it the same way, and a wrong-arity
call as well, so `/`, `^`, and array access are refused. A call is effect-free only over a pure
script function of matching parameter count that declares no `ByRef` parameter, its arguments
effect-free with it; no builtin call is, because a builtin's value-dependent fatals are
unpinned and the builtin name universe phase owns the table that would change that. A function
is pure when its may-write summary is empty, its body holds no `Exit`, and every expression in
it is effect-free where a call inside the body names a pure function — the fixpoint of that
rule, so a mutually recursive cluster qualifies when no body in it is impure for any other
reason.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import NAME_PARAMETERS
from refinery.lib.scripts.au3.analysis.propagation import execute_kills
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.model import (
    Au3ArrayLiteral,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3DefaultLiteral,
    Au3Directive,
    Au3EnumDeclarator,
    Au3ExitStatement,
    Au3FloatLiteral,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IntLiteral,
    Au3Macro,
    Au3MemberAccess,
    Au3NullLiteral,
    Au3Script,
    Au3StringLiteral,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Au3VariableDeclarator,
    Expression,
)
from refinery.lib.scripts.au3.parser import Au3Parser

_EFFECT_FREE_READS = (
    Au3BooleanLiteral,
    Au3DefaultLiteral,
    Au3FloatLiteral,
    Au3Identifier,
    Au3IntLiteral,
    Au3Macro,
    Au3NullLiteral,
    Au3StringLiteral,
    Au3Variable,
)


@dataclass(frozen=True)
class Au3UsageModel:
    """
    What one tree version does with its names, built once per tree version by
    `build_usage_model`: the script's functions, the direct-identifier call count of each, the
    functions that are pure, the calls that may consume a computed name, the lowercased text of
    every string literal and directive, and the storage every variable occurrence binds — per
    scope for locals, per name for globals, the script level among them as `None`.
    """

    functions: dict[str, Au3FunctionDeclaration]
    call_counts: dict[str, int]
    pure_functions: frozenset[str]
    channels: frozenset[Au3Call]
    spellings: str
    local_bindings: dict[Au3FunctionDeclaration, frozenset[str]]
    global_bindings: dict[str, frozenset[Au3FunctionDeclaration | None]]

    def spells(self, name: str) -> bool:
        """
        Whether *name* — a function name, or a variable name without its `$` — is a substring of
        any string literal or directive the tree holds: a computed name has to be built from
        string data, so a name some string spells is one no removal may take away.
        """
        return name.lstrip('$') in self.spellings

    def effect_free(self, expression: Expression | None) -> bool:
        """
        Whether evaluating *expression* writes nothing observable and cannot terminate the
        script.
        """
        return _effect_free(expression, self.functions, self.pure_functions)


def _effect_free(
    expression: Expression | None,
    functions: dict[str, Au3FunctionDeclaration],
    pure: frozenset[str],
) -> bool:
    node = ast.unwrap_parens(expression)
    if node is None or isinstance(node, _EFFECT_FREE_READS):
        return True
    if isinstance(node, Au3BinaryExpression):
        if node.operator in ('/', '^'):
            return False
        return (
            _effect_free(node.left, functions, pure)
            and _effect_free(node.right, functions, pure)
        )
    if isinstance(node, Au3UnaryExpression):
        return _effect_free(node.operand, functions, pure)
    if isinstance(node, Au3Ternary):
        return (
            _effect_free(node.condition, functions, pure)
            and _effect_free(node.consequent, functions, pure)
            and _effect_free(node.alternate, functions, pure)
        )
    if isinstance(node, Au3ArrayLiteral):
        return all(_effect_free(element, functions, pure) for element in node.elements)
    if isinstance(node, Au3Call):
        return _call_is_effect_free(node, functions, pure)
    return False


def _call_is_effect_free(
    call: Au3Call,
    functions: dict[str, Au3FunctionDeclaration],
    pure: frozenset[str],
) -> bool:
    callee = ast.direct_callee(call)
    if callee is None:
        return False
    if callee.name not in functions:
        if callee.name == 'execute':
            return _execute_is_effect_free(call, functions, pure)
        return False
    if callee.name not in pure:
        return False
    function = functions[callee.name]
    if len(call.arguments) != len(function.params):
        return False
    if any(parameter.by_ref for parameter in function.params):
        return False
    return all(_effect_free(argument, functions, pure) for argument in call.arguments)


def _execute_is_effect_free(
    call: Au3Call,
    functions: dict[str, Au3FunctionDeclaration],
    pure: frozenset[str],
) -> bool:
    """
    An `Execute` call over one string literal: the payload must parse, write nothing — the one
    question `execute_kills` answers — and its parse must be effect-free.
    """
    if execute_kills(call) is None:
        return False
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return False
    expression = Au3Parser(literal.value).parse_expression()
    if expression is None:
        return False
    return _effect_free(expression, functions, pure)


def _holds_exit(function: Au3FunctionDeclaration) -> bool:
    return any(isinstance(node, Au3ExitStatement) for node in ast.scope_nodes(function.body))


def _holds_only_effect_free_expressions(
    function: Au3FunctionDeclaration,
    functions: dict[str, Au3FunctionDeclaration],
    pure: frozenset[str],
) -> bool:
    for node in ast.scope_nodes(function.body):
        if isinstance(node, Expression) and not isinstance(node.parent, Expression):
            if not _effect_free(node, functions, pure):
                return False
    return True


def _build_purity(
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> frozenset[str]:
    """
    The pure functions of the script: every function whose may-write summary is empty and whose
    body holds no `Exit`, shrunk until every survivor's body also holds no expression that is
    not effect-free under the survivors themselves.
    """
    functions = scope_model.functions
    pure = {
        name
        for name, function in functions.items()
        if summaries.get(name) == frozenset()
        and not _holds_exit(function)
    }
    while True:
        survivors = {
            name
            for name in pure
            if _holds_only_effect_free_expressions(functions[name], functions, frozenset(pure))
        }
        if survivors == pure:
            return frozenset(pure)
        pure = survivors


def _collect_bindings(
    root: Au3Script,
    scope_model: Au3ScopeModel,
) -> tuple[
    dict[Au3FunctionDeclaration, frozenset[str]],
    dict[str, frozenset[Au3FunctionDeclaration | None]],
]:
    """
    The storage every variable occurrence binds, over every scope of *root*: a write through the
    scope model's write binding and a read through its read binding, the declarator variables
    themselves excluded — the declarations are what the answers are asked about. A write that
    proves nothing binds no storage: its value reaches a global only through a read somewhere,
    and that read is the occurrence that protects the name.
    """
    local: dict[Au3FunctionDeclaration, set[str]] = {}
    global_names: dict[str, set[Au3FunctionDeclaration | None]] = {}
    for scope, body in ast.scope_bodies(root):
        for node in ast.scope_nodes(body):
            if not isinstance(node, Au3Variable):
                continue
            if isinstance(node.parent, (Au3VariableDeclarator, Au3EnumDeclarator)):
                continue
            statement = ast.owning_statement(node)
            if statement is None:
                continue
            if ast.is_write_occurrence(node):
                binding = scope_model.binding(scope, statement, node.name)
            else:
                binding = scope_model.read_binding(scope, node, node.name)
            if binding is Binding.LOCAL:
                assert scope is not None
                local.setdefault(scope, set()).add(node.name)
            elif binding is Binding.GLOBAL:
                global_names.setdefault(node.name, set()).add(scope)
    return (
        {scope: frozenset(names) for scope, names in local.items()},
        {name: frozenset(scopes) for name, scopes in global_names.items()},
    )


def _collect_channels(root: Au3Script, scope_model: Au3ScopeModel) -> frozenset[Au3Call]:
    """
    Every call that may consume a computed name: a callee that is neither an identifier nor a
    member access, an `Execute` whose payload `execute_kills` refuses, and a non-literal in a
    name-parameter position of a builtin the table knows. A member callee dispatches through an
    object and reaches no script function or variable, so it is the one non-identifier callee
    that is not a channel. A call naming a script function is answered by the call-count and
    spelling facts instead.
    """
    channels: set[Au3Call] = set()
    for node in root.walk():
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is None:
            if not isinstance(ast.unwrap_parens(node.callee), Au3MemberAccess):
                channels.add(node)
            continue
        if callee.name in scope_model.functions:
            continue
        if callee.name == 'execute':
            if execute_kills(node) is None:
                channels.add(node)
            continue
        for index in NAME_PARAMETERS.get(callee.name, frozenset()):
            if index >= len(node.arguments):
                continue
            if not isinstance(ast.unwrap_parens(node.arguments[index]), Au3StringLiteral):
                channels.add(node)
                break
    return frozenset(channels)


def _collect_call_counts(root: Au3Script, scope_model: Au3ScopeModel) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for node in root.walk():
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is not None and callee.name in scope_model.functions:
            counts[callee.name] += 1
    return dict(counts)


def _collect_spellings(root: Au3Script) -> str:
    pieces = []
    for node in root.walk():
        if isinstance(node, Au3StringLiteral):
            pieces.append(node.value)
        elif isinstance(node, Au3Directive):
            pieces.append(node.text)
    return '\n'.join(pieces).lower()


def build_usage_model(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> Au3UsageModel:
    """
    Collect what *root* does with its names over the scope model's bindings and the propagation
    walk's may-write summaries.
    """
    local_bindings, global_bindings = _collect_bindings(root, scope_model)
    return Au3UsageModel(
        functions=scope_model.functions,
        call_counts=_collect_call_counts(root, scope_model),
        pure_functions=_build_purity(scope_model, summaries),
        channels=_collect_channels(root, scope_model),
        spellings=_collect_spellings(root),
        local_bindings=local_bindings,
        global_bindings=global_bindings,
    )
