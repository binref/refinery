"""
The alias map: which variables provably name one function, per scope. The indirection obfuscation
assigns a builtin or a function name to a variable and calls through it — `Local $e = Execute`,
`$b = Execute("BinaryToString")` — and the rewrite in
`refinery.lib.scripts.au3.deobfuscation` replaces such call callees with the named function.

A variable qualifies only when the whole scope agrees: it is the target of exactly one write,
and every other occurrence of it is the callee of a call. A reassignment, an argument position,
an index, a read — any of those forfeits the rewrite for that variable, because what the
variable holds past that point is no longer pinned. The gate is per scope, so two functions
holding same-named aliases never collide.

Two initializer shapes qualify: the bare builtin identifier `Execute`, and a call to the builtin
`Execute` whose single argument is a string literal naming a script function or a table builtin.
What `Execute` evaluates to as a value is never assumed — the rewrite is structural. A script
function named `Execute` shadows the builtin, so a script declaring one has no aliases at all.
"""
from __future__ import annotations

from dataclasses import dataclass

from refinery.lib.scripts import Node
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import BUILTIN_NAMES
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3Call,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3ParenExpression,
    Au3Script,
    Au3StringLiteral,
    Au3Variable,
    Au3VariableDeclarator,
    Expression,
)


@dataclass(frozen=True)
class Au3Alias:
    """
    The function one variable provably names: its lowercase name, and the spelling the
    synthesizer prints for it.
    """
    name: str
    raw: str


@dataclass(frozen=True)
class Au3AliasModel:
    """
    Per scope, the alias-qualified variables and the functions they name. Built once per tree
    version by `build_alias_model`.
    """
    scopes: dict[Au3FunctionDeclaration | None, dict[str, Au3Alias]]

    def alias(self, scope: Au3FunctionDeclaration | None, name: str) -> Au3Alias | None:
        """
        The function variable *name* provably stands for inside *scope* — a function declaration
        node, or `None` at script level — or `None` when the variable is not an alias there.
        """
        return self.scopes.get(scope, {}).get(name)


@dataclass
class _VariableUses:
    writes: int = 0
    initializer: Expression | None = None
    every_read_is_a_call: bool = True


def _written_initializer(node: Au3Variable) -> Expression | None:
    """
    The expression one write stores, when the write carries one: a declarator's initializer or an
    assignment's value. Bindings without an expression answer `None` and never shape an alias.
    """
    parent = node.parent
    if isinstance(parent, Au3VariableDeclarator):
        return parent.initializer
    if isinstance(parent, Au3Assignment):
        return parent.value
    return None


def _is_callee(node: Au3Variable) -> bool:
    cursor: Node = node
    parent = cursor.parent
    while isinstance(parent, Au3ParenExpression):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Au3Call) and parent.callee is cursor


def _aliased_function(initializer: Expression | None, functions: frozenset[str]) -> Au3Alias | None:
    expression = ast.unwrap_parens(initializer)
    if isinstance(expression, Au3Identifier):
        if expression.name == 'execute':
            return Au3Alias('execute', expression.raw)
        return None
    if not isinstance(expression, Au3Call):
        return None
    callee = ast.direct_callee(expression)
    if callee is None or callee.name != 'execute' or len(expression.arguments) != 1:
        return None
    argument = ast.unwrap_parens(expression.arguments[0])
    if not isinstance(argument, Au3StringLiteral):
        return None
    name = argument.value.lower()
    if name in functions or name in BUILTIN_NAMES:
        return Au3Alias(name, argument.value)
    return None


def build_alias_model(root: Au3Script, functions: frozenset[str]) -> Au3AliasModel:
    """
    Collect the alias-qualified variables of *root*, validating names against the script's
    function names.
    """
    if 'execute' in functions:
        return Au3AliasModel({})
    uses: dict[Au3FunctionDeclaration | None, dict[str, _VariableUses]] = {}
    for node in root.walk():
        if not isinstance(node, Au3Variable):
            continue
        scope = ast.enclosing_function(node)
        use = uses.setdefault(scope, {}).setdefault(node.name, _VariableUses())
        if ast.is_write_occurrence(node):
            use.writes += 1
            use.initializer = _written_initializer(node)
        elif not _is_callee(node):
            use.every_read_is_a_call = False
    scopes: dict[Au3FunctionDeclaration | None, dict[str, Au3Alias]] = {}
    for scope, variables in uses.items():
        aliases = {}
        for name, use in variables.items():
            if use.writes != 1 or not use.every_read_is_a_call:
                continue
            aliased = _aliased_function(use.initializer, functions)
            if aliased is not None:
                aliases[name] = aliased
        if aliases:
            scopes[scope] = aliases
    return Au3AliasModel(scopes)
