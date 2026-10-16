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

A write that leaves no occurrence in the tree forfeits the same way. `Assign` names a variable at
run time and `Execute` runs one expression of code, so a call to either costs the alias the name
it may rebind — an `Assign` with a constant first argument costs that name alone, one of any
other shape costs every alias whose write may target a global, and an `Execute` over a string
literal that parses to code holding a call costs the same. A call to a script function costs the
alias what that function's may-write summary says, which `Assign` and `Execute` feed; a name the
script and the builtin table do not know, or a summary of "may write any", costs every alias
whose write may target a global — but never a provably local one, which no other function can
reach. Two shapes cost nothing: a call through a variable, and an `Execute` over anything but a
string literal — the payload of either is a value this module cannot read, and forfeiting on
either would freeze the chain of rewrites that resolve the indirection at its links, where the
decoder's payload still sits behind an alias call.

Two initializer shapes qualify: the bare builtin identifier `Execute`, and a call to the builtin
`Execute` whose single argument is a string literal naming a script function or a table builtin.
What `Execute` evaluates to as a value is never assumed — the rewrite is structural. A script
function named `Execute` shadows the builtin, so a script declaring one has no aliases at all,
and neither has a script with an include or a parse error, either of which may hide such a
declaration from every walk of the tree. The rewrite prints the spelling the argument holds,
which resolves exactly as a direct call of that spelling does; the official spelling of a
builtin is the case normalization's to print.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import call_is_bounded
from refinery.lib.scripts.au3.analysis.existence import assign_kills, execute_kills
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.functions import AUTOIT_FUNCTION_NAMES
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3Call,
    Au3FunctionDeclaration,
    Au3Identifier,
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
    binding: Binding = Binding.NONE


@dataclass
class _RebindThreats:
    """
    What a rebinding write may cost an alias: the names no scope may keep, the names no
    global-backed alias may keep, whether any global-backed alias survives at all, and the
    scopes where not even a provably local one does.
    """
    names: set[str] = field(default_factory=set)
    global_names: set[str] = field(default_factory=set)
    no_global_aliases: bool = False
    forfeited_scopes: set[Au3FunctionDeclaration | None] = field(default_factory=set)


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
    """
    Whether the variable occurrence stands in the callee position of a call, through any number
    of parentheses.
    """
    return ast.in_callee_position(node)


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
    if name not in functions and name not in AUTOIT_FUNCTION_NAMES:
        return None
    return Au3Alias(name, argument.value)


def _pinned_execute(call: Au3Call) -> bool:
    """
    Whether an `Execute` call takes one string literal — the only argument shape whose executed
    code `execute_kills` can read. Anything else the call takes is a blind spot this module
    documents, not a threat it forfeits on.
    """
    if len(call.arguments) != 1:
        return False
    return isinstance(ast.unwrap_parens(call.arguments[0]), Au3StringLiteral)


def _scan_rebinds(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> _RebindThreats:
    """
    Every way a call may rebind an alias without a write occurrence in the tree, collected over
    all of *root*'s scopes: an `Assign` or a code-running `Execute` standing lexically inside a
    scope threatens that scope's locals, and everything the calls of the whole script may write
    threatens the globals — a `Call` and a registration builtin included, because the script
    function one of them runs may rebind any global (`call_is_bounded`).
    """
    threats = _RebindThreats()
    for scope, body in ast.scope_bodies(root):
        for node in ast.scope_nodes(body):
            if not isinstance(node, Au3Call):
                continue
            callee = ast.direct_callee(node)
            if callee is None:
                continue
            if callee.name in scope_model.functions:
                summary = summaries.get(callee.name)
                if summary is None:
                    threats.no_global_aliases = True
                else:
                    threats.global_names |= summary
                continue
            if callee.name == 'execute':
                if _pinned_execute(node) and execute_kills(node) is None:
                    threats.no_global_aliases = True
                    threats.forfeited_scopes.add(scope)
                continue
            if callee.name == 'assign':
                names = assign_kills(node)
                if names is None:
                    threats.no_global_aliases = True
                    threats.forfeited_scopes.add(scope)
                else:
                    threats.names |= names
                continue
            if not call_is_bounded(callee.name):
                threats.no_global_aliases = True
    return threats


def _threatened(
    threats: _RebindThreats,
    scope: Au3FunctionDeclaration | None,
    name: str,
    binding: Binding,
) -> bool:
    """
    Whether a rebinding write may have reached the variable *name* stands for in *scope*: a
    provably local binding only inside its own scope, every other binding everywhere a global
    write can.
    """
    if name in threats.names or scope in threats.forfeited_scopes:
        return True
    if binding is Binding.LOCAL:
        return False
    return threats.no_global_aliases or name in threats.global_names


def _record_use(
    node: Au3Variable,
    scope: Au3FunctionDeclaration | None,
    scope_model: Au3ScopeModel,
    uses: dict[Au3FunctionDeclaration | None, dict[str, _VariableUses]],
) -> None:
    use = uses.setdefault(scope, {}).setdefault(node.name, _VariableUses())
    if ast.is_write_occurrence(node):
        use.writes += 1
        use.initializer = _written_initializer(node)
        statement = ast.owning_statement(node)
        if statement is not None:
            use.binding = scope_model.binding(scope, statement, node.name)
    elif not _is_callee(node):
        use.every_read_is_a_call = False


def build_alias_model(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> Au3AliasModel:
    """
    Collect the alias-qualified variables of *root*, validating names against the script's
    function names and cutting every name a rebinding write may cost.
    """
    if (
        'execute' in scope_model.functions
        or scope_model.holds_an_include
        or scope_model.holds_a_parse_error
    ):
        return Au3AliasModel({})
    threats = _scan_rebinds(root, scope_model, summaries)
    uses: dict[Au3FunctionDeclaration | None, dict[str, _VariableUses]] = {}
    for scope, body in ast.scope_bodies(root):
        if scope is not None:
            for parameter in scope.params:
                if parameter.variable is not None:
                    _record_use(parameter.variable, scope, scope_model, uses)
        for node in ast.scope_nodes(body):
            if isinstance(node, Au3Variable):
                _record_use(node, scope, scope_model, uses)
    functions = scope_model.function_names
    scopes: dict[Au3FunctionDeclaration | None, dict[str, Au3Alias]] = {}
    for scope, variables in uses.items():
        aliases = {}
        for name, use in variables.items():
            if use.writes != 1 or not use.every_read_is_a_call:
                continue
            if _threatened(threats, scope, name, use.binding):
                continue
            aliased = _aliased_function(use.initializer, functions)
            if aliased is not None:
                aliases[name] = aliased
        if aliases:
            scopes[scope] = aliases
    return Au3AliasModel(scopes)
