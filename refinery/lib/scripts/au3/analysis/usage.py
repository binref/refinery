"""
The usage model: what the script does with its names. The dead-code elimination in
`refinery.lib.scripts.au3.deobfuscation.eliminate` asks it what a direct call names, which names
a string or a directive spells, which calls may consume a computed name, which storage every
variable occurrence binds or may bind, how often every name is read, and which expressions are
effect-free — each fact owned by the module that pinned it: the bindings by
`refinery.lib.scripts.au3.analysis.scopes`, the may-write summaries by
`refinery.lib.scripts.au3.analysis.propagation`, the builtin knowledge by
`refinery.lib.scripts.au3.analysis.builtins`.

Source text the parser could not read — an error node in the tree — is live source AutoIt may
run when it reaches it, so the model reads it through
`refinery.lib.scripts.au3.analysis.unparsed.read_unparsed` and counts every name it spells as a
reference: a call, a binding that may fall either side, a spelling, a read. Text that opens a
call on a computed callee or names the builtin `Call` makes any callee possible — the text
cannot show the literalness of `Call`'s argument, and whether a name it spells shadows a
builtin is unpinned — an `Execute` it spells joins the names the census counts, and the
error-state macros it spells count as reads. The model holds the facts of every error node
keyed by its node and the variables of every error node, for the transforms that ask them. The
parser's record list is not an input: it outlives the edits that remove the nodes it names, so
a model over it would keep refusing a tree its own transforms had cleaned.

Whether a call may read a name no census sees is the question beside the write-side channel one,
and the same walk answers both. A computed callee reads — it could name `Eval`; so does an
`Execute` whose payload the tree does not show as one literal expression, and a non-literal in a
name-parameter position of a builtin the table knows: a literal there reaches a name only through
a string the spelling corpus holds, which is what the spelling answer refuses a removal over. A
literal `Execute` payload is parsed and its expression judged by the same shapes, recursed to a
bounded depth; a payload that fails to parse may still be one AutoIt runs, so it reads — the
empty payload AutoIt answers `""` for (probe3) reads nothing — and past the depth bound the
payload is not parsed and reads. A `Call` invocation over a string literal resolves through
`refinery.lib.scripts.au3.analysis.existence.call_target`, and the target is judged as if the tree
called it directly; every refusal reads, because unread text cannot resolve what a name shadows.
A script function's reads stand in the tree, and a member callee dispatches through an object
and reads no script name. The reads of a name are counted per storage through
`refinery.lib.scripts.au3.analysis.scopes.Au3ScopeModel.read_storages`: an occurrence reads when
it is not a write occurrence or reads what it writes, and every storage it may reach — one
function's local, or the global — counts it, a variable of unread text counting into both facts
of its node's scope. Both counts are may-answers: a read whose claim shares its statement counts
into the local and the global alike.

An expression is effect-free when evaluating it writes nothing observable and cannot terminate
the script. Termination is what the arithmetic refuses: a division by zero ends the script
(pinned by the probe corpus), an out-of-range subscript ends it the same way, and a wrong-arity
call as well, so `/`, `^`, and array access are refused. A call is effect-free only over a pure
script function of matching parameter count that declares no `ByRef` parameter, its arguments
effect-free with it; no builtin call is, because a builtin's value-dependent fatals are
unpinned and the builtin name universe phase owns the table that would change that. A function
is pure when its may-write summary is empty, its body holds no `Exit` and no `Static` — a
static's value survives the call that first initializes it, so which call runs first is
observable — and every expression in it is effect-free where a call inside the body names a
pure function that cannot reach itself through the survivors' calls — the fixpoint of that
rule. Entering a function clears `@error` and `@extended` (probe9 A17/A17b), so a script that
may read the error state holds no pure function at all: every call into one writes what the
script observes. A recursion cycle may never return — AutoIt ends the script at its recursion
limit — so a call into one is not an effect-free evaluation and no member of a cycle is pure.
"""
from __future__ import annotations

import itertools

from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field

from refinery.lib.scripts import Node
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import NAME_PARAMETERS
from refinery.lib.scripts.au3.analysis.existence import call_target, execute_kills, parse_payload
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding, INCLUDE_SPELLING
from refinery.lib.scripts.au3.analysis.unparsed import Au3UnparsedText, read_unparsed
from refinery.lib.scripts.au3.model import (
    Au3ArrayLiteral,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3DefaultLiteral,
    Au3Directive,
    Au3EnumDeclarator,
    Au3ErrorNode,
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
    Au3VariableDeclaration,
    Au3VariableDeclarator,
    Expression,
)

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
    `build_usage_model`: the script's functions, the direct-identifier call count of each, how
    often each storage is read — one function's local, or the global per scope, the variables of
    unread text among its readers — the functions that are pure, the calls and error nodes that
    may consume a computed name, the calls and error nodes that may read one that no census
    sees, the lowercased text of every string literal and directive, parsed or unread, the
    local storage an occurrence in a scope may bind, per scope, and the storage every occurrence
    provably binds globally, per name, the script level among the readers as `None`. The facts
    of every error node are held keyed by their node, and the variables of every error node
    answer the transforms that ask which names unread text may reference.
    """

    functions: dict[str, Au3FunctionDeclaration]
    call_counts: dict[str, int]
    local_read_counts: dict[Au3FunctionDeclaration, dict[str, int]]
    global_read_counts: dict[Au3FunctionDeclaration | None, dict[str, int]]
    pure_functions: frozenset[str]
    channels: frozenset[Au3Call | Au3ErrorNode]
    reading_channels: frozenset[Au3Call | Au3ErrorNode]
    spellings: str
    local_bindings: dict[Au3FunctionDeclaration, frozenset[str]]
    global_bindings: dict[str, frozenset[Au3FunctionDeclaration | None]]
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText]
    unparsed_variables: frozenset[str]
    _spelled: dict[str, bool] = field(default_factory=dict, compare=False, repr=False)

    def spells(self, name: str) -> bool:
        """
        Whether *name* — a function name, or a variable name without its `$` — is a substring of
        any string literal or directive the tree holds, parsed or unread: a computed name has to
        be built from string data, so a name some string spells is one no removal may take away.
        The answer is memoized per name — the scan is linear in the corpus — and the model is
        rebuilt per tree version, so a memo never outlives the facts it answered from.
        """
        answer = self._spelled.get(name)
        if answer is None:
            answer = name.lstrip('$') in self.spellings
            self._spelled[name] = answer
        return answer

    def holds_block_keyword_text(self, root: Node) -> bool:
        """
        Whether *root*'s subtree holds error text the reader marks with an AutoIt block keyword:
        deleting it could move where the real parser's block boundaries fall, and with them which
        code is live at all.
        """
        return any(
            self.unparsed[node].block_keyword
            for node in root.walk()
            if isinstance(node, Au3ErrorNode)
        )

    def holds_unread_include(self) -> bool:
        """
        Whether unread source text holds an include directive: the file it names is outside every
        fact the tree holds, and may call anything a removal would take away.
        """
        return any(
            INCLUDE_SPELLING.match(directive)
            for facts in self.unparsed.values()
            for directive in facts.directives
        )

    def effect_free(self, expression: Expression | None) -> bool:
        """
        Whether evaluating *expression* writes nothing observable and cannot terminate the
        script.
        """
        return _effect_free(expression, self.functions, self.pure_functions)


#: The interpreter's error-state macros: entering a user function clears both, so a read of
#: either observes what every call wrote.
ERROR_MACROS = frozenset({'error', 'extended'})


@dataclass(frozen=True)
class Au3CalleeCensus:
    """
    What the calls of one tree name, gathered once for every question that asks it: the names a
    direct identifier or a `Call` invocation over a string literal spells, whether any callee is
    computed at run time — a value the tree does not show, which could name anything — and
    whether the tree reads the interpreter's `@error` or `@extended`.
    """
    callees: frozenset[str]
    computed_callee: bool
    reads_error_macros: bool

    def observes_error_state(self) -> bool:
        """
        Whether the script may read the interpreter's `@error` and `@extended` at run time: a
        read of either macro anywhere, or a call to `Execute` by any spelling the census sees —
        whose payload text is a reader no walk reads.
        """
        return (
            self.reads_error_macros
            or self.computed_callee
            or 'execute' in self.callees
        )


def callee_census(
    root: Au3Script,
    functions: Mapping[str, Au3FunctionDeclaration],
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> Au3CalleeCensus:
    """
    Count what the calls of *root* name. A member callee is the one exception to every reader: it
    dispatches through an object and reaches no builtin and no script function. A script function
    named `Call` shadows the builtin, so its first argument is an ordinary argument rather than a
    name; otherwise a `Call` names the callee `call_target` resolves its string literal to, and
    one whose name is no literal or whose resolution refuses makes any callee possible. Source
    text the parser could not read is read through the facts *unparsed* holds: a
    computed callee it opens, or a `Call` it spells — whose argument's literalness the text cannot
    show — makes any callee possible, an `Execute` it spells joins the names, and the error-state
    macros it spells count as reads.
    """
    callees: set[str] = set()
    computed_callee = False
    reads_error_macros = False
    function_names = frozenset(functions)
    for node in root.walk():
        if isinstance(node, Au3Macro):
            reads_error_macros = reads_error_macros or node.name in ERROR_MACROS
        elif isinstance(node, Au3Call):
            callee = ast.direct_callee(node)
            if callee is not None:
                callees.add(callee.name)
                if callee.name == 'call' and callee.name not in functions:
                    literal = (
                        ast.unwrap_parens(node.arguments[0])
                        if node.arguments else None
                    )
                    target = (
                        call_target(literal.value, node.arguments[1:], function_names)
                        if isinstance(literal, Au3StringLiteral) else None
                    )
                    if target is None:
                        computed_callee = True
                    else:
                        callees.add(target)
            elif not isinstance(ast.unwrap_parens(node.callee), Au3MemberAccess):
                computed_callee = True
    for facts in unparsed.values():
        computed_callee = (
            computed_callee
            or facts.computed_callee
            or 'call' in facts.identifiers
        )
        reads_error_macros = (
            reads_error_macros
            or not ERROR_MACROS.isdisjoint(facts.macros)
        )
        if 'execute' in facts.identifiers:
            callees.add('execute')
    return Au3CalleeCensus(frozenset(callees), computed_callee, reads_error_macros)


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
    expression = parse_payload(literal.value)
    if expression is None:
        return False
    return _effect_free(expression, functions, pure)


def _holds_exit(function: Au3FunctionDeclaration) -> bool:
    return any(isinstance(node, Au3ExitStatement) for node in ast.scope_nodes(function.body))


def _holds_static(function: Au3FunctionDeclaration) -> bool:
    return any(
        isinstance(node, Au3VariableDeclaration) and node.is_static
        for node in ast.scope_nodes(function.body)
    )


def _called_names(function: Au3FunctionDeclaration) -> set[str]:
    """
    The names the calls directly in *function*'s body name — a nested function's body is a scope
    of its own and its calls are not this function's.
    """
    names: set[str] = set()
    for node in ast.scope_nodes(function.body):
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is not None:
            names.add(callee.name)
    return names


def _cyclic_within(
    pure: set[str],
    functions: dict[str, Au3FunctionDeclaration],
) -> set[str]:
    """
    The functions of *pure* that can reach themselves through calls into *pure*: a call into one
    of them may never return — AutoIt ends the script at its recursion limit — so no evaluation
    of such a call is effect-free.
    """
    graph = {name: _called_names(functions[name]) & pure for name in pure}
    cyclic: set[str] = set()
    for name in pure:
        reachable: set[str] = set()
        pending = list(graph[name])
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending.extend(graph[current])
        if name in reachable:
            cyclic.add(name)
    return cyclic


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
    root: Au3Script,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> frozenset[str]:
    """
    The pure functions of the script: every function whose may-write summary is empty, whose body
    holds no `Exit` and no `Static` — a static's value survives the call that first initializes
    it, so which call runs first is observable — shrunk until every survivor's body also holds no
    expression that is not effect-free under the survivors themselves and no survivor can reach
    itself through the survivors' calls, which casts its callers out with it: a recursion cycle
    may never return, and AutoIt ends the script at its recursion limit.

    Entering a function clears `@error` and `@extended` (probe9 A17/A17b), so a script that may
    read the error state holds no pure function at all: every call into one writes what the
    script observes.
    """
    if callee_census(root, scope_model.functions, unparsed).observes_error_state():
        return frozenset()
    functions = scope_model.functions
    pure = {
        name
        for name, function in functions.items()
        if summaries.get(name) == frozenset()
        and not _holds_exit(function)
        and not _holds_static(function)
    }
    while True:
        survivors = {
            name
            for name in pure
            if _holds_only_effect_free_expressions(functions[name], functions, frozenset(pure))
            and name not in _cyclic_within(pure, functions)
        }
        if survivors == pure:
            return frozenset(pure)
        pure = survivors


@dataclass(frozen=True)
class Au3StorageCensus:
    """
    The storage every variable occurrence binds or may bind, and how often each storage is read:
    the names a function's occurrences may bind locally, the scopes every name provably binds
    globally in, the reads that may reach one function's local, and the reads standing in each
    scope that may reach the global — script level keyed under `None`. Both read counts are
    may-answers: a read that may reach either storage counts into both.
    """
    local_bindings: dict[Au3FunctionDeclaration, frozenset[str]]
    global_bindings: dict[str, frozenset[Au3FunctionDeclaration | None]]
    local_read_counts: dict[Au3FunctionDeclaration, dict[str, int]]
    global_read_counts: dict[Au3FunctionDeclaration | None, dict[str, int]]


def _collect_bindings(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> Au3StorageCensus:
    """
    The storage every variable occurrence binds or may bind, over every scope of *root*, and how
    often each storage is read: a write through the scope model's write binding and a read
    through its read binding, an occurrence that may reach a local of its scope through
    `may_bind_local`, and the variables of a function's parameter defaults among the occurrences
    — a default evaluates in the function when a call leaves its argument out. The declared
    variable of a declarator is excluded — the declaration is what the answers are asked about
    — while a bare-variable initializer reads like any other occurrence: it is not the
    declarator's own variable. A write that proves nothing binds no storage: its value reaches a
    global only through a read somewhere, and that read is the occurrence that protects the
    name. A read counts once per storage it may reach, through `read_storages`; a variable of
    unread text counts into both facts of its node's scope — unread text may bind either side,
    and a script-level error node has no local.
    """
    local: dict[Au3FunctionDeclaration, set[str]] = {}
    global_names: dict[str, set[Au3FunctionDeclaration | None]] = {}
    local_reads: dict[Au3FunctionDeclaration, dict[str, int]] = {}
    global_reads: dict[Au3FunctionDeclaration | None, dict[str, int]] = {}
    for scope, body in ast.scope_bodies(root):
        occurrences: Iterator[Node] = ast.scope_nodes(body)
        if scope is not None:
            occurrences = itertools.chain(occurrences, *(
                parameter.default.walk()
                for parameter in scope.params
                if parameter.default is not None
            ))
        for node in occurrences:
            if not isinstance(node, Au3Variable):
                continue
            parent = node.parent
            if (
                isinstance(parent, (Au3VariableDeclarator, Au3EnumDeclarator))
                and parent.variable is node
            ):
                continue
            statement = ast.owning_statement(node)
            if statement is None:
                continue
            if not ast.is_write_occurrence(node) or ast.reads_what_it_writes(node):
                for storage in scope_model.read_storages(scope, node, node.name):
                    if storage is Binding.GLOBAL:
                        counts = global_reads.setdefault(scope, {})
                    else:
                        assert scope is not None
                        counts = local_reads.setdefault(scope, {})
                    counts[node.name] = counts.get(node.name, 0) + 1
            if ast.is_write_occurrence(node):
                binding = scope_model.binding(scope, statement, node.name)
            else:
                binding = scope_model.read_binding(scope, node, node.name)
            if binding is Binding.GLOBAL:
                global_names.setdefault(node.name, set()).add(scope)
            if (
                binding is Binding.LOCAL
                or scope_model.may_bind_local(scope, node, node.name)
            ):
                assert scope is not None
                local.setdefault(scope, set()).add(node.name)
    for node, facts in unparsed.items():
        scope = ast.enclosing_function(node)
        for name in facts.variables:
            counts = global_reads.setdefault(scope, {})
            counts[name] = counts.get(name, 0) + 1
            if scope is not None:
                counts = local_reads.setdefault(scope, {})
                counts[name] = counts.get(name, 0) + 1
                local.setdefault(scope, set()).add(name)
            global_names.setdefault(name, set()).add(scope)
    return Au3StorageCensus(
        {scope: frozenset(names) for scope, names in local.items()},
        {name: frozenset(scopes) for name, scopes in global_names.items()},
        local_reads,
        global_reads,
    )


#: The depth a literal `Execute` payload's read verdict recurses to: each level is one payload
#: parse, and past the bound the payload is not parsed and counts as reading. Literal payloads
#: are short and rare once the constant fold has run.
_PAYLOAD_READ_DEPTH = 8


def _name_parameter_is_computed(name: str, arguments: Sequence[Expression]) -> bool:
    """
    Whether a call to *name* holds a non-literal in a name-parameter position the builtin table
    knows: a value the tree does not show reaches a name through it.
    """
    for index in NAME_PARAMETERS.get(name, frozenset()):
        if index >= len(arguments):
            continue
        if not isinstance(ast.unwrap_parens(arguments[index]), Au3StringLiteral):
            return True
    return False


def _collect_channels(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> tuple[frozenset[Au3Call | Au3ErrorNode], frozenset[Au3Call | Au3ErrorNode]]:
    """
    Every call and error node that may consume a computed name, and every call and error node
    that may read one that no census sees — the write-side question and the read-side one,
    answered by the same walk. A write channel: a callee that is neither an identifier nor a
    member access, an `Execute` whose payload `execute_kills` refuses, and a non-literal in a
    name-parameter position of a builtin the table knows. A read channel: the shapes
    `_named_callee_reads` names. A member callee dispatches through an object and reaches no
    script function or variable, so it is the one non-identifier callee that is neither. A call
    naming a script function is answered by the call-count and spelling facts instead. An error
    node joins both under one rule: its text opens a call on a computed callee or spells
    `Execute` or a name-parameter builtin — whether a name it spells shadows the builtin is
    unresolvable in unread text, so a name it spells always counts.
    """
    channels: set[Au3Call | Au3ErrorNode] = set()
    reading: set[Au3Call | Au3ErrorNode] = set()
    for node in root.walk():
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is None:
            if not isinstance(ast.unwrap_parens(node.callee), Au3MemberAccess):
                channels.add(node)
                reading.add(node)
            continue
        if callee.name in scope_model.functions:
            continue
        if _named_callee_reads(callee.name, node.arguments, scope_model, _PAYLOAD_READ_DEPTH):
            reading.add(node)
        if callee.name == 'execute':
            if execute_kills(node) is None:
                channels.add(node)
            continue
        if _name_parameter_is_computed(callee.name, node.arguments):
            channels.add(node)
    for node, facts in unparsed.items():
        if (
            facts.computed_callee
            or 'execute' in facts.identifiers
            or not NAME_PARAMETERS.keys().isdisjoint(facts.identifiers)
        ):
            channels.add(node)
            reading.add(node)
    return frozenset(channels), frozenset(reading)


def _named_callee_reads(
    name: str,
    arguments: Sequence[Expression],
    scope_model: Au3ScopeModel,
    depth: int,
) -> bool:
    """
    Whether a call to *name* over *arguments* — as the tree spells it, or as a `Call` invocation
    over a string literal resolves it — may read a name no census sees: a computed callee could
    name `Eval`, an `Execute` whose payload is not one literal expression can execute arbitrary
    code, and a non-literal in a name-parameter position reaches a name through a value the tree
    does not show. A script function's reads stand in the tree, and a member callee is answered
    by the caller. Every resolution refusal reads: unread text cannot resolve what a name
    shadows.
    """
    if name in scope_model.functions:
        return False
    if name == 'execute':
        return _execute_reads(arguments, scope_model, depth)
    if name == 'call':
        literal = ast.unwrap_parens(arguments[0]) if arguments else None
        if not isinstance(literal, Au3StringLiteral):
            return True
        target = call_target(literal.value, arguments[1:], scope_model.function_names)
        return target is None or _named_callee_reads(target, arguments[1:], scope_model, depth)
    return _name_parameter_is_computed(name, arguments)


def _execute_reads(
    arguments: Sequence[Expression],
    scope_model: Au3ScopeModel,
    depth: int,
) -> bool:
    """
    Whether an `Execute` over *arguments* may read a name no census sees: a payload the tree does
    not show as one literal expression can execute arbitrary code, and a literal one reads only
    what its parsed expression holds of the shapes `_named_callee_reads` names, judged one depth
    level down. A payload that fails to parse may still be one AutoIt runs, so it reads; the
    empty payload AutoIt answers `""` for (probe3) reads nothing.
    """
    if depth <= 0 or len(arguments) != 1:
        return True
    literal = ast.unwrap_parens(arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return True
    if not literal.value.strip():
        return False
    expression = parse_payload(literal.value)
    if expression is None:
        return True
    for node in expression.walk():
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is None:
            if not isinstance(ast.unwrap_parens(node.callee), Au3MemberAccess):
                return True
        elif _named_callee_reads(callee.name, node.arguments, scope_model, depth - 1):
            return True
    return False


def _collect_call_counts(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for node in root.walk():
        if not isinstance(node, Au3Call):
            continue
        callee = ast.direct_callee(node)
        if callee is not None and callee.name in scope_model.functions:
            counts[callee.name] += 1
    for facts in unparsed.values():
        for identifier in facts.identifiers:
            if identifier in scope_model.functions:
                counts[identifier] += 1
    return dict(counts)


def _collect_spellings(
    root: Au3Script,
    unparsed: Mapping[Au3ErrorNode, Au3UnparsedText],
) -> str:
    pieces = []
    for node in root.walk():
        if isinstance(node, Au3StringLiteral):
            pieces.append(node.value)
        elif isinstance(node, Au3Directive):
            pieces.append(node.text)
    for facts in unparsed.values():
        pieces.extend(facts.strings)
        pieces.extend(facts.directives)
    return '\n'.join(pieces).lower()


def _collect_unparsed(scope_model: Au3ScopeModel) -> dict[Au3ErrorNode, Au3UnparsedText]:
    """
    The facts of every error node the scope model holds, keyed by the node.
    """
    return {node: read_unparsed(node.text) for node in scope_model.error_nodes}


def build_usage_model(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    summaries: dict[str, frozenset[str] | None],
) -> Au3UsageModel:
    """
    Collect what *root* does with its names over the scope model's bindings and the propagation
    walk's may-write summaries.
    """
    unparsed = _collect_unparsed(scope_model)
    unparsed_variables = {
        name
        for facts in unparsed.values()
        for name in facts.variables
    }
    census = _collect_bindings(root, scope_model, unparsed)
    channels, reading_channels = _collect_channels(root, scope_model, unparsed)
    return Au3UsageModel(
        functions=scope_model.functions,
        call_counts=_collect_call_counts(root, scope_model, unparsed),
        local_read_counts=census.local_read_counts,
        global_read_counts=census.global_read_counts,
        pure_functions=_build_purity(root, scope_model, summaries, unparsed),
        channels=channels,
        reading_channels=reading_channels,
        spellings=_collect_spellings(root, unparsed),
        local_bindings=census.local_bindings,
        global_bindings=census.global_bindings,
        unparsed=unparsed,
        unparsed_variables=frozenset(unparsed_variables),
    )
