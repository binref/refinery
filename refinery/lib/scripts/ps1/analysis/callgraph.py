"""
The call graph of one PowerShell script: which function definitions a command name denotes, which
invocations reach that name, and whether the two together are the whole story.

Two questions are asked of it, and they fail in opposite directions, which is why one walk answers
both. *Reachability* decides whether a definition may be deleted, so a call site the walk misses
deletes live code. *Output flow* — `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow` —
decides whether a bare value inside a body may be deleted, so a call site the walk misses deletes a
payload. The reachability expansion this replaced descended only into bodies it had already proven
reachable: sound for its own question, and a deletion licence for the other, because a call site
sitting inside an unreached function was never read at all.

The graph is structure and nothing more. It says who can call what; what a call *does* with the
value it produces is the effect layer's question, asked through here rather than answered here.
"""
from __future__ import annotations

from typing import Mapping, NamedTuple, Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.types import TypeOracle
from refinery.lib.scripts.ps1.ast import (
    assignment_target_variables,
    get_command_name,
    implicit_get_retry,
    is_opaque_dispatch,
    normalize_command_name,
    resolve_command_name,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1CommandInvocation,
    Ps1FunctionDefinition,
    Ps1MethodMember,
    Ps1ScopeModifier,
    Ps1Script,
)

#: The variable namespaces that name a command rather than a value. Kept in step with
#: `refinery.lib.scripts.ps1.analysis.world._IDENTITY_SCOPES`, which this module cannot reuse
#: because the world reports one verdict for the whole script and this one needs the single node.
_IDENTITY_SCOPES = frozenset({
    Ps1ScopeModifier.ALIAS,
    Ps1ScopeModifier.FUNCTION,
})

#: Commands that hand a name to code outside this file. A `.psm1` exporting a function has call
#: sites in whatever imported it, and no walk over this tree can see them. Read through
#: `refinery.lib.scripts.ps1.ast.resolve_command_name`, which is the deny-list reading of a name:
#: a hit here withholds every name-keyed removal, so a spelling that dodges the table is the
#: dangerous direction. That closes a module qualifier written after the call operator, quoted or
#: not — `& Microsoft.PowerShell.Core\Export-ModuleMember` arrives as one token either way. Written
#: as a bare command statement the lexer splits the name at the backslash and the table is dodged;
#: see `refinery.lib.scripts.ps1.ast.resolve_command_name` for why that hole is the lexer's.
_EXPORTING_COMMANDS = frozenset({
    'export-modulemember',
})


def binds_command_identity(node: Node) -> bool:
    """
    Whether `node` writes the `function:` or `alias:` namespace, binding a command name to something
    the definition scan does not read as a definition and the call scan does not read as a call.
    Every name-keyed decision has to treat such a node as an unknown: it can bind the name about to
    be deleted, and it can be the only thing that reaches it.
    """
    if not isinstance(node, Ps1AssignmentExpression):
        return False
    return any(
        variable.scope in _IDENTITY_SCOPES
        for variable in assignment_target_variables(node.target)
    )


def _is_class_method(definition: Ps1FunctionDefinition) -> bool:
    """
    Whether a function definition is the body of a class method rather than a command. A method is
    reached through `$object.Method()` and never through its bare name, so it is neither a
    definition a call site can name nor a definition this graph can find the callers of.
    """
    return isinstance(definition.parent, Ps1MethodMember)


def _enclosing_function(node: Node) -> str | None:
    """
    The key of the **outermost** function definition whose body holds `node`, or `None` when `node`
    runs as part of the script itself.

    Outermost rather than innermost, because the only reader is `Ps1CallGraph.reachable_names` and a
    nested definition is never called by name. `function Outer { function Inner { Payload } }`
    credits the call to `Outer`: reading it as `Inner`'s leaves `Payload` reached by nothing, so it
    is deleted while `Inner` — which no pass removes, since only a top-level definition is
    removable — stands there calling a name the emitted script no longer defines. Attribution to the
    enclosing scope is what makes the two answers agree.

    A class method anywhere on the way out answers `None` and stops the walk, which is the
    conservative direction. A method body runs whenever something constructs or calls into the
    class, and this graph cannot see that happen; treating its calls as unconditional keeps every
    name they reach reachable, and `Ps1OutputFlow` separately refuses to ground a method body
    because no call site ever names it. Carrying on to the enclosing function instead would make
    those calls conditional on a name that reaches the *class*, which nothing here can prove.
    """
    found: str | None = None
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, Ps1FunctionDefinition):
            if _is_class_method(cursor):
                return None
            found = normalize_command_name(cursor.name)
        cursor = cursor.parent
    return found


class Ps1CallSite(NamedTuple):
    """
    One invocation of a command name, paired with the key of the outermost function whose body holds
    it — see `_enclosing_function` — which is the edge's source, where the invocation is its target.
    """
    invocation: Ps1CommandInvocation
    caller: str | None


class Ps1CallGraph:
    """
    The verdict of `build_call_graph`. Definitions and call sites are keyed through
    `refinery.lib.scripts.ps1.ast.normalize_command_name`, so `function global:F` and a bare call to
    `F` meet on one key, and every definition sharing a key is kept: a redefinition shadows the
    earlier body only from the point it runs, which is order and scope information no walk over the
    tree carries.
    """

    def __init__(
        self,
        definitions: Mapping[str, Sequence[Ps1FunctionDefinition]],
        call_sites: Mapping[str, Sequence[Ps1CallSite]],
        readable: bool,
        exports: bool,
    ):
        self._definitions = dict(definitions)
        self._call_sites = dict(call_sites)
        self._readable = readable
        self._exports = exports

    @property
    def is_readable(self) -> bool:
        """
        Whether this tree is the whole story about what a command name denotes and who reaches it.
        Five independent things say it is not, and every one of them has to be asked, because none
        implies another:

        - the type world is open, so a dot-sourced file, an imported module or an `iex` holds
          definitions and call sites the walk never read;
        - an invocation dispatches opaquely (`& $f`), so a name is reached without being written;
        - an assignment binds the `function:` or `alias:` namespace, which defines a command under a
          spelling the definition scan does not read — and leaves the world closed while doing it,
          since `${function:j} = { }` remaps nothing in the type system;
        - the script calls `Export-ModuleMember`, which hands a name to a caller outside the file;
        - a call written under a qualifier resolves onto a name this script defines; see
          `_collides_with_a_definition`.

        Every consumer reads this as fail-closed: an unreadable graph keeps more, never less.

        The `Export-ModuleMember` row catches the explicit export and not the general case. A
        `.psm1` with no export statement exports every function by default, and nothing in a file
        says it is a module — the assumption the bare-output default rests on, stated where a
        caller can see it in `refinery.units.scripting.ps1`.
        """
        return self._readable

    @property
    def exports_a_name(self) -> bool:
        """
        Whether this script hands a command name to code outside the file, which is one of the four
        things `is_readable` reads and the only one that says a *definition* has a reader elsewhere.

        The distinction is worth the separate name because the two questions have different answers
        for the same script. An `Invoke-Expression` opens the type world and could in principle call
        anything, and every pass here has long accepted that risk in exchange for resolving the
        trampolines obfuscators are built out of. An export is not a risk taken for anything: the
        script says in as many words that a caller it cannot see will call this name, so a pass that
        deletes the definition deletes a reachable entry point.
        """
        return self._exports

    def definitions(self, name: str) -> Sequence[Ps1FunctionDefinition]:
        """
        Every function definition a call to `name` could reach, in source order.
        """
        return self._definitions.get(normalize_command_name(name), ())

    def call_sites(self, name: str) -> Sequence[Ps1CallSite]:
        """
        Every invocation of `name` standing in this tree, in source order, wherever it sits. This
        is what separates the graph from the reachability query below, which reads only the edges it
        can reach from the script itself.
        """
        return self._call_sites.get(normalize_command_name(name), ())

    @property
    def defined_names(self) -> Sequence[str]:
        """
        Every key this script defines a function under, in source order of the first definition.
        """
        return tuple(self._definitions)

    def reachable_names(self) -> frozenset[str]:
        """
        Every command name some path from the script itself can reach: the names called outside any
        function, then the names those functions call, to a fixpoint. A function whose key is absent
        is called from nowhere in this tree.

        An unreadable graph answers with every name it saw, defined or called, since a name reached
        from outside is reached by a path this cannot trace.
        """
        if not self._readable:
            return frozenset(self._definitions) | frozenset(self._call_sites)
        calls_from: dict[str | None, set[str]] = {}
        for name, sites in self._call_sites.items():
            for site in sites:
                calls_from.setdefault(site.caller, set()).add(name)
        reachable = set(calls_from.get(None, ()))
        frontier = [name for name in reachable if name in self._definitions]
        while frontier:
            for name in calls_from.get(frontier.pop(), ()):
                if name in reachable:
                    continue
                reachable.add(name)
                if name in self._definitions:
                    frontier.append(name)
        return frozenset(reachable)


def _collides_with_a_definition(
    resolved: Sequence[str],
    definitions: Mapping[str, Sequence[Ps1FunctionDefinition]],
) -> bool:
    """
    Whether some call keyed under a qualifier resolves onto a name this script defines.

    `& 'MyModule\\Qzmr'` keys as `mymodule\\qzmr` while `function Qzmr` keys as `qzmr`, so nothing
    matches, the definition reads as uncalled, and deleting it leaves a script calling a name it no
    longer defines. `resolved` holds every name a call may run that its written key does not spell,
    which is the deny-list reading `refinery.lib.scripts.ps1.ast.resolve_command_name` gives — so an
    alias is here too, and `iex $x` beside a `function Invoke-Expression` collides for the same
    reason, as does `item` beside a `function Get-Item`, which the implicit `Get-` retry reaches.

    **The two arrive under different conditions, because they sit at opposite ends of the
    precedence.** An alias is the highest tier and beats a script function, so `iex` reaches
    `Invoke-Expression` however the script spells its own definitions. The implicit `Get-` retry is
    the lowest, reached only once the function tier has missed, so `item` reaches `Get-Item` only in
    a script that defines no `item` of its own — and `build_call_graph` therefore withholds a retry
    name when the bare key is one this script defines. The set it withholds against is the one
    `defined_names` reports, which is what the command model's own function tier reads, so the two
    cannot disagree about which calls the retry is reached from.

    **The condition is the collision and not the qualifier.** A quoted executable path is the same
    shape: `& 'C:\\tools\\stage2.exe'` keys as the path and resolves to `stage2.exe`. Reading the
    backslash itself as the signal would make every script that invokes an executable by path
    unreadable, and `& 'C:\\Windows\\Temp\\payload.exe'` is one of the commonest shapes there is;
    that is not failing closed, it is switching the analysis off. Asked this way it costs nothing
    unless the stripped name is one this tree actually defines.

    **This has no PowerShell oracle and is a policy choice.** Real PowerShell errors on
    `& 'MyModule\\Qzmr'` when no such module is loaded — it does not reach the local definition — so
    the language does not say the definition must survive. What says so is the internal invariant
    that no removal leaves a dangling reference, plus a decision to fail closed in front of the
    lexer's qualified-name hole rather than behind it. `& 'global:Qzmr'` is a different case and is
    oracle-backed: the scope qualifier is stripped by the *key*, so the call and the definition
    already meet and nothing here fires.

    The call is not filed under the stripped key instead, which would be the other way to make the
    two meet. The same list feeds `refinery.lib.scripts.ps1.analysis.effects.Ps1OutputFlow`, where
    an extra call site *grounds* a function and licenses deleting what its body writes — so a guess
    that keeps a definition alive would buy that at the price of a payload.
    """
    return any(name in definitions for name in resolved)


def build_call_graph(root: Ps1Script, oracle: TypeOracle) -> Ps1CallGraph:
    """
    Walk the whole tree once, recording every function definition, every statically named invocation
    with the function that holds it, and every reason the result is not the whole story.

    The walk runs in source order so that a consumer removing what it finds removes from the front,
    and cannot short-circuit on the first unknown, because the definitions and call sites are still
    needed to decide what to keep.

    The collision row is decided after the walk rather than during it, because a definition may be
    written below the call that resolves onto it and a script is not read top to bottom.
    """
    definitions: dict[str, list[Ps1FunctionDefinition]] = {}
    call_sites: dict[str, list[Ps1CallSite]] = {}
    qualified: list[str] = []
    retried: dict[str, list[str]] = {}
    readable = oracle.world_closed_at(root)
    exports = False
    for node in root.walk_in_order():
        if isinstance(node, Ps1FunctionDefinition):
            if not _is_class_method(node):
                definitions.setdefault(normalize_command_name(node.name), []).append(node)
        elif isinstance(node, Ps1CommandInvocation):
            name = get_command_name(node)
            if name is None:
                if is_opaque_dispatch(node):
                    readable = False
                continue
            key = normalize_command_name(name)
            resolved = resolve_command_name(node)
            if resolved in _EXPORTING_COMMANDS:
                readable = False
                exports = True
            if resolved is not None and resolved != key:
                qualified.append(resolved)
            retry = None if resolved is None else implicit_get_retry(resolved)
            if retry is not None:
                retried.setdefault(key, []).append(retry)
            call_sites.setdefault(key, []).append(Ps1CallSite(node, _enclosing_function(node)))
        elif binds_command_identity(node):
            readable = False
    for key, names in retried.items():
        if key not in definitions:
            qualified.extend(names)
    if _collides_with_a_definition(qualified, definitions):
        readable = False
    return Ps1CallGraph(definitions, call_sites, readable, exports)
