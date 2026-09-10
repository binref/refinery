"""
Where a PowerShell script block runs: at what point, in whose scope, and how many times.

Three places in this package already answer part of this privately, each drawing the line somewhere
else — `refinery.lib.scripts.analysis.cycles.CycleModel.repeats` walks lexically and says so in its
own docstring, `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel` binds every bare write to
the scope it is written in, and `refinery.lib.scripts.ps1.analysis.effects` draws the
stored-versus-invoked line a third time. A block is a value, so the code around it is where it was
*written*, which is a different question from where it runs, and every pass that has needed the
second has had to guess it from the first.

**The answers here come from real PowerShell 5.1, not from the shape of the syntax.** `. { }` runs in
the caller's scope and `& { }` opens a child one, which is the pair the whole question turns on; a
`ForEach-Object` or `Where-Object` body also runs in the caller's scope, including when the block
reaches the cmdlet through a variable, and so does a `catch` or `finally` body; a `function` body, an
`Invoke-Command -ScriptBlock` without `-NoNewScope`, and a calculated property's block all open a
child scope. A `trap` body opens a child scope too, which
`refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel` does not model — its body is a `Block`
rather than a `Ps1ScriptBlock`, so no block here stands for it.

**`CHILD` is the answer that has to be earned.** Calling a body `CALLER` that is really `CHILD` adds a
kill nobody performs, which only ever loses an inlining; calling one `CHILD` that is really `CALLER`
drops a kill somebody does perform, which silently keeps a stale value. So `UNKNOWN` is projected as
`CALLER`, and only a position that *proves* a child scope answers `CHILD`.

**`.` is the invoker's scope, not the writer's.** `function TakeDot([scriptblock] $b) { . $b }`
dot-sources into `TakeDot`'s scope, so `TakeDot { $x = 'b' }` leaves the original caller's `$x` alone.
That is why a literal `. { }` is decidable from where it sits and a block handed anywhere else is not.

`ForEach-Object -Begin { }` and `-End { }` run once where `-Process { }` runs per input object, and
every one of them is reported `REPEATED` here anyway. The parser does not bind a parameter name to
the value that follows it — `-Begin` arrives as a switch argument and its block as the next
positional one — so telling them apart means inferring the association from argument order, and
inferring it wrongly reports a body that iterates as running once, which is the direction that keeps
a stale value. The precision is not worth depending on that shape; a begin block loses an inlining
and nothing else.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.model import (
    NAME_ROLES,
    Occurrence,
    is_write_occurrence,
    occurrence_role,
)
from refinery.lib.scripts.ps1.analysis.naming import (
    Ps1NameRole,
    Ps1NameTarget,
    named_references,
)
from refinery.lib.scripts.ps1.analysis.opaque import writes_nobody_can_attribute
from refinery.lib.scripts.ps1.ast import (
    binding_key,
    binds_parameter,
    bound_argument_value,
    free_positional_values,
    resolve_command_name,
)
from refinery.lib.scripts.ps1.data import (
    EVERY_PARAMETER_SET,
    parameter_sets,
    positional_scriptblock_sets,
    scriptblock_parameters,
)
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1FunctionDefinition,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1Variable,
)

#: The commands that run a scriptblock argument once per input object. A hit *withholds* the
#: single-visit reading a caller would otherwise take, so this is a deny-list and is read through
#: `refinery.lib.scripts.ps1.ast.resolve_command_name`, which follows `%` and `?` to the full names —
#: the opposite of what a grant table may do. It is deliberately not floored against the collected
#: command metadata for the same reason: a spelling the capture host never reported must still be
#: allowed to match.
_ITERATING_COMMANDS = frozenset({
    'foreach-object',
    'where-object',
})


def names_an_intact_iterating_command(
    cmd: Ps1CommandInvocation,
    shadowed: frozenset[str] = frozenset(),
) -> str | None:
    """
    The enumerating cmdlet *cmd* names — `foreach-object` or `where-object`, following `%`,
    `foreach` and `?` to the full name — when the script has not taken it over, or `None`.

    *shadowed* is the whole-run set of redefined command names (`Ps1TypeWorld.shadowed_names`). A
    name in it runs the script's own body rather than the cmdlet, so a block handed to it is data:
    measured on 5.1, `function ForEach-Object { 'H' }` makes `1, 2 | % { $_ }` run `H`, and `%`
    follows the redefinition because it resolves to `foreach-object`. A `function foreach` binds
    the separate `foreach` name the built-in keyword outranks and leaves `foreach-object` alone,
    which is why the resolved name, not the written spelling, is what the set is asked about.
    """
    name = resolve_command_name(cmd)
    if name in _ITERATING_COMMANDS and name not in shadowed:
        return name
    return None


class Ps1BlockReach(enum.Enum):
    """
    When the body runs relative to the point it is written at.

    `IMMEDIATE` — the statement that mentions the block runs it.
    `FUNCTION` — it is a named function's body, run by that function's call sites.
    `STORED` — its value is kept rather than run, so when it runs is not a question this layer holds.
    `UNKNOWN` — it is handed to something that may or may not run it.
    """
    IMMEDIATE = 'immediate'
    FUNCTION  = 'function'   # noqa
    STORED    = 'stored'     # noqa
    UNKNOWN   = 'unknown'    # noqa


class Ps1BlockScope(enum.Enum):
    """
    Whose variables the body's bare writes land in.

    `CALLER` — the scope of the code that runs it, so its writes are the caller's writes.
    `CHILD` — a fresh scope, so its writes are invisible outside and a name it assigns shadows.
    `UNKNOWN` — not decidable here, and treated as `CALLER` everywhere the difference is a kill.
    """
    CALLER  = 'caller'   # noqa
    CHILD   = 'child'    # noqa
    UNKNOWN = 'unknown'  # noqa


class Ps1BlockIteration(enum.Enum):
    """
    How often the site runs the body.

    `ONCE` — one invocation per visit to the site.
    `REPEATED` — the site runs it per input object, so a fact taken from one visit is not a fact.
    `UNKNOWN` — not decidable here.
    """
    ONCE     = 'once'     # noqa
    REPEATED = 'repeated'  # noqa
    UNKNOWN  = 'unknown'  # noqa


@dataclass(frozen=True)
class Ps1BlockFacts:
    """
    What is known about one `refinery.lib.scripts.ps1.model.Ps1ScriptBlock`. `site` is the element
    whose evaluation runs the body, and is `None` whenever that element is not in this script or is
    not decidable — a function body's callers, a stored block's eventual invocation.
    """
    reach: Ps1BlockReach
    scope: Ps1BlockScope
    iteration: Ps1BlockIteration
    site: Node | None


_UNPLACED = Ps1BlockFacts(
    reach=Ps1BlockReach.UNKNOWN,
    scope=Ps1BlockScope.UNKNOWN,
    iteration=Ps1BlockIteration.UNKNOWN,
    site=None,
)


def _invoked_directly(block: Ps1ScriptBlock) -> Ps1CommandInvocation | None:
    """
    The invocation that runs *block* by naming it, as `& { }` and `. { }` do, or `None`.
    """
    parent = block.parent
    if isinstance(parent, Ps1CommandInvocation) and parent.name is block:
        return parent
    return None


def _handed_to_command(block: Ps1ScriptBlock) -> Ps1CommandInvocation | None:
    """
    The invocation *block* is an argument of, named or positional, or `None`. The block reaching a
    command as an argument says nothing about whether the command runs it — `f { }`,
    `Invoke-Command -ScriptBlock { }` and `ForEach-Object { }` are one shape — so the caller still
    has to recognise the command.
    """
    parent = block.parent
    if isinstance(parent, Ps1CommandArgument):
        parent = parent.parent
    if isinstance(parent, Ps1CommandInvocation) and parent.name is not block:
        return parent
    return None


def _named_writes(cmd: Ps1CommandInvocation) -> Iterator[Occurrence]:
    """
    The names *cmd* writes as strings into the scope it is written in.

    A read is not one of them: it changes no value, so it is no fact about what the block leaves
    behind. Neither is a write that names its target scope outright, whose landing place does not
    depend on where the command sits, nor one aimed at a scope the lexical chain cannot name — for
    the latter there is no key to report, and `unattributable_writes_reaching_caller` is what
    carries it.
    """
    for reference in named_references(cmd):
        if reference.role is Ps1NameRole.READS:
            continue
        if reference.target is not Ps1NameTarget.LOCAL:
            continue
        yield Occurrence(node=cmd, role=NAME_ROLES[reference.role], key=reference.key)


#: The scriptblock parameters of `_ITERATING_COMMANDS` that run their body once per input object,
#: which is what binds `$_`. `-Begin` and `-End` run once beside them and leave `$_` at whatever the
#: scope around the pipeline holds, so a block in either binds nothing.
_PER_OBJECT_PARAMETERS = frozenset({
    'filterscript',
    'process',
})


def _selects_a_scriptblock_set(cmd: Ps1CommandInvocation, command: str) -> bool:
    """
    Whether every parameter *cmd* names leaves the call in a parameter set whose first positional
    argument is a script block the command runs.

    5.1 picks one set from the arguments a call writes, and the same position means a different
    thing in each. Measured: `1, 2 | ForEach-Object -MemberName ToString { Write-Host 'X' }` writes
    the block's own text twice, because `-MemberName` selects the set in which the argument after it
    is the method's argument list rather than a body. `ForEach-Object -InputObject 5 { Write-Host
    "P:$_" }` writes `P:5`, because `-InputObject` belongs to the scriptblock set as well.

    A parameter that belongs to every set decides nothing, which is what every common parameter is.
    A name the collected surface does not carry, and a prefix reaching any parameter that excludes
    the set, both refuse: a wrong grant here calls a value the command passes on a body it runs.
    """
    wanted = positional_scriptblock_sets(command)
    if not wanted:
        return False
    table = parameter_sets(command)
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            continue
        if argument.kind is Ps1CommandArgumentKind.POSITIONAL:
            continue
        reached = [
            sets for parameter, sets in table.items()
            if binds_parameter(argument.name, parameter)
        ]
        if not reached:
            return False
        if any(
            EVERY_PARAMETER_SET not in sets and sets.isdisjoint(wanted)
            for sets in reached
        ):
            return False
    return True


def binds_the_pipeline_variable(
    block: Ps1ScriptBlock,
    shadowed: frozenset[str] = frozenset(),
) -> Ps1CommandInvocation | None:
    """
    The invocation whose input `$_` ranges over inside *block*, or `None` where *block* is not a
    body run once per input object.

    The slot is read by name where it is written by name, and otherwise from position: a lone free
    positional block is the per-object body, where three of them are `begin`, `process` and `end` in
    that order — so a positional block beside another is refused rather than guessed at.

    *shadowed* is the whole-run set of command names the script has taken over. A name in it no
    longer denotes the enumerating cmdlet, so its body is not run once per object and `$_` inside it
    is whatever the surrounding scope holds — see `Ps1TypeWorld.shadowed_names`.
    """
    command = _handed_to_command(block)
    if command is None:
        return None
    name = names_an_intact_iterating_command(command, shadowed)
    if name is None:
        return None
    for parameter in scriptblock_parameters(name) & _PER_OBJECT_PARAMETERS:
        if bound_argument_value(command, parameter) is block:
            return command
    positional = free_positional_values(command, name)
    if len(positional) == 1 and positional[0] is block and _selects_a_scriptblock_set(command, name):
        return command
    return None


def _fills_a_scriptblock_slot(
    cmd: Ps1CommandInvocation,
    block: Ps1ScriptBlock,
    command: str,
) -> bool:
    """
    Whether *block* sits in a slot of *cmd* that the command runs, rather than one it takes as data.
    `ForEach-Object -Process { }` runs the block, `ForEach-Object -InputObject { }` hands it on
    untouched, and a `site` is a claim about the first only.

    A named slot is decided by the declared parameter type. A positional one is granted to the
    *first* free positional argument alone, and only where the parameters the call names leave it
    in a set whose first positional argument is a body — `_selects_a_scriptblock_set`. Three
    positional blocks are `begin`, `process` and `end`, so a later one is not the first slot; and
    a call that writes `-MemberName` is in the set where the first slot is a method name.
    """
    for parameter in scriptblock_parameters(command):
        if bound_argument_value(cmd, parameter) is block:
            return True
    positional = free_positional_values(cmd, command)
    return (
        bool(positional)
        and positional[0] is block
        and _selects_a_scriptblock_set(cmd, command)
    )


def classify_block(
    block: Ps1ScriptBlock,
    shadowed: frozenset[str] = frozenset(),
) -> Ps1BlockFacts:
    """
    The facts readable from where *block* sits.

    *shadowed* is the whole-run set of command names the script has taken over
    (`Ps1TypeWorld.shadowed_names`). An enumerating command whose name is in it runs the script's
    own definition rather than the cmdlet, so a block handed to it is data this cannot place, and
    the iterating branch below falls through to `_UNPLACED`. The default is empty for a caller that
    reads the name at face value and applies its own trust; `Ps1WorldReach` does that positionally.
    """
    parent = block.parent
    if isinstance(parent, Ps1FunctionDefinition) and parent.body is block:
        return Ps1BlockFacts(
            reach=Ps1BlockReach.FUNCTION,
            scope=Ps1BlockScope.CHILD,
            iteration=Ps1BlockIteration.UNKNOWN,
            site=None,
        )
    invocation = _invoked_directly(block)
    if invocation is not None:
        scope = {
            '.': Ps1BlockScope.CALLER,
            '&': Ps1BlockScope.CHILD,
        }.get(invocation.invocation_operator, Ps1BlockScope.UNKNOWN)
        return Ps1BlockFacts(
            reach=Ps1BlockReach.IMMEDIATE,
            scope=scope,
            iteration=Ps1BlockIteration.ONCE,
            site=invocation,
        )
    command = _handed_to_command(block)
    if command is not None:
        name = names_an_intact_iterating_command(command, shadowed)
        if name is not None and _fills_a_scriptblock_slot(command, block, name):
            return Ps1BlockFacts(
                reach=Ps1BlockReach.IMMEDIATE,
                scope=Ps1BlockScope.CALLER,
                iteration=Ps1BlockIteration.REPEATED,
                site=command,
            )
        return _UNPLACED
    return Ps1BlockFacts(
        reach=Ps1BlockReach.STORED,
        scope=Ps1BlockScope.UNKNOWN,
        iteration=Ps1BlockIteration.UNKNOWN,
        site=None,
    )


class Ps1BlockModel:
    """
    Where each script block of one root runs. Facts are read off the tree on first request and kept,
    since the tree is fixed for as long as this model lives.
    """

    def __init__(self, root: Ps1Script, shadowed: frozenset[str] = frozenset()):
        self.root = root
        self._shadowed = shadowed
        self._facts: dict[int, Ps1BlockFacts] = {}
        self._caller_writes: dict[int, tuple[Occurrence, ...]] = {}
        self._caller_unattributable: dict[int, bool] = {}

    def facts(self, block: Ps1ScriptBlock) -> Ps1BlockFacts:
        """
        What is known about where *block* runs.
        """
        found = self._facts.get(id(block))
        if found is None:
            found = self._facts[id(block)] = classify_block(block, self._shadowed)
        return found

    def may_write_caller_scope(self, block: Ps1ScriptBlock) -> bool:
        """
        Whether a bare write inside *block* may land in the scope of the code that runs it. True for
        everything but a proven child scope — see the module docstring for why that asymmetry is the
        safe one.
        """
        return self.facts(block).scope is not Ps1BlockScope.CHILD

    def writes_reaching_caller(self, block: Ps1ScriptBlock) -> tuple[Occurrence, ...]:
        """
        The write occurrences inside *block* that land in the scope of whatever runs it — the ones
        written directly in its body, and those of any nested block that reaches its own caller in
        turn. Empty for a proven child scope, since nothing a child scope writes outlives it.

        A name addressed as a *string* is a write here exactly as a bare `$x =` is. `Remove-Variable
        x`, `New-Variable x 'b'` and `Get-Process -OutVariable x` each write the scope they are
        written in and each contains no occurrence of the name, so a caller reading only the
        variables of the body sees `. { Remove-Variable x }` touch nothing at all. That the answer
        is an `Occurrence` rather than a `Ps1Variable` is what lets the two arrive as one kind of
        thing.

        That the recursion stops at a child scope is what makes `& { . { $x = 'b' } }` write nothing
        outside: the inner dot writes the `&` block's scope, and that scope ends with it. Qualified
        writes are left out because a `$script:` or `$global:` write names its scope outright and
        reaches the same binding whichever body it sits in, so it is not a fact about where the block
        runs — and a `Set-Variable -Scope Global x` is left out for that same reason.
        """
        found = self._caller_writes.get(id(block))
        if found is None:
            if not self.may_write_caller_scope(block):
                found = ()
            else:
                found = tuple(self._collect_writes(block))
            self._caller_writes[id(block)] = found
        return found

    def unattributable_writes_reaching_caller(self, block: Ps1ScriptBlock) -> bool:
        """
        Whether *block* runs a write whose name this cannot read — `Set-Variable $n 'v'` — into the
        scope of whatever runs it. The name is unknown, so the write may have landed on any binding
        of that scope, and a caller can place *when* it happened without knowing *what* it hit.

        Only the writes a command places in its own scope are reported. One that names a scope
        outright reaches the same binding whichever body it sits in, so it is not a fact about where
        this block runs, and reporting it here would have it stop at a child scope that does not
        stop it — the same reason `writes_reaching_caller` leaves a `$script:` write out.
        """
        found = self._caller_unattributable.get(id(block))
        if found is None:
            found = self._caller_unattributable[id(block)] = (
                self.may_write_caller_scope(block)
                and self._runs_unattributable_write(block)
            )
        return found

    def _runs_unattributable_write(self, block: Ps1ScriptBlock) -> bool:
        stack: list[Node] = list(block.children())
        while stack:
            node = stack.pop()
            if isinstance(node, Ps1ScriptBlock):
                if self.unattributable_writes_reaching_caller(node):
                    return True
                continue
            if writes_nobody_can_attribute(node):
                return True
            stack.extend(node.children())
        return False

    def _collect_writes(self, block: Ps1ScriptBlock) -> Iterator[Occurrence]:
        stack: list[Node] = list(block.children())
        while stack:
            node = stack.pop()
            if isinstance(node, Ps1ScriptBlock):
                yield from self.writes_reaching_caller(node)
                continue
            if (
                isinstance(node, Ps1Variable)
                and node.scope is Ps1ScopeModifier.NONE
                and is_write_occurrence(node)
            ):
                yield Occurrence(node=node, role=occurrence_role(node), key=binding_key(node))
            elif isinstance(node, Ps1CommandInvocation):
                yield from _named_writes(node)
            stack.extend(node.children())

    def body_site(self, owner: Node) -> tuple[Node, bool] | None:
        """
        The `refinery.lib.scripts.analysis.cycles.BodySite` answer for a body: the element that runs
        *owner*, and whether it runs it more than once.

        `None` for the script root, which nothing in the script runs, and for any block whose site is
        not decidable — a stored block, a function body, a block handed to a command that may or may
        not invoke it. The cycle walk reads that as *fall back to where the block is written*, which
        is what it did everywhere before this model existed, so answering nothing changes nothing.
        """
        if not isinstance(owner, Ps1ScriptBlock):
            return None
        facts = self.facts(owner)
        if facts.site is None:
            return None
        return facts.site, facts.iteration is Ps1BlockIteration.REPEATED


def build_block_model(
    root: Ps1Script,
    shadowed: frozenset[str] = frozenset(),
) -> Ps1BlockModel:
    """
    Build the `Ps1BlockModel` for a script. *shadowed* is the whole-run set of command names the
    script takes over (`Ps1TypeWorld.shadowed_names`), so a body handed to a `ForEach-Object` or
    `Where-Object` the script has redefined is placed as data rather than as a body it runs.
    """
    return Ps1BlockModel(root, shadowed)
