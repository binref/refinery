"""
The closed-world model of the PowerShell analysis substrate: whether the script leaves the .NET type
system and the command table intact, so that a present-member purity grant in
`refinery.lib.scripts.ps1.analysis.effects` can be trusted. A member read the metadata proves inert
(`String.Length` is a plain property) still runs code when the script has re-pointed that member
through the Extended Type System (`Update-TypeData -Force`), and a resolved type name still
constructs a different type when the script has remapped its accelerator — both confirmed possible
on Windows PowerShell. The gate therefore grants a present-member read only where the world is
*closed*: no code the script runs can have performed such a mutation.

The predicate opens the world on two axes with opposite defaults. **Dispatch** is an allow-list: a
command is inert only when its name is statically known, so any `& $x` / `. $x` / computed-name
call opens the world, closing the open-ended escape of runtime-constructed code without a list to
forget.
**Mutation** is a curated, documented deny-list — a pure allow-list would be vacuous, since the
collected metadata omits hundreds of host cmdlets and every one would then read as a possible
mutator. The deny-list is enumerated here rather than left silent, and its residual — an exotic
aliasing spelling, a `using module` statement, a computed provider path — is a *soundness* gap, not a
recall gap: a mutator the list misses leaves the world reading closed, which fires the grants and
deletes the reads that mutator makes effectful. Every name added to it buys correctness, not recall.

This is a leaf model in Phase 5c — a one-shot whole-script verdict — cached in
`refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` and queried through
`refinery.lib.scripts.ps1.analysis.types.TypeOracle`. `Ps1TypeWorld.world_closed_at` takes the read
node so a flow-sensitive successor can make the answer depend on where the read sits relative to the
leaks that reach it; in this phase the node is not yet consulted.
"""
from __future__ import annotations

import enum

from typing import NamedTuple

from refinery.lib.scripts.ps1.ast import (
    assignment_target_variables,
    get_member_name,
    is_execution_context_invoke,
    is_opaque_dispatch,
    is_scriptblock_create,
    is_scriptblock_invoke,
    normalize_command_name,
    normalize_dotnet_type_name,
    resolve_command_name,
    string_value,
    unwrap_assignment_target,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import KNOWN_ALIAS
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1ClassDefinition,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1EnumDefinition,
    Ps1FunctionDefinition,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)


class WorldRole(enum.Enum):
    """
    What a command does to the type world and the command table. The three opening roles are kept
    apart rather than collapsed into one boolean because a caller acts differently on each: a pass
    deleting an alias definition has to know that the invocation blocking it is another alias
    definition, which it may yet be able to delete too, and not a leak, which it never can.

    `NONE` and `UNKNOWN` are the two ways of not naming a role, and they are as far apart as they
    are in `refinery.lib.scripts.ps1.analysis.commands.CommandKind`: `NONE` says the command leaves
    the world as it found it, `UNKNOWN` says nothing static bounds what it runs.
    """
    #: Runs code supplied as data, so what it does to the world is whatever that data says.
    LEAK = enum.auto()
    #: Mutates the .NET type system, after which reflection no longer describes a type's members.
    MUTATION = enum.auto()
    #: Redefines command identity, after which a bareword no longer names what the metadata says.
    IDENTITY = enum.auto()
    #: Leaves both intact.
    NONE = enum.auto()
    #: Dispatches to whatever an expression yields, so it may be any of the above.
    UNKNOWN = enum.auto()


#: Commands that execute arbitrary code supplied as data. `Invoke-Expression` is the canonical one;
#: the opaque dispatch and scriptblock-execution forms are recognized syntactically instead. The job
#: and remoting cmdlets belong here rather than beside the mutators: each takes a scriptblock the
#: walk cannot read when it is written as a variable, and the type-system effects such a block
#: performs are runspace-global, so a child scope does not contain them.
_LEAK_CMDLETS = frozenset({
    'invoke-command',
    'invoke-expression',
    'start-job',
    'start-threadjob',
})

#: Commands that mutate the .NET type system, so reflection can no longer be trusted to describe a
#: type's members. Curated and documented rather than derived — the module docstring says why a
#: mutation allow-list would be vacuous. Names are compared after alias resolution.
_MUTATION_CMDLETS = frozenset({
    'add-member',
    'add-type',
    'import-module',
    'new-module',
    'update-typedata',
})

#: Commands that redefine command identity, after which a later bareword can no longer be trusted to
#: name what the metadata says — including a mutator hidden behind the new name. A static
#: single-definition alias is inlined away before this runs, so a *surviving* one is an alias the
#: inliner could not resolve.
_ALIAS_CMDLETS = frozenset({
    'import-alias',
    'new-alias',
    'remove-alias',
    'set-alias',
})

#: The file extension of a PowerShell script. Invoking one runs its definitions and whatever type
#: mutations it performs into this session, whichever operator carries the call.
_SCRIPT_FILE_SUFFIX = '.ps1'

#: The variable namespaces that name a command rather than a value: assigning into either redefines
#: command identity the way `_ALIAS_CMDLETS` do.
_IDENTITY_SCOPES = frozenset({
    Ps1ScopeModifier.ALIAS,
    Ps1ScopeModifier.FUNCTION,
})

#: The provider names that address command identity, written as a path argument to an item cmdlet
#: (`Set-Item alias:x ...`). Matched by name rather than by enumerating every aliasing cmdlet, which
#: is the family the mutation deny-list cannot close by name.
_IDENTITY_PROVIDERS = ('alias', 'function')


def command_role(name: str) -> WorldRole:
    """
    What the command `name` does to the world, or `WorldRole.NONE` when no deny-list holds it. Never
    `WorldRole.UNKNOWN`: a name is by construction something this can look up, and not knowing what
    an invocation runs is a fact about the invocation rather than about any name.

    The lookup key is the *deny-list* reading `refinery.lib.scripts.ps1.ast.resolve_command_name`
    describes, taken here rather than owed by the caller: the module and scope qualifiers dropped
    and one hop through the built-in alias table, so that neither `Microsoft.PowerShell.Utility\\iex`
    nor `global:iex` nor plain `iex` can dodge a table the bare `Invoke-Expression` matches. Eight
    of the entries below are reachable only through that hop, so a caller handing over a name it
    had not resolved would otherwise read a deny-list answer of `NONE` — the one direction a
    deny-list must never fail in. Taking the key here is what makes that impossible to get wrong at
    a call site. It is idempotent: no built-in alias names what another one resolves to.

    This is the one place the three tables are read. `refinery.lib.scripts.ps1.analysis.commands`
    asks the same question of a name it reached by following the script's own aliases — which this
    module cannot follow, since the command model is built over the shadow set this one produces —
    and a second reading of the tables there would be a second deny-list to keep in step.
    """
    key = normalize_command_name(name.rpartition('\\')[2])
    key = KNOWN_ALIAS.get(key, key).lower()
    if key in _LEAK_CMDLETS:
        return WorldRole.LEAK
    if key in _MUTATION_CMDLETS:
        return WorldRole.MUTATION
    if key in _ALIAS_CMDLETS:
        return WorldRole.IDENTITY
    return WorldRole.NONE


class Ps1TypeWorld:
    """
    The verdict of `build_closed_world`: whether the running script leaves the type system and
    command table intact. It carries both command-table facts the purity gate needs — the
    whole-world verdict (`world_closed_at`) and the set of command names the script redefines
    (`command_shadowed`) — so the two cannot drift apart. Held in a
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot and consulted through
    `refinery.lib.scripts.ps1.analysis.types.TypeOracle`.
    """

    def __init__(self, closed: bool, shadowed: frozenset[str]):
        self._closed = closed
        self._shadowed = shadowed

    def world_closed_at(self, node) -> bool:
        """
        Whether the type world is closed at `node`. In Phase 5c this is the whole-script verdict and
        `node` is not consulted — it is a forward-declared seam for the flow-sensitive successor,
        which will make the answer depend on whether a leak reaches this read rather than whether
        the script contains one anywhere.
        """
        return self._closed

    def command_shadowed(self, name: str) -> bool:
        """
        Whether `name` is a command the script redefines with a script-local `function`/`filter`
        or a `function:`/`alias:`-scope assignment, so the collected metadata no longer describes
        what the name runs. The analysis must not trust such a name for typing or purity. The set is
        whole-script and conservative — an inner-scope redefinition distrusts the name everywhere,
        which only keeps more — mirroring `world_closed_at`'s whole-script granularity.

        The query is normalized the way the set was built, so the spelling a caller happens to hold
        cannot answer `False` for a name the walk recorded under its canonical key.
        """
        return normalize_command_name(name) in self._shadowed

    @property
    def shadowed_names(self) -> frozenset[str]:
        """
        Every command name the script redefines, keyed through
        `refinery.lib.scripts.ps1.ast.normalize_command_name`. Exposed so a transform that must not
        rewrite a name the script has taken over reads the one set the whole-tree walk built,
        instead of keeping a narrower private one that sees only `function` definitions.
        """
        return self._shadowed


def build_closed_world(root: Ps1Script) -> Ps1TypeWorld:
    """
    Walk the whole tree once, computing both command-table facts: whether any node opens the world
    (a single opener anywhere is global and retroactive, so it closes off the verdict) and the set
    of command names the script redefines. The walk cannot short-circuit on the first opener
    because the shadow set needs every redefinition, wherever it sits.
    """
    closed = True
    shadowed: set[str] = set()
    for node in root.walk():
        redefined = _identity_redefinitions(node)
        shadowed.update(record.name for record in redefined)
        if _opens_world(node, redefined):
            closed = False
    return Ps1TypeWorld(closed, frozenset(shadowed))


class _IdentityBody(enum.Enum):
    """
    What a command redefinition binds the name to, which is what decides whether the redefinition
    also opens the type world. An enum rather than a boolean because the two ways of *not* being a
    visible block are unrelated — one hides a body inside a value, the other names another command
    entirely — and collapsing them would make the world rule read as if it had one reason.
    """
    #: A scriptblock literal standing in the tree, so the whole-tree walk reads its statements and
    #: catches a mutation inside it by presence. The only kind that leaves the world closed.
    VISIBLE_BLOCK = enum.auto()
    #: A value the walk cannot see through — a variable, a call's result, or a compound assignment
    #: folding in whatever the name held before.
    OPAQUE_VALUE = enum.auto()
    #: Another command, named rather than defined. Its body is not in this script at all.
    EXTERNAL_COMMAND = enum.auto()


class _IdentityRedefinition(NamedTuple):
    name: str
    body: _IdentityBody


def _identity_redefinitions(node) -> tuple[_IdentityRedefinition, ...]:
    """
    The command names `node` redefines, each normalized to the key a call resolves under and paired
    with what it binds, or an empty tuple. A `function`/`filter` definition names one command
    directly; an assignment into the `function:`/`alias:` variable namespace names one per slot it
    writes, so the multi-assignment `${function:Get-Date}, $y = { ... }, 2` records `get-date` where
    matching one target shape against one variable would miss it.

    Normalizing is what makes the name usable: `function global:Get-Date` defines exactly what a
    later unqualified `Get-Date` runs, and a shadow set holding the qualified spelling answers `False`
    to every consumer that asks about the unqualified one.

    Only a plain `=` onto a single target reports `VISIBLE_BLOCK`. A multi-assignment could be
    paired up with the values on its right, but the target list drops non-variable slots, so the
    position a variable came from is already lost — and the shape is rare enough that reading
    every slot of one as opaque costs nothing.
    """
    if isinstance(node, Ps1FunctionDefinition):
        return (_IdentityRedefinition(
            normalize_command_name(node.name), _IdentityBody.VISIBLE_BLOCK),)
    if not isinstance(node, Ps1AssignmentExpression):
        return ()
    targets = assignment_target_variables(node.target)
    single = len(targets) == 1 and not isinstance(
        unwrap_assignment_target(node.target), Ps1ArrayLiteral)
    return tuple(
        _IdentityRedefinition(
            normalize_command_name(variable.name),
            _assigned_identity_body(node, variable, single),
        )
        for variable in targets
        if variable.scope in _IDENTITY_SCOPES
    )


def _assigned_identity_body(
    node: Ps1AssignmentExpression, variable: Ps1Variable, single: bool,
) -> _IdentityBody:
    """
    What an identity-scope assignment binds its name to. The `alias:` namespace always names another
    command; the `function:` namespace binds a scriptblock, which is readable only when written out
    as a literal and this assignment plainly rebinds one target.
    """
    if variable.scope is Ps1ScopeModifier.ALIAS:
        return _IdentityBody.EXTERNAL_COMMAND
    if not single or node.operator != '=' or node.value is None:
        return _IdentityBody.OPAQUE_VALUE
    if isinstance(unwrap_parens(node.value), Ps1ScriptBlock):
        return _IdentityBody.VISIBLE_BLOCK
    return _IdentityBody.OPAQUE_VALUE


def _opens_world(node, redefined: tuple[_IdentityRedefinition, ...]) -> bool:
    """
    Whether `node` leaves the type system or the command table in a state the collected metadata no
    longer describes. `redefined` is the identity classification of the same node, so an assignment
    into the identity namespaces is recognized once, not by two functions that can drift apart.

    A redefinition binding a visible scriptblock does *not* open the world. Its body stands in the
    tree, so a mutation inside it is caught by presence like any other statement, and the same
    construct spelled `function X { }` has always left the world closed. Opening on it would kill
    every member grant in the script over a name the shadow set already distrusts.

    A `class` or `enum` definition does open it, for the reason `Add-Type` does: it puts a type into
    the session under a name the collected metadata never described, and a name it *did* describe is
    exactly the interesting case — `class Math { static [int] Abs([int]$x) { <payload> } }` makes
    `[Math]::Abs(1)` run that body while `resolve_type` still vouches for `System.Math`. The
    definition standing in the tree does not help, because the grant is keyed on the type name
    rather than on the presence of a body.
    """
    if isinstance(node, (Ps1ClassDefinition, Ps1EnumDefinition)):
        return True
    if isinstance(node, Ps1CommandInvocation):
        return _command_opens_world(node)
    if isinstance(node, Ps1InvokeMember):
        return (
            is_scriptblock_create(node)
            or is_scriptblock_invoke(node)
            or is_execution_context_invoke(node)
            or _is_type_accelerator_mutation(node)
            or _is_psobject_member_mutation(node)
        )
    if isinstance(node, Ps1AssignmentExpression):
        return any(record.body is not _IdentityBody.VISIBLE_BLOCK for record in redefined)
    return False


def _command_opens_world(cmd: Ps1CommandInvocation) -> bool:
    if is_opaque_dispatch(cmd):
        return True
    if runs_another_script_file(cmd):
        return True
    name = resolve_command_name(cmd)
    if name is None:
        return False
    if command_role(name) is not WorldRole.NONE:
        return True
    return touches_identity_provider(cmd)


def runs_another_script_file(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether `cmd` runs a `.ps1` file that is not part of this tree, so the analysis cannot see what
    it defines or mutates. Dot-sourcing is the spelling that matters most — it runs the file's
    definitions into the current scope — but the operator is not what makes the file opaque: a
    `& '.\\stage2.ps1'` or a bareword `stage2.ps1` runs the same code, and the Extended Type System
    and accelerator mutations it may perform are runspace-global rather than scope-local, so the
    child scope a call operator opens does not contain them.

    A dot-sourced inline block (`.{ ... }`) runs only its visible body, which the walk covers, and
    `. $x` is already opaque dispatch.
    """
    if not isinstance(cmd.name, Ps1StringLiteral):
        return False
    return (
        cmd.invocation_operator == '.'
        or cmd.name.value.lower().endswith(_SCRIPT_FILE_SUFFIX)
    )


def touches_identity_provider(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether any argument is a literal path into the `alias:` or `function:` provider, the vector
    that escapes a name-keyed deny-list because `Set-Item alias:x Update-TypeData` mutates identity
    without `Set-Item` being an aliasing cmdlet. Recognized by the provider the path names, not by
    resolving the aliased target, so an obfuscated or dynamic target cannot slip through.

    The provider is read after the same two decorations `resolve_command_name` strips from a
    command name, because a path addresses the identical namespace through either:
    `Microsoft.PowerShell.Core\\Function::Get-Date` is what `function:Get-Date` is short for, and a
    prefix test keyed on the short spelling reads the long one as an ordinary file path.
    """
    for arg in cmd.arguments:
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        text = string_value(value)
        if text is None:
            continue
        provider = text.rpartition('\\')[2].partition(':')[0].lower()
        if provider in _IDENTITY_PROVIDERS:
            return True
    return False


def _is_type_accelerator_mutation(node: Ps1InvokeMember) -> bool:
    """
    Whether `node` adds or removes a type accelerator through
    `[…PSObject+TypeAccelerators]::Add/Remove`, which remaps what a type name resolves to.
    """
    obj = node.object
    return (
        node.access is Ps1AccessKind.STATIC
        and isinstance(obj, Ps1TypeExpression)
        and 'typeaccelerators' in normalize_dotnet_type_name(obj.name)
        and isinstance(node.member, str)
        and node.member.lower() in ('add', 'remove')
    )


def _is_psobject_member_mutation(node: Ps1InvokeMember) -> bool:
    """
    Whether `node` adds or removes a member through the reflective
    `$obj.PSObject.Members.Add/Remove` chain, the Extended Type System mutation that is not a cmdlet
    call and so escapes the name-keyed deny-list.
    """
    if node.access is not Ps1AccessKind.INSTANCE:
        return False
    if not (isinstance(node.member, str) and node.member.lower() in ('add', 'remove')):
        return False
    members = node.object
    if not isinstance(members, Ps1MemberAccess):
        return False
    members_name = get_member_name(members.member)
    if members_name is None or members_name.lower() != 'members':
        return False
    psobject = members.object
    if not isinstance(psobject, Ps1MemberAccess):
        return False
    psobject_name = get_member_name(psobject.member)
    return psobject_name is not None and psobject_name.lower() == 'psobject'
