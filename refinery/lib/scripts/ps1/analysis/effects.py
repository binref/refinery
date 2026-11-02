"""
The effect layer of the PowerShell analysis substrate: whether evaluating a node produces an
observable side effect, and what a standalone statement contributes to the body it sits in. Every
pass that decides "is it safe to delete this?" asks here, so that no two of them can disagree.

Most of these are free functions because the facts they compute are syntactic: a conservative
allow-list over one expression, needing no information from anywhere else in the tree.
`Ps1OutputFlow` is the exception and the first genuine summary fact here — where a body's output
ends up cannot be read off the body, only off every call that reaches it — so it is a model built
once over the whole script and held in a
`refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot.

**Scope.** Three questions about a statement are separable and all three are now answered, each by a
different thing, and no one of them may stand in for another:

- whether it performs a side effect — `statement_effect`;
- whether it may *throw* — `refinery.lib.scripts.ps1.analysis.raising`, the one answer every
  removal site reads. Its context-free half is `is_fault_free`, which grants what the value domain
  computes and what a syntactic allow-list names and answers `False` for everything else; the rest
  is what the script rather than the expression decides. Purity is not this question:
  `is_side_effect_free` accepts `[Int]$x` and `$a / $b`, both of which raise;
- where the value it writes to the output stream is read — `output_sink` positionally, and
  `Ps1OutputFlow` through the call graph, which is the only one that can see past a function
  boundary.

One site still answers an emission question with a purity verdict: `_command_body_is_pure` reads an
`EFFECT` statement as disqualifying, where what it means to ask is whether the body emits. It costs
recall rather than safety — a body that acts is kept — and it is named here so the split above is
read as incomplete rather than as done.
"""
from __future__ import annotations

import enum

from typing import Callable, Iterator, NamedTuple, Sequence

from refinery.lib.scripts import Block, Node, tree_root
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph, Projection, flood_labels
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.arguments import Ps1WrittenSlots, written_slots
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.dispatch import Ps1ErrorKind
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.analysis.faults import (
    Ps1FaultReach,
    Ps1StepOverRegion,
    RaiseVerdicts,
)
from refinery.lib.scripts.ps1.analysis.handlers import handler_acts
from refinery.lib.scripts.ps1.analysis.identity import object_sources
from refinery.lib.scripts.ps1.analysis.model import occurrence_role, scope_local_nodes
from refinery.lib.scripts.ps1.analysis.raising import (
    Ps1RaiseModel,
    TreeStamp,
    bound_default_may_throw,
    lies_in_a_block_within,
    point_raise_kinds,
    statement_raise_kinds,
)
from refinery.lib.scripts.ps1.analysis.session import session_of
from refinery.lib.scripts.ps1.analysis.values import (
    candidate_types,
    is_fault_free,
)
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import (
    assignment_target_is_all_variables,
    assignment_target_variables,
    extract_new_object,
    get_body,
    get_command_name,
    get_member_name,
    get_named_blocks,
    get_param_block,
    is_builtin_variable,
    is_null_discard,
    is_reference_cast,
    is_void_cast,
    resolve_command_name,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1Attribute,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1DataSection,
    Ps1DoLoop,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FileRedirection,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1MergingRedirection,
    Ps1ParamBlock,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1RedirectionStream,
    Ps1ReturnStatement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)


def _canonical_read_set(
    entries: set[tuple[str, str]],
) -> frozenset[tuple[Ps1TypeName, str]]:
    """
    A frozenset of `(canonical type key, lowercased member)` reads, each floored against the
    data the way `data.required_type_key` floors a type: the type must resolve, and the member
    must be collected as a reflection property or field. An *instance* field needs no entry —
    reading a bare memory slot runs no code — so this table is for a property (whose getter may run
    code) or a *static* field (whose first read runs the declaring type's static constructor). An
    entry that names an Extended Type System member (which runs code) or a member the type no longer
    carries fails the load rather than silently granting a read the data cannot vouch for. It keys
    on the same canonical `FullName` as the invoke-side tables, so the per-member effect data a
    later regeneration adds can replace it without rekeying.
    """
    result: set[tuple[Ps1TypeName, str]] = set()
    for type_name, member in entries:
        type_key = data.required_type_key(type_name)
        record = data.member_record(type_key, member)
        gated = isinstance(record, dict) and record['source'] == 'reflection' and (
            record['kind'] == 'property'
            or (record['kind'] == 'field' and record.get('static') is True)
        )
        if not gated:
            raise ValueError(
                F'the PowerShell pure-read allow-list names {type_name}.{member}, which the '
                F'collected metadata does not carry as a reflection property or static field; an '
                F'instance field is pure without listing, so the data and allow-list are out of step.'
            )
        result.add((type_key, member.lower()))
    return frozenset(result)


def _canonical_command_set(names: set[str]) -> frozenset[str]:
    """
    A frozenset of lowercased command names, each floored against the collected metadata the
    way `data.required_type_key` floors a type: a name no capture host reported is a name this
    module has no evidence about, and a table that keeps it fails open the moment the command is
    renamed or the module holding it stops shipping. The load fails instead.

    This is for a table keyed on what a command *is*, never for a deny-list of what a script may do:
    `refinery.lib.scripts.ps1.analysis.world` names `start-threadjob` and `remove-alias`, which the
    capture host does not carry, and a deny-list has to be allowed to outrun the data.
    """
    result: set[str] = set()
    for name in names:
        if data.command(name) is None:
            raise ValueError(
                F'the PowerShell command table names {name!r}, which the collected metadata does '
                F'not carry as a command; the data and the table are out of step.'
            )
        result.add(name.lower())
    return frozenset(result)


def _canonical_sealed_value_type_set(names: set[str]) -> frozenset[Ps1TypeName]:
    """
    A frozenset of canonical type keys like `data.required_type_keys`, additionally floored
    against the shipped `sealed` flag. A type on the pure-read allow-list must be sealed: the
    whole-surface grant bets that a value of the type carries exactly the members reflection
    reports, which a subtype could violate. An entry the collected metadata does not mark sealed
    fails the load.
    """
    keys = data.required_type_keys(names)
    for key in keys:
        if not data.type_is_sealed(key):
            raise ValueError(
                F'the PowerShell pure-read allow-list names {key!r}, which the collected metadata '
                F'does not mark sealed; a subtype could carry a member the whole-surface grant does '
                F'not see, so the data and the allow-list are out of step.'
            )
    return keys


#: Types whose entire static surface is granted purity at once. Listing a type here asserts that no
#: static member of it writes anything — a bet re-checked against the real .NET surface whenever an
#: entry is added, because a single writing member makes every call on the type removable.
#: `_IMPURE_STATIC_METHODS` and the written-slot table in
#: `refinery.lib.scripts.ps1.analysis.arguments` carve out the members where the bet is wrong but
#: the type is still worth granting wholesale, and out-parameters are handled generically,
#: from the collected signature in `_writes_through_out_parameter` and syntactically in
#: `_is_writable_reference`, rather than per method. The readable source spellings are resolved to
#: canonical `FullName` keys at import, so a spelling variant is one entry and an unresolvable name
#: fails the load.
_PURE_STATIC_METHOD_TYPES = data.required_type_keys({
    'bitconverter',
    'char',
    'collections.arraylist',
    'collections.generic.dictionary`2',
    'collections.generic.hashset`1',
    'collections.generic.list`1',
    'convert',
    'datetime',
    'decimal',
    'double',
    'guid',
    'hashtable',
    'int',
    'int64',
    'io.path',
    'ipaddress',
    'math',
    'object',
    'securestring',
    'string',
    'text.stringbuilder',
    'timespan',
    'version',
})

_PURE_STATIC_METHODS = data.required_member_keys({
    ('diagnostics.process', 'getcurrentprocess'),
    ('threading.tasks.task', 'delay'),
    ('array', 'asreadonly'),
    ('array', 'binarysearch'),
    ('array', 'createinstance'),
    ('array', 'empty'),
    ('array', 'indexof'),
    ('array', 'lastindexof'),
    ('environment', 'expandenvironmentvariables'),
    ('environment', 'getcommandlineargs'),
    ('environment', 'getenvironmentvariable'),
    ('environment', 'getenvironmentvariables'),
    ('environment', 'getfolderpath'),
    ('environment', 'getlogicaldrives'),
})

#: Members that do something observable whatever they are handed, on a type whose remaining static
#: surface is pure enough to keep granting wholesale. Unlike a member that writes through a slot,
#: these are not saved by being called on a temporary: `[IO.Path]::GetTempFileName()` takes no
#: arguments and still creates a file on disk.
_IMPURE_STATIC_METHODS = data.required_member_keys({
    ('io.path', 'gettempfilename'),
})

#: Types whose entire reflection-read surface is pure: the sealed, immutable value types whose
#: property and field getters only return stored data and whose members never mutate or throw. A
#: read of any member of one of these — present or absent — has no side effect, which is what lets a
#: member the type does not carry resolve to `$null` safely. The bet is the type is sealed, so the
#: runtime value is exactly this type and not a subtype with a member of its own; the shipped
#: `sealed` flag is checked at import by `_canonical_sealed_value_type_set`, so an entry the data
#: does not mark sealed fails the load rather than resting on a hand assertion. Absent-safe stays
#: scoped to this set rather than to any sealed type: a value of one of these carries no member a
#: module's `types.ps1xml` could have added that our capture missed, which sealedness alone does
#: not guarantee for a reference type. `IPAddress` is deliberately absent — its `.Address` throws
#: for an IPv6 address and its `.ScopeId` for an IPv4 one, so its read surface is not uniformly
#: pure. A value type that ever gained an effectful reflection getter would move to `_PURE_READS`,
#: member by member.
_PURE_READ_TYPES = _canonical_sealed_value_type_set({
    'byte',
    'datetime',
    'decimal',
    'double',
    'guid',
    'int',
    'int16',
    'int64',
    'sbyte',
    'single',
    'string',
    'timespan',
    'uint16',
    'uint32',
    'uint64',
    'version',
})

#: Individual reflection reads granted purity where the type's surface as a whole is not. Each
#: `(type, member)` asserts that reading it runs no observable code and cannot throw — a property
#: whose getter only returns cached data (`Process.ProcessName`, where `Process.ExitCode` throws
#: until exit and is deliberately absent), or a static field whose declaring type's static
#: constructor is inert (`Math.PI`). The floor confirms each names a collected reflection property
#: or field, so an entry that turns into an Extended Type System member across a regeneration fails
#: the load rather than vouching for a member that now runs code.
_PURE_READS = _canonical_read_set({
    ('diagnostics.process', 'processname'),
    ('environment', 'machinename'),
    ('environment', 'systemdirectory'),
    ('environment', 'username'),
    ('math', 'e'),
    ('math', 'pi'),
    ('microsoft.powershell.commands.genericmeasureinfo', 'count'),
    ('microsoft.powershell.commands.genericobjectmeasureinfo', 'count'),
    ('text.encoding', 'utf8'),
    ('threading.tasks.task', 'status'),
    ('threading.thread', 'currentthread'),
    ('threading.thread', 'managedthreadid'),
})


def reflection_read_cannot_throw(type_key: Ps1TypeName, member: str) -> bool:
    """
    Whether the curated cannot-throw table vouches for reading `member` off the type `type_key` —
    the entries of `_PURE_READS`, each asserting that reading it runs no observable code and
    cannot throw. That assertion is the one fact a rewrite spelling a reflection read as the direct
    member needs: a getter that throws surfaces through `GetValue` wrapped in a
    `MethodInvocationException` and through the direct read as itself, so the two spellings agree
    only where nothing throws. The whole-surface grants of `_PURE_READ_TYPES` are deliberately
    absent here — they answer for a value of a type, whose subtype could carry a member of its own,
    and not for the one static member a type expression names.
    """
    return (type_key.generic_definition, member.lower()) in _PURE_READS


def _writing_parameters() -> frozenset[str]:
    """
    The parameter spellings whose presence makes a command write, however pure the transform it
    names.

    `refinery.lib.scripts.ps1.data.OUT_VARIABLE_PARAMETERS` is most of it: those bind their argument
    as the *name* of a variable the command fills, so `Get-Date -OutVariable d` sets `$d` and is an
    out-parameter in cmdlet clothing, no more removable than `[Int]::TryParse($s, [ref]$n)`.
    `-SetSeed` is added on top — not a common parameter, and not one that names a variable at all,
    but a `Get-Random` switch that rewrites the session's generator state, which is the same kind of
    hidden write. That is why this set and the one it is built from are kept apart: a caller asking
    which parameters *name* a variable must not be handed `setseed` and take the `5` of
    `Get-Random -SetSeed 5` for a variable.

    The match in `_is_writing_parameter` accepts unambiguous abbreviations of every spelling here.
    """
    return data.OUT_VARIABLE_PARAMETERS | {'setseed'}


_WRITING_PARAMETERS = _writing_parameters()

#: The binary operators whose evaluation writes the automatic `$Matches` variable, so an expression
#: built on one is a store to engine state rather than a value. Every case-sensitivity and negation
#: spelling is listed, because the engine populates `$Matches` for all of them.
MATCH_OPERATORS = frozenset({
    '-cmatch',
    '-cnotmatch',
    '-imatch',
    '-inotmatch',
    '-match',
    '-notmatch',
})

#: The expression forms that are literally their own value: the base case of `is_side_effect_free`.
_LITERAL_EXPRESSIONS = (
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1RealLiteral,
    Ps1StringLiteral,
)

#: The expression forms that provably hold no code, read by `_cannot_be_a_scriptblock`. This asks a
#: different question from `_LITERAL_EXPRESSIONS` and is a table of its own even though the two
#: coincide today, because their correct extensions differ: an expandable string can never be a
#: scriptblock and belongs here, while `is_side_effect_free` may not grant one wholesale, since
#: `"$(Start-Process x)"` runs a command. Sharing one table would turn either extension into a
#: silent grant on the other question.
_NON_BLOCK_EXPRESSIONS = (
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1RealLiteral,
    Ps1StringLiteral,
)

#: The expression forms that can never be read as the name of a member, used by `_invokes_a_member`.
#: The polarity is deliberately the opposite of the two tables above: a form that is *absent* here
#: is treated as a member name, so extending an allow-list elsewhere can never quietly turn a member
#: invocation into a proof of purity. Only numbers qualify — every string form spells a member name
#: however it is quoted, and a here-string named one that `Ps1StringLiteral` alone did not catch.
_NON_MEMBER_EXPRESSIONS = (
    Ps1IntegerLiteral,
    Ps1RealLiteral,
)


def _is_writing_parameter(name: str) -> bool:
    """
    Whether a command parameter, as written in the source, names one of `_WRITING_PARAMETERS`.

    The leading dash is part of the parsed name and is stripped here. PowerShell also binds any
    unambiguous abbreviation of a parameter, so `-OutVar` is `-OutVariable` and has to be recognized
    as one: the match is a prefix test, not equality. An abbreviation short enough to be ambiguous
    is a runtime error in PowerShell, so rejecting it here costs nothing.
    """
    name = name.lstrip('-').lower()
    return bool(name) and any(parameter.startswith(name) for parameter in _WRITING_PARAMETERS)


def _denotes_shared_storage(node) -> bool:
    """
    Whether an expression denotes storage that something outside it can already reach: a variable, a
    property, or an array slot. A literal, a constructed array and a call result are temporaries —
    the expression that produced them is the only holder — so mutating one of those is unobservable
    while mutating shared storage is a side effect.

    This is what separates `[Array]::Reverse('ab'.ToCharArray())`, a junk statement whose result
    nothing can read, from `[Array]::Reverse($buffer)`, which rewrites a live variable.

    **An expression that may give back the object it was handed is looked through rather than
    trusted to allocate**, as `refinery.lib.scripts.ps1.analysis.identity.object_sources` names
    them. A cast may hand the callee a fresh array built out of what the name holds, and `-as` over
    a value already of the target type converts by nothing at all: measured on 5.1,
    `$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x` writes `3 2 1`, so the call
    turned `$x` itself around, and so does `[Array]::Reverse($x * 1)`. Which of the two such an
    expression does is decided by the operand's runtime type and not by its spelling, so every one
    of them is read as the storage underneath.
    """
    while node is not None:
        if isinstance(node, (Ps1Variable, Ps1MemberAccess, Ps1IndexExpression)):
            return True
        node = object_sources(node).operand
    return False


def _writes_shared_storage(written: Ps1WrittenSlots, arguments: Sequence[Expression]) -> bool:
    """
    Whether a call writes through a slot holding storage something outside the call can already
    reach. Such a call is a side effect; one that writes only temporaries is not, which is what
    separates `[Array]::Reverse('ab'.ToCharArray())` — a junk statement whose result nothing can
    read — from `[Array]::Reverse($buffer)`, which rewrites a live variable.

    Only the slots the call actually writes are looked at, so `[Array]::Copy($live, $scratch, 3)` is
    pure and `[Array]::Copy($scratch, $live, 3)` is not. The table this replaces asked the question
    of every argument at once and called both of them impure.

    A slot this cannot address is answered `True` and not skipped. The receiver is one — it is
    `refinery.lib.scripts.ps1.analysis.arguments.RECEIVER` rather than a position, and the receiver
    is not among *arguments* — and so is a slot outside the call's arity. Skipping either would
    leave a call whose only written slot this cannot see reading as one that writes nothing, and a
    deny table that grants on the slot it failed to read has the polarity of an allow-list.
    """
    return any(
        not 0 <= slot < len(arguments) or _denotes_shared_storage(arguments[slot])
        for slot in written.slots
    )


def _is_writable_reference(node) -> bool:
    """
    Whether an argument hands the callee a `[ref]` to storage it can write back through. A method
    taking one is an out-parameter API — `[Int]::TryParse($s, [ref]$n)` assigns `$n` — so it mutates
    the caller's state no matter how pure the transformation itself is. Every `TryParse` on the
    numeric, date and network types takes one, which is why this is a rule about the argument rather
    than an entry per method.

    Only the syntactic form is recognized. A reference stashed in a variable first
    (`$r = [ref]$n` and then `[Int]::TryParse($s, $r)`) needs dataflow to see, and treating every
    variable argument as a possible reference would make `[Math]::Max($a, $b)` impure.

    Parentheses are transparent: `([ref]$n)` is how the idiom is most often written, and reading the
    cast only at the top level made the whole call look pure.
    """
    while isinstance(node, Ps1ParenExpression):
        node = node.expression
    return is_reference_cast(node) and _denotes_shared_storage(node.operand)


def _writes_through_out_parameter(
    type_name: str,
    member: str,
    arguments: Sequence[Expression],
) -> bool:
    """
    Whether a `[Type]::Member(args)` call hands one of its arguments to a by-reference parameter it
    can write back through, which makes it an out-parameter API no purer than `[Int]::TryParse($s,
    $n)` however pure the transform itself is. The collected signature is consulted over the static
    overloads of that arity: if one marks position *i* as `byref` and `args[i]` denotes shared
    storage, the call may assign it.

    This reads the parameter direction from the data, so it catches a bare `$n` handed to an
    out-parameter that `_is_writable_reference` — which sees only the syntactic `[ref]$n` cast —
    misses. Arity is matched exactly: an optional trailing parameter the call omits simply removes
    that overload from consideration, so the match never over-rejects a shorter call.
    """
    for overload in data.static_overloads(type_name, member):
        parameters = overload.get('parameters') or ()
        if len(parameters) != len(arguments):
            continue
        if any(
            parameter['byref'] and _denotes_shared_storage(argument)
            for parameter, argument in zip(parameters, arguments)
        ):
            return True
    return False


_PURE_INSTANCE_METHODS = frozenset({
    'adddays',
    'addhours',
    'addminutes',
    'addmonths',
    'addseconds',
    'addyears',
    'compareto',
    'contains',
    'endswith',
    'equals',
    'gethashcode',
    'gettype',
    'indexof',
    'lastindexof',
    'length',
    'padleft',
    'padright',
    'split',
    'startswith',
    'substring',
    'tochar',
    'tochararray',
    'tolower',
    'tostring',
    'touniversaltime',
    'toupper',
    'trim',
    'trimend',
    'trimstart',
})

_PURE_CMDLETS = _canonical_command_set({
    'get-childitem',
    'get-command',
    'get-content',
    'get-date',
    'get-item',
    'get-location',
    'get-process',
    'get-random',
    'get-variable',
    'measure-object',
    'out-null',
    'out-string',
    'select-object',
    'sort-object',
    'where-object',
})

#: The pure command whose every call advances a state a script can make observable: measured on 5.1,
#: after `Get-Random -SetSeed 7` the next `Get-Random -Maximum 1000` is 819, and 832 once another
#: call stands between them. So it is pure only where the generator is never seeded; see
#: `refinery.lib.scripts.ps1.analysis.session.Ps1Session.seeded`.
_SEEDABLE_CMDLET = 'get-random'

_PURE_PIPELINE_CMDLETS = _canonical_command_set({
    'foreach-object',
    'select-object',
    'sort-object',
    'where-object',
})


def _argument_values(cmd: Ps1CommandInvocation) -> Iterator[Expression | None]:
    """
    The expression behind every argument of a command, named or positional. A switch parameter
    carries no value and yields `None`.
    """
    for arg in cmd.arguments:
        yield arg.value if isinstance(arg, Ps1CommandArgument) else arg


def _scriptblock_arguments(cmd: Ps1CommandInvocation) -> list[Ps1ScriptBlock]:
    """
    The literal scriptblocks a command is handed, named or positional.
    """
    return [value for value in _argument_values(cmd) if isinstance(value, Ps1ScriptBlock)]


def _arguments_are_pure(
    arguments: Sequence[Expression],
    world: Ps1WorldReach,
) -> bool:
    """
    Whether an argument list is safe to evaluate *and* hands the callee nothing to write back
    through. Both halves have to hold for every call, so they are asked in one place: a `[ref]`
    argument is side-effect free to evaluate and still makes the call an out-parameter API.
    """
    return all(
        not _is_writable_reference(a) and is_side_effect_free(a, world)
        for a in arguments
    )


def _command_arguments_are_pure(
    cmd: Ps1CommandInvocation,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether every non-scriptblock argument of a command is side-effect free. A cmdlet being a pure
    transform says nothing about what its operands cost to evaluate, so
    `Out-String -InputObject (Start-Process x)` is as impure as the call it is handed. Scriptblock
    arguments are excluded because binding one does not run it; that is `_command_body_is_pure`.

    A parameter that `_is_writing_parameter` names is rejected whatever its argument evaluates to:
    the argument is a variable *name* the command writes, not a value it reads. A splatted argument
    is rejected for the same reason one step removed — `Get-Date @options` supplies parameters that
    are not in the source at all, so it can carry `-OutVariable` as easily as `-Format` and there is
    nothing here to judge.
    """
    for arg in cmd.arguments:
        if isinstance(arg, Ps1CommandArgument) and _is_writing_parameter(arg.name):
            return False
        value = arg.value if isinstance(arg, Ps1CommandArgument) else arg
        if value is None or isinstance(value, Ps1ScriptBlock):
            continue
        if isinstance(value, Ps1Variable) and value.splatted:
            return False
        if _is_writable_reference(value) or not is_side_effect_free(value, world):
            return False
    return True


def _cannot_be_a_scriptblock(value) -> bool:
    """
    Whether an argument provably does not carry a scriptblock the command could run. Only literals
    qualify: a variable, a member access or a call result is whatever it was assigned at runtime,
    and a pipeline cmdlet hands exactly such an argument to the engine to invoke per input item.
    """
    return isinstance(value, _NON_BLOCK_EXPRESSIONS)


def _may_name_a_member(value) -> bool:
    """
    Whether an argument could be the string that names the member a `ForEach-Object` invokes. Read
    through `_NON_MEMBER_EXPRESSIONS`, so an unrecognized form counts as a member name rather than
    as proof there is none.
    """
    if value is None or isinstance(value, Ps1ScriptBlock):
        return False
    return not isinstance(value, _NON_MEMBER_EXPRESSIONS)


def _block_runs_only_its_body(block: Ps1ScriptBlock) -> bool:
    """
    Whether every statement a scriptblock runs is one that `refinery.lib.scripts.ps1.ast.get_body`
    reports. A `begin`/`process`/`end` block and a `param` block are code that it does not report —
    the parser fills either those or `body`, never both — so a caller that judges a block by `body`
    alone judges an empty list and proves nothing about `| ForEach-Object { end { Remove-Item $p }}`
    or `| ForEach-Object { param($p = (Start-Process x)) [Void]$_ }`. This is the hole that
    `body_is_inert` guards for a function body, asked of a block handed to a command.
    """
    return not get_named_blocks(block) and get_param_block(block) is None


def _invokes_a_member(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether a `ForEach-Object` carries its work as a member to call rather than as a scriptblock.
    The member is named by a string argument — `-MemberName Kill` and the positional
    `| ForEach-Object Kill` are the same call — and nothing static says what that member does, so no
    inspection of the blocks beside it proves anything about it.

    The question is therefore asked of the arguments, never of whether a block happened to be seen:
    `| ForEach-Object { [Void]$_ } -MemberName Delete` has a block *and* invokes a member, so
    reading the answer off the block would let a discarding body vouch for the deletion sitting next
    to it.

    A `ForEach-Object` with no scriptblock at all is the same answer with the argument unread: there
    is no body to prove anything from.

    The parser reports `-Name value` as a switch followed by a positional argument and binds no
    values to parameter names, so the argument a member name sits in is not knowable here. Every
    non-numeric argument therefore counts, and `| ForEach-Object { [Void]$_ } -ErrorAction Stop`
    is rejected along with the member forms. That over-rejection keeps junk; distinguishing the two
    needs the parameter positions and types that `refinery.lib.scripts.ps1.data` does not carry.
    """
    name = get_command_name(cmd)
    if name is None or name.lower() != 'foreach-object':
        return False
    if not any(isinstance(value, Ps1ScriptBlock) for value in _argument_values(cmd)):
        return True
    return any(_may_name_a_member(value) for value in _argument_values(cmd))


def _runs_only_visible_blocks(cmd: Ps1CommandInvocation) -> bool:
    """
    Whether every piece of work a pipeline cmdlet could run is a literal scriptblock this module can
    read. These cmdlets take their work through their arguments, so an argument that is neither a
    readable block nor provably blockless hides code: `| Where-Object $filter` and
    `| ForEach-Object { [Void]$_ } -End $sb` both run whatever the variable holds,
    `_invokes_a_member` covers the member form, and a block whose statements sit in a named or
    `param` block is one `_block_runs_only_its_body` refuses to call readable.

    Every caller that judges such a command by the blocks it can see has to ask this first, or it
    decides on a body it was never shown.
    """
    if _invokes_a_member(cmd):
        return False
    return all(
        value is None
        or _cannot_be_a_scriptblock(value)
        or (isinstance(value, Ps1ScriptBlock) and _block_runs_only_its_body(value))
        for value in _argument_values(cmd)
    )


def _command_body_is_pure(
    cmd: Ps1CommandInvocation,
    world: Ps1WorldReach,
) -> bool:
    """
    Check whether all script block arguments of a pipeline cmdlet (ForEach-Object, Where-Object,
    etc.) have side-effect-free bodies. These cmdlets are pure transforms: they evaluate a script
    block per input item without mutating state themselves.

    A scriptblock body is a sequence of statements, so it is `statement_effect` that decides, not
    the expression-level `is_side_effect_free`: a body of `$Null = <pure>` or `[Void]<pure>`
    discards is as harmless as one of bare pure expressions, and only the statement layer knows
    that. The mutual recursion between the two terminates because a body is strictly nested inside
    the command it belongs to.

    The blocks have to be all of the work to be worth reading, which is `_runs_only_visible_blocks`.
    A command that also hides work behind an argument proves nothing here however pure its visible
    bodies are.
    """
    if not _runs_only_visible_blocks(cmd):
        return False
    return not any(
        statement_effect(stmt, world) is StatementEffect.EFFECT
        for block in _scriptblock_arguments(cmd)
        for stmt in block.body
    )


def _reflection_read_is_pure(type_key: Ps1TypeName, member: str) -> bool:
    """
    Whether reading `member` off a value of the single .NET type `type_key` runs no code and cannot
    throw. An uncollected type is never pure: nothing is known about its surface, so a getter that
    shells out cannot be ruled out. On a collected type an Extended Type System member runs arbitrary
    PowerShell and is impure. An *instance* field is a bare memory slot with no getter, so reading
    one is pure whatever the type. A *static* field is not: its first read runs the declaring type's
    static constructor (`beforefieldinit` relaxes the timing, not the fact), so it is gated like a
    property — as is a property, whose getter may run code (`Process.Path` shells out). Both are pure
    only when the whole read surface is granted (`_PURE_READ_TYPES`) or the specific read is
    (`_PURE_READS`). A member the type does not carry reads as `$null` and is pure — but only on a
    sealed value type, because a candidate that is an imprecise supertype would otherwise vouch for a
    read its runtime subtype does carry.

    A member the object adapter supplies (`source == 'engine'`) is read off the adapter rather than
    off the type, so no getter of the type's own runs. What could still make it run one is the
    runtime value being a *subtype* that carries a real member of that name, which the collected
    record for the static type would then not be describing — so a sealed type settles it and is the
    condition. An absent member needs more than that, and keeps the narrower
    `_PURE_READ_TYPES` gate: reading one yields `$null` only while nothing has *added* the member,
    and a module's `types.ps1xml` can add one to a sealed reference type.
    """
    record = data.member_record(type_key, member)
    surface = type_key.generic_definition
    if record is data.MemberLookup.UNCOLLECTED:
        return False
    if record is data.MemberLookup.ABSENT:
        return surface in _PURE_READ_TYPES
    if record['source'] == 'engine':
        return surface in _PURE_READ_TYPES or data.type_is_sealed(type_key)
    if record['source'] in ('ets', 'wmi'):
        return False
    if record['kind'] == 'field' and record.get('static') is False:
        return True
    if record['kind'] in ('field', 'property'):
        return surface in _PURE_READ_TYPES or (surface, member.lower()) in _PURE_READS
    return False


def _member_read_is_pure(obj, member: str, world: Ps1WorldReach) -> bool:
    """
    Whether reading the named `member` off `obj` has no side effect, decided over every type
    `refinery.lib.scripts.ps1.analysis.values.candidate_types` says `obj` could carry. The read is
    pure only when it is pure for *all* of them: a method return or cmdlet output may be one of
    several types, and a value that could be any of them must be safe whichever it is. An empty
    candidate set — `obj`'s type is unknown — is never pure, since an unknown object could be a type
    whose getter runs code.
    """
    candidates = candidate_types(obj, world)
    return bool(candidates) and all(
        _reflection_read_is_pure(candidate, member) for candidate in candidates
    )


def _grant(verdict: bool, node, world: Ps1WorldReach) -> bool:
    """
    A present-member or present-type purity grant, conditioned on the type world being closed at
    `node`. Every branch of `is_side_effect_free` that returns `True` because a member, static
    method or constructor resolves to a known-pure .NET operation routes its verdict through here:
    the grant holds only when no code that runs *before this node* could have shadowed that member
    through the Extended Type System or remapped its type name through an accelerator, which is
    `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach.closed_at`. A world open at the node
    answers `False`, so such a caller keeps the access — even when the world is closed elsewhere in
    the same script. An impurity *deny* is never routed through here; it holds unconditionally.
    """
    return verdict and world.closed_at(node)


#: The one variable whose read is not a read. `$input` names the enumerator over a function's
#: pipeline input, and enumerating it advances it: measured on 5.1, `function f { $input; $input |
#: ForEach-Object { $_ } }` fed `1, 2` writes `1` and `2` once, because the bare read drained what
#: the pipeline below it would have enumerated. Only the enumerating spellings consume —
#: `[Void]$input` and `$Null = $input` leave it whole, both measured — but the name is denied
#: whole rather than per context, because a rule that reads the surrounding shape would have to
#: be right about every spelling to stay sound and is only ever asked in the granting direction.
_ENUMERATOR_VARIABLE = 'input'


def _reads_the_pipeline_enumerator(node: Ps1Variable) -> bool:
    """
    Whether *node* is the unqualified `$input`, whose evaluation may advance the enumerator the rest
    of the body reads — see `_ENUMERATOR_VARIABLE`.
    """
    return (
        node.scope is Ps1ScopeModifier.NONE
        and node.name.lower() == _ENUMERATOR_VARIABLE
    )


def is_side_effect_free(node, world: Ps1WorldReach) -> bool:
    """
    Conservative check: return `True` only when evaluating `node` is guaranteed to produce no
    observable side effects beyond yielding a value. The `world` decides whether a present-member
    grant may be trusted and whether a command name still denotes what the metadata says, each at
    the position of the node it is asked about: a world opened, or a name rebound, only by
    statements no path places before the node still answers for it.

    A variable read is one of the few things that is free of its own accord, and `$input` is the
    exception the grant has to name: reading it advances an enumerator the statements below it read,
    so a statement whose only content is that read still changes what the next one writes.
    """
    if isinstance(node, _LITERAL_EXPRESSIONS):
        return True
    if isinstance(node, Ps1TypeExpression):
        return True
    if isinstance(node, Ps1Variable):
        return not _reads_the_pipeline_enumerator(node)
    if isinstance(node, Ps1ParenExpression):
        return node.expression is None or is_side_effect_free(node.expression, world)
    if isinstance(node, Ps1CastExpression):
        # A cast is a conversion the engine performs by calling into the target type, so it is a
        # present-type grant like any other: a remapped accelerator invalidates it, and a name the
        # metadata cannot resolve is not a type this analysis knows anything about. `Add-Type`, a
        # PowerShell `class` and `[Reflection.Assembly]::Load` all make such a name denote code —
        # PowerShell converts a string to it by running a constructor — so granting on the operand
        # alone would delete a call that runs one. Resolving is necessary here, not sufficient: a
        # conversion to a collected type can still run code (`[xml]$s` parses, and follows external
        # DTDs), which `_PURE_CAST_TYPES` is the eventual answer to. The world is read before either
        # check because it is a stored bool that can only veto, while both checks below walk.
        if not world.closed_at(node):
            return False
        if data.resolve_type(node.type_name) is None:
            return False
        return is_side_effect_free(node.operand, world)
    if isinstance(node, Ps1UnaryExpression):
        if node.operator in ('++', '--'):
            return False
        return is_side_effect_free(node.operand, world)
    if isinstance(node, Ps1BinaryExpression):
        # The regex operators write the automatic `$Matches`, which the statements after them read;
        # that is a store to shared engine state, not a value the expression merely yields, so the
        # operator has to be read and not just the operands. Deleting `$s -match 'p(.*)q'` left the
        # `$Matches[1]` that carries the payload reading an unset variable.
        if node.operator.lower() in MATCH_OPERATORS:
            return False
        return is_side_effect_free(node.left, world) and is_side_effect_free(node.right, world)
    if isinstance(node, Ps1RangeExpression):
        return is_side_effect_free(node.start, world) and is_side_effect_free(node.end, world)
    if isinstance(node, Ps1ArrayLiteral):
        return all(is_side_effect_free(e, world) for e in node.elements)
    if isinstance(node, Ps1HashLiteral):
        return all(
            is_side_effect_free(key, world) and is_side_effect_free(value, world)
            for key, value in node.pairs
        )
    if isinstance(node, Ps1ArrayExpression):
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                return is_side_effect_free(stmt.expression, world)
        return len(node.body) == 0
    if isinstance(node, Ps1IndexExpression):
        # Indexing selects the `Item` member, so it is the bracket spelling of the member read
        # below and carries the same Extended Type System exposure.
        pure = is_side_effect_free(node.object, world) and is_side_effect_free(node.index, world)
        return _grant(pure, node, world)
    if isinstance(node, Ps1MemberAccess):
        # A read is side-effect free only when the object is pure to evaluate *and* selecting the
        # member runs no code. Returning the object's own purity would clear `(Get-Process).Path`,
        # an Extended Type System getter that shells out, because the pipeline that produced the
        # object was itself pure. A literal member name —
        # bare (`.Path`) or quoted (`.'Path'`) — names one member the gate can check; a computed
        # member name (`$x.$(...)`) leaves the selected member unknown, so a read through it can
        # never be proven pure however pure the name expression is.
        if not is_side_effect_free(node.object, world):
            return False
        member = get_member_name(node.member)
        if member is None:
            return False
        return _grant(_member_read_is_pure(node.object, member, world), node, world)
    if isinstance(node, Ps1InvokeMember):
        if not _arguments_are_pure(node.arguments, world):
            return False
        if node.access == Ps1AccessKind.STATIC:
            obj = node.object
            member = node.member
            # A computed or quoted member name (`[IO.Path]::$m()`, `[IO.Path]::'GetTempFileName'()`)
            # cannot be matched against the carve-outs, so the whole-type grant below must not fire
            # for it either — that is how an obfuscated call reaches the one writing member of an
            # otherwise pure type.
            if isinstance(obj, Ps1TypeExpression) and isinstance(member, str):
                # The type name is resolved through the collected metadata, not truncated, so every
                # spelling of a type lands on one canonical key, and a type the data does not
                # describe resolves to nothing and falls through to impure: the fail-closed default.
                resolved = data.resolve_type(obj.name)
                if resolved is not None:
                    type_key = resolved.generic_definition
                    key = (type_key, member.lower())
                    if key in _IMPURE_STATIC_METHODS:
                        return False
                    written = written_slots(
                        resolved, member, len(node.arguments), static=True)
                    if written.slots:
                        return _grant(
                            not _writes_shared_storage(written, node.arguments), node, world)
                    if not written.settled:
                        # The table names the member and no overload takes this many arguments, so
                        # 5.1 binds none and raises. Granting purity here would let the junk remover
                        # delete a statement that writes an error record and stops the pipeline.
                        return False
                    if _writes_through_out_parameter(obj.name, member, node.arguments):
                        return False
                    if type_key in _PURE_STATIC_METHOD_TYPES:
                        return _grant(True, node, world)
                    if key in _PURE_STATIC_METHODS:
                        return _grant(True, node, world)
        elif is_side_effect_free(node.object, world):
            member = node.member
            if isinstance(member, str) and member.lower() in _PURE_INSTANCE_METHODS:
                return _grant(True, node, world)
        return False
    if isinstance(node, Ps1CommandInvocation):
        if node.redirections:
            return False
        new_object = extract_new_object(node)
        if new_object is not None:
            if not world.may_trust_command_name_at('new-object', node):
                return False
            type_name, ctor_args = new_object
            resolved = data.resolve_type(type_name)
            if (
                resolved is not None
                and resolved.generic_definition in _PURE_STATIC_METHOD_TYPES
            ):
                return _grant(_arguments_are_pure(ctor_args, world), node, world)
            return False
        name = get_command_name(node)
        if name is None:
            return False
        name = name.lower()
        # A command a reachable statement may have rebound no longer surely runs what the metadata
        # describes, so its purity is not the built-in's. The gate is positional — the same check as
        # `_grant` below — trusting the name only where no opener and no redefinition of this very
        # name can have run first.
        if not world.may_trust_command_name_at(name, node):
            return False
        # The pipeline set is checked through the same gate rather than after the plain one: three
        # of its four members are in both, so testing the plain set first would make the body check
        # below unreachable for `Where-Object`, `Select-Object` and `Sort-Object`.
        if name not in _PURE_CMDLETS and name not in _PURE_PIPELINE_CMDLETS:
            return False
        if name == _SEEDABLE_CMDLET and session_of(node).seeded:
            return False
        if not _command_arguments_are_pure(node, world):
            return False
        # Routed through `_grant` like every other grant. `may_trust_command_name_at` above refuses
        # a name a rebinding statement can reach; `_grant` here refuses a member the type world
        # does not hold at this node. The two check different hazards — the name gate adds the
        # per-name rebinding the type axis never reads — so a name that passed the first is still
        # gated on the second, and narrowing either check back into the other would reopen a
        # fail-open hole with nothing in the path to catch it.
        if name in _PURE_PIPELINE_CMDLETS:
            return _grant(_command_body_is_pure(node, world), node, world)
        return _grant(True, node, world)
    if isinstance(node, Ps1Pipeline):
        return all(
            isinstance(el, Ps1PipelineElement)
            and not el.redirections
            and is_side_effect_free(el.expression, world)
            for el in node.elements
        )
    if isinstance(node, Ps1ExpandableString):
        return all(is_side_effect_free(p, world) for p in node.parts)
    return False


def may_be_dropped(node, world: Ps1WorldReach) -> bool:
    """
    Whether an expression the script evaluates may be deleted without changing what the script does.

    This is the question a rewrite asks about the parts it does not carry forward: the elements a
    selection indexes past, which building the container evaluated all the same. Both axes are
    asked, and neither answers for the other in principle. `is_side_effect_free` rules out
    `$x++` and `(Start-Process calc)` — work the folded script would stop doing.
    `is_fault_free` rules out `[Int]'abc'`, which raises where it stands, so
    `try { $r = @(1, [Int]'abc')[0] } catch { <payload> }` keeps a handler the drop would otherwise
    leave unreachable.

    **The fault half is still the narrower of the two, and it is the only one a test can see
    refuse.** What `is_fault_free` grants is a constant, a container of constants, and whatever the
    value domain can compute — none of which does anything — so it goes on refusing everything
    purity refuses and more. Purity is asked anyway because that containment is a fact about what
    the two currently reach rather than about the question, and the fault half has already been
    widened once: the domain arm admits `6 * 7` and `[Int]'42'`, and an arm admitting an increment
    on a variable it has typed would start answering yes to work. The conjunction lives here, under
    one name, so that the guard a caller installs is one thing a probe can mutate rather than a pair
    whose second half nothing can be shown to notice.
    """
    return is_side_effect_free(node, world) and is_fault_free(node)


class StatementEffect(enum.Enum):
    """
    The observable effect of evaluating a standalone statement, used by every pass that decides
    whether a statement can be pruned from a body:

    - `EFFECT`: the statement performs a side effect (a command call, a store to a real variable, an
      increment); it must be preserved.
    - `OUTPUT`: the statement is side-effect-free but yields a value to the enclosing pipeline (a
      bare constant, a pure expression); it is junk at a discarding position, but in a captured body
      it may be the return value, so removing it needs an emit-safety check.
    - `DISCARD`: the statement is a syntactic no-op that yields nothing and does nothing observable
      (an empty statement, the `$Null = <pure>` and `[Void]<pure>` discard idioms, an `Out-Null`
      pipeline, a discarding `ForEach`); it is always safe to remove, even when it empties the body.

    A discard idiom throws away a *value*, never the work that produced it: every one of them is
    recognized only over an operand that `is_side_effect_free` accepts, so `[Void](Start-Process x)`
    is an `EFFECT` like any other call.

    `EFFECT` deliberately says nothing about emission, and splitting it into an emitting and a
    silent member would not pay: a silent `EFFECT` is still un-removable, so every consumer would
    grow a branch to reach the verdict it already reaches. `Write-Host x` and `Get-Item x` are both
    `EFFECT`, and nothing here distinguishes them because nothing needs to.

    Nor does any member say whether the statement can *throw*. That is
    `refinery.lib.scripts.ps1.analysis.raising`, which a caller about to remove an `OUTPUT`
    statement has to ask separately: `[Int]'abc'` and
    `1/0` are both `OUTPUT`, and removing either resumes a script that had terminated.
    """
    EFFECT = 'effect'
    OUTPUT = 'output'
    DISCARD = 'discard'


def _emits_nothing(expr, world: Ps1WorldReach) -> bool:
    """
    Whether evaluating *expr* as a standalone statement writes nothing to the output stream.

    PowerShell writes the value of a bare expression statement to the output stream, so a statement
    emits exactly what its expression produces — and a method declared to return `System.Void`
    produces no value at all. `[Array]::Reverse($a)` is the shape: it reverses the array and yields
    nothing, so a script that writes it as a statement is writing a mutation, never an output.

    **Only a static call is read**, because only a static call has a receiver the resolver can name:
    an instance method would need its receiver's type traced and its overloads selected by argument
    type, and a guess there is a claim about emission that no measurement backs.

    **The rule is the candidate set, not a walk over the overloads.** Asking whether every overload
    returns void is vacuously true of a member the metadata does not know, which would call an
    unknown call silent; asking whether the set of types the call may produce is exactly
    `{System.Void}` says the same thing about a known member and says nothing about an unknown one,
    because a member with no metadata contributes the empty set.

    This is emission alone and answers nothing about faults or effects. `[Console]::WriteLine('x')`
    returns void and writes to the host, and what keeps it out of this is the impurity deny its
    caller asks first; `[Array]::Clear` returns void and throws on a bad index, and what keeps
    *that* honest is the removal veto, which asks where the error would go.
    """
    if not isinstance(expr, Ps1InvokeMember) or expr.access is not Ps1AccessKind.STATIC:
        return False
    return {name.name for name in candidate_types(expr, world)} == {'System.Void'}


def statement_effect(stmt, world: Ps1WorldReach) -> StatementEffect:
    """
    Classify the observable effect of a standalone statement as a `StatementEffect`. This is the one
    shared authority the dead-code and junk-removal passes consult so they never disagree about
    whether a statement carries a body's output: a `DISCARD` emits nothing, an `OUTPUT` yields a
    value that emit-safety must protect in a captured body, and an `EFFECT` must always be kept.

    **`DISCARD` is a claim about emission and about nothing else.** A call returning `System.Void`
    emits nothing and can still throw, so what decides whether dropping it changes anything is the
    removal veto — `deletion_is_observable` — and not this.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return StatementEffect.EFFECT
    expr = stmt.expression
    if expr is None:
        return StatementEffect.DISCARD
    if is_void_cast(expr):
        if is_side_effect_free(expr.operand, world):
            return StatementEffect.DISCARD
        return StatementEffect.EFFECT
    if isinstance(expr, Ps1Pipeline):
        # The prefix is walked exactly once and every branch below is derived from that one answer.
        # Asking `_pipeline_prefix_is_pure` per idiom and then falling through to
        # `is_side_effect_free(expr)` re-walks the same elements, and because a pipeline cmdlet
        # body re-enters here through `_command_body_is_pure`, that doubling compounds into 2^depth
        # work on the nested `... | ForEach-Object { ... } | Out-Null` shape.
        prefix_is_pure = _pipeline_prefix_is_pure(expr, world)
        if prefix_is_pure and (
            _pipeline_ends_with_out_null(expr, world)
            or _pipeline_ends_with_void_foreach(expr, world)
        ):
            return StatementEffect.DISCARD
        if _pipeline_ends_with_cmdlet(expr, _PURE_PIPELINE_CMDLETS):
            # A pure pipeline cmdlet (`... | Where-Object {...}`) yields a filtered value a caller
            # may consume, so it is kept even though it performs no side effect of its own.
            return StatementEffect.EFFECT
        if prefix_is_pure and _pipeline_final_is_pure(expr, world):
            return StatementEffect.OUTPUT
        return StatementEffect.EFFECT
    if is_null_discard(expr):
        if expr.value is not None and is_side_effect_free(expr.value, world):
            return StatementEffect.DISCARD
        return StatementEffect.EFFECT
    if is_side_effect_free(expr, world):
        if _emits_nothing(expr, world):
            return StatementEffect.DISCARD
        return StatementEffect.OUTPUT
    return StatementEffect.EFFECT


def _terminal_invocation(pipeline: Ps1Pipeline) -> Ps1CommandInvocation | None:
    """
    The unredirected command invocation that terminates a multi-element pipeline, else `None`. A
    single-element pipeline has no terminator in this sense: there is no upstream value for it to
    consume.
    """
    if len(pipeline.elements) < 2:
        return None
    last = pipeline.elements[-1]
    if not isinstance(last, Ps1PipelineElement) or last.redirections:
        return None
    expr = last.expression
    if not isinstance(expr, Ps1CommandInvocation) or expr.redirections:
        return None
    return expr


def _terminal_command(pipeline: Ps1Pipeline, name: str) -> Ps1CommandInvocation | None:
    """
    The invocation that terminates a pipeline when it is an unredirected call to `name`, written
    under exactly that spelling, else `None`.
    """
    expr = _terminal_invocation(pipeline)
    if expr is None:
        return None
    command = get_command_name(expr)
    if command is None or command.lower() != name:
        return None
    return expr


def _pipeline_ends_with_out_null(
    pipeline: Ps1Pipeline,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether a pipeline is terminated by an `Out-Null` that throws its input away *and* costs nothing
    to reach. The terminator's own arguments are part of the question:
    `... | Out-Null -InputObject (Start-Process x)` runs the call it is handed, so it discards a
    value the pipeline never carried and is not a junk sink.
    """
    out_null = _terminal_command(pipeline, 'out-null')
    if out_null is None or not world.may_trust_command_name_at('out-null', out_null):
        return False
    return _command_arguments_are_pure(out_null, world)


def _pipeline_prefix_is_pure(
    pipeline: Ps1Pipeline,
    world: Ps1WorldReach,
) -> bool:
    for el in pipeline.elements[:-1]:
        if not isinstance(el, Ps1PipelineElement) or el.redirections:
            return False
        if not is_side_effect_free(el.expression, world):
            return False
    return True


def _pipeline_final_is_pure(
    pipeline: Ps1Pipeline,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether the last element of a pipeline is side-effect free. Together with
    `_pipeline_prefix_is_pure` this is the purity of the whole pipeline, split so that a caller
    which already knows about the prefix does not walk it a second time.
    """
    if not pipeline.elements:
        return True
    last = pipeline.elements[-1]
    return (
        isinstance(last, Ps1PipelineElement)
        and not last.redirections
        and is_side_effect_free(last.expression, world)
    )


def _pipeline_ends_with_void_foreach(
    pipeline: Ps1Pipeline,
    world: Ps1WorldReach,
) -> bool:
    """
    Detect junk pipelines like `... | ForEach-Object { [Void]$_ }` or
    `... | ForEach-Object { $Null = $_ }` where the ForEach body explicitly discards all output.
    These are anti-analysis noise injected into malware scripts. Whether a body statement discards
    is `statement_effect`'s answer rather than a second copy of the idiom table, so a discard of a
    value that is not itself side-effect free does not count — the body

        ForEach-Object { [Void](Start-Process x) }

    discards the result of a call that still happens.

    A `ForEach-Object` that carries work no block accounts for is not a match, whether that work is
    a member to invoke (`| ForEach-Object { [Void]$_ } -MemberName Delete`) or a block a variable
    holds (`| ForEach-Object { [Void]$_ } -End $sb`). That is `_runs_only_visible_blocks`, asked
    here for the same reason `_command_body_is_pure` asks it: the discards below prove a property of
    the blocks they saw, and a body that was never shown is not among them.
    """
    foreach = _terminal_command(pipeline, 'foreach-object')
    if foreach is None or not world.may_trust_command_name_at('foreach-object', foreach):
        return False
    if not _command_arguments_are_pure(foreach, world):
        return False
    if not _runs_only_visible_blocks(foreach):
        return False
    blocks = _scriptblock_arguments(foreach)
    return bool(blocks) and all(
        statement_effect(stmt, world) is StatementEffect.DISCARD
        for block in blocks
        for stmt in block.body
    )


def _pipeline_ends_with_cmdlet(pipeline: Ps1Pipeline, names: frozenset[str]) -> bool:
    expr = _terminal_invocation(pipeline)
    if expr is None:
        return False
    name = get_command_name(expr)
    return name is not None and name.lower() in names


class OutputSink(enum.Enum):
    """
    Who reads what a statement body writes to the output stream. Every pruning pass has to answer
    this before it removes anything, because in PowerShell a statement that merely yields a value
    has written to that stream:

    - `HOST`: the user sees it. The script root, and every plain block that propagates outward to
      it — a loop or `if` body, a `trap`, a `finally`, a `switch` clause, a bare `&{ ... }` in
      statement position at script level.
    - `CALLER`: a function's caller sees it. Only a function, `filter` or class method body is this
      boundary, along with everything nested inside one.
    - `CAPTURED`: something other than a reader holds it — an assignment right-hand side,
      `$( ... )`, `@( ... )`, a `data` section, a stored or argument scriptblock, an upstream
      pipeline position, a redirection to a file. The body is never pruned at all, so no statement
      in it is ever weighed.

    `CALLER` is not a destination, it is a deferral: it says the value leaves this body and nothing
    about where it lands. `Ps1OutputFlow` resolves it into one of the other two by reading every
    call site, and `Ps1OutputFlow.resolved` therefore never answers `CALLER`. Only `output_path` and
    `output_sink`, the positional question, do — and a caller that reads that answer as a
    destination is guessing.

    Position is the wrong question: the same block propagates to a different reader depending on
    what encloses it, and only the walk outward answers that.
    """
    HOST = 'host'
    CALLER = 'caller'
    CAPTURED = 'captured'


def _redirection_takes_output_away(
    redirection: Ps1FileRedirection | Ps1MergingRedirection,
) -> bool:
    """
    Whether a single redirection moves the output stream somewhere the enclosing body cannot see it.
    A file redirection of `OUTPUT` or of `ALL` (`>`, `>>`, `*>`) writes the values to disk; a merge
    carries them into whichever stream it names, so it takes them away exactly when it reads *from*
    output and writes somewhere that is not output.

    The direction is what decides this, and reading the wrong end inverts the answer on the common
    forms: `2>&1` and `3>&1` merge another stream *into* output and leave emission untouched, while
    `1>&2` is the one that silences it. `*>&1` names `ALL` as its source, which includes output
    merged onto itself, so it is not a removal either.
    """
    if isinstance(redirection, Ps1FileRedirection):
        return redirection.stream in (Ps1RedirectionStream.OUTPUT, Ps1RedirectionStream.ALL)
    return (
        redirection.from_stream in (Ps1RedirectionStream.OUTPUT, Ps1RedirectionStream.ALL)
        and redirection.to_stream is not Ps1RedirectionStream.OUTPUT
    )


def takes_output_away(node) -> bool:
    """
    Whether any redirection written on `node` moves its output somewhere the enclosing body cannot
    see it. Where a merge and a file redirection are written together (`2>&1 > C:\\log`), the file
    redirection is still a removal and any one of them is enough to answer yes.

    The redirection list is read off the node rather than matched against the node types the model
    declares as carriers, because only one of the two is ever filled: the parser writes every
    redirection onto the command invocation and constructs `Ps1PipelineElement` without one, so a
    guard spelled against the element is dead however it is written. Reading by name keeps this
    right whichever carrier the parser starts using, and the failure of the alternative is
    asymmetric — a carrier this did not recognize would report that the output propagates, which is
    the answer that deletes a payload into a file.
    """
    return any(_redirection_takes_output_away(r) for r in getattr(node, 'redirections', ()))


def _redirection_opens_a_file(redirection) -> bool:
    """
    Whether a single redirection opens a file on disk.

    `> $Null` is PowerShell's discard and creates nothing: the shell special-cases the automatic
    variable rather than writing a file of that name. Every other target is read as a path,
    including one this cannot evaluate, because a target it does not understand is a file it cannot
    promise is absent.
    """
    if not isinstance(redirection, Ps1FileRedirection):
        return False
    return not is_builtin_variable(unwrap_parens(redirection.target), {'null'})


def opens_a_redirection_target(node) -> bool:
    """
    Whether any redirection written on `node` opens a file. PowerShell creates or truncates the
    target as it sets the redirection up, whatever the command then writes, so `j > log` touches the
    disk even when `j` does nothing at all.

    The stream is deliberately not consulted, which is what separates this from
    `_redirection_takes_output_away`: `2> err.txt` creates its file exactly as `> out.txt` does, and
    a caller asking whether a statement is nothing but a call has to know about both. A merge names
    no file and is not one of these — `j 2>&1` on a silent command really is a no-op — and neither
    is a discard, which is why the target is read rather than the node type alone.
    """
    return any(_redirection_opens_a_file(r) for r in getattr(node, 'redirections', ()))


def unconsumed_statement(expr: Node) -> Ps1ExpressionStatement | None:
    """
    The statement whose output is exactly what `expr` yields — `expr` standing alone as an
    expression statement, or as the sole element of a statement-level pipeline — or `None` when the
    value is consumed on the way out: by an assignment, an argument, a longer pipeline, or a
    redirection that writes the output stream elsewhere.

    **This is not a capture test**, and the two are one walk apart. `$r = @(f)` and `$r = $(f)` hold
    `f` as a whole statement, so this answers with that statement while the value is very much
    captured — by the `@( ... )` around the *body* the statement sits in, which only the outward
    walk in `output_path` sees. Reading this as "the value escapes" would mark an assigned call
    discardable.

    What it does answer is where the value goes *next*, which is why the redirections are read here:
    `f > out.txt` yields nothing to the body around it, and a caller that judges it by shape alone
    deletes the call together with the file it writes.
    """
    if takes_output_away(expr):
        return None
    parent = expr.parent
    if isinstance(parent, Ps1ExpressionStatement):
        return parent
    if isinstance(parent, Ps1PipelineElement):
        if takes_output_away(parent):
            return None
        pipeline = parent.parent
        if (
            isinstance(pipeline, Ps1Pipeline)
            and len(pipeline.elements) == 1
            and isinstance(pipeline.parent, Ps1ExpressionStatement)
        ):
            return pipeline.parent
    return None


def _scriptblock_is_captured(block: Ps1ScriptBlock) -> bool:
    """
    Return `True` when the value of a `refinery.lib.scripts.ps1.model.Ps1ScriptBlock` is captured
    rather than run for its observable output. A bare `&{ ... }` / `.{ ... }` in statement position
    produces output that the pass may prune into; every other scriptblock (a stored closure
    `$x = { ... }`, an argument block, or an invocation whose result is assigned, passed, piped or
    redirected) is treated as captured and left opaque.
    """
    parent = block.parent
    if isinstance(parent, Ps1FunctionDefinition):
        return False
    if not (isinstance(parent, Ps1CommandInvocation) and parent.name is block):
        return True
    return unconsumed_statement(parent) is None


def _feeds_downstream(element: Ps1PipelineElement) -> bool:
    """
    Whether a pipeline element hands its output to the element after it rather than out of the
    pipeline. Only the last element's output leaves, which is what makes `f | Out-Null` a capture of
    `f` and not a bare call to it.
    """
    pipeline = element.parent
    if not isinstance(pipeline, Ps1Pipeline) or not pipeline.elements:
        return True
    return element is not pipeline.elements[-1]


class Ps1OutputPath(NamedTuple):
    """
    Where the value written at some point in the tree is read, as far as position alone can say.
    `function` is the definition whose body was left on the way out, and is set exactly when `sink`
    is `OutputSink.CALLER`: it is the handle `Ps1OutputFlow` needs to carry the question across the
    boundary that position cannot see past.

    `guarded` is set when the outward walk left a `trap` or `catch` body — a handler that runs only
    when the region it guards faults. Such a body's value reaches `sink` on the fault path and not the
    normal one, so a caller pruning normal-path console noise must leave it alone: it is emitted
    exactly when the handler fires, which the position of the handler statement cannot say. A
    `finally` body is not guarded, because it runs whether or not the region faults.
    """
    sink: OutputSink
    function: Ps1FunctionDefinition | None
    guarded: bool = False


def _output_writes_through(cursor, prev) -> bool:
    """
    Whether `cursor` hands the value produced at `prev` on to whatever encloses it, rather than
    being the thing that reads it.

    **This is an allow-list of propagating positions.** The walk that reads it answers for any node
    in the tree, so a position this does not recognize is a position whose reader is unknown, and
    the answer to an unknown reader is `CAPTURED` — the one that prunes nothing. Enumerating the
    *consumers* instead and propagating by default is the inverse, and it deletes payloads: every
    value slot such an enumeration missed — a command argument, an `if` condition, a `foreach`
    source, an index, a `param` default — reads as a value nobody holds, so the function called
    there is judged to write only to the console and the bare values in its body are deleted.

    A `refinery.lib.scripts.Block` is only ever a write-through statement list: an `if` branch, a
    loop or `switch` body, a `try`, `catch` or `finally` body, a `trap` body. The two spellings that
    are not — the body of a `data` section and a named block of a script block — are answered by
    their holder before the walk reaches here. `Ps1CatchClause` is the one clause node standing
    between such a block and the construct holding it.

    `return` is the one `refinery.lib.scripts.ps1.model.Ps1Exit` that propagates: its value is what
    the enclosing body yields. `throw` and `exit` name no value the body writes and are left to the
    default answer.
    """
    if isinstance(prev, (Block, Ps1CatchClause)):
        return True
    if isinstance(cursor, (Ps1ExpressionStatement, Ps1ParenExpression)):
        return cursor.expression is prev
    if isinstance(cursor, Ps1ReturnStatement):
        return cursor.pipeline is prev
    if isinstance(cursor, Ps1CommandInvocation):
        return isinstance(prev, Ps1ScriptBlock) and cursor.name is prev
    if isinstance(cursor, Ps1Pipeline):
        return isinstance(prev, Ps1PipelineElement) and not _feeds_downstream(prev)
    if isinstance(cursor, Ps1PipelineElement):
        return cursor.expression is prev and not _feeds_downstream(cursor)
    body = get_body(cursor)
    return body is not None and prev in body


def output_path(node) -> Ps1OutputPath:
    """
    Walk outward from `node` until something *reads* the value written there, stepping past only the
    positions `_output_writes_through` recognizes. A function boundary answers `CALLER`, the script
    root answers `HOST`, and everything else — a value slot, a redirection, an upstream pipeline
    position, and every position the allow-list does not name — answers `CAPTURED`.

    So the same node answers differently depending on where it sits, by design:

        if ($x) { 1 }                    at script level  ->  HOST
        function f { if ($x) { 1 } }                      ->  CALLER
        &{ if ($x) { 1 } }               at script level  ->  HOST

    Ambiguous capture resolves to `CAPTURED`, which is the answer that prunes nothing.

    This takes any node and not only a body owner, because the same walk answers both questions that
    need it: where a body's output goes, and where the value produced by one call site goes. Asking
    it of a call site is what lets `Ps1OutputFlow` resolve a `CALLER` into a real destination, and
    it is also what makes the allow-list polarity load bearing — a body owner only ever sits in a
    handful of positions, while a call site sits in every position an expression can.
    """
    cursor = node
    guarded = False
    while True:
        if takes_output_away(cursor):
            return Ps1OutputPath(OutputSink.CAPTURED, None, guarded)
        if isinstance(cursor, (Ps1SubExpression, Ps1ArrayExpression, Ps1DataSection)):
            return Ps1OutputPath(OutputSink.CAPTURED, None, guarded)
        if isinstance(cursor, Ps1ScriptBlock):
            holder = cursor.parent
            if isinstance(holder, Ps1FunctionDefinition) and holder.body is cursor:
                return Ps1OutputPath(OutputSink.CALLER, holder, guarded)
            if _scriptblock_is_captured(cursor):
                return Ps1OutputPath(OutputSink.CAPTURED, None, guarded)
        if isinstance(cursor, Ps1Script):
            return Ps1OutputPath(OutputSink.HOST, None, guarded)
        parent = cursor.parent
        if parent is None or not _output_writes_through(parent, cursor):
            return Ps1OutputPath(OutputSink.CAPTURED, None, guarded)
        if isinstance(parent, (Ps1TrapStatement, Ps1CatchClause)):
            guarded = True
        cursor = parent


def output_sink(node) -> OutputSink | None:
    """
    Who reads the output of the statement body that `node` owns as far as position can say, or
    `None` when `node` owns no prunable body — which is also how `@( ... )` stays out of every
    pruning walk, since `refinery.lib.scripts.ps1.ast.get_body` deliberately does not recognize it.

    A body does not carry a sink of its own; it is found by the outward walk in `output_path`.
    This is the positional answer and it stops at a function boundary, which is enough for a caller
    that only needs to know whether the body is prunable at all. A caller deciding whether to delete
    a *write* to the output stream needs `Ps1OutputFlow.resolved` on the whole `Ps1OutputPath`
    instead, which turns `CALLER` into a destination by reading the call graph.
    """
    if get_body(node) is None:
        return None
    return output_path(node).sink


class Ps1OutputFlow:
    """
    Where each function body's output ends up, resolved across the call graph. The verdict of
    `build_output_flow`, held in a `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot so
    that every pass in a run reads the same one.

    This is the fact `output_sink` alone cannot supply. A function body's output is whatever its
    callers do with it, so the same `function f { 'junk'; Write-Host 'go' }` is a script that prints
    two lines when `f` is called bare, and a value someone stored when it is called as `$r = f`.
    """

    def __init__(self, reaching_host: frozenset[Ps1FunctionDefinition]):
        self._reaching_host = reaching_host

    def resolved(self, path: Ps1OutputPath) -> OutputSink:
        """
        The destination a positional `Ps1OutputPath` really names, and never `OutputSink.CALLER`. A
        path that already names a destination is returned unchanged; a `CALLER` path is `HOST` only
        when its function is one this flow proved writes to the process output, and `CAPTURED`
        otherwise — including for a class method, which no call site in the tree names and which is
        therefore never among them.

        It takes the whole path rather than the node, so that a caller which already has the
        positional answer — every one of them does, since it is what decides whether the body is
        prunable at all — pays for the outward walk once.
        """
        if path.sink is not OutputSink.CALLER:
            return path.sink
        if path.function in self._reaching_host:
            return OutputSink.HOST
        return OutputSink.CAPTURED


def _path_reaches_host(
    path: Ps1OutputPath,
    key_of: dict[Ps1FunctionDefinition, str],
    grounded: set[str],
) -> bool:
    """
    Whether one call site's value is known to end up on the process output: it reaches the host
    directly, or it leaves a function that is itself known to.
    """
    if path.sink is OutputSink.HOST:
        return True
    return path.sink is OutputSink.CALLER and key_of.get(path.function) in grounded


def _path_is_captured(
    path: Ps1OutputPath,
    key_of: dict[Ps1FunctionDefinition, str],
    captured: set[str],
) -> bool:
    """
    Whether one call site's value goes anywhere other than the process output: it is captured where
    it stands, or it leaves a function that is itself captured — or one whose name nothing in this
    tree calls, which is the same unknown seen from the other side.
    """
    if path.sink is OutputSink.CAPTURED:
        return True
    if path.sink is not OutputSink.CALLER:
        return False
    key = key_of.get(path.function)
    return key is None or key in captured


def build_output_flow(graph: Ps1CallGraph) -> Ps1OutputFlow:
    """
    Resolve every function in `graph` to the destination its output reaches, by joining the readers
    of its call sites.

    A function writes to the process output only when **both** halves hold, and they are separate
    fixpoints running in opposite directions because they answer opposite failures:

    - *grounded* — some call site really does carry the value out to the host, computed forward from
      the script itself. This is what an ungrounded recursion cycle fails: `function a { 'x'; b }`
      and `function b { a }` with nothing calling either would otherwise vouch for each other and
      hand a deletion licence to a cycle carrying no evidence at all, while the identical evidence —
      none — keeps an uncalled `function c { 'x' }`. Seeding at the root and propagating outward
      makes those two answer alike.
    - *not captured* — no call site sends the value anywhere else, computed as the least set closed
      under "some call site captures it". One captured call site captures the whole function, since
      the definitions are what get pruned and every caller reads the same body.

    Both are needed and neither implies the other. `$r = b` beside a bare `a` — where `a` calls `b`
    and `b` calls `a` — leaves both grounded and both captured, and only the second fixpoint keeps
    them.

    An unreadable graph resolves nothing: with a name bindable from outside the tree, a call site
    the walk never read can capture any function in it.
    """
    if not graph.is_readable:
        return Ps1OutputFlow(frozenset())
    key_of = {
        definition: name
        for name in graph.defined_names
        for definition in graph.definitions(name)
    }
    readers = {
        name: [output_path(site.invocation) for site in graph.call_sites(name)]
        for name in graph.defined_names
    }
    grounded: set[str] = set()
    captured: set[str] = set()
    for target, test in ((grounded, _path_reaches_host), (captured, _path_is_captured)):
        growing = True
        while growing:
            growing = False
            for name, paths in readers.items():
                if name in target:
                    continue
                if any(test(path, key_of, target) for path in paths):
                    target.add(name)
                    growing = True
    return Ps1OutputFlow(frozenset(
        definition
        for definition, name in key_of.items()
        if name in grounded and name not in captured
    ))


def _leaves_a_block_of(site: Node, stmt: Node, faults: Ps1FaultReach, kinds: Ps1ErrorKind) -> bool:
    """
    Whether an error raised at *site* has no destination that deleting *stmt* could change: *site*
    stands inside a script block written within *stmt*, and no handler of that block settles the
    error.

    Such an error arrives at one of two places, and neither is this gate's business. Where the block
    runs where it is written, the error leaves it and arrives exactly where an error raised by
    *stmt* itself arrives — which is *stmt*'s own point, weighed beside this one in the same loop.
    Where the block is kept rather than run, the value holding it is built by evaluating *stmt*, so
    a script without *stmt* never builds the block and never reaches the point at all.

    Without this, an error a function body hands to its caller is observed
    (`refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.observed_at`), and that keeps the
    definition writing the body although a script without the definition calls nothing.
    """
    return (
        site is not stmt
        and lies_in_a_block_within(site, stmt)
        and faults.escapes_the_body(site, kinds)
    )


def fault_is_observed(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None = None,
    raises: RaiseVerdicts | None = None,
) -> bool:
    """
    Whether deleting *stmt* may change which handler runs.

    Two things have to be true for a deletion to be observable on this axis: something the deletion
    removes has to be able to raise, and the error it would raise has to reach a handler that acts
    — or end the body, which a `trap` set that may decline it does. Neither half answers for the
    other, and the pass this exists for gets both wrong in opposite directions if it asks only one:
    a gate that refuses whatever might raise keeps the padding an obfuscator writes by the hundred,
    and a gate that refuses only what a `catch` clause is written *beside* deletes the statement a
    handler one nesting level away was waiting for.

    The first half is what *raises* says a point raises
    (`refinery.lib.scripts.ps1.analysis.raising.Ps1RaiseModel.kinds`), and the second is
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.observed_at`. Both are asked once per
    point the graphs evaluate inside *stmt*, because a construct is deleted whole and each of its
    parts raises where it stands; a construct the graphs place nothing for at all is refused, since
    a subtree nothing models is one nothing can clear. A point in the body of a `trap` nothing may
    fire runs on no path and is passed over
    (`refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.never_runs`), where *raises* says
    what may fire it.

    A caller holding no raise model reads each point with
    `refinery.lib.scripts.ps1.analysis.raising.point_raise_kinds` at *stmt*, and every `trap` body as
    one that may run: *stmt* is what the removal takes away, so what may have run before it is what
    decides whether the analysis can see the semantics its parts run under.

    **This is not the question asked before a handler is deleted.** A `trap` cannot raise, so
    nothing about its own position decides anything: what a removal changes is where the errors of
    *other* statements go, and that is
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.removing_traps_is_observed`.
    Nor is it the question asked before a guarded body is emptied, which is
    `emptying_unhooks_a_handler` — a policy about what a listing should still show rather than a
    claim about what runs.
    """
    judged = False
    for site in faults.points_in(stmt):
        judged = True
        if raises is not None and faults.never_runs(site, raises):
            continue
        kinds = _point_kinds(site, stmt, faults, world, raises)
        if not kinds:
            continue
        if _leaves_a_block_of(site, stmt, faults, kinds):
            continue
        if faults.observed_at(site, kinds):
            return True
    return not judged


def deletion_is_observable(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None = None,
    error_state: Ps1ErrorStateReach | None = None,
    raises: RaiseVerdicts | None = None,
) -> bool:
    """
    Whether deleting *stmt* may change what the script does — the removal veto. Three ways it can,
    and a removal site has to refuse on any.

    The first is `fault_is_observed`: the error *stmt* would raise reaches a handler that acts, or
    ends a body. The second is a resurrected continuation: a statement that raises a fault a `try`
    would catch, written before a live continuation that runs only because the raise pre-empts it,
    is dead only for that reason — deleting the raiser starts the continuation running. Two
    mechanisms resurrect such a continuation and both are one observable: an empty `catch` swallows
    the error and resumes past the tail of the `try` body, and a firing `trap` body raise ends the
    scope that would otherwise run on past it, and an error nothing takes inside a `try` or `catch`
    body is reported past the whole statement.
    `Ps1FaultReach.deleting_the_raise_resurrects_a_continuation` is the position half and
    `point_raise_kinds` the raise half, paired at every point the graphs place inside
    *stmt*, because a construct is deleted whole and each of its parts raises where it stands: the
    test of an `if` and a statement inside an `@( )` are points of their own. A point inside a
    script block written in *stmt* is not one of them, for the reason `_leaves_a_block_of` gives:
    what its error skips inside the block is deleted with *stmt*, and an error that leaves the block
    arrives where one raised by *stmt*'s own point does, or nowhere where the block is not run
    there. Nor is a point in the body of a `trap` nothing may fire, as `fault_is_observed` reads
    *raises*.

    The third is a read of the record the raise leaves behind. Windows PowerShell 5.1 files every
    terminating error in `$Error` whether or not a handler ran, so a later read of that record
    observes the raise even where no handler took it, and deleting the raiser empties a `$Error` the
    original filled. This is paired the same way: *stmt* has to be able to leave a record — a point
    of it may raise, so a raiser the analysis proves cannot fault leaves none and stays removable —
    and a persistent-record read
    has to be reachable after it, which
    `refinery.lib.scripts.ps1.analysis.errorstate.Ps1ErrorStateReach` answers positionally.
    `error_state=None` skips the channel, the fail-open direction a caller with no such model
    takes, consistent with `world=None`.

    All three clauses are raise-keyed: this function answers *raise and handler* observability. `$?`
    resets on every statement rather than persisting a raise, so its reset rule is not a fourth
    clause here but a peer axis asked beside this one in
    `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan._vetoed`, over the same
    `Ps1ErrorStateReach` model through `success_flag_write_observed`.
    """
    for point in faults.points_in(stmt):
        if (
            isinstance(point, Ps1ThrowStatement)
            or lies_in_a_block_within(point, stmt)
            or (raises is not None and faults.never_runs(point, raises))
        ):
            continue
        kinds = _point_kinds(point, stmt, faults, world, raises)
        if kinds and faults.deleting_the_raise_resurrects_a_continuation(point, kinds):
            return True
    if (
        error_state is not None
        and _may_leave_a_record(stmt, faults, world, raises)
        and error_state.persistent_read_observed_after(stmt)
    ):
        return True
    return fault_is_observed(stmt, faults, world, raises)


def _point_kinds(
    point: Node,
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
    raises: RaiseVerdicts | None,
) -> Ps1ErrorKind:
    """
    What *point*, a point of *stmt*, may raise: what *raises* says, or, for a caller holding no raise
    model, `refinery.lib.scripts.ps1.analysis.raising.point_raise_kinds` judged at *stmt*.
    """
    if raises is None:
        return point_raise_kinds(point, stmt, faults, world)
    return raises.kinds(point)


def _may_leave_a_record(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
    raises: RaiseVerdicts | None,
) -> bool:
    """
    Whether a point of *stmt* outside the script blocks written in it may raise, which leaves a
    record in `$Error`; a statement the graphs place nothing of may.
    """
    if raises is None:
        return bool(statement_raise_kinds(stmt, stmt, faults, world))
    judged = False
    for point in faults.points_in(stmt):
        judged = True
        if not lies_in_a_block_within(point, stmt) and raises.kinds(point):
            return True
    return not judged


#: Commands that read a variable named by data rather than spelled, so one on a trap's continuation
#: may read any name and no skipped write over it can be called dead. Resolved through
#: `resolve_command_name`, so every spelling arrives canonical. `Invoke-Expression` is deliberately
#: absent: the analysis already treats the code it runs as unseen for reads (see
#: `refinery.lib.scripts.ps1.analysis.opaque`), the same contract the dead-store passes rely on.
_DYNAMIC_VARIABLE_READERS = frozenset({'get-variable'})


class Ps1BodyReads(NamedTuple):
    """
    What the functions and stored scriptblocks of one tree read, which a call anywhere may run: the
    names read inside one, and whether a command reading a name given as data stands inside one.
    """
    names: frozenset[str]
    dynamic: bool


def _reads_a_name_given_as_data(node: Node) -> bool:
    """
    Whether *node* is a command that reads a variable named by data rather than spelled.
    """
    if not isinstance(node, Ps1CommandInvocation):
        return False
    resolved = resolve_command_name(node)
    return resolved is not None and resolved in _DYNAMIC_VARIABLE_READERS


def _name_read(node: Node) -> str | None:
    """
    The name *node* reads, where it is a variable occurrence that observes the value.
    """
    if isinstance(node, Ps1Variable) and occurrence_role(node).observes:
        return node.name.lower()
    return None


def reads_in_bodies(root: Node) -> Ps1BodyReads:
    """
    The `Ps1BodyReads` of the tree under *root*, scope by scope as
    `refinery.lib.scripts.ps1.analysis.model.scope_local_nodes` partitions it. It is the same
    answer for every graph of the tree, so its owner asks it once per tree version; a walk per graph
    is the size of the script once per function a resuming `trap` guards.
    """
    names: set[str] = set()
    dynamic = False
    scopes: list[Node] = [root]
    while scopes:
        scope = scopes.pop()
        for node in scope_local_nodes(scope):
            if isinstance(node, Ps1ScriptBlock):
                scopes.append(node)
            elif scope is root:
                continue
            elif _reads_a_name_given_as_data(node):
                dynamic = True
            elif (name := _name_read(node)) is not None:
                names.add(name)
    return Ps1BodyReads(frozenset(names), dynamic)


class _ContinuationReads:
    """
    Where the names a resuming trap's step-over reader may ask about are read across one script,
    indexed so the reader can ask whether a skipped write is read on a continuation without
    re-walking the graph per question.

    `by_name` maps a name to the graph nodes whose statements read it — the statement each read sits
    in, resolved once by climbing to the first placed ancestor. An occurrence counts as a read when
    it `occurrence_role.observes` the value, so a `++`/`--`, a compound assignment and a store
    through an index or member read the name as well as write it; only a plain `=` store, a
    `foreach` variable and a parameter replace the value without reading it. `in_a_body` is the
    names read inside a function or stored scriptblock, which a call on the continuation may run
    wherever the body sits. `dynamic_readers` is the nodes of commands that read a variable named by
    data, which may read any name; a continuation reaching one keeps every skipped write.
    `dynamic_reader_in_a_body` marks such a command written inside a stored body, which a call on
    the continuation may run from anywhere, so it keeps every skipped write the way `in_a_body`
    keeps the names read there.

    Only the scope of the graph's owner, as
    `refinery.lib.scripts.ps1.analysis.model.scope_local_nodes` gives it, can be placed in the
    graph, so that is all it walks, and a graph owned by a stored body places nothing of its own;
    what the stored bodies read is the same for every graph of the tree and arrives as *bodies*.
    Only the names in *asked* — the names a skipped statement of this graph writes — are carried
    through the continuation walk, one bit per name per component, so a name no question can reach
    costs nothing.
    """

    def __init__(self, graph: ControlFlowGraph, bodies: Ps1BodyReads, asked: frozenset[str]):
        self.by_name: dict[str, set[int]] = {}
        self.dynamic_readers: set[int] = set()
        self.in_a_body = bodies.names
        self.dynamic_reader_in_a_body = bodies.dynamic
        self._asked = asked
        if not isinstance(graph.owner, Ps1ScriptBlock):
            for node in scope_local_nodes(graph.owner):
                if _reads_a_name_given_as_data(node):
                    placed = _placed_statement(node, graph)
                    if placed is not None:
                        self.dynamic_readers.add(placed)
                elif (name := _name_read(node)) is not None:
                    placed = _placed_statement(node, graph)
                    if placed is not None:
                        self.by_name.setdefault(name, set()).add(placed)
        nodes = {id(node): node for node in graph.nodes}
        sources: dict[str | None, list[CfgNode]] = {
            name: [nodes[placed] for placed in sites]
            for name, sites in self.by_name.items() if name in asked
        }
        sources[None] = [nodes[placed] for placed in self.dynamic_readers]
        self._reach = flood_labels(sources, forward=False, projection=Projection.FORWARD)

    def read_on(self, name: str, resumed: frozenset[CfgNode]) -> bool:
        """
        Whether *name* may be read on the continuation that starts at *resumed*: by a statement
        control reaches from there over plain edges, by a command that reads a name given as data
        there, or by a body something there may call. A name outside the asked set was never carried
        through the walk, and asking for one is refused rather than answered from nothing.
        """
        if self.dynamic_reader_in_a_body or name in self.in_a_body:
            return True
        if name not in self._asked:
            raise LookupError(F'the continuation reads were not indexed for {name!r}')
        reach = self._reach
        return any(reach.reaches(None, node) or reach.reaches(name, node) for node in resumed)


class _PastVerdicts:
    """
    The questions about a point that read where its error goes with what the raise model of the
    world reading says it raises: whether an error raised inside a statement may be taken past it,
    whether a store may fail and leave the value it overwrites in place, and the two questions the
    `catch` lift asks. Every table is one per tree, refused once the tree moves in the direction
    that keeps code.
    """

    def __init__(
        self,
        faults: Ps1FaultReach,
        raises: Callable[[], Ps1RaiseModel],
        stamp: TreeStamp,
    ):
        self._faults = faults
        self._model = raises
        self._stamp = stamp
        self._memo: dict[int, float] = {}
        self._within: dict[int, Ps1ErrorKind] = {}

    def _raises(self, point: Node) -> Ps1ErrorKind:
        return self._model().kinds(point)

    def raises_past(self, statement: Node) -> bool:
        if self._stamp.moved():
            return True
        return self._faults.raises_past(statement, self._raises, self._memo)

    def certain_handler(self, raiser: Node) -> Ps1CatchClause | None:
        """
        The `catch` clause every error *raiser* may raise lands in, with nothing else on the way: no
        `trap` runs on it first, and it carries on nowhere else.
        """
        if self._stamp.moved():
            return None
        kinds = self._raises(raiser)
        if not kinds:
            return None
        fate = self._faults.dispatch.fate(raiser, kinds)
        if fate is None or len(fate.caught) != 1:
            return None
        if fate.trapped or fate.offered_to_traps or fate.carried or fate.leaves or fate.replaces:
            return None
        clause, = fate.caught
        return clause

    def lifts_unchanged(self, clause: Ps1CatchClause) -> bool:
        """
        Whether every error a point of the body of *clause* may raise ends up where it would were
        the statements of that body standing in place of the `try` the clause belongs to
        (`refinery.lib.scripts.ps1.analysis.dispatch.Ps1Lift`).

        A statement of the body that may run another body hands that body the flag the `catch` body
        runs under, which passes every error outward, so the called body abandons its remaining
        statements on an error it would report and step over at script scope. That error is the
        kind `refinery.lib.scripts.ps1.analysis.dispatch.Ps1ErrorKind.CALLED`, which a point that may
        run a body raises, and which reaches the list a point stands in only where that list passes
        errors outward: where the list around the `try` does not, it ends up nowhere lifted and the
        two readings differ.
        """
        if self._stamp.moved():
            return False
        body = clause.body
        if body is None:
            return True
        faults = self._faults
        lift = faults.dispatch.lifted(clause)
        if lift is None:
            return not body.body
        for member in body.body:
            if lift.keeps_the_flag:
                kinds = self._raised_within(member)
                if kinds and not lift.member_alike(member, kinds | Ps1ErrorKind.MARKED):
                    return False
            else:
                for point in faults.points_in(member):
                    kinds = self._raises(point)
                    if kinds and not lift.point_alike(point, kinds):
                        return False
        return True

    def fails_and_carries_on(self, store: Node) -> bool:
        """
        Whether the point *store* writes a variable at may raise instead, with the run going on
        somewhere — after a statement, in a handler, or in whatever called the body — rather than
        ending: the variable then keeps the value it held, and a later read sees it.
        """
        if self._stamp.moved():
            return True
        kinds = self._raises(store)
        if not kinds:
            return False
        fate = self._faults.dispatch.fate(store, kinds)
        if fate is None:
            return True
        goes_on = fate.carried or fate.caught or fate.swallowed or fate.trapped or fate.to_caller
        return bool(goes_on) or not fate.ends_run

    def _raised_within(self, node: Node) -> Ps1ErrorKind:
        """
        Every kind of error a point the graphs place inside *node* may raise, a script block written
        there left out: what it raises arrives where the point that runs it stands, as what that
        point hands back. Kept for every node asked about, so that a nest of bodies costs its size.
        """
        within = self._within
        faults = self._faults
        stack: list[tuple[Node, bool]] = [(node, False)]
        while stack:
            current, expanded = stack.pop()
            if id(current) in within:
                continue
            children = [child for child in current.children() if not isinstance(child, Ps1ScriptBlock)]
            if not expanded:
                stack.append((current, True))
                stack.extend((child, False) for child in children if id(child) not in within)
                continue
            kinds = self._raises(current) if faults.places(current) else Ps1ErrorKind.NONE
            for child in children:
                kinds |= within[id(child)]
            within[id(current)] = kinds
        return within[id(node)]


class _SkipVerdicts:
    """
    Whether a statement one run executes and another skips does something a run can see, read with
    `_skipped_statement_is_observable` under one world. It owns everything that judgment keeps: what
    each skipped statement writes, what the stored bodies of the tree read, and the continuation
    reads of each graph. The names a graph's continuation index carries and the names a skipped
    statement is judged by are both read off `_writes_at`, so the index holds every name a judgment
    can ask about. Refused once the tree moves, as "observed".
    """

    def __init__(self, world: Callable[[], Ps1WorldReach], root: Node, stamp: TreeStamp):
        self._world = world
        self._root = root
        self._stamp = stamp
        self._bodies: Ps1BodyReads | None = None
        self._writes: dict[Node, _Writes] = {}
        self._reads: dict[int, _ContinuationReads] = {}

    def observers(
        self,
        graph: ControlFlowGraph,
        regions: Sequence[Ps1StepOverRegion],
    ) -> list[Callable[[CfgNode], bool]]:
        """
        For each of *regions* of *graph*, whether a statement of it does something a run can see,
        a write read where the region rejoins the other run among it; one index of the reads of the
        graph serves them all.
        """
        if self._stamp.moved():
            return [lambda member: True for _ in regions]
        if self._bodies is None:
            self._bodies = reads_in_bodies(self._root)
        reads = self._reads.get(id(graph))
        if reads is None:
            asked = _names_written_under(graph.owner, {graph.owner})
            reads = self._reads[id(graph)] = _ContinuationReads(graph, self._bodies, asked)
        world = self._world()

        def observer(resumed: frozenset[CfgNode]) -> Callable[[CfgNode], bool]:
            def observed(member: CfgNode) -> bool:
                element = member.element
                if isinstance(element, Ps1TrapStatement):
                    return handler_acts(element)
                return element is not None and _skipped_statement_is_observable(
                    element, resumed, world, reads, self._written(element))
            return observed

        return [observer(region.resumed) for region in regions]

    def _written(self, element: Node) -> _Writes:
        writes = self._writes.get(element)
        if writes is None:
            writes = self._writes[element] = _skipped_writes(element)
        return writes


class Ps1HandlerVerdicts:
    """
    The semantic half of where an error goes, for one version of one tree: whether deleting `trap`
    statements changes what runs — what the points offered to a set raise, read without a world or
    under the world, and whether what one run executes and the other skips is observable under the
    world — whether an error raised inside a statement may be taken past it, which the store sweep
    asks, and the two questions the `catch` lift asks: the one clause a certain throw lands in, and
    whether its body means the same standing in place of its `try`. Held in a
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` slot, so it is rebuilt with the fault
    model it reads, and handed to
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.removing_traps_is_observed` through the
    removal plan. *raises* hands out the raise model of each reading of the world, built on the
    first verdict that reads it, so a pass that never weighs a handler under the world never has
    one built.
    """

    def __init__(
        self,
        faults: Ps1FaultReach,
        raises: Callable[[bool], Ps1RaiseModel],
        root: Node,
    ):
        root = tree_root(root)
        stamp = TreeStamp(root)
        self.faults = faults
        self._raises_of = raises
        self._raises: dict[bool, Ps1RaiseModel] = {}
        self.skips = _SkipVerdicts(lambda: self.world, root, stamp)
        self._past = _PastVerdicts(faults, lambda: self.raises(True), stamp)

    @property
    def world(self) -> Ps1WorldReach:
        """
        The world the verdicts read, built on first use.
        """
        world = self.raises(True).world
        if world is None:
            raise LookupError('the raise model of the world reading holds no world')
        return world

    def raises(self, under_the_world: bool) -> Ps1RaiseModel:
        """
        The raise model read under `world` when *under_the_world*, and without one otherwise.
        """
        found = self._raises.get(under_the_world)
        if found is None:
            found = self._raises[under_the_world] = self._raises_of(under_the_world)
        return found

    def raises_past(self, statement: Node) -> bool:
        """
        Whether an error raised inside *statement* may be taken past it, under `world`.
        """
        return self._past.raises_past(statement)

    def certain_handler(self, raiser: Node) -> Ps1CatchClause | None:
        """
        The `catch` clause every error *raiser* may raise lands in with nothing else on the way,
        under `world`.
        """
        return self._past.certain_handler(raiser)

    def lifts_unchanged(self, clause: Ps1CatchClause) -> bool:
        """
        Whether the body of *clause* may stand in place of its `try` with every error a point of it
        may raise ending up where it does now, under `world`.
        """
        return self._past.lifts_unchanged(clause)

    def fails_and_carries_on(self, store: Node) -> bool:
        """
        Whether the point *store* writes a variable at may raise instead with the run going on, so
        that the value it overwrites may still be read, under `world`.
        """
        return self._past.fails_and_carries_on(store)


def _skipped_statement_is_observable(
    element: Node,
    resumed: frozenset[CfgNode],
    world: Ps1WorldReach,
    reads: _ContinuationReads,
    writes: _Writes,
) -> bool:
    """
    Whether *element*, run on the untrapped fall-through the trap skips, does something observable,
    where *writes* is what `_skipped_writes` reports for it and *resumed* is where the trap carries
    on.

    A statement that emits to the output stream is observable outright. Otherwise it is observable
    only for a *real* effect — a command, a method call, a read of a member whose getter is not
    provably pure, or a write the continuation can see — never merely because it *might throw*: a
    failing cast is the trap's own business, not an output the run produces, so a pure loop condition
    `$i -lt $x.Length` and a dead counter `$i++` are not observable although neither is
    side-effect-free. This is why the reducible-write test walks for effects rather than reading
    `is_side_effect_free`, whose purity folds in the fault potential the trap already accounts for.

    A bare member read is a real effect unless the member is a shape member — `Length`, `Count` or
    `Rank`, the ones `data.SHAPE_MEMBERS` names — whose value the receiver's shape decides and whose
    getter is pure. Every other property may run a side-effecting getter this analysis cannot read,
    so a resuming trap over one is kept; the shape members are what keep the payload loop's
    `($x).Length` droppable.

    A write is one the continuation can see when it stores a plain local a later statement reads, or
    when `_skipped_writes` cannot prove it dead — a scope- or drive-qualified store, a store through
    an index or member, or a `$Matches`-writing `-match` — whose reads may sit where the reach never
    looks, so it is kept rather than guessed dead.
    """
    if isinstance(element, Ps1ExpressionStatement):
        effect = statement_effect(element, world)
        if effect is StatementEffect.OUTPUT:
            return True
        if effect is StatementEffect.DISCARD:
            return False
    for node in element.walk():
        if isinstance(node, (Ps1CommandInvocation, Ps1InvokeMember)):
            return True
        if isinstance(node, Ps1MemberAccess):
            member = get_member_name(node.member)
            if member is None or member.lower() not in data.SHAPE_MEMBERS:
                return True
    if writes.escapes:
        return True
    return any(reads.read_on(name, resumed) for name in writes.names)


class _Writes(NamedTuple):
    """
    What a skipped statement writes, split into the part the continuation's reads can prove dead and
    the part they cannot — see `_skipped_writes`.
    """
    escapes: bool
    names: tuple[str, ...]


def _writes_at(node: Node) -> _Writes:
    """
    What *node* itself writes, its descendants left out: the per-node rule `_skipped_writes` folds
    over a statement and `_names_written_under` folds over every skipped statement of a graph.
    """
    if isinstance(node, Ps1AssignmentExpression):
        if not assignment_target_is_all_variables(node.target):
            return _Writes(True, ())
        names: list[str] = []
        escapes = False
        for target in assignment_target_variables(node.target):
            if _is_plain_local(target):
                names.append(target.name.lower())
            else:
                escapes = True
        return _Writes(escapes, tuple(names))
    if isinstance(node, Ps1UnaryExpression) and node.operator in ('++', '--'):
        operand = node.operand
        if isinstance(operand, Ps1Variable) and _is_plain_local(operand):
            return _Writes(False, (operand.name.lower(),))
        return _Writes(True, ())
    if isinstance(node, Ps1BinaryExpression) and node.operator.lower() in MATCH_OPERATORS:
        return _Writes(True, ())
    return _Writes(False, ())


def _skipped_writes(element: Node) -> _Writes:
    """
    What a skipped statement writes, split into the part the continuation's reads can prove dead and
    the part they cannot.

    The names are the unqualified local names *element* assigns or increments — a plain `$name` an
    assignment stores into (a multi-assignment slot and a `[Type]$name` target among them, which
    `assignment_target_variables` resolves) or a `++`/`--` operand — whose liveness on the
    continuation decides the write. The flag is `True` when *element* performs a write no
    continuation read can be matched against: a scope- or drive-qualified store
    (`$global:`/`$script:`/`$env:`), a store through an index or member (`$a[0] = …`, `$o.P = …`),
    a multi-assignment slot that is not a plain variable, a qualified `++`/`--`, or a
    `$Matches`-writing `-match`. A qualified target's reads may sit in a scope or a place the reach
    never visits, and a store through a value mutates an object the name-liveness index does not
    track, so neither can be called dead — the trap over it is kept.
    """
    escapes = False
    names: list[str] = []
    for node in element.walk():
        writes = _writes_at(node)
        escapes = escapes or writes.escapes
        names.extend(writes.names)
    return _Writes(escapes, tuple(names))


def _names_written_under(owner: Node, skipped: set[Node]) -> frozenset[str]:
    """
    Every name a statement of *skipped* writes, in one walk of the scope of *owner* that visits each
    node once however many skipped statements hold it: the skipped statements of nested resuming
    blocks contain one another, and folding `_skipped_writes` over each would walk the inner ones
    once per level around them. A nested scriptblock is entered only inside a skipped statement,
    which is where `_skipped_writes` reads it too.
    """
    names: set[str] = set()
    stack: list[tuple[Node, bool]] = [(owner, False)]
    while stack:
        node, inside = stack.pop()
        inside = inside or node in skipped
        if inside:
            names.update(_writes_at(node).names)
            stack.extend((child, True) for child in node.children())
        else:
            stack.extend((child, False) for child in node.children() if not isinstance(child, Ps1ScriptBlock))
    return frozenset(names)


def _is_plain_local(variable: Ps1Variable) -> bool:
    """
    Whether *variable* names an ordinary local — no scope qualifier and no provider drive — so its
    every read is a `$name` this analysis can find. A `$script:`/`$global:`/`$env:` name may be read
    from a scope or a place the reach never visits, so a write to one is never called dead here.
    """
    return variable.scope in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL) and not variable.drive


def _placed_statement(node: Node, graph: ControlFlowGraph) -> int | None:
    """
    The id of the graph node standing for the statement *node* sits in, or `None` where the graph
    places nothing over it. The graph places statements, not the expressions inside them, so the walk
    climbs to the first ancestor the graph holds a node for.
    """
    cursor: Node | None = node
    while cursor is not None:
        placed = graph.node_of(cursor)
        if placed is not None:
            return id(placed)
        cursor = cursor.parent
    return None


def emptying_unhooks_a_handler(block: Node) -> bool:
    """
    Whether clearing *block* would leave a `catch` clause that acts with nothing left to trigger it:
    *block* is the `try` block of a construct one of whose clauses has a body.

    This is a policy about the listing rather than a claim about what runs. A `try` body holding
    only statements that cannot raise already reaches its handler on no path, so emptying it changes
    nothing a run can see — but it turns `try { 42 } catch { Start-Process calc }` into a construct
    the next pass dissolves, and the payload leaves the output with it. What a triage tool must not
    do is delete the thing an analyst opened it to read.

    An empty `catch { }` is deliberately not a clause that acts. It swallows the error and execution
    continues either way, so nothing is hidden by letting the body go — and that is the shape
    obfuscators emit, which is why this policy costs the cleanup passes almost nothing.
    """
    guard = block.parent
    if not isinstance(guard, Ps1TryCatchFinally) or guard.try_block is not block:
        return False
    return any(
        clause.body is not None and clause.body.body
        for clause in guard.catch_clauses
    )


_BODY_BEARING_STATEMENTS = (
    Ps1DoLoop,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1IfStatement,
    Ps1SwitchStatement,
    Ps1TryCatchFinally,
    Ps1WhileLoop,
)


def pruning_erases_body(node, survivors: Sequence[Node]) -> bool:
    """
    Whether pruning the body that `node` owns down to `survivors` would erase it: nothing would
    survive, and this body must not become empty. Only the script root qualifies — a script that is
    nothing but function definitions is a module whose functions may be dot-sourced, and a script
    that is nothing but `42` still emits `42` — so emptying it would delete real code. Every other
    body may legitimately prune to nothing; that is what turns an injected junk function inert.

    The node decides this and not its `OutputSink`, deliberately. A `trap` or an `if` body at script
    level is `HOST` like the root is, and refusing to empty those is a different and wider rule than
    the one meant here.

    `survivors` is the surviving statement set itself and never a node to walk up from. A caller may
    hold freshly synthesized statements that are not parented into a body yet, and statements
    hoisted out of a pruned block still point at the block they came from; answering this kind of
    question by walking `parent` would misjudge a hoisted return value as belonging to the pruned
    block.

    **A `trap` left standing is not something that survived**, for the reason
    `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1JunkStatementRemoval` does not count a
    definition: it is machinery for the statements around it rather than one of them, and a body
    holding nothing else runs nothing at all. Counting one would let `trap { break }` beside a bare
    `'a'` erase the whole script in two steps: `'a'` dropped because the `trap` reads as a survivor,
    then the `trap` dropped because nothing raises into it any more.
    """
    return isinstance(node, Ps1Script) and not any(
        not isinstance(statement, Ps1TrapStatement) for statement in survivors
    )


def _parameter_is_inert(
    parameter: Ps1ParameterDeclaration,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether declaring this parameter runs nothing observable on a call that omits its argument.
    Declaring the name binds storage and evaluates nothing, but three things it may carry do: an
    attribute is work of its own — a `[ValidateScript({...})]` body runs on every call that supplies
    one and a `[Parameter(Mandatory)]` makes the call prompt — a default value is an expression the
    engine runs, and a type constraint converts that default on every such call.

    Attributes are rejected wholesale rather than matched against a table: which of them do
    something observable is not a question this module can answer. A type constraint is not an
    attribute here and does nothing on its own, but the conversion it names is asked of the default
    it converts, because that conversion is what turns `[int] $x = 'abc'` into a call that throws
    where `[int] $x = '42'` does not.
    """
    if any(isinstance(a, Ps1Attribute) for a in parameter.attributes):
        return False
    if parameter.default_value is None:
        return True
    return (
        is_side_effect_free(parameter.default_value, world)
        and not bound_default_may_throw(parameter)
    )


def _param_block_is_inert(
    block: Ps1ParamBlock | None,
    world: Ps1WorldReach,
) -> bool:
    """
    Whether a `param( ... )` block runs nothing when the function is called, which is that every
    parameter it declares is inert by `_parameter_is_inert`. A block-level attribute is rejected the
    same way a parameter's is — `[CmdletBinding()]` turns the function into an advanced one — so a
    block that carries one is never inert.
    """
    if block is None:
        return True
    if block.attributes:
        return False
    return all(_parameter_is_inert(parameter, world) for parameter in block.parameters)


def body_is_inert(node, world: Ps1WorldReach) -> bool:
    """
    Whether the body that `node` owns neither emits a value nor performs a side effect: `node` is
    `None`, the body is empty, or every statement in it is a `StatementEffect.DISCARD`. An inert
    function body makes the function itself unobservable, so its definition and its bare call sites
    can be dropped together.

    A node that owns a `begin`/`process`/`end` block is never inert: `get_body` reports an empty
    statement list for it, and reading that as "nothing happens here" would delete an advanced
    function together with every call to it. A `param` block is the same hole — `get_body` does not
    report it either, and `function f { param($x = (Start-Process n)) }` runs a command on every
    call that omits the argument — but unlike a named block it is not code by its mere presence, so
    it is judged by `_param_block_is_inert` rather than counted. Anything else `get_body` does not
    recognize is not a body owner and cannot be shown to be inert either.
    """
    if node is None:
        return True
    body = get_body(node)
    if body is None or get_named_blocks(node):
        return False
    if not _param_block_is_inert(get_param_block(node), world):
        return False
    return all(statement_effect(stmt, world) is StatementEffect.DISCARD for stmt in body)
