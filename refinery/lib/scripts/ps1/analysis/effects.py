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
- whether it may *throw* — `expression_cannot_fault`, the one gate every removal site goes through.
  Its context-free half is `is_fault_free`, which grants what the value domain computes and what a
  syntactic allow-list names and answers `False` for everything else; the other half is the single
  fault the script rather than the expression decides, a read of a variable that was never set.
  Purity is not this question: `is_side_effect_free` accepts `[Int]$x` and `$a / $b`, both of which
  raise;
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

from typing import Iterator, NamedTuple, Sequence, TypeGuard

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.analysis.arguments import Ps1WrittenSlots, written_slots
from refinery.lib.scripts.ps1.analysis.callgraph import Ps1CallGraph
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.values import (
    UNKNOWN,
    candidate_types,
    convert,
    evaluate,
    integer_of,
    read,
)
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import (
    extract_new_object,
    get_body,
    get_command_name,
    get_member_name,
    get_named_blocks,
    get_param_block,
    is_builtin_variable,
    is_reference_cast,
    unwrap_parens,
)
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
    fails the load,
    retiring the sealedness the table used to assert by hand.
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
    ('threading.tasks.task', 'status'),
    ('threading.thread', 'currentthread'),
    ('threading.thread', 'managedthreadid'),
})


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
_MATCH_OPERATORS = frozenset({
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

    **A conversion is looked through rather than trusted to allocate**, and `-as` is the reason it
    has to be. A cast may hand the callee a fresh array built out of what the name holds, and `-as`
    over a value already of the target type converts by nothing at all: measured on 5.1,
    `$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x` writes `3 2 1`, so the call
    turned `$x` itself around. Which of the two a conversion performs is decided by the operand's
    runtime type and not by its spelling, so both spellings are read as the storage underneath.
    """
    while True:
        if isinstance(node, Ps1ParenExpression):
            node = node.expression
        elif isinstance(node, Ps1CastExpression):
            node = node.operand
        elif isinstance(node, Ps1BinaryExpression) and node.operator.lower() == '-as':
            node = node.left
        else:
            break
    return isinstance(node, (Ps1Variable, Ps1MemberAccess, Ps1IndexExpression))


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
    `| ForEach-Object { [Void]$_ } -MemberName Delete` has a block *and* invokes a member, and
    reading the answer off the block is what let a discarding body vouch for the deletion sitting
    next to it.

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
        # alone deleted the call. Resolving is necessary here, not sufficient: a conversion to a
        # collected type can still run code (`[xml]$s` parses, and follows external DTDs), which
        # `_PURE_CAST_TYPES` is the eventual answer to. The world is read before either check
        # because it is a stored bool that can only veto, while both checks below walk.
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
        if node.operator.lower() in _MATCH_OPERATORS:
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
        # member runs no code. Returning the object's own purity was the fail-open shape this gate
        # replaces: it deleted `(Get-Process).Path`, an Extended Type System getter that shells out,
        # because the pipeline that produced the object was itself pure. A literal member name —
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
        # describes, so its purity is not the built-in's. The gate is positional — the identity
        # twin of the `_grant` below — trusting the name only where no opener and no redefinition
        # of this very name can have run first.
        if not world.may_trust_command_name_at(name, node):
            return False
        # The pipeline set is checked through the same gate rather than after the plain one: three
        # of its four members are in both, so testing the plain set first would make the body check
        # below unreachable for `Where-Object`, `Select-Object` and `Sort-Object`.
        if name not in _PURE_CMDLETS and name not in _PURE_PIPELINE_CMDLETS:
            return False
        if not _command_arguments_are_pure(node, world):
            return False
        # Routed through `_grant` like every other grant. `may_trust_command_name_at` above refuses
        # a name a rebinding statement can reach; `_grant` here refuses a member the type world
        # does not hold at this node. The two read different floods — the name gate adds the
        # per-name redefinition flood the type axis never reads — so a name that passed the first
        # is still gated on the second, and narrowing either check back into the other would reopen
        # a fail-open hole with nothing in the path to catch it.
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


#: The widest and narrowest values PowerShell's range operator accepts. Both bounds go through
#: `Int32`, so an endpoint outside this window raises the same conversion error a bad cast does.
_INT32_MIN = -0x80000000
_INT32_MAX = +0x7FFFFFFF

#: How many elements a range may span before *building* it is the fault rather than converting its
#: endpoints. PowerShell materializes the whole array eagerly, so `0..2147483647` is two perfectly
#: good `Int32` bounds and an `OutOfMemoryException` an enclosing handler may well be catching.
_MAX_FAULT_FREE_RANGE = 0x10000


def _is_numeric_constant(node) -> bool:
    """
    Whether `node` is a constant that PowerShell reads as a number without running a conversion that
    can fail: a numeric literal or one of the built-in constants, through parentheses and a further
    unary sign.

    A string literal is deliberately not one, which is the whole of why this is separate from
    `is_fault_free`. `is_fault_free('abc')` is `True` because *evaluating* a string cannot raise,
    while `-'abc'` raises the `Int32` conversion error the caller is trying to rule out.
    """
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return True
    if is_builtin_variable(node):
        return True
    if isinstance(node, Ps1ParenExpression):
        return _is_numeric_constant(node.expression)
    if isinstance(node, Ps1UnaryExpression) and node.operator in ('+', '-'):
        return _is_numeric_constant(node.operand)
    return False


def _signed_integer_value(node) -> int | None:
    """
    The integer an expression names, read through any number of unary signs, or `None` when it
    names something else.

    The value is asked of the domain and not of the node, because a node reports the digits it was
    written with rather than the number they denote: `0xFFFFFFFF` is the Int32 -1 and reading it as
    4294967295 rejected a two-element range as one that might exhaust memory.

    A sign is *applied* rather than walked past, for the spelling that still has one of its own —
    the parser puts a sign written against a numeral inside the numeral, so what reaches here is
    `- 5` with a space, and discarding that sign weighs a value the source never names.
    """
    if isinstance(node, Ps1UnaryExpression) and node.operator in ('+', '-'):
        value = _signed_integer_value(node.operand)
        if value is None:
            return None
        return -value if node.operator == '-' else value
    return integer_of(read(node))


def _range_is_fault_free(node: Ps1RangeExpression) -> bool:
    """
    Whether the range operator provably neither converts nor allocates its way into a fault.

    Two separate faults, and weighing only the first is how a range that had already stopped the
    script came to be deleted. Both endpoints go through `Int32`, so `4242424242..4242424245` is two
    perfectly good integer literals that still raise — the reason this is narrower than
    `_is_numeric_constant`, which merely reads a number, and why a real literal is not an endpoint
    at all since it rounds rather than converting cleanly. Then the operator materializes the whole
    array eagerly, so `0..2147483647` converts cleanly and raises `OutOfMemoryException` instead;
    only a span under `_MAX_FAULT_FREE_RANGE` provably survives both.
    """
    start = _signed_integer_value(node.start)
    end = _signed_integer_value(node.end)
    if start is None or end is None:
        return False
    if not _INT32_MIN <= start <= _INT32_MAX or not _INT32_MIN <= end <= _INT32_MAX:
        return False
    return abs(end - start) < _MAX_FAULT_FREE_RANGE


def is_fault_free(node) -> bool:
    """
    Whether evaluating an expression provably cannot raise. Two readings grant that, and neither
    subsumes the other: the value domain answers it for anything it can actually compute, and a
    syntactic allow-list answers it for the constructions the domain does not model. Everything
    else answers `False`, including expressions that are obviously fine, because the safe answer to
    an expression neither reading claims is that it might raise.

    **The value domain is asked first, because it is the one that knows.**
    `refinery.lib.scripts.ps1.analysis.values.Ps1Outcome.may_throw` is `False` only where that
    module claims an operation cannot throw, and not knowing is a throw there as it is here, so the
    two axes already agree about which direction is safe. It reaches what no list of shapes can:
    `6 * 7`, `[Int]'42'` and `'ab' + 'cd'` cannot raise and are not literals, and a gate that called
    them unsafe refused to delete the padding an obfuscator writes by the hundred. It declines every
    call and every expression naming a variable, which is why the sweep behind this grant is a grid
    of constants — 9210 expressions it calls throw-free, every one of them confirmed against a
    Windows PowerShell 5.1 host.

    **The allow-list is what the domain does not model**, not a weaker copy of it: a range and a
    hash literal are constructions rather than operations, and the domain names no value for either.
    The container arm recurses into the elements rather than granting the form, so `@{ a = 1 }`
    cannot fail while `@{ a = [Int]'x' }` still can and is rejected by the element it holds. A hash
    literal with a duplicate key is the one construction PowerShell refuses outright, so the keys
    are compared rather than trusted; see `_hash_literal_is_fault_free`.

    Purity is a different question and neither implies the other. `is_side_effect_free` accepts
    `[Int]$x`, `$a / $b` and `$a[$i]`, all of which raise on the wrong operand, and it is the
    predicate that was standing in for this one — a `try` body cannot be hoisted out of its own
    construct on a purity argument, because an empty `catch` was swallowing what the hoisted
    statement now raises into the caller.

    **A unary sign and a range coerce, and coercion is the fault this predicate exists to see.**
    Both read their operands through `Int32`, so `-'abc'` and `'a'..'z'` raise exactly what
    `[Int]'abc'` raises; neither may inherit the string-literal grant, and both go through
    `_is_numeric_constant` and `_range_is_fault_free` instead.

    **A removal site asks `expression_cannot_fault` and not this**, because one fault is decided by
    the script rather than by the operands. What still reads this directly asks a narrower question
    on purpose: `may_be_dropped` and the range fold weigh work a rewrite would stop doing, where
    the operand's own faults are the whole question, and
    `refinery.lib.scripts.ps1.deobfuscation.deadcode._try_body_survivors` needs a second property
    beside fault-freedom — that what it accepts is a constant it can carry out of the construct.
    """
    if not evaluate(node).may_throw:
        return True
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral, Ps1StringLiteral)):
        return True
    if is_builtin_variable(node):
        return True
    if isinstance(node, Ps1ParenExpression):
        return is_fault_free(node.expression)
    if isinstance(node, Ps1UnaryExpression) and node.operator in ('+', '-'):
        return _is_numeric_constant(node.operand)
    if isinstance(node, Ps1ArrayLiteral):
        return all(is_fault_free(element) for element in node.elements)
    if isinstance(node, Ps1RangeExpression):
        return _range_is_fault_free(node)
    if isinstance(node, Ps1HashLiteral):
        return _hash_literal_is_fault_free(node)
    if isinstance(node, Ps1ArrayExpression):
        if len(node.body) == 1:
            stmt = node.body[0]
            return isinstance(stmt, Ps1ExpressionStatement) and is_fault_free(stmt.expression)
        return len(node.body) == 0
    return False


def certainly_throws(node) -> bool:
    """
    Whether evaluating `node` is guaranteed to raise a terminating error under every runtime state
    consistent with what is known — the must-throw dual of `is_fault_free`'s cannot-throw, and the
    opposite polarity from `may_throw`. `False` is *not knowing*, never a claim of safety: an
    expression this cannot prove throws answers `False` exactly as one that provably cannot does, so
    a caller must read this only where a false positive is the cost it cannot pay and a false
    negative merely declines to act.

    **The value domain is the one that knows**, and this reads its `ALWAYS`: a leaf is certain only
    where a value-precise computation on concrete operands reaches a throw 5.1 also takes — an
    overflow, a division by zero, a String the invariant coercion cannot read — never from the
    measured grid, which is a witnessed lower bound. An unknown operand makes the outcome `MAYBE`
    (the domain answers `UNKNOWN` for an unread variable rather than reading it as `$null`), so
    `[int]$x` is never certain and nothing built on this ever fires on a guessed value.

    **A `throw` statement is the one certain throw that is not a value**: reaching it transfers
    control abnormally whatever its argument is, so it answers `True` directly. Everything else is
    the expression's outcome — including a statement the value domain names nothing for, which is
    `MAYBE` and so `False`.
    """
    if isinstance(node, Ps1ThrowStatement):
        return True
    return evaluate(node).certainly_throws


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


def _hash_literal_is_fault_free(node: Ps1HashLiteral) -> bool:
    """
    Whether building a hash literal is guaranteed to succeed. Every key and value has to be
    fault-free in its own right, and the keys additionally have to be distinct — PowerShell rejects
    `@{ a = 1; a = 2 }` outright, so a script carrying one never runs at all, and deleting it would
    make the rest of the script run. That is exactly the change this predicate exists to prevent,
    and it is why the keys are compared here rather than assumed apart.

    Only a string or integer key is compared, folded to a lowercased string, so the case-insensitive
    collision and the `@{ 1 = 'a'; '1' = 'b' }` cross-type one both count. Anything else — a real
    literal, a computed key — is rejected without comparison, since a key this cannot read is a
    duplicate it cannot rule out.
    """
    keys: set[str] = set()
    for key, value in node.pairs:
        if not isinstance(key, (Ps1IntegerLiteral, Ps1StringLiteral)):
            return False
        if not is_fault_free(value):
            return False
        written = str(key.value).lower()
        if written in keys:
            return False
        keys.add(written)
    return True


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

    Nor does any member say whether the statement can *throw*. That is `expression_cannot_fault`,
    which a caller about to remove an `OUTPUT` statement has to ask separately: `[Int]'abc'` and
    `1/0` are both `OUTPUT`, and removing either resumes a script that had terminated.
    """
    EFFECT = 'effect'
    OUTPUT = 'output'
    DISCARD = 'discard'


def _is_void_cast(node) -> TypeGuard[Ps1CastExpression]:
    """
    Whether a node is a cast to `[Void]`, the discard idiom that throws a value away. The name is
    resolved rather than compared as text, so every spelling of the type — `[System.Void]` among
    them — is the same idiom.
    """
    return (
        isinstance(node, Ps1CastExpression)
        and data.is_type(node.type_name, 'System.Void')
    )


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


def _is_null_discard(node) -> TypeGuard[Ps1AssignmentExpression]:
    """
    Whether a node is the `$Null = ...` discard idiom, which evaluates its right-hand side and puts
    nothing on the output.
    """
    return (
        isinstance(node, Ps1AssignmentExpression)
        and node.operator == '='
        and is_builtin_variable(node.target, {'null'})
    )


def statement_effect(stmt, world: Ps1WorldReach) -> StatementEffect:
    """
    Classify the observable effect of a standalone statement as a `StatementEffect`. This is the one
    shared authority the dead-code and junk-removal passes consult so they never disagree about
    whether a statement carries a body's output: a `DISCARD` emits nothing, an `OUTPUT` yields a
    value that emit-safety must protect in a captured body, and an `EFFECT` must always be kept.

    **`DISCARD` is a claim about emission and about nothing else.** It used to be read as *always
    safe to drop*, which held only because the one thing it admitted was a discard idiom over a pure
    expression. A call returning `System.Void` emits as little and can still throw, so what decides
    whether dropping it changes anything is the removal veto — `fault_is_observed` — and not this.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return StatementEffect.EFFECT
    expr = stmt.expression
    if expr is None:
        return StatementEffect.DISCARD
    if _is_void_cast(expr):
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
    if _is_null_discard(expr):
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

    This replaced a `BodyRole` that answered *where a body sits* and was read as *who reads it*.
    Under that enum a bare value at the script root was unprotected, because the root was not a
    "returning" body — so `'payload-marker'` beside `Write-Host 'go'` was deleted, and a `'junk'`
    ahead of a `Write-Output` inside a function changed the caller's value from a two-element array
    to a scalar. Position is the wrong question; the same block propagates to a different reader
    depending on what encloses it, and only the walk outward answers that.
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
    walk in `output_path` sees. Reading this as "the value escapes" is how an assigned call came
    to look like a discardable one.

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

    **This is an allow-list of propagating positions, and the polarity is the whole point.** The
    walk that reads it answers for any node in the tree, so a position this does not recognize is a
    position whose reader is unknown, and the answer to an unknown reader is `CAPTURED` — the one
    that prunes nothing. Enumerating the *consumers* instead and propagating by default is the
    inverse, and it deletes payloads: every value slot such an enumeration missed — a command
    argument, an `if` condition, a `foreach` source, an index, a `param` default — read as a value
    nobody holds, so the function called there was judged to write only to the console and the bare
    values in its body were deleted.

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

    So the same node answers differently depending on where it sits, and this is the point rather
    than an inconsistency to resolve later:

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


def fault_operand(stmt: Node) -> Node | None:
    """
    The expression whose fault is *stmt*'s fault, or `None` where *stmt* is not one expression.

    A discard idiom performs no work of its own: `$Null = X` and `[Void]X` evaluate `X`, name
    nothing and emit nothing, so what either of them can raise is what `X` can raise. Asking the
    statement's own expression instead asks about an assignment, which no reading of the value
    domain calls safe, and every discarded constant in an obfuscated script then reads as something
    that might throw.
    """
    if not isinstance(stmt, Ps1ExpressionStatement):
        return None
    expression = stmt.expression
    if expression is None:
        return None
    if _is_void_cast(expression):
        return expression.operand
    if _is_null_discard(expression):
        return expression.value
    return expression


def _is_bare_variable_read(node: Node) -> bool:
    """
    Whether *node* is an unqualified variable read and nothing else — the one expression shape whose
    only way to raise is a setting of the script rather than a property of its operands.

    Splatting is excluded because `@x` is not a read of the value at all, and every qualified
    spelling is excluded because none of them shares the fact this rests on. `$global:x` and
    `$script:x` read the same store and were measured not to raise, but `$using:x` is a different
    construct outside the block that binds it; and a drive qualifier reads no store at all —
    `${SomeDrive:path}` runs a provider, and what an arbitrary provider raises is not a question
    this can answer for the drives it has never seen. One test covers them because the lexer spells
    a drive as `Ps1ScopeModifier.DRIVE` like every other qualifier.

    **Purity does not gain this gate and must not.** `is_side_effect_free` accepts a bare read
    unconditionally, because reading a variable changes nothing whether or not the read raises. The
    two questions are separate here, and a reader expecting them to be symmetric would be wrong.
    """
    return (
        isinstance(node, Ps1Variable)
        and not node.splatted
        and node.scope is Ps1ScopeModifier.NONE
    )


def expression_cannot_fault(
    operand: Node,
    position: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None,
) -> bool:
    """
    Whether evaluating *operand* cannot raise **where *position* stands** — the question a removal
    site asks before it deletes an expression whose fault would have been observed.

    `is_fault_free` is the context-free half and stays exactly that: it grants only what cannot
    raise under any semantics, so a bare `$x` is not fault-free there and must not become so. What
    is added here is the one fault the *script* decides rather than the expression. Reading a
    variable that was never set yields `$null` under the default semantics and raises only where
    strict mode is armed, so a script that never arms it cannot fault on such a read — and the
    padding an obfuscator writes as `$junk | ForEach-Object { [void]$_ }` goes.

    **Two models answer that, and neither half alone is enough.**
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.strict_mode_may_be_in_force` reads what
    the script itself arms, wherever it is written;
    `refinery.lib.scripts.ps1.analysis.worldflow.Ps1WorldReach.closed_at` says whether anything the
    analysis cannot read may have run before *position*, and a payload it cannot read may arm strict
    mode as easily as a spelled-out call does. A caller with no world therefore gets the
    context-free answer alone, which is the fail-closed direction: a grant refused keeps a
    statement, a grant made in error deletes one whose handler runs.

    **The world half is a bound and not an answer.** What it reports is the type world's openers,
    and a command that runs code no tree holds is not always one of them — `Set-PSDebug -Strict`
    arms strict mode for the *global* scope, so any call this analysis cannot read through can arm
    it without being a leak the world names. The bound it does give is the one that covers the
    shapes an obfuscator writes, and everything it misses is stated with the entry-scope assumption
    on `strict_mode_may_be_in_force` rather than left silent.

    It is one function rather than a clause repeated at each caller because two removal sites
    answering it differently is a contradiction and not a difference of opinion: the same `$x` in
    the same script would be dropped as a discard and kept as a bare output.
    """
    if is_fault_free(operand):
        return True
    return (
        _is_bare_variable_read(operand)
        and world is not None
        and world.closed_at(position)
        and not faults.strict_mode_may_be_in_force()
    )


def _lies_in_a_block_within(site: Node, stmt: Node) -> bool:
    """
    Whether *site* stands inside a script block that is itself written inside *stmt*. A script block
    is the boundary asked about because it is what the graph builder gives a body of its own; a
    `catch` or `trap` body written in *stmt* stays in the same graph and is judged there.
    """
    cursor = site.parent
    crossed = False
    while cursor is not None and cursor is not stmt:
        crossed = crossed or isinstance(cursor, Ps1ScriptBlock)
        cursor = cursor.parent
    return crossed and cursor is stmt


def _leaves_a_block_of(site: Node, stmt: Node, faults: Ps1FaultReach) -> bool:
    """
    Whether an error raised at *site* has no destination that deleting *stmt* could change: *site*
    stands inside a script block written within *stmt*, and no handler of that block settles the
    error.

    Such an error arrives at one of two places, and neither is this gate's business. Where the block
    runs where it is written, the error leaves it and arrives exactly where an error raised by
    *stmt* itself arrives — which is *stmt*'s own point, weighed beside this one in the same loop.
    Where the block is kept rather than run, the value holding it is built by evaluating *stmt*, so
    a script without *stmt* never builds the block and never reaches the point at all.

    Without this, the fallback `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.observed_at`
    takes for a body something may call — whether a handler that acts is written anywhere else in
    this script — answers for every block an obfuscator writes inside a discarded pipeline, and a
    single `try` written elsewhere in the file keeps all of them.
    """
    return (
        site is not stmt
        and _lies_in_a_block_within(site, stmt)
        and faults.escapes_the_body(site)
    )


def fault_is_observed(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None = None,
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

    The first half is `expression_cannot_fault` over `fault_operand`, and the second is
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.observed_at`. Both are asked once per
    point the graphs evaluate inside *stmt*, because a construct is deleted whole and each of its
    parts raises where it stands; a construct the graphs place nothing for at all is refused, since
    a subtree nothing models is one nothing can clear.

    *stmt* is the position every point is weighed at, rather than the point itself: *stmt* is what
    the removal takes away, so what may have run before it is what decides whether the analysis can
    see the semantics its parts run under. A point inside a script block has no position in the root
    graph at all, and asking the world there refuses the shape this exists to clear.

    **This is not the question asked before a handler is deleted.** A `trap` cannot raise, so
    nothing about its own position decides anything: what a removal changes is where the errors of
    *other* statements go, and that is the transpose,
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.removing_a_handler_is_observed`.
    Nor is it the question asked before a guarded body is emptied, which is
    `emptying_unhooks_a_handler` — a policy about what a listing should still show rather than a
    claim about what runs.
    """
    judged = False
    for site in faults.points_in(stmt):
        judged = True
        operand = fault_operand(site)
        if operand is not None and expression_cannot_fault(operand, stmt, faults, world):
            continue
        if _leaves_a_block_of(site, stmt, faults):
            continue
        if faults.observed_at(site):
            return True
    return not judged


def statement_can_raise(
    stmt: Node,
    faults: Ps1FaultReach,
    world: Ps1WorldReach | None = None,
) -> bool:
    """
    Whether evaluating *stmt* may raise where it stands — the fault-possibility half of the
    transpose, asked of a statement a `trap` guards to decide whether that guard is load bearing.

    This is `fault_is_observed`'s first clause read on its own: a statement whose fault is one
    expression that `expression_cannot_fault` clears cannot reach a handler, so a `trap` written
    over nothing but such statements guards nothing and may go. Everything else may raise, which is
    the direction that keeps a handler rather than dropping one — a command whose errors the model
    does not read, a statement that is not one expression, a cast on the wrong operand.

    It is built here rather than in `refinery.lib.scripts.ps1.analysis.faults` because the predicate
    that decides it lives here, and it is injected into
    `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.removing_a_handler_is_observed` the way
    `expression_cannot_fault` is asked forward: the fault module stays free of the semantic model
    and takes the answer as a function. `world` widens the one bare-variable read
    `expression_cannot_fault` clears under a closed world, and is left out where a caller has none,
    which is the fail-closed direction — an unread world keeps the handler.
    """
    operand = fault_operand(stmt)
    if operand is None:
        return True
    return not expression_cannot_fault(operand, stmt, faults, world)


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
    question by walking `parent` is what used to delete live return values.

    **A `trap` left standing is not something that survived**, for the reason
    `refinery.lib.scripts.ps1.deobfuscation.unused.Ps1JunkStatementRemoval` does not count a
    definition: it is machinery for the statements around it rather than one of them, and a body
    holding nothing else runs nothing at all. Counting one let `trap { break }` beside a bare `'a'`
    erase the whole script in two steps — this pass deleted `'a'` because the `trap` looked like a
    survivor, and the next deleted the `trap` because nothing raised into it any more.
    """
    return isinstance(node, Ps1Script) and not any(
        not isinstance(statement, Ps1TrapStatement) for statement in survivors
    )


def _bound_default_may_throw(parameter: Ps1ParameterDeclaration) -> bool:
    """
    Whether the conversion a type constraint runs over this parameter's default value can raise. A
    default with no constraint is stored as it is written and a constraint with no default converts
    nothing; only the two together reach a conversion, and it runs on every call that omits the
    argument. Measured on 5.1, `[int] $x = 'abc'` throws it and `[int] $x = '42'` binds the Int32
    42.

    Not knowing is a throw, the direction `refinery.lib.scripts.ps1.analysis.values.Ps1Outcome`
    already reads as safe: a default the value domain cannot evaluate, or a constraint naming a type
    it does not model, is one this cannot prove converts, so its call is kept rather than dropped.
    """
    default = parameter.default_value
    constraint = next(
        (a for a in parameter.attributes if isinstance(a, Ps1TypeExpression)),
        None,
    )
    if default is None or constraint is None:
        return False
    target = data.resolve_type(constraint.name)
    if target is None:
        return True
    outcome = evaluate(default)
    if outcome.may_throw or outcome.value is UNKNOWN:
        return True
    return convert(outcome.value, target).may_throw


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
        and not _bound_default_may_throw(parameter)
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
