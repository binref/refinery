"""
What command a name denotes at a point in one PowerShell script.

Command resolution is one language fact: which command a name runs, following aliases and the
precedence and scoping rules that decide it. A name used before its definition, or defined in a
scope the use is not in, denotes no command at all, and an alias can shadow a user function of the
same name. This model answers the whole question once, so a caller rewrites a name only where 5.1
would resolve it the same way.

Three outcomes, kept apart because a caller does different things with each:

- **a name** — the invocation resolves to a concrete command, reached through a resolution step
  (`CommandKind.ALIAS`), or named directly as a script function (`CommandKind.FUNCTION`) or a known
  cmdlet (`CommandKind.CMDLET`). `Denotation.target` carries the canonical command name. A
  resolution step is an alias, or the implicit `Get-` retry that 5.1 falls back on — see
  `Ps1CommandModel._resolve`, which is why `alias zzq` reports the name `Get-Alias` rather than the
  command it in turn denotes.
- **nothing** (`CommandKind.NOTHING`) — the name denotes no command at this point, so 5.1 raises
  `CommandNotFoundException` and rewriting it is not meaning-preserving. It arises from an alias
  cycle, a wildcard alias target, a use its definition does not reach, or a definition in a scope the
  use is not in. The faithful output is the script exactly as written.
- **unknown** (`CommandKind.UNKNOWN`) — the model cannot decide: a computed name, an alias whose
  target is not a literal, a `Set-Alias` carrying `-Force`/`-Option` whose writability outcome is not
  static, or a definition that collides with a name the running host already binds. A caller refuses.

**Precedence is measured, not assumed.** On a 5.1 host `Get-Command` returns an alias over a function
of the same name and a function over a cmdlet, so this model resolves an alias before a function and a
function before a cmdlet. A default alias therefore wins over a script `function` of its name, which
is why `function echo { }; echo` runs `Write-Output` and not the body.

The precedence covers the names a script takes over through the `function:`/`alias:` variable
namespace (`${function:Get-ChildItem} = { ... }`), not only `function`/`filter` keyword definitions.
Such an assignment redefines command identity under a spelling this model cannot follow to a body, so
when no alias wins the name denotes *unknown* rather than the cmdlet the metadata would otherwise
report — the caller keeps it as written. The set of taken-over names is the world's
(`refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld.shadowed_names`), so this model and the closed-
world model cannot disagree about which names the script has shadowed.

**Writability is handled by refusal, not by a rebind table.** Nearly every default alias is
`ReadOnly` or `AllScope`, and a plain `Set-Alias` rebinds neither — measured on 5.1 as
`AliasNotWritable` for the first and `AliasAllScopeOptionCannotBeRemoved` for the second — so a
script `Set-Alias` naming an existing builtin alias almost never takes effect. Which aliases the
handful of exceptions are is deliberately not written down here: it is a property of the host's
table rather than of the language, it cannot be measured without reading the state of a machine, and
nothing below depends on it. Rather than ship the per-alias `Options` that would say which outcome a
collision had, the model treats every such collision — and any `-Force`/`-Option` definition — as
unknown and keeps the name as written, which is faithful whichever way the rebind went. Precise
builtin-rebind resolution waits on that metadata.

**A scope qualifier is part of an alias name, unlike a command name.** `Set-Alias global:foo X`
creates an alias called `global:foo`, which no later `foo` runs, so a definition is keyed by the
literal name it writes and `normalize_command_name` is not applied to it. That is the opposite of
what the same qualifier means on a `function` definition, where `function global:Get-Date` is what a
later bare `Get-Date` runs.

**What a command does to the world is asked here too**, through `Ps1CommandModel.world_role`, and for
the same reason the rest is: `refinery.lib.scripts.ps1.analysis.world` follows a name one hop through
the built-in alias table and cannot follow the script's own, so `Set-Alias e iex` hides a leak from
it. It cannot be fixed there — this model is built over the shadow set that one produces, so a world
consulting this one would be a cycle — and the deny-lists themselves stay there, where the argument
for what belongs on them is written. What is added here is the resolution, not a second list.

**Whether the alias table this answers from is the whole one is asked here too.** A binding written
by a statement whose own command this could not resolve — `Set-Alias mk Set-Alias -Force` followed
by `mk zzq Write-Output` — takes a name back without ever entering the table, and a resolution that
answered from the table anyway would name the command the script had just stopped running.
`unread_alias_bindings` reports those statements, and the resolution treats each as a kill: a use
before one still resolves, a use after one is refused with evidence. What such a statement did to a
name the script never defines is the open-world residual `Ps1CommandModel._resolve` declares.

**Whether a definition is still doing anything is asked here too.** A pass that has rewritten every
use it could would otherwise have to work out which definitions the uses it left behind still resolve
through, and that is this model's own resolution run backwards. `implicated_definitions` reports it
forwards instead — from the use — and `binding_only_definition`, `introspected_names` and
`reads_command_success` answer the three other things a definition's absence could change: what its
statement does besides bind, who reads the name back out of the alias table rather than using it, and
whether the engine state a statement writes is read. What to do with those answers is not decided
here; see `refinery.lib.scripts.ps1.deobfuscation.aliases`.

**Position and scope come from dominance**, which is why the ordering models precede this. A `Set-Alias` binds a
use only where its statement strictly dominates the use — it is guaranteed to have run — and the
per-script-block control-flow graphs put a definition in a function body and a use outside it in
different graphs, so the body's definition cannot reach the outer use. The reaching-definition
selection is `refinery.lib.scripts.analysis.reaching.ReachabilityQuery.reaching_definition`, the same
one variable flow uses: an alias name's `Set-Alias` statements are its writes and an invocation is a
read.
"""
from __future__ import annotations

import enum
import re

from typing import NamedTuple, Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    Projection,
)
from refinery.lib.scripts.analysis.dominance import DominatorModel
from refinery.lib.scripts.analysis.reaching import ReachabilityQuery
from refinery.lib.scripts.ps1.analysis.aliasdef import (
    ALIAS_DEFINING_COMMANDS,
    AliasDefinition,
    extract_alias_definition,
)
from refinery.lib.scripts.ps1.analysis.blocks import Ps1BlockModel, Ps1BlockReach
from refinery.lib.scripts.ps1.analysis.faults import a_stop_may_be_in_force
from refinery.lib.scripts.ps1.analysis.model import is_write_occurrence
from refinery.lib.scripts.ps1.analysis.naming import Ps1NameRole, named_references
from refinery.lib.scripts.ps1.analysis.world import (
    WorldRole,
    assigns_an_alias_name,
    command_role,
    may_touch_identity_provider,
    runs_another_script_file,
    runs_code_in_the_calling_scope,
    touches_identity_provider,
)
from refinery.lib.scripts.ps1.ast import (
    consumes_a_value,
    get_command_name,
    has_wildcard,
    implicit_get_retry,
    is_opaque_dispatch,
    normalize_command_name,
    resolve_command_name,
    string_value,
)
from refinery.lib.scripts.ps1.data import KNOWN_ALIAS, KNOWN_CMDLETS
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1HereString,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1Variable,
)


class CommandKind(enum.Enum):
    """
    What kind of command a name denotes. `ALIAS`, `FUNCTION` and `CMDLET` are the three ways it names
    a concrete command — the "a name" outcome — and `NOTHING` and `UNKNOWN` are the other two.
    """
    ALIAS = enum.auto()
    FUNCTION = enum.auto()
    CMDLET = enum.auto()
    NOTHING = enum.auto()
    UNKNOWN = enum.auto()


class Denotation(NamedTuple):
    """
    What an invocation's command name denotes: the `CommandKind` and, when it names a concrete
    command, its canonical spelling in `target`. `target` is `None` for `NOTHING` and `UNKNOWN`.
    """
    kind: CommandKind
    target: str | None

    @property
    def is_a_name(self) -> bool:
        """
        Whether the name denotes a concrete command, so `target` is set.
        """
        return self.kind in (CommandKind.ALIAS, CommandKind.FUNCTION, CommandKind.CMDLET)


class Ps1ErrorReadSites(NamedTuple):
    """
    The statements of one script that read back what a raise leaves behind, split by the two
    channels a raise writes and kept apart because they observe a raise under different rules.

    `persistent` is every node-placed read of `$Error`/`$StackTrace`, the record a terminating error
    leaves in place session-globally: a variable sigil and a cmdlet named-reference
    (`Get-Variable Error`) alike, since both name the store and neither survives inlining as text. A
    read of one observes a raise from anywhere forward-reachable before it.

    `success` is every node-placed read of `$?`, which every statement resets, so only a read that
    runs immediately after a raise observes it — the rule
    `refinery.lib.scripts.ps1.analysis.errorstate` layers on the persistent one for cluster 4.

    A read spelled in string text or built from a payload is in neither: it has no control-flow node
    until it is inlined, so it has no position, and the whole-script text scan
    `Ps1CommandModel.reads_the_error_record` owns it. These are the reads the graph places.
    """
    persistent: frozenset[Node]
    success: frozenset[Node]


#: The commands that read the whole alias table however they are asked, so that any of their
#: arguments may name an alias. `Export-Alias` writes every alias when no `-Name` selects one, and
#: its first positional argument is a path rather than a name; `Trace-Command` names trace sources,
#: and what it reports about a traced command is not bounded by them. Neither is worth binding
#: parameters for when the sound answer is that every name is read.
_TABLE_READING_COMMANDS = frozenset({'export-alias', 'trace-command'})

#: The commands that report on the named commands they are given, so that those names are the only
#: ones they read. A form that names none reads the whole table and is treated as one of the above.
#: `help` is here beside `Get-Help` because it is the 5.1 function that `help` and `man` resolve
#: to, and a reader the metadata identifies but this does not list reads a name nothing records.
_NAME_READING_COMMANDS = frozenset({'get-alias', 'get-command', 'get-help', 'help'})

#: The parameters under which the commands above take the name they report on. A bare `n` is not
#: among them although it is a prefix of `Name`: `Get-Command` also has `-Noun`, so `-N` names
#: neither on its own, and reading it as the name would record one name for a form that reports on
#: every command carrying a noun.
_READ_NAME_PARAMS = frozenset({'na', 'nam', 'name'})

#: The automatic variable holding whether the last command succeeded. A statement that runs sets it,
#: so removing one is visible to any read of it.
_SUCCESS_VARIABLE = '?'

#: The automatic variables a terminating error writes and a handler does not clear, beside `$?`.
#: `$LASTEXITCODE` is not among them: measured on 5.1, a caught `CommandNotFoundException`
#: leaves it at whatever the last native program put there.
#:
#: Case-folded on the way in rather than by the hand that writes an entry. One of the two readers
#: compares against a lowered name and the other is `re.IGNORECASE`, so a name added in PowerShell's
#: own casing would keep every text row green while the node walk silently stopped seeing it.
_ERROR_RECORD_VARIABLES = frozenset(name.lower() for name in ('Error', 'StackTrace'))

#: The record names as one alternation, escaped, so that a name added to `_ERROR_RECORD_VARIABLES`
#: reaches the pattern below and none of them can turn into regular-expression syntax on the way:
#: `?` and `^` are automatic variables whose unescaped spelling is a quantifier and an anchor.
_ERROR_RECORD_NAMES = '|'.join(
    re.escape(name) for name in sorted(_ERROR_RECORD_VARIABLES))

#: Every name a removal that rests on a raise disturbs — the two the record is written under and
#: `_SUCCESS_VARIABLE` beside them — spelled the way text a payload is written in spells them, where
#: no variable node exists to be walked. Built from those two constants rather than written out, so
#: that neither can be extended without this following.
#:
#: The sigil is what makes a spelling a read and the word alone is not, which is why this is a
#: pattern where `refinery.lib.scripts.ps1.analysis.worldflow._names_own_path` gets by with
#: containment: the names it looks for are coined ones nothing else says, and `error` is a word
#: English uses. The trailing boundary is load-bearing in the other direction —
#: `$ErrorActionPreference` and `$ErrorView` are ordinary settings that no raise writes and no
#: handler clears.
#:
#: Two spellings it answers `True` for that read nothing, both wider than the one the method
#: docstring owns. A scope prefix is any word, so `$env:Error` — an environment variable — is read
#: as the record; and the success variable is matched wherever its two characters stand, so a
#: regular expression written for an optional leading dollar sign is read as a use of it. Both only
#: ever keep a statement, which is why they are stated rather than narrowed: narrowing either is a
#: decision to delete more.
_ERROR_RECORD_SPELLED_OUT = re.compile(
    RF'\${{?(?:[A-Za-z]+:)?(?:{_ERROR_RECORD_NAMES})\b|\${re.escape(_SUCCESS_VARIABLE)}',
    re.IGNORECASE,
)

#: The command a definition must denote for its removal to be nothing but the unbinding of a name.
_SET_ALIAS = 'set-alias'

#: The block reaches that make a script block a value first and code second, so that its statements
#: are read out as text whether or not anything ever runs them.
_HELD_BLOCK_REACH = frozenset({Ps1BlockReach.STORED, Ps1BlockReach.UNKNOWN})


def _read_name_arguments(cmd: Ps1CommandInvocation, command: str) -> frozenset[str] | None:
    """
    The literal command names `cmd` reports on, or `None` when it names none, names one this cannot
    read, or selects what to report by anything other than a name. `-Name` carries them, and so
    does every free positional argument.

    **Every one of them is read, not the first.** `-Name` binds an array and sits at position zero,
    so `Get-Alias ls zzq` reports on both names; stopping at `ls` left `zzq` out of a set whose
    whole job is to say which names a definition is still about, and the definition went while the
    statement mentioning it stayed.

    A parameter that takes a value and is not the name answers `None` rather than being passed
    over. `Get-Alias -Definition Write-Output` reports every alias of a command, `-Exclude` reports
    everything but a pattern, and a parameter this does not know may have taken the very argument
    that would otherwise have read as a name — the same ambiguity
    `refinery.lib.scripts.ps1.analysis.aliasdef.extract_alias_definition` describes, in the
    direction where reading on means reporting one name for a form that reports on many. A
    parameter that takes no value narrows how the report is written rather than deciding what it
    is about, and it moves no argument, so reading on past one is safe.
    """
    written: list = []
    for argument in cmd.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            written.append(argument)
            continue
        if argument.kind is Ps1CommandArgumentKind.POSITIONAL:
            written.append(argument.value)
            continue
        if argument.name.lstrip('-').lower() not in _READ_NAME_PARAMS:
            if consumes_a_value(command, argument.name):
                return None
            continue
        if argument.kind is Ps1CommandArgumentKind.NAMED:
            written.append(argument.value)
    names: set[str] = set()
    for value in written:
        found = string_value(value) if value is not None else None
        if found is None:
            return None
        names.add(found)
    return frozenset(names) or None


class _BinderReach(NamedTuple):
    """
    Where one binder's binding can be ordered: the control-flow node it runs at in each graph it can
    be projected into, keyed by that graph's identity, and whether the projection ran out before it
    reached one that runs where it is written.

    `unordered` is not "reaches everything" spelled differently. A binder in a function body binds
    whenever that function is called, which may be before the definition it invalidates, after it,
    or not at all — so there is no node to compare against and every definition is refused.
    """
    binder: Node
    sites: dict[int, CfgNode]
    unordered: bool


class _Binding(NamedTuple):
    """
    What the alias table holds for one name at one use: the `definition` that reaches it, or the
    fact that a binding this model could not read may have `rebound` the name before it got there.

    The two are kept apart from "no definition reaches" because they are different answers. A name
    the script defines out of reach of a use denotes nothing — 5.1 raises — while a name a binding
    may have rebound denotes something this cannot name, and a caller that treated the second as the
    first would emit a `CommandNotFoundException` where the script ran a command.
    """
    definition: AliasDefinition | None
    rebound: bool


class _Resolution(NamedTuple):
    """
    What `Ps1CommandModel._resolve` found: the `Denotation`, the definitions it consulted on the way,
    and whether a binding it could not read through is why it names no command.

    The consulted definitions are what makes a definition's removal decidable. A caller that has
    rewritten every use it could cannot tell from the tree which definitions the uses it left behind
    still need — a use may reach one through three hops, or be refused *because* of one, or denote
    nothing precisely because one exists somewhere it cannot reach. All three are recorded, because
    all three are reasons the definition is doing something.

    The last is not a shade of the first — it separates two outcomes `CommandKind.UNKNOWN` and
    `CommandKind.NOTHING` each cover both of. A name nothing was seen to bind, which the collected
    metadata simply does not describe, is a refusal reached from ignorance: the world model's
    deny-list stance applies, an unrecognized command is not treated as a mutator, and
    `Ps1CommandModel.world_role` answers `WorldRole.NONE`. A name something *was* seen to bind, to
    something this model could not read through — a `-Force` rebind, a `function:` takeover, a
    definition that does not statically reach, a `Get-` retry landing on a name the host itself
    aliases — is a refusal reached *with* evidence, and answering that it leaves the world as it
    found it would be this model contradicting its own denotation.

    The evidence is usually the script's own, and then the definitions carrying it are in
    `implicated`; where it is the host's table instead there is nothing to implicate. The two are
    deliberately not told apart, because what a caller acts on is that the refusal had a reason,
    not whose it was.
    """
    denotation: Denotation
    implicated: tuple[AliasDefinition, ...]
    unread_binding: bool


def _stands_alone(at: CfgNode, definition: AliasDefinition) -> bool:
    """
    Whether the statement standing at *at* evaluates nothing beside *definition*, so that a claim
    about what the defining command can raise is a claim about the whole statement — see
    `Ps1CommandModel._binding_has_taken`.

    Answered by climbing from the invocation to the node the graph placed and refusing the first
    level that holds a sibling. What a sibling is worth is not weighed: an array element, a pipeline
    stage and an interpolated sub-expression are all evaluated by the same statement, any of them
    may raise before the binding is attempted, and which of them can is a question the fault model
    answers about a *position* rather than one this can read off an argument list.
    """
    element = at.element
    if element is None:
        return False
    cursor: Node = definition.node
    while cursor is not element:
        parent = cursor.parent
        if parent is None or len(parent.children()) != 1:
            return False
        cursor = parent
    return True


def _collect_alias_definitions(root: Ps1Script) -> dict[str, list[AliasDefinition]]:
    """
    Every invocation of the script that spells an alias definition, grouped by the name it binds and
    in source order within each group.

    Read by spelling, which is what makes this a *seed*: a script that has taken `Set-Alias` over
    with a function of its own spells a definition that never binds anything, and one that reaches a
    defining command under a name of its own spells no definition where there is one.
    `build_command_model` settles both against a model built over this.
    """
    collected: dict[str, list[AliasDefinition]] = {}
    for node in root.walk_in_order():
        if not isinstance(node, Ps1CommandInvocation):
            continue
        definition = extract_alias_definition(node)
        if definition is not None:
            collected.setdefault(definition.name, []).append(definition)
    return collected


class Ps1CommandModel:
    """
    What each command invocation of one script denotes. Build it through `build_command_model`; every
    query is `denotation`.
    """

    def __init__(
        self,
        root: Ps1Script,
        control_flow: ControlFlowModel,
        reach: ReachabilityQuery,
        blocks: Ps1BlockModel,
        functions: frozenset[str],
        shadowed: frozenset[str],
        definitions: dict[str, list[AliasDefinition]] | None = None,
        binders: tuple[Node, ...] = (),
    ):
        """
        `definitions` replaces the alias table this would otherwise read out of the tree, and
        `binders` names the nodes that may bind an alias without this having read the binding. Both
        are what `build_command_model` computes from a first instance of this class and hands to a
        second; neither is something a caller works out for itself.
        """
        self._root = root
        self._flow = control_flow
        self._reach = reach
        self._blocks = blocks
        self._functions = functions
        self._shadowed = shadowed
        self._alias_defs = (
            _collect_alias_definitions(root) if definitions is None else definitions)
        self._stop_in_force: bool | None = None
        self._binders = binders
        self._binder_reach = tuple(self._project_binder(binder) for binder in binders)
        self._binders_run_unordered = any(reach.unordered for reach in self._binder_reach)
        self._sites_by_graph: dict[int, list[CfgNode]] = {}
        self._memo: dict[int, _Resolution] = {}
        self._roles: dict[int, WorldRole] = {}
        self._introspected: frozenset[str] | None = None
        self._introspected_known = False
        self._reads_success: bool | None = None
        self._reads_error_record: bool | None = None
        self._error_read_sites: Ps1ErrorReadSites | None = None
        self._function_drive_reads: frozenset[str] | None = None

    def _project_binder(self, binder: Node) -> _BinderReach:
        """
        Where `binder`'s binding can be ordered: the node it stands at in its own control-flow
        graph, and the site of each enclosing block that runs where it is written, by the same
        outward projection `_reaching_alias_binding` performs on a use.

        A binder the projection cannot carry out to the script — one in a function body, one in a
        block held as a value, one in no graph at all — runs at a time nothing here orders, and is
        reported as such rather than as reaching a particular few nodes.

        **A binder in the script's own `process` block is one of them.** That block runs once per
        object the pipeline hands the script, and the per-body graph draws it straight through with
        no edge back to its first statement — so a binder written below a use reaches it on the
        second object and on every one after, along a path no walk over this graph can take. This is
        the refusal `refinery.lib.scripts.ps1.analysis.worldflow.build_world_reach` already makes for
        the same block and the same reason.
        """
        if self._in_the_process_block(binder):
            return _BinderReach(binder, {}, True)
        sites: dict[int, CfgNode] = {}
        located = self._flow.locate(binder)
        while located is not None:
            graph, node = located
            sites[id(graph)] = node
            owner = graph.owner
            if not isinstance(owner, Ps1ScriptBlock):
                return _BinderReach(binder, sites, False)
            facts = self._blocks.facts(owner)
            if facts.reach is not Ps1BlockReach.IMMEDIATE or facts.site is None:
                break
            located = self._flow.locate(facts.site)
        return _BinderReach(binder, sites, True)

    def _in_the_process_block(self, node: Node) -> bool:
        """
        Whether *node* is written inside the script's own `process` block, which re-runs once per
        object the pipeline hands it — see `_project_binder`.
        """
        block = self._root.process_block
        return block is not None and node.is_descendant_of(block)

    def denotation(self, invocation: Ps1CommandInvocation) -> Denotation:
        """
        What `invocation`'s command name denotes at its position — see this module's own
        documentation for the three outcomes. Memoized for as long as the tree is unchanged.
        """
        return self._resolution(invocation).denotation

    def _resolution(self, invocation: Ps1CommandInvocation) -> _Resolution:
        found = self._memo.get(id(invocation))
        if found is None:
            found = self._memo[id(invocation)] = self._resolve(invocation)
        return found

    def alias_definitions(self, name: str) -> Sequence[AliasDefinition]:
        """
        Every alias definition the script writes for `name`, in source order, wherever it sits.

        The key is the literal name the definition writes, lowercased and nothing more, because a
        scope qualifier is part of an alias name — see this module's own documentation.
        """
        return self._alias_defs.get(name.lower(), ())

    def every_alias_definition(self) -> Sequence[AliasDefinition]:
        """
        Every alias definition the script writes, for any name, grouped by name and in source order
        within each group.

        This is what the script's alias definitions *are* as far as this model is concerned, and a
        caller that must account for all of them reads it rather than enumerating names it thought
        of. It is not the same as every command that defines an alias: a definition this could not
        read — a computed name, a defining command reached under another name — is not here, and a
        caller that needs that guarantee asks `world_role` of every invocation instead.
        """
        return [definition for group in self._alias_defs.values() for definition in group]

    def implicated_definitions(self, invocation: Ps1CommandInvocation) -> Sequence[AliasDefinition]:
        """
        The alias definitions whose presence decides what `invocation` denotes: every one the
        resolution read on the way to its answer — see `_Resolution`. Empty when the name resolves
        without consulting any, which is what makes a definition removable.

        This is the question "is this definition still needed", asked from the use rather than from
        the definition. Asking it the other way round means predicting which uses *would* resolve
        through a definition that is no longer there, and that is the resolution run backwards.
        """
        return self._resolution(invocation).implicated

    def binding_only_definition(self, definition: AliasDefinition) -> bool:
        """
        Whether `definition` does nothing but bind its name — so that a script from which it is
        absent differs only in that the name is unbound.

        Every clause is a way for the statement to do something else besides:

        - It must **denote the `Set-Alias` cmdlet**, asked of the model rather than read off the
          spelling. The kind is checked as well as the target, because a script defining
          `function Set-Alias { <payload> }` denotes `FUNCTION` under a target that is the
          function's own spelling — reading only the target there says the statement binds a name
          when what it does is run the payload, and taking it out deletes a call that ran.
          `New-Alias` is refused although it binds: it throws when the name already has a binding,
          and the error it writes is an effect of its own.
        - Its name must not be one the **host already binds**. Nearly every default alias refuses a
          plain rebind, so the statement's whole observable effect is the error it raises; which
          error it is depends on host metadata this model does not carry, and it writes one either
          way.
        - Its target must not be a **wildcard**, which binds a name that resolves to no command, so
          removing it turns a `CommandNotFoundException` into whatever the name means without it.
        - Its name must carry **no scope qualifier**. `Set-Alias global:foo X` binds an alias called
          `global:foo` — measured on 5.1 — and this model keys definitions by the literal name, so
          the reaching-definition question that decides whether a use needs one was never asked of
          such a name.
        - It must carry **no argument** beyond the name and the value, and both must be **literal**.
          `refinery.lib.scripts.ps1.analysis.aliasdef.extract_alias_definition` reports this as a
          refusal, because a parameter it does not consume is one it cannot be sure did not
          consume the name.
        - It must stand where it **runs**, rather than inside a script block held as a value.
          PowerShell renders a scriptblock as its own source text, so `Write-Output { Set-Alias x
          Y }` writes the definition out instead of running it, and a script without the statement
          writes `{}` — a difference no question about the alias table can see, because the
          statement never reached the table.
          `refinery.lib.scripts.ps1.analysis.blocks.Ps1BlockReach` names the two block kinds this
          covers: one whose value is kept and one handed to something that may not run it.
        """
        node = definition.node
        if _denotes_a_defining_command(self, node) != _SET_ALIAS:
            return False
        if definition.refuse or definition.wildcard or definition.target is None:
            return False
        if definition.name in KNOWN_ALIAS:
            return False
        if self._stands_inside_a_held_block(node):
            return False
        return normalize_command_name(definition.name) == definition.name

    def _stands_inside_a_held_block(self, node: Ps1CommandInvocation) -> bool:
        cursor = node.parent
        while cursor is not None:
            if (
                isinstance(cursor, Ps1ScriptBlock)
                and self._blocks.facts(cursor).reach in _HELD_BLOCK_REACH
            ):
                return True
            cursor = cursor.parent
        return False

    def introspected_names(self) -> frozenset[str] | None:
        """
        The lowercased command names the script reads out of the alias table, or `None` when it
        reads names this cannot enumerate — which stands for *every* name.

        A rewrite reaches the uses of an alias, not the mentions of it. `Get-Alias foo` names the
        alias in an argument and reports what it is bound to, so a definition the uses no longer
        need is still what that answer is about, and `${alias:foo}` reads it through the variable
        namespace instead. The reader is identified through `denotation`, so `alias foo` and a
        script's own `Set-Alias g Get-Alias; g foo` are both recognized and neither is matched by
        spelling.

        `None` is the top element rather than an error: a reader given a computed name
        (`Get-Alias $n`), a wildcard, or no name at all reports on names this cannot list, and a set
        that quietly omitted them would answer `False` for exactly the definitions most likely to be
        in it. Every caller must read `None` as "every name is read".

        A command this model cannot identify is *not* read as a reader. That is the stance
        `refinery.lib.scripts.ps1.analysis.world` takes on mutation, taken here for the same reason —
        the collected metadata omits hundreds of host commands, and reading every one of them as a
        possible reader would make this answer `None` for almost any script — and it carries the same
        residual: `alias`, the built-in name of `Get-Alias`, must resolve through the alias table,
        or a statement that reads the alias table goes unrecognized.

        A name refused **with evidence** is the opposite case and answers `None`. Something was seen
        to bind it to something this model could not read through, so whether the statement is a
        reader is precisely what is not known, and a set that passed over it would report that nobody
        reads a name the statement may be reporting on.
        """
        if not self._introspected_known:
            self._introspected = self._collect_introspected_names()
            self._introspected_known = True
        return self._introspected

    def _collect_introspected_names(self) -> frozenset[str] | None:
        names: set[str] = set()
        for node in self._root.walk():
            if isinstance(node, Ps1Variable):
                if node.scope is Ps1ScopeModifier.ALIAS:
                    names.add(node.name.lower())
                continue
            if not isinstance(node, Ps1CommandInvocation):
                continue
            resolution = self._resolution(node)
            if resolution.unread_binding:
                return None
            target = resolution.denotation.target
            if target is None:
                continue
            reader = normalize_command_name(target)
            if reader in _TABLE_READING_COMMANDS:
                return None
            if reader not in _NAME_READING_COMMANDS:
                continue
            found = _read_name_arguments(node, reader)
            if found is None or any(has_wildcard(name) for name in found):
                return None
            names.update(name.lower() for name in found)
        return frozenset(names)

    def reads_command_success(self) -> bool:
        """
        Whether the script reads `$?`, the automatic variable holding whether the last command
        succeeded.

        Every statement that runs a command writes it, so removing one is observable to a later read
        even when the statement's own output is not: a `Set-Alias` that succeeds sets `$?` to true,
        and taking it out lets the failure before it through to the read. The variable is not the
        only engine state a removal disturbs, but it is the one a script can read back, and this is
        the fact a pass needs to decline the removal rather than reason about it.

        Memoized for as long as the tree is unchanged, like every other whole-tree answer here: the
        walk is the size of the script and a pass asks once per attempt at a removal.
        """
        if self._reads_success is None:
            self._reads_success = self._collect_reads_command_success()
        return self._reads_success

    def _collect_reads_command_success(self) -> bool:
        return any(
            isinstance(node, Ps1Variable)
            and node.scope is Ps1ScopeModifier.NONE
            and node.name == _SUCCESS_VARIABLE
            for node in self._root.walk()
        )

    def function_drive_reads(self) -> frozenset[str]:
        """
        The normalized command names a script reads back out of the function table through the
        `$function:` variable namespace. `$function:K` reports the scriptblock bound to `K`, so a
        pass that removes the definition of `K` deletes what that read is about, and a group is kept
        whole where a name is read this way — the rule `reads_command_success` applies to `$?`,
        applied to the function drive.

        Only a read is one: a `$function:K = { }` write is itself a definition, and
        `Ps1CallGraph.is_readable` already answers `False` wherever the tree holds one, so a caller
        weighing this beside that gate reads over reads alone. The `Get-Item function:K` provider
        path is the other spelling and reaches the same fact through `touches_identity_provider`,
        which opens the whole world; this one names a single function and keeps only it.

        Memoized for as long as the tree is unchanged, like every other whole-tree answer here.
        """
        if self._function_drive_reads is None:
            self._function_drive_reads = frozenset(
                normalize_command_name(node.name)
                for node in self._root.walk()
                if isinstance(node, Ps1Variable)
                and node.scope is Ps1ScopeModifier.FUNCTION
                and not is_write_occurrence(node)
            )
        return self._function_drive_reads

    def reads_the_error_record(self) -> bool:
        """
        Whether the script can read back what a terminating error leaves behind after a handler has
        caught it: `$Error`, `$?` and `$StackTrace`.

        A removal resting on a statement having raised and the raise having been swallowed still
        deletes the record the raise wrote. `reads_command_success` answers the `$?` half of that
        over variable nodes and this asks all three, that half included, over the nodes and over
        text beside them. The two therefore answer the same fact differently for a `$?` a script
        spells only in text: this one sees it and that one does not, and
        `refinery.lib.scripts.ps1.deobfuscation.aliases`, which reads that one, keeps its narrower
        answer. Widening it there would refuse an alias batch over text no payload runner can
        reach, since the gate beside it already refuses every script that can run text.

        A read spelled inside a payload has no variable node until the payload is inlined, and the
        removals that ask this run before that happens: measured, the drop is taken on an earlier
        fixpoint iteration than the inline, so a walk over variable nodes alone reports no read.
        Text is therefore scanned beside the nodes, and by spelling rather than by word: what a
        script says is a read of `$Error` is the sigil, so `Write-Host 'an error occurred'` is not
        one.

        **The sigil and the name have to stand in one literal**, which is narrower than "the payload
        can be decoded" and is the whole of what this reaches. A payload the passes fold into one
        string before the drop — `Invoke-Expression $c` over a stored `'$Error.Count'` — is caught;
        the same read split across two of them is not, and neither is one built out of characters.
        Measured, `$a = '$Err'; $b = 'or.Count'; iex ($a + $b)` and
        `$c = -join [char[]](36, 69, 114, 114, 111, 114); iex $c` both leave `$Error` standing in
        the output while the statement that filled it is deleted, so the output reads a different
        number than the input gave it. Those are wrong answers rather than the residual below, and
        they are pinned in `test.lib.scripts.ps1.deobfuscation.test_removal_observability`.

        Its cost in the other direction is one kind of false refusal: a script that *prints*
        `'$Error.Count'` and reads nothing is kept for saying the words. Its limit is the payload
        no walk decodes at all, where the record is read by code no scan here ever sees; that
        residual belongs to the caller, and
        `refinery.lib.scripts.ps1.deobfuscation.deadcode._is_injected_noise_bareword` states it.

        Reading the record through a cmdlet that names it — `Get-Variable Error`, `Get-Item
        Variable:Error` — is caught through
        `refinery.lib.scripts.ps1.analysis.naming.named_references`, which reports the name a command
        reads as a string the same way a `Ps1Variable` reports one read as a sigil, so a spelling
        that stores the result first is read as a read all the same. A name that is computed or a
        wildcard names no one variable this can list and is not caught here; that residual is the
        payload no walk decodes, which
        `refinery.lib.scripts.ps1.deobfuscation.deadcode._is_injected_noise_bareword` states.

        Memoized for as long as the tree is unchanged, like every other whole-tree answer here.
        """
        if self._reads_error_record is None:
            self._reads_error_record = (
                self.reads_command_success()
                or self._collect_reads_the_error_record())
        return self._reads_error_record

    def _collect_reads_the_error_record(self) -> bool:
        for node in self._root.walk():
            if isinstance(node, Ps1Variable):
                if node.name.lower() in _ERROR_RECORD_VARIABLES:
                    return True
            elif isinstance(node, (Ps1StringLiteral, Ps1HereString)):
                value = node.value
                if '$' in value and _ERROR_RECORD_SPELLED_OUT.search(value):
                    return True
            elif isinstance(node, Ps1CommandInvocation):
                if any(
                    reference.role is Ps1NameRole.READS
                    and reference.key in _ERROR_RECORD_VARIABLES
                    for reference in named_references(node)
                ):
                    return True
        return False

    def error_state_read_sites(self) -> Ps1ErrorReadSites:
        """
        The statements this script places that read back what a raise leaves behind — see
        `Ps1ErrorReadSites` for the split. This is the node-placed half of the same knowledge
        `reads_the_error_record` answers whole-script: it names the reads the control-flow graph
        can order, so `refinery.lib.scripts.ps1.analysis.errorstate` can ask whether one runs
        after a raise rather than merely anywhere in the file. The text and payload spellings the
        whole-script bool also catches have no node and are deliberately absent, since a position
        is exactly what they lack until they are inlined.

        Split by channel here, where the naming knowledge already lives, so the reach model layered
        on this need not re-derive which channel each name belongs to. Memoized for as long as the
        tree is unchanged, like every other whole-tree answer here.
        """
        if self._error_read_sites is None:
            self._error_read_sites = self._collect_error_state_read_sites()
        return self._error_read_sites

    def _collect_error_state_read_sites(self) -> Ps1ErrorReadSites:
        persistent: set[Node] = set()
        success: set[Node] = set()
        for node in self._root.walk():
            if isinstance(node, Ps1Variable):
                if node.name.lower() in _ERROR_RECORD_VARIABLES:
                    persistent.add(node)
                elif node.scope is Ps1ScopeModifier.NONE and node.name == _SUCCESS_VARIABLE:
                    success.add(node)
            elif isinstance(node, Ps1CommandInvocation):
                for reference in named_references(node):
                    if reference.role is not Ps1NameRole.READS:
                        continue
                    if reference.key in _ERROR_RECORD_VARIABLES:
                        persistent.add(node)
                    elif reference.key == _SUCCESS_VARIABLE:
                        success.add(node)
        return Ps1ErrorReadSites(frozenset(persistent), frozenset(success))

    def world_role(self, invocation: Ps1CommandInvocation) -> WorldRole:
        """
        What `invocation` does to the type world and the command table, with the script's own
        aliases followed — the question
        `refinery.lib.scripts.ps1.analysis.world.build_closed_world` asks of every node, re-asked
        where command identity is known. Memoized for as long as the tree is unchanged.

        The world model reads a name one hop through the built-in alias table and no further, so
        `Set-Alias e iex` followed by `e $payload` reads there as an ordinary command and the world
        reads closed over a script that runs whatever `$payload` says. It cannot read further: this
        model is built over the shadow set that one produces, so a world that consulted this one
        would be a cycle. The refinement therefore belongs here, and it is a refinement rather than
        a second opinion — the name as written is classified first, so this can only ever name a
        role where the world named one, or name one where the world named none.

        A command the collected metadata does not describe reads as `WorldRole.NONE`, which is the
        world model's stance and not a weaker one: mutation is a deny-list there, an unrecognized
        command is not treated as a mutator, and that residual is the declared soundness gap its own
        documentation names. Answering `UNKNOWN` for every command outside the metadata would make
        this a different, vacuous question.

        `UNKNOWN` is for the two ways nothing static bounds what runs: dispatch that is open by
        construction, which is the axis the world model runs as an allow-list, and a name something
        was seen to bind to something this model could not read through — see `_Resolution`. The
        second is why not naming a command is not on its own an answer of `NONE`: `Set-Alias e iex
        -Force` and `${function:Get-Date} = $x` each leave this model unable to say what a later use
        runs, and it knows exactly why.
        """
        found = self._roles.get(id(invocation))
        if found is None:
            found = self._roles[id(invocation)] = self._resolve_world_role(invocation)
        return found

    def _resolve_world_role(self, invocation: Ps1CommandInvocation) -> WorldRole:
        if is_opaque_dispatch(invocation):
            return WorldRole.UNKNOWN
        if runs_another_script_file(invocation):
            return WorldRole.LEAK
        written = resolve_command_name(invocation)
        if written is not None and (role := command_role(written)) is not WorldRole.NONE:
            return role
        resolution = self._resolution(invocation)
        target = resolution.denotation.target
        if target is not None and (role := command_role(target)) is not WorldRole.NONE:
            return role
        if touches_identity_provider(invocation):
            return WorldRole.IDENTITY
        if target is None and resolution.unread_binding:
            return WorldRole.UNKNOWN
        return WorldRole.NONE

    def _resolve(self, invocation: Ps1CommandInvocation) -> _Resolution:
        """
        Resolve `invocation`, recording the alias definitions it consults and, at every exit that
        names no command, whether the script's own definitions are the reason — see `_Resolution`.

        A definition is recorded wherever the resolution *read* it, not only where it followed one.
        Refusing because of a definition and denoting nothing because one exists out of reach are
        both uses of it: delete it and this invocation resolves to something else. Recording only
        the followed hops is the shape that reports `Set-Alias foo Get-*` and `Set-Alias foo *` as
        needed by nobody, and a differential cannot catch either — 5.1 raises
        `CommandNotFoundException` before and after, and the two errors differ only in a field the
        oracle drops.

        **A `New-Alias` among several definitions of one name is refused, not followed.** The
        reaching-definition selection answers which write is nearest, which is what a rebinding
        `Set-Alias` does; `New-Alias` raises instead of rebinding, so where the name has more than
        one definition the effective one is the *first* that ran, and nearest is exactly the wrong
        answer. Deciding which one that is needs the order the definitions execute in and what the
        host already bound, so the model says it cannot tell. Every definition of the name is
        implicated, because any of them could be the one that took.

        **The last tier is the implicit `Get-` retry**, which 5.1 falls back on for a name nothing
        else claims — `alias zzq` runs `Get-Alias`, `childitem` runs `Get-ChildItem`. Whether there
        is a retry at all, and what name it tries, is
        `refinery.lib.scripts.ps1.ast.implicit_get_retry`; that it is reached here and nowhere
        earlier is what makes it the last resort it is measured to be.

        What the retry produces is a **name**, not a command, so the prefixed spelling is resolved
        through the ordinary precedence in turn: `function Get-Alias { 'from-function' }; alias zzq`
        also writes `from-function`. Rewriting `alias` to `Get-Alias` is meaning-preserving
        whichever tier ends up claiming the prefixed spelling, and once rewritten every other model
        reads an ordinary call — which is what keeps the call graph from deleting a function whose
        only caller spelled it as a bare noun.

        **Being the last tier is what makes the retry the one resolution an open world can take
        back, and that is a residual this does not close.** A definition injected by code the walk
        cannot read — a dot-sourced file, a string an `iex` runs — beats a retry, where it loses to
        an alias; so `. .\\other.ps1` followed by `item env:x` is rewritten to `Get-Item` although
        the file may define `function item`. The tiers below are read from `_functions`, `_shadowed`
        and the host's tables, none of which is closed under a world this model never asked about.
        The reasoning that made the built-in alias table safe here does not carry over, precisely
        because an alias outranks an injected function and a retry does not.

        The prefixed name's own tiers are asked in this same sequence but more coarsely, and every
        refusal among them is an unread binding like any other: a script that writes `Set-Alias
        Get-Alias Get-Date` makes `alias zzq` run `Get-Date`, so that definition is implicated by
        the bare noun although the noun never named it. Refusing without saying so is what let it be
        deleted as needed by nobody, after which the noun was rewritten to the name it had rebound.
        Asking the shadow set before the function tier would refuse every ordinary
        `function Get-X { }` as well, since a `function` definition puts its name in both.

        **Coarsely, and that is a known residual.** A definition of the prefixed name is refused for
        merely existing, where the bare name's is sought by reaching definition and followed; a
        built-in alias of it is refused where the bare name's is hopped through. So `Set-Alias
        Get-Item Write-Host` beside `item env:x` answers `UNKNOWN` rather than `Write-Host`, and a
        bare noun whose prefixed spelling the host binds as an alias — `apppackage` for
        `Get-AppPackage` — answers `UNKNOWN` although 5.1 resolves it. Both refuse, so both are the
        safe direction; what they cost is recall, and closing them means making the retry a hop in
        the loop above rather than a second copy of it.

        **A binding this model could not read takes its name back**, wherever it runs between a
        definition and a use. `Set-Alias mk Set-Alias -Force` followed by `mk zzq Write-Output`
        binds `zzq` through a statement whose own name this cannot resolve, so an earlier
        `Set-Alias zzq Write-Host` no longer says what a later `zzq` runs. Those statements are
        `unread_alias_bindings`, and `_reaching_alias_binding` hands them to the reaching-definition
        selection as kills — which is why a use before them still resolves, and why the loader that
        rebinds a name and then uses it is unaffected.

        **What such a binding did to a name the script never defines is not modelled**, and that is
        the same open-world residual the paragraph above declares. A binder may bind `ls` as readily
        as `zzq`, and this still answers `Get-ChildItem` for it. Closing that means refusing every
        resolution downstream of any opaque dispatch, which is most of the scripts this exists for;
        what is closed here is the narrower claim the model actually makes, that the table it built
        from the script's own definitions says what those names run.

        An inline scriptblock (`&{ ... }`) is not an unread binding: its body stands in the tree, so
        the whole-tree walk reads whatever it does. The unlocatable node is, defensively — a node in
        no control-flow graph is one this model knows nothing about, including whether the script
        bound the name it carries.
        """
        implicated: list[AliasDefinition] = []

        def resolved(kind: CommandKind, target: str | None, unread: bool = False) -> _Resolution:
            return _Resolution(Denotation(kind, target), tuple(implicated), unread)

        name = get_command_name(invocation)
        if name is None:
            return resolved(CommandKind.UNKNOWN, None)
        if self._flow.locate(invocation) is None:
            return resolved(CommandKind.UNKNOWN, None, True)
        visited: set[str] = set()
        current = normalize_command_name(name)
        spelling = name
        hops = 0
        while True:
            if current in visited:
                return resolved(CommandKind.NOTHING, None)
            binding = self._reaching_alias_binding(current, invocation)
            if binding.rebound:
                implicated.extend(self._alias_defs[current])
                return resolved(CommandKind.UNKNOWN, None, True)
            reaching = binding.definition
            if reaching is not None:
                implicated.append(reaching)
                if current in KNOWN_ALIAS or reaching.refuse:
                    return resolved(CommandKind.UNKNOWN, None, True)
                if reaching.throws_if_bound and len(self._alias_defs[current]) > 1:
                    implicated.extend(self._alias_defs[current])
                    return resolved(CommandKind.UNKNOWN, None, True)
                if reaching.wildcard or reaching.target is None:
                    return resolved(CommandKind.NOTHING, None)
                visited.add(current)
                spelling = reaching.target
                current = normalize_command_name(reaching.target)
                hops += 1
                continue
            if current in self._alias_defs:
                implicated.extend(self._alias_defs[current])
                return resolved(CommandKind.NOTHING, None, True)
            builtin = KNOWN_ALIAS.get(current)
            if builtin is not None:
                visited.add(current)
                spelling = builtin
                current = normalize_command_name(builtin)
                hops += 1
                continue
            break
        if hops > 0:
            return resolved(CommandKind.ALIAS, KNOWN_CMDLETS.get(current, spelling))
        if current in self._functions:
            return resolved(CommandKind.FUNCTION, spelling)
        if current in self._shadowed:
            return resolved(CommandKind.UNKNOWN, None, True)
        if current in KNOWN_CMDLETS:
            return resolved(CommandKind.CMDLET, KNOWN_CMDLETS[current])
        prefixed = implicit_get_retry(current)
        if prefixed is None:
            return resolved(CommandKind.UNKNOWN, None)
        definitions = self._alias_defs.get(prefixed)
        if definitions is not None:
            implicated.extend(definitions)
            return resolved(CommandKind.UNKNOWN, None, True)
        if prefixed in KNOWN_ALIAS:
            return resolved(CommandKind.UNKNOWN, None, True)
        if prefixed in self._functions:
            return resolved(CommandKind.ALIAS, KNOWN_CMDLETS.get(prefixed, prefixed.capitalize()))
        if prefixed in self._shadowed:
            return resolved(CommandKind.UNKNOWN, None, True)
        canonical = KNOWN_CMDLETS.get(prefixed)
        if canonical is not None:
            return resolved(CommandKind.ALIAS, canonical)
        return resolved(CommandKind.UNKNOWN, None)

    def _reaching_alias_binding(
        self,
        name: str,
        invocation: Ps1CommandInvocation,
    ) -> _Binding:
        """
        What the alias table holds for `name` at the use in `invocation` — see `_Binding`.

        An alias is session-wide: a `Set-Alias` in one scope is visible in the scopes nested inside
        it, so a definition at the top level reaches a use inside a `ForEach-Object` block. The use
        is therefore projected outward — onto the site where each enclosing block runs — and a
        definition sought in that scope, climbing until one is found or a body is reached that does
        not run when its site does (a function body, a stored block), which a definition inside does
        not escape. This is the projection `refinery.lib.scripts.ps1.analysis.dataflow` performs for
        a variable read; the nearest enclosing scope with a reaching definition wins, so a
        block-local rebinding shadows an outer one. A definition strictly dominates the projected
        use, so it is guaranteed to have run before it.

        A binder standing at the use's own node is not among the kills. A command's name is resolved
        before the command runs, so whatever it goes on to bind cannot decide which command it was —
        and a binder that killed its own use would answer that `mkalias gd Get-Date` cannot tell
        what `mkalias` is.

        **A binder is a kill, and it is asked about only where the script defines the name.** A
        binding this model could not read may rebind anything, so a definition it does not run
        between is untouched and one it does is gone — which is what
        `refinery.lib.scripts.analysis.reaching.ReachabilityQuery.reaching_definition` already means
        by a kill, and why the binders are handed to it rather than compared by position. Where the
        script defines no such name there is nothing to invalidate and the answer is the same either
        way: what a binder may have bound to a name this model never saw defined is the open-world
        residual `_resolve` declares, not a fact the alias table holds.

        **A definition in the script's own `process` block that is not the one reaching is a
        refusal, by the same reading `_project_binder` makes of a binder there.** That block runs
        once per object the pipeline hands the script and the per-body graph draws it straight
        through, so a definition dominance places *after* the use has in fact bound the name for
        every object but the first. Ordering it by this graph reports a binding that is not the one
        the run observes, and answers with a command spelling rather than a refusal.
        """
        definitions = self._alias_defs.get(name, ())
        if not definitions:
            return _Binding(None, False)
        if self._binders_run_unordered:
            return _Binding(None, True)
        located = self._flow.locate(invocation)
        while located is not None:
            graph, use = located
            candidates = [
                (definition, placed[1])
                for definition in definitions
                if (placed := self._flow.locate(definition.node)) is not None
                and placed[0] is graph
            ]
            if candidates:
                kills = [id(site) for site in self._binder_sites_in(graph) if site is not use]
                reaching = self._reach.reaching_definition(graph, use, candidates, kills)
                if any(
                    definition is not reaching and self._in_the_process_block(definition.node)
                    for definition, _ in candidates
                ):
                    return _Binding(None, True)
                if reaching is not None:
                    at = next(node for definition, node in candidates if definition is reaching)
                    if not self._binding_has_taken(graph, at, use, reaching):
                        return _Binding(None, True)
                    if self._rebind_may_be_refused(graph, use, reaching, candidates, kills):
                        return _Binding(None, True)
                    return _Binding(reaching, False)
                if (
                    self._a_binder_reaches(graph, use)
                    or id(use) not in self._reach.reachable(graph.entry, forward=True)
                ):
                    return _Binding(None, True)
            owner = graph.owner
            if not isinstance(owner, Ps1ScriptBlock):
                break
            facts = self._blocks.facts(owner)
            if facts.reach is not Ps1BlockReach.IMMEDIATE or facts.site is None:
                break
            located = self._flow.locate(facts.site)
        return _Binding(None, False)

    def _binding_has_taken(
        self,
        graph: ControlFlowGraph,
        at: CfgNode,
        use: CfgNode,
        definition: AliasDefinition,
    ) -> bool:
        """
        Whether the definition standing at `definition` has certainly bound its name by the time
        `use` runs.

        Dominance says the definition *runs first* on every path to the use. It does not say the
        definition *finished*: a statement that raises an error a handler takes has run and bound
        nothing, and where that handler resumes the block — or where a `catch` beside it carries on
        past the construct — the use runs anyway. Resolving there rewrites the call to whatever the
        definition was going to bind, which is a command the run does not execute.

        Two ways out, and the second is what keeps the recall this exists to have. Either no run
        leaves the definition on a raise and still reaches the use — every edge out of it that is
        taken only on a throw leads somewhere the use is not — or the definition cannot raise a
        terminating error in the first place, which `_cannot_raise` decides. A plainly written
        `Set-Alias name value` is the second, and that is the shape obfuscated PowerShell wraps in
        resuming traps.

        **The second way out is about a command and the edges are about a statement, so it is asked
        only where the two are the same thing.** The raise-taken edges hang off the node the graph
        places, which is the whole statement; `_cannot_raise` reads the defining invocation and its
        arguments. Where the statement holds anything else — an operand beside it in an array, a
        stage upstream of it in a pipeline, an interpolation before it in a string — that other
        thing may raise before the binding is ever attempted, and the handler resumes past the whole
        statement with the name still unbound. `_stands_alone` is that question, and without it a
        `trap { continue }` over `$x = "$(1/0)$(Set-Alias zzq Get-Date)"` resolves a use of `zzq`
        below it to a command the run never binds.
        """
        raising = [target for target in at.successors if graph.raise_taken(at, target)]
        if not any(
            id(use) in self._reach.reachable(target, forward=True) for target in raising
        ):
            return True
        return _stands_alone(at, definition) and self._cannot_raise(definition)

    def _cannot_raise(self, definition: AliasDefinition) -> bool:
        """
        Whether running `definition` certainly ends in the binding being made, so that a use below
        it observes it however the block it is written in carries on.

        A definition this model resolves through carries nothing but its name and its target, both
        statically spelled: every other parameter — `-Force`, `-Option`, an `-ErrorAction`, a third
        positional — makes `refinery.lib.scripts.ps1.analysis.aliasdef.AliasDefinition.refuse`
        true, and an argument with no static reading leaves the target unread, which does the
        same. So the only errors left are the ones the engine reports for the binding itself, and
        5.1 reports those *non-terminating*: a rebinding refused against a read-only entry writes
        an error record and control carries straight on. A `trap` is offered nothing, and this is
        a completion.

        That reading holds only while nothing has armed `Stop`, which turns every reported error
        into one a handler takes — so `a_stop_may_be_in_force` is asked of the whole script, in its
        strict spelling rather than the fault model's lax one.

        `New-Alias` is the exception among the defining commands: it raises rather than rebinding
        where the name already has a binding, and that error is terminating.
        """
        if definition.refuse or definition.throws_if_bound:
            return False
        if self._stop_in_force is None:
            self._stop_in_force = a_stop_may_be_in_force(self._root)
        return not self._stop_in_force

    def _rebind_may_be_refused(
        self,
        graph: ControlFlowGraph,
        use: CfgNode,
        reaching: AliasDefinition,
        candidates: Sequence[tuple[AliasDefinition, CfgNode]],
        kills: Sequence[int],
    ) -> bool:
        """
        Whether the plain rebind `reaching` may have been refused against a name an earlier
        definition left read-only, so the use runs the earlier binding rather than this one.

        A `Set-Alias`/`New-Alias` carrying `-Option` or `-Force` may install a `ReadOnly` or
        `Constant` alias — the model does not read which, so
        `refinery.lib.scripts.ps1.analysis.aliasdef.AliasDefinition.refuse` covers them all — and
        a plain `Set-Alias` to a name so locked is refused rather than rebinding it. 5.1 reports
        that refusal *non-terminating*: control reaches the use with the earlier binding still in
        place, so the command the call runs is not the one this definition names. Measured on 5.1,
        `Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'` runs
        `Write-Error`, and rewriting the call to `Write-Output` runs a command the script does not.

        Asked only of a plain rebind whose failure would carry on. A definition that itself carries
        an option is already refused where it is the one reaching, and under an armed `Stop` the
        refusal terminates the statement instead — so a use the run reaches is one the rebind took,
        which is what `_cannot_raise` decides and why the two are asked together here. The lock is
        sought by reaching definition among the same candidates: only one that strictly dominates
        the use could have run before it, and only a locking definition earlier than the reaching
        rebind is here to find, since a nearer one would be the reaching definition itself.
        """
        if reaching.refuse or not self._cannot_raise(reaching):
            return False
        locking = [(definition, node) for definition, node in candidates if definition.refuse]
        if not locking:
            return False
        return self._reach.reaching_definition(graph, use, locking, kills) is not None

    def _binder_sites_in(self, graph: ControlFlowGraph) -> list[CfgNode]:
        found = self._sites_by_graph.get(id(graph))
        if found is None:
            found = self._sites_by_graph[id(graph)] = [
                site for reach in self._binder_reach
                if (site := reach.sites.get(id(graph))) is not None
            ]
        return found

    def _a_binder_reaches(self, graph: ControlFlowGraph, use: CfgNode) -> bool:
        """
        Whether any binder recorded in `graph` runs on some path to `use`, its own node aside.

        Asked to tell the two ways no definition reaches apart: one a binder took away, and one that
        was never going to reach anyway. They arrive here as the same `None` and mean opposite
        things — a name nothing bound raises, a name something rebound runs whatever it rebound it
        to.
        """
        return any(
            site is not use and id(use) in self._reach.reachable(site, forward=True)
            for site in self._binder_sites_in(graph)
        )

    def unread_alias_bindings(self) -> Sequence[Node]:
        """
        Every node that may bind an alias whose binding this model did not read — a defining command
        reached under a name this could not resolve, a computed alias name, a provider path into the
        `alias:` drive, an opaque dispatch, an `Invoke-Expression` or a dot-source. Empty means the
        script's alias table is exactly what `every_alias_definition` reports, so every resolution
        through it is complete.

        **A use whose own name this could not resolve is one of them**, which is what makes the set
        larger than the statements that look like definitions. `Set-Alias mk Set-Alias -Force`
        followed by `mk zzq Write-Output` binds `zzq` through a statement that spells no binding at
        all, and there is no reading of `mk` under which this is a definition — the only thing known
        about it is that it is a command this model cannot name, and a command it cannot name may
        be a defining one.

        That is broader than it has to be, and the residual is the same one the deferred discovery
        pass would close. A refusal reached through a definition this model *did* read has a known
        candidate set — the host's binding and the definition's target — and where neither of those
        is a defining command the use cannot bind anything: `Set-Alias gci Write-Output; gci` is
        reported although `gci` runs either `Get-ChildItem` or `Write-Output`. Narrowing it means
        carrying the candidates rather than a single answer, which is the may-set formulation, so
        the refusal stays whole rather than being narrowed by a second rule that would have to say
        what a resolution already knows.

        Public, and carrying the nodes rather than a boolean, because every whole-tree answer here
        is derived from resolutions and each of them fails *open* under a refusal it was not told
        about: an empty `implicated_definitions` reads as "removable", an empty `introspected_names`
        as "no names read". A caller that must know whether this model saw the whole table asks, and
        a test that must tell "incomplete" from "this one name is computed" reads the same fact.
        """
        return self._binders

    def unread_alias_bindings_reaching(self, invocation: Ps1CommandInvocation) -> Sequence[Node]:
        """
        The subset of `unread_alias_bindings` that may have run before `invocation`, so that a
        caller can say which binding is why a name it expected to resolve did not.

        Empty for an invocation no binder reaches, including one that runs before every binder in
        the script — a binding takes effect from where it runs, and refusing a use ahead of it would
        refuse the loader this exists to unpack over a rebind it never saw.
        """
        return tuple(
            reach.binder for reach in self._binder_reach
            if self._binder_may_precede(reach, invocation)
        )

    def _binder_may_precede(self, reach: _BinderReach, invocation: Ps1CommandInvocation) -> bool:
        if reach.unordered:
            return True
        located = self._flow.locate(invocation)
        while located is not None:
            graph, use = located
            site = reach.sites.get(id(graph))
            if site is not None and id(use) in self._reach.reachable(site, forward=True):
                return True
            owner = graph.owner
            if not isinstance(owner, Ps1ScriptBlock):
                return False
            facts = self._blocks.facts(owner)
            if facts.reach is not Ps1BlockReach.IMMEDIATE or facts.site is None:
                return True
            located = self._flow.locate(facts.site)
        return True


def _denotes_a_defining_command(model: Ps1CommandModel, node: Ps1CommandInvocation) -> str | None:
    """
    The alias-defining command `node` denotes, or `None` when it denotes something else.

    The kind is checked as well as the target, because a script defining `function Set-Alias { … }`
    denotes `FUNCTION` under a target that is the function's own spelling. Reading the target alone
    says the statement binds a name when what it does is run that body — which is how a call that
    ran came to be deleted, and how a binding that never happened came to be resolved through.
    """
    denotation = model.denotation(node)
    if denotation.kind not in (CommandKind.ALIAS, CommandKind.CMDLET):
        return None
    if denotation.target is None:
        return None
    command = normalize_command_name(denotation.target)
    return command if command in ALIAS_DEFINING_COMMANDS else None


class _SettledTable(NamedTuple):
    """
    The seeded alias table after the model has been asked about the statements that spell it: the
    `definitions` to build the second model over — `None` when the seed needs no correcting — and
    the `unread` statements whose binding this could not read, which are binders like any other.
    """
    definitions: dict[str, list[AliasDefinition]] | None
    unread: tuple[Ps1CommandInvocation, ...]


def _settle_alias_definitions(model: Ps1CommandModel) -> _SettledTable:
    """
    The seeded alias table with every entry whose own invocation does not denote a defining command
    marked refused.

    `refinery.lib.scripts.ps1.analysis.aliasdef.extract_alias_definition` matches by spelling, so
    the seed holds a binding for every statement that *reads* as one. Asking the model what each of
    those statements denotes is the same resolution the table is there to serve, one step earlier:
    a script that has taken `Set-Alias` over with a function of its own binds nothing, and a table
    that says otherwise resolves later uses through a binding that never happened.

    **Refused, not removed.** A statement that spells a binding of `ls` and does something else is
    still a statement about `ls`, and dropping it would let the name fall through to the host's
    table and be rewritten to `Get-ChildItem` — the definition's absence answering more confidently
    than its presence did. Marking it refused keeps the name occupied by the one thing that is
    known about it, which is that this model cannot say what it holds.
    """
    settled: dict[str, list[AliasDefinition]] = {}
    unread: list[Ps1CommandInvocation] = []
    for definition in model.every_alias_definition():
        if _denotes_a_defining_command(model, definition.node) is None:
            unread.append(definition.node)
            definition = definition._replace(refuse=True)
        settled.setdefault(definition.name, []).append(definition)
    return _SettledTable(settled if unread else None, tuple(unread))


def _may_bind_an_alias(model: Ps1CommandModel, node: Ps1CommandInvocation) -> bool:
    role = model.world_role(node)
    if role is WorldRole.IDENTITY or may_touch_identity_provider(node):
        return True
    if role is WorldRole.LEAK:
        return runs_code_in_the_calling_scope(node, model.denotation(node).target)
    return role is WorldRole.UNKNOWN and model.denotation(node).kind is CommandKind.UNKNOWN


def _unread_alias_binders(
    model: Ps1CommandModel,
    root: Ps1Script,
    read: frozenset[int],
) -> tuple[Node, ...]:
    """
    Every node that may bind an alias and is not one of the `read` definitions the alias table
    holds — the set `Ps1CommandModel.unread_alias_bindings` reports.

    **May bind is `WorldRole.IDENTITY`, or `WorldRole.UNKNOWN` over a name that denotes something.**
    The first is the deny-list the world model already keeps, re-asked where the script's own
    aliases are followed. It is neither of the other two opening roles: `MUTATION` is
    `Import-Module`, which does bind aliases but binds them on nearly every real script, and `LEAK`
    runs its code somewhere this table is not — a `Start-Job` block in another runspace, an
    `Invoke-Expression` that already arrives as `UNKNOWN` when its callee is computed. Reading
    either as a binder refuses the loaders this exists to unpack.

    The second is the two ways nothing static bounds what a node runs, and the denotation is asked
    beside the role because `WorldRole.UNKNOWN` also covers a name that denotes **nothing**. A use
    ahead of its own definition runs no command at all — 5.1 raises — so it binds nothing, and
    reading the evidence behind its refusal as a possible binding lets every such use invalidate
    the table it was refused by.

    **A binding the model read is not among them**, or a readable `Set-Alias` would invalidate its
    own use and no alias would resolve anywhere. That includes one read but refused — a `-Force`
    rebind is in the table under the name it writes, and the resolution refuses it exactly where it
    reaches, which is finer than anything a whole-node refusal could say.

    The two binding forms that have no `world_role` to ask are named directly:
    `refinery.lib.scripts.ps1.analysis.world.assigns_an_alias_name` for the `alias:` namespace write,
    which is an assignment rather than a command, and `may_touch_identity_provider` for an item
    cmdlet whose path is an expression — the deny-list keyed on the drive a *literal* names cannot
    see `Set-Item $p Write-Host`, and the world model deliberately does not widen for it.
    """
    binders: list[Node] = []
    for node in root.walk_in_order():
        if id(node) in read:
            continue
        if isinstance(node, Ps1CommandInvocation):
            if _may_bind_an_alias(model, node):
                binders.append(node)
        elif assigns_an_alias_name(node):
            binders.append(node)
    return tuple(binders)


def build_command_model(
    root: Ps1Script,
    control_flow: ControlFlowModel,
    dominance: DominatorModel,
    blocks: Ps1BlockModel,
    functions: frozenset[str],
    shadowed: frozenset[str],
) -> Ps1CommandModel:
    """
    Build the `Ps1CommandModel` for a script from its control-flow model, its dominators, the block
    model that says where each script block runs, the set of command names it defines as `function`
    or `filter`, and the wider set of names it takes over by any means — the latter from
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld.shadowed_names`.

    **Two questions about the alias table can only be asked of a model that has one**, so a seed is
    built first and the answer is a second model carrying what the seed reported: which of the
    statements that spell a binding actually denote one, and which nodes may bind without this
    having read the binding. A script whose table the seed read whole — every script with no alias
    at all, and most that have them — gets the seed itself back.

    Two immutable instances rather than one that learns. A model that gained the binder set after
    answering questions would have memoized the answers it gave before it had them, and clearing
    that memo by hand is a discipline the next query to be added would not know about. The seed's
    memo is discarded with the seed.

    **One round is enough**, and the reason is the shape of the refusal rather than a fixpoint
    argument. A node the second model refuses where the seed did not is one a binder reaches; if
    that refusal would make it a binder in turn, everything it could reach is downstream of it and
    therefore downstream of the binder that refused it, so already refused. A third model would
    have nothing left to say.
    """
    seed = Ps1CommandModel(
        root,
        control_flow,
        ReachabilityQuery(dominance, Projection.FORWARD),
        blocks,
        functions,
        shadowed,
    )
    settled = _settle_alias_definitions(seed)
    unread = {id(node) for node in settled.unread}
    read = frozenset(
        id(definition.node) for definition in seed.every_alias_definition()
        if id(definition.node) not in unread
    )
    binders = _unread_alias_binders(seed, root, read)
    if settled.definitions is None and not binders:
        return seed
    return Ps1CommandModel(
        root,
        control_flow,
        ReachabilityQuery(dominance, Projection.FORWARD),
        blocks,
        functions,
        shadowed,
        settled.definitions if settled.definitions is not None else _collect_alias_definitions(root),
        binders,
    )
