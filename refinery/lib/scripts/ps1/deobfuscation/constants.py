"""
Inline constant variable references in PowerShell scripts.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterator

from refinery.lib.scripts import (
    Expression,
    Node,
    Transformer,
    _clone_node,
)
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.errorstate import Ps1ErrorStateReach
from refinery.lib.scripts.ps1.analysis.faults import Ps1FaultReach
from refinery.lib.scripts.ps1.analysis.handoff import Ps1Handoff
from refinery.lib.scripts.ps1.analysis.identity import passage_out_of
from refinery.lib.scripts.ps1.analysis.model import (
    NARROWER_QUALIFIERS,
    VARIABLE_QUALIFIERS,
    Binding,
    binding_key,
    is_assignment_write_target,
    is_mutated_in_place,
    is_substitutable_position,
    is_write_occurrence,
)
from refinery.lib.scripts.ps1.analysis.mutation import value_after
from refinery.lib.scripts.ps1.analysis.naming import unreadable_name_target
from refinery.lib.scripts.ps1.analysis.separator import coerced_text_at
from refinery.lib.scripts.ps1.analysis.values import (
    UNKNOWN,
    Ps1Fact,
    convert,
    folded_binary,
    folded_increment,
    integer_of,
    make_string_literal,
    read,
    render,
    survives_being_written,
    type_of,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.analysis.variable_types import (
    constraint_converts,
    value_under_declared_constraint,
)
from refinery.lib.scripts.ps1.analysis.world import runs_code_supplied_as_data
from refinery.lib.scripts.ps1.ast import (
    assignment_of,
    get_member_name,
    stored_value,
    unwrap_assignment_target,
    unwrap_parens,
)
from refinery.lib.scripts.ps1.data import (
    ALL_SCOPE_VARIABLES,
    PS1_KNOWN_VARIABLES,
    SHAPE_MEMBERS,
    VARIABLE_TYPES,
    is_enum,
    resolve_type,
)
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlans
from refinery.lib.scripts.ps1.deobfuscation.substitution import substitute, substitute_field
from refinery.lib.scripts.ps1.model import (
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ClassDefinition,
    Ps1CommandInvocation,
    Ps1DoLoop,
    Ps1EnumDefinition,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScopeModifier,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SwitchStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.lib.scripts.win32const import DEFAULT_ENVIRONMENT_TEMPLATE

#: The value an engine variable holds when the script never writes it, for the names whose default
#: does not depend on how the script was launched. `$PSCommandPath` and `$PSScriptRoot` are
#: deliberately absent: they are empty only at an interactive prompt and hold the script's own path
#: under file execution, so no single value stands for them — and inlining the interactive one both
#: rewrites what a file-run script prints and erases the self-path names
#: `refinery.lib.scripts.ps1.analysis.worldflow.build_world_reach` refuses over.
_PS1_DEFAULT_VARIABLES: dict[str, str] = {
    key.lower(): value for key, value in {
        'ConfirmPreference'          : r'High',
        'ConsoleFileName'            : r'',
        'DebugPreference'            : r'SilentlyContinue',
        'ErrorActionPreference'      : r'Continue',
        'ErrorView'                  : r'NormalView',
        'InformationPreference'      : r'SilentlyContinue',
        'ProgressPreference'         : r'Continue',
        'PSCulture'                  : r'en-US',
        'PSEdition'                  : r'Desktop',
        'PSEmailServer'              : r'',
        'PSHome'                     : r'C:\Windows\System32\WindowsPowerShell\v1.0',
        'PSSessionApplicationName'   : r'wsman',
        'PSSessionConfigurationName' : r'http://schemas.microsoft.com/powershell/Microsoft.PowerShell',
        'PSUICulture'                : r'en-US',
        'ShellID'                    : r'Microsoft.PowerShell',
        'VerbosePreference'          : r'SilentlyContinue',
        'WarningPreference'          : r'Continue',
    }.items()
}

PS1_ENV_CONSTANTS = {
    lower_key: value
    for key, value in DEFAULT_ENVIRONMENT_TEMPLATE.items()
    if not (lower_key := key.lower()).startswith(('path', 'processor'))
    and '{u}' not in value
    and '{h}' not in value
}


def _ambient_default_fact(key: str, value: str) -> Ps1Fact:
    """
    The value an engine default names: the text `_PS1_DEFAULT_VARIABLES` records, converted to the
    enum `refinery.lib.scripts.ps1.data.VARIABLE_TYPES` says the variable holds where it holds one.
    The preference variables hold `ActionPreference` and `ConfirmImpact` members, whose text is a
    name and whose value is an ordinal — `SilentlyContinue` is the falsy 0 — and the bare text
    would be read as the truthy String it spells. A default the value domain cannot convert — a
    text that names no member, an enum it does not compute — is `UNKNOWN`, which `render` spells
    as nothing, so the variable is left unread rather than inlined as a value it does not hold.
    """
    fact = read(make_string_literal(value))
    declared = VARIABLE_TYPES.get(key)
    holder = None if declared is None else resolve_type(declared)
    if holder is None or not is_enum(holder):
        return fact
    outcome = convert(fact, holder)
    return UNKNOWN if outcome.may_throw else outcome.value


#: The value each engine default names, read once: which type a variable holds and what its text
#: converts to are facts about the tables and not about any script, where the expression spelling
#: one is minted per script by `render`, because a node is adopted by the tree it is installed in.
_PS1_DEFAULT_FACTS: dict[str, Ps1Fact] = {
    key: _ambient_default_fact(key, value) for key, value in _PS1_DEFAULT_VARIABLES.items()
}


PS1_AUTOMATIC_VARIABLES = frozenset({
    '?',
    '_',
    'args',
    'error',
    'event',
    'eventargs',
    'eventsubscriber',
    'executioncontext',
    'false',
    'foreach',
    'home',
    'host',
    'input',
    'lastexitcode',
    'matches',
    'myinvocation',
    'nestedpromptlevel',
    'null',
    'ofs',
    'pid',
    'profile',
    'psboundparameters',
    'pscmdlet',
    'pscommandpath',
    'psitem',
    'psscriptroot',
    'psversiontable',
    'pwd',
    'sender',
    'sourceargs',
    'sourceeventargs',
    'stacktrace',
    'switch',
    'this',
    'true',
})

_PS1_SKIP_VARIABLES = (
    PS1_AUTOMATIC_VARIABLES
    | frozenset(PS1_KNOWN_VARIABLES)
    | frozenset(_PS1_DEFAULT_VARIABLES)
)

#: The names the engine maintains between statements, so what the script last assigned to one is not
#: what it is worth at the next read: `$_` is rebound per pipeline object, `$Matches` at every
#: `-match`, `$LASTEXITCODE` by every native command, and a preference variable is read by the
#: engine itself. No write of one of these establishes a value this pass may carry to a reader.
PS1_ENGINE_VARIABLES = PS1_AUTOMATIC_VARIABLES | frozenset(_PS1_DEFAULT_VARIABLES)

_MIN_EXPANSION_BUDGET = 256


def _collect_mutated_variables(root: Node) -> set[str]:
    """
    Every variable key some occurrence in the tree writes: an assignment target, a `foreach`
    variable, a `++`/`--` operand, a parameter, a `[ref]`, a store through a part of the value, and
    a slot of a call the callee writes through.

    That list is `refinery.lib.scripts.ps1.analysis.model.is_write_occurrence`'s to keep, and this
    asks it rather than repeating it.

    The key is `refinery.lib.scripts.ps1.ast.binding_key` for every write: a write reaches the
    binding its qualifier names, so `$script:q = 5` writes the name `q` a later bare `$q` reads, and
    reading it under a key that refused every qualifier left that name looking never-written, so
    `Ps1NullVariableInlining` replaced the bare read with `$Null` and folded `$q + 1` to `1`.
    """
    mutated: set[str] = set()
    for node in root.walk():
        if not isinstance(node, Ps1Variable) or not is_write_occurrence(node):
            continue
        mutated.add(binding_key(node))
    return mutated


#: The spellings of a read `_candidate_key` names a key for: bare, `$env:`, and every qualifier
#: that names a script variable.
_INLINED_SCOPES = frozenset({
    Ps1ScopeModifier.NONE,
    Ps1ScopeModifier.ENV,
    *VARIABLE_QUALIFIERS,
})


def _candidate_key(var: Ps1Variable) -> str | None:
    """
    The constant-inlining lookup key for a variable — `refinery.lib.scripts.ps1.ast.binding_key`
    for an unqualified variable, an `$env:` variable and one spelled with a qualifier that names a
    script variable, and `None` for any other scope.
    """
    if var.scope in _INLINED_SCOPES:
        return binding_key(var)
    return None


def _survives_this_position(value: Node, occurrence: Ps1Variable) -> bool:
    """
    Whether writing *value* where *occurrence* stands leaves the program meaning what it did.

    One value does not: a `System.Decimal` whose value is a whole number written to places. 5.1
    folds a constant expression in its parser and a numeral reaching that fold loses those places,
    so putting one where an operator can reach it moves the computation from run time to parse time
    — measured, `$z = 1.0d; $z + 0d` is `1.0` and the `1.0d + 0d` written for it is `1`. Anywhere an
    operator cannot reach it the numeral is read as itself and the substitution is what it was:
    `$z = 1.0d; ,$z` still writes `1.0`.

    See `refinery.lib.scripts.ps1.analysis.values.survives_being_written` for the value half of this
    and `read_operand` for the rule both stand on.
    """
    if survives_being_written(read(value)):
        return True
    return not isinstance(
        _ancestor_past_parens(occurrence), (Ps1BinaryExpression, Ps1UnaryExpression))


def _preserves_sharing(occurrence: Ps1Variable, value: Expression, state: _Inlining) -> bool:
    """
    Whether installing *value* where *occurrence* stands leaves every other name for the object it
    reads observing what it observed.

    A bare read hands over the object the name holds rather than a copy of it, so `$y = $x` gives
    one array two names. Writing the array's value where `$x` stands gives `$y` an array of its own,
    and a `[Array]::Reverse($x)` below then reaches one and not the other. Measured: without this,
    `$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]` emits `1` where 5.1 prints `9`.

    Where the object goes is `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.handoff`.
    Where nothing keeps it and where what is kept is never changed in place (`_may_change_at`), a
    copy is the object.

    A plain `$y = $x` whose target the semantic model files stores across, between two names
    nothing else keeps, is decided on those two names: no store through either may be spelled
    anywhere, and no code nobody can read may run after the hand-off, since such code may store
    through either name. Every other hand-off keeps the object somewhere no name spells — a
    container, a callee, the output a caller collects — so the copy is refused wherever anything
    may change an object in place after it. The one store excused is the one the hand-off itself
    makes into a container, which changes the container and not the object, unless the container
    is a name for the object itself.

    A script that spells no change in place at all lets every hand-off but the one to a name
    through. That is a doubt taken on purpose rather than a claim: a callee may keep what it is
    handed where code nobody can read finds it, and refusing that doubt refuses the decoded buffer
    a loader hands to the call whose result it runs. A second name is no such doubt, since that
    code may store through the name itself.
    """
    if not _may_be_changed_in_place(value):
        return True
    handoff = state.flow.handoff(occurrence)
    if handoff is Ps1Handoff.NOWHERE or not _may_change_at(value, handoff):
        return True
    read_from = state.binding_of(occurrence)
    if read_from is None:
        return False
    target = _assignment_target(occurrence)
    if handoff is Ps1Handoff.A_NAME:
        stored_into = None if target is None else state.binding_of(target)
        if stored_into is None or stored_into is read_from:
            return False
        if (
            state.flow.files_stores_across(read_from, stored_into)
            and state.flow.exposure(read_from) is Ps1Handoff.NOWHERE
        ):
            return not (
                _is_changed_in_place(read_from)
                or state.flow.unreadable_code_may_follow(occurrence)
            )
    elif not state.changes_an_object_in_place:
        return True
    if target is not None and any(write.node is target for write in read_from.writes):
        target = None
    return not state.flow.change_may_follow(occurrence, apart_from=target)


def _may_change_at(value: Expression, handoff: Ps1Handoff) -> bool:
    """
    Whether a store can change what a hand-off keeps of *value*: the object itself, or only the
    objects inside it where the hand-off keeps `PARTS` of
    `refinery.lib.scripts.ps1.analysis.handoff.Ps1Handoff`. The elements of `1, 2, 3` are numbers,
    so taking them apart hands on nothing a store can reach.
    """
    if handoff is not Ps1Handoff.PARTS:
        return _may_be_changed_in_place(value)
    array = _get_array_literal(value)
    if array is None:
        return _may_be_changed_in_place(value)
    return any(_may_be_changed_in_place(element) for element in array.elements)


def _may_be_changed_in_place(value: Expression) -> bool:
    """
    Whether a store can reach the object *value* names, so that a copy of it and a second name for
    it are two different things.

    A String, a number, a Char and a Boolean are what 5.1 hands over by value or never changes at
    all — `$s[0] = 'x'` on a String raises rather than writing — so a copy of one is the object.
    An array is not, and neither is a value the domain declines to name: the list of objects a store
    can reach is not one this can finish, so anything it cannot read is answered `True`. A type
    literal is the one value the inliner carries that the domain does not name, and it is the
    `System.Type` it spells, which holds nothing a store can reach.
    """
    if isinstance(unwrap_parens(value), Ps1TypeExpression):
        return False
    named = type_of(read(value))
    return named is None or bool(named.ranks)


def _is_changed_in_place(binding: Binding) -> bool:
    """
    Whether anything stores through a name for the object *binding* holds. The semantic model files
    a store through any name of the alias class against every member of it, so asking one member
    answers for all of them.
    """
    return any(write.role.through for write in binding.writes)


def _assignment_target(occurrence: Ps1Variable) -> Ps1Variable | None:
    """
    The one variable a plain assignment stores *occurrence* into, where the occurrence is the whole
    of what it stores, or `None` where the position names no single variable.

    A target reaching into a value — `$h['k']`, `$o.P`, `$a[0]` — names the variable its chain is
    rooted at, because that is the name every later store through the same place is spelled on and
    so the name a caller has to watch. `None` is every position whose destination this cannot name
    that way, and a caller reads it as such: a hash literal's entry, one slot of a multi-assignment,
    an argument of a call or of a command.

    What is climbed on the way to the assignment is every expression that may give back the object
    it was handed, as `refinery.lib.scripts.ps1.analysis.identity.passage_out_of` names them, and
    an array literal: the `$a = ,$x` that builds a fresh outer array whose one element is the array
    `$x` names still stores that array under `$a`, one level down.
    """
    cursor: Node = occurrence
    while True:
        passage = passage_out_of(cursor)
        if passage is not None and not isinstance(passage.expression, Ps1AssignmentExpression):
            cursor = passage.expression
        elif isinstance(cursor.parent, Ps1ArrayLiteral):
            cursor = cursor.parent
        else:
            break
    parent = cursor.parent
    if not isinstance(parent, Ps1AssignmentExpression) or parent.operator != '=':
        return None
    if parent.value is not cursor:
        return None
    target = unwrap_assignment_target(parent.target)
    while isinstance(target, (Ps1IndexExpression, Ps1MemberAccess)):
        target = unwrap_assignment_target(target.object)
    return target if isinstance(target, Ps1Variable) else None


def _ancestor_past_parens(node: Node) -> Node | None:
    """
    The first ancestor of *node* that is not a parenthesis, which is what decides whether an
    operator reaches it: a parenthesis does not stop 5.1 folding what it wraps.
    """
    parent = node.parent
    while isinstance(parent, Ps1ParenExpression):
        parent = parent.parent
    return parent


def _shape_member_of(var: Ps1Variable) -> str | None:
    """
    The lowercased shape member — `length`, `count` or `rank` — a reference reads off *var* through
    any parentheses, or `None` where *var* is not the receiver of one.

    A reference there folds to the digits of a count once *var* is inlined to its constant
    collection, so it costs the expansion budget those digits and not the whole value, the same way
    a constant index costs it one element. `_ancestor_past_parens` is what climbs the parentheses
    5.1 folds through, so `(($a)).Length` is read the same as `$a.Length`.
    """
    ancestor = _ancestor_past_parens(var)
    if not isinstance(ancestor, Ps1MemberAccess):
        return None
    name = get_member_name(ancestor.member)
    if name is None:
        return None
    lowered = name.lower()
    return lowered if lowered in SHAPE_MEMBERS else None


def _accumulation_terms(node: Node) -> tuple[str, Expression] | None:
    """
    The binary operator and right-hand operand that an accumulating write of `node` reads its
    previous value against, or `None` when the write is not one — `('+', e)` for `$x += e`.

    A plain `=` is excluded: it replaces the value without reading it, and its constant is the
    ordinary `by_write` entry. An accumulating one reads the value as well, so its constant is the
    fold of the previous value against the operand rather than a value written down anywhere. A
    compound `op=` genuinely is `$x op e`, which is why its fold goes through `folded_binary`;
    `++` and `--` are not, and are read by `_increment_delta` instead.

    Only a write that is itself a statement counts. Its previous value is asked of the flow model,
    which tracks control flow between statements but not within an expression: a `$i += 1` inside
    `$false -and ($i += 1)` never runs, yet the model reports it as the definite last write to `$i`,
    so folding it in would compute a value the script never reaches. Held to a statement, whether the
    write runs at all is the flow model's own question to answer, and this only supplies the value
    once it does.
    """
    if not isinstance(node, Ps1Variable):
        return None
    assignment = assignment_of(node)
    if assignment is None:
        return None
    if assignment.operator == '=' or not isinstance(assignment.parent, Ps1ExpressionStatement):
        return None
    value = assignment.value
    return (assignment.operator[:-1], value) if isinstance(value, Expression) else None


def _increment_delta(node: Node) -> int | None:
    """
    The amount a statement-level `$x++` or `$x--` adds to its previous value — `+1` or `-1` — or
    `None` when the write of `node` is not one.

    This is kept apart from `_accumulation_terms` because `$x++` is not `$x + 1`: the increment
    operators require a number and throw on a String, a Char or a Boolean, where binary `+` would
    concatenate or coerce one, so their fold goes through `folded_increment` rather than the binary
    path. The statement-only rule is `_accumulation_terms`', for the reason written there: the flow
    model reports a write inside a never-run expression as the definite last one.
    """
    if not isinstance(node, Ps1Variable):
        return None
    parent = node.parent
    if not isinstance(parent, Ps1UnaryExpression) or parent.operand is not node:
        return None
    if not isinstance(parent.parent, Ps1ExpressionStatement):
        return None
    if parent.operator == '++':
        return 1
    if parent.operator == '--':
        return -1
    return None


def _constant_value_key(node: Node) -> tuple | None:
    """
    A hashable key for the constant value of a node, or `None` where the node names no value. Two
    nodes with the same key name the same value, which is what the inliner needs in order to know
    that re-assigning a variable to what it already holds changes nothing.

    The value comes from the domain and not from the spelling, so a Char is one — `[char]39` names
    the apostrophe and is a constant this may carry, where a reader that matched literals by their
    node class saw a cast and stopped. `Ps1Fact` is already the key: it carries the type beside the
    payload, so a Char and the one-character String that holds the same character are different
    keys, which is the whole point of asking the domain rather than the node.

    A type literal is not a value the domain names — `[int]` as a value is a `System.RuntimeType` —
    and it is keyed here by the name it writes, because the inliner only ever compares one of these
    against another.

    """
    node = unwrap_parens(node)
    if isinstance(node, Ps1TypeExpression):
        return ('type', node.name)
    fact = read(node)
    return None if fact is UNKNOWN else ('value', fact)


def _get_array_literal(node: Node) -> Ps1ArrayLiteral | None:
    """
    Return the indexable `refinery.lib.scripts.ps1.model.Ps1ArrayLiteral` from either a bare literal
    or `@(...)`.
    """
    if isinstance(node, Expression):
        return unwrap_to_array_literal(node)
    return None


def _clone_constant(node: Node) -> Expression:
    """
    Create a fresh copy of a constant value node without following parent references. This avoids
    the catastrophic cost of `copy.deepcopy` which traverses the entire AST through parents.

    What is copied is the *spelling* and not the value, deliberately: a numeral the source wrote in
    a command argument keeps its own text there — `Write-Host 1.10` prints `1.10` and
    `notepad.exe 0x10` receives `0x10` — so an inliner that spelled the value afresh would change
    what a command is handed. `@(...)` around a bare list is the one thing normalized away, because
    the parenthesis this adds is what the value needs where it lands.
    """
    unwrapped = unwrap_parens(node)
    if isinstance(unwrapped, Ps1ArrayExpression):
        unwrapped = unwrap_to_array_literal(unwrapped) or unwrapped
    if not isinstance(unwrapped, Expression):
        raise TypeError(F'cannot clone {type(unwrapped).__name__}')
    clone = _clone_node(unwrapped)
    if isinstance(clone, Ps1ArrayLiteral) and len(clone.elements) > 1:
        return Ps1ParenExpression(expression=clone)
    return clone


def _interpolated(value: Expression, site: Ps1Variable, flow: Ps1VariableFlow) -> Expression | None:
    """
    What a value contributes where it is interpolated into an expandable string, which is the text
    it renders to and not the way it was written.

    This is the one place where how a value is spelled and what it renders to are different
    questions, and installing the spelling answered the wrong one: measured, `$s = 0xFF; "$s"` is
    the String `255` on 5.1 where the literal written in reads `0xFF`, and `$c = [char]65; "$c"` is
    `A` where the cast reads as itself. `coerced_text_at` is that second question, asked at *site*
    because a collection is separated by `$OFS`; a value it names no text for is left alone rather
    than written down some other way.

    A here-string is refused because a part is not a standalone literal: the synthesizer writes a
    part's characters into the surrounding quotes, so a spelling that carries its own delimiters has
    nowhere to put them.
    """
    text = coerced_text_at(value, site, flow)
    if text is None:
        return None
    literal = make_string_literal(text)
    return literal if isinstance(literal, Ps1StringLiteral) else None


def _walk_outer_scope(root: Node):
    """
    Walk the AST like `root.walk()` but skip the bodies of function, class, and enum definitions.
    The definition node itself is yielded so that it can still be removed or inspected.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (Ps1FunctionDefinition, Ps1ClassDefinition, Ps1EnumDefinition)):
            continue
        for child in node.children():
            stack.append(child)


def _find_removable_statement(node: Node) -> Node | None:
    """
    Walk upward from an expression node to find the statement-level node that can be removed from
    its parent's body list.
    """
    cursor = node
    while cursor.parent is not None:
        parent = cursor.parent
        if isinstance(parent, Ps1ExpressionStatement):
            cursor = parent
            continue
        if isinstance(parent, Ps1PipelineElement):
            cursor = parent
            continue
        if isinstance(parent, Ps1Pipeline):
            if len(parent.elements) == 1:
                cursor = parent
                continue
        return cursor
    return None


class _ConstantTable:
    """
    The constant value each write of a script establishes, keyed by the identity of the occurrence
    that writes it, and the constants of the names the script never writes at all.

    Two tables because they answer two questions. A write is a point in the program and the flow
    model orders it against a read; an ambient constant is a value the engine established before the
    script ran — `$env:ComSpec`, `$ErrorActionPreference` — and there is no point to order it
    against.

    A write with no entry here is not a lesser kind of write. It is a write whose value this pass has
    nothing to say about, and the flow model orders and kills it exactly as it does any other:
    sorting writes by whether their value happens to be constant is what made `if ($c) { $x = 'b' }`
    fold and `if ($c) { $x = $y }` refuse.
    """

    def __init__(self, root: Node):
        self.by_write: dict[int, Expression] = {}
        self.ambient: dict[str, Expression] = {}
        self.values: defaultdict[str, list[Expression]] = defaultdict(list)
        self._collect_writes(root)
        self._collect_ambient(root)

    def _collect_writes(self, root: Node):
        """
        Record the value of every plain assignment to one variable. A multi-assignment is not
        recorded even where the value a slot is handed is known: the assignment is removed once
        every read of a recorded value is replaced, and removing it would lose what it stores into
        its other slots.
        """
        for node in root.walk():
            if not isinstance(node, Ps1AssignmentExpression):
                continue
            target = unwrap_assignment_target(node.target)
            if not isinstance(target, Ps1Variable):
                continue
            stored = stored_value(target)
            if stored is None or stored.value is None:
                continue
            key = binding_key(target)
            if key in PS1_ENGINE_VARIABLES:
                # A preference or automatic variable is the engine's as much as the script's, so a
                # write of one is not recorded here; the ambient table answers for it, and only
                # while the script leaves the name alone.
                continue
            if _constant_value_key(stored.value) is None:
                continue
            value = unwrap_parens(stored.value)
            self.by_write[id(target)] = value
            self.values[key].append(value)

    def _collect_ambient(self, root: Node):
        """
        A default the engine supplies is only this name's value while the script leaves the name
        alone. Any write of it anywhere replaces the default with something this table has no claim
        on — including a write inside a block, which `Ps1SemanticModel` binds locally but `. { }`
        performs on the caller, and a write that reaches *through* the name, which
        `is_write_occurrence` counts as the write it is.

        A write nobody can attribute is *not* collected here, because it is not a fact about the
        whole script: it lands at a point, and an ambient default is a definition at the script's
        entry, so the two are ordered like anything else. `Ps1VariableFlow.ambient_value_survives`
        asks that per read — silencing every default here instead was measured, and it costs the
        `$PSHome` unpacking that an obfuscated loader's first stage is built out of.
        """
        touched: set[str] = set()
        for node in root.walk():
            if isinstance(node, Ps1Variable) and is_write_occurrence(node):
                touched.add(binding_key(node))
        for key, fact in _PS1_DEFAULT_FACTS.items():
            if key in touched:
                continue
            spelled = render(fact)
            if spelled is not None:
                self._add_ambient(key, spelled)
        for name, value in PS1_ENV_CONSTANTS.items():
            key = F'env:{name}'
            if key not in touched:
                self._add_ambient(key, make_string_literal(value))

    def _add_ambient(self, key: str, value: Expression):
        self.ambient[key] = value
        self.values[key].append(value)

    def __bool__(self) -> bool:
        return bool(self.by_write or self.ambient)


class _InlineRecord:
    """
    The read occurrences one substitution walk replaced, per binding.

    The count is what licenses removing the binding's writes — every occurrence in `Binding.reads`
    has to be accounted for, and that set includes reads this pass never walked, such as one inside a
    function body — and the replacement nodes are where the value now stands, so they are what the
    pass can point at when it claims that removing the write destroys nothing.
    """

    def __init__(self):
        self._bindings: dict[int, Binding] = {}
        self._replacements: defaultdict[int, list[Node]] = defaultdict(list)

    def add(self, binding: Binding, replacement: Node):
        self._bindings[id(binding)] = binding
        self._replacements[id(binding)].append(replacement)

    def __iter__(self) -> Iterator[tuple[Binding, list[Node]]]:
        for key, binding in self._bindings.items():
            yield binding, self._replacements[key]


class _Inlining:
    """
    The state one substitution walk carries: the constants it may install, the flow model that says
    which of them a read observes, the keys the expansion budget has already refused, the variable
    occurrences an enclosing index expression has already spoken for, and what was replaced.
    """

    def __init__(self, table: _ConstantTable, flow: Ps1VariableFlow, blocked: set[str]):
        self.table = table
        self.flow = flow
        self.blocked = blocked
        self.handled: set[int] = set()
        self.record = _InlineRecord()

    def value_at(self, var: Ps1Variable, key: str) -> Expression | None:
        """
        The constant *var* holds where it stands, or `None` when no single value does.

        The write the flow model names is only the value if the object it installed is still what
        it was. One held somewhere no occurrence of the name spells — an element of a container, the
        argument of a callee, the output a caller collects — may be changed through there without
        any write of the name, so such a value is refused wherever something may change an object
        in place between the write and the read and the value is one a store can change.
        Measured, `$x = 1, 2, 3; function f { ,$x }; $y = f; $y[0] = 9; $x[0]` is `9`.
        """
        return self._value_at(var, key, frozenset())

    def _value_at(self, var: Ps1Variable, key: str, chased: frozenset[int]) -> Expression | None:
        binding = self.binding_of(var)
        if binding is None:
            value = self.table.ambient.get(key)
            if value is None or not self._reaches_the_default(var, key):
                return None
            return value
        write = self.flow.reaching_definition(var)
        if write is None:
            return None
        value = self._value_from(write, key, binding, chased)
        if value is None or not _may_be_changed_in_place(value):
            return value
        changed = self.flow.unseen_change(write, var)
        if changed is Ps1Handoff.NOWHERE or not _may_change_at(value, changed):
            return value
        return None

    def _value_from(
        self,
        write: Ps1Variable,
        key: str,
        binding: Binding,
        chased: frozenset[int],
    ) -> Expression | None:
        """
        The value *write* leaves under *binding*, chasing a write that changes the value before it
        rather than replacing it.
        """
        accumulation = _accumulation_terms(write)
        delta = _increment_delta(write)
        through = isinstance(write, Ps1Variable) and is_mutated_in_place(write)
        if not through and accumulation is None and delta is None:
            value = self.table.by_write.get(id(write))
            if value is None:
                return None
            if not constraint_converts(binding, value):
                return value
            return value_under_declared_constraint(write, value)
        if id(write) in chased:
            return None
        previous = self._value_at(write, key, chased | {id(write)})
        if previous is None:
            return None
        if accumulation is not None:
            operator, right = accumulation
            return folded_binary(previous, operator, right)
        if delta is not None:
            return folded_increment(previous, delta)
        return value_after(write, previous)

    def _reaches_the_default(self, var: Ps1Variable, key: str) -> bool:
        """
        Whether the read *var* observes the default the engine gave the name *key* before the script
        ran. A read that names one narrower scope finds a default only where every scope holds one,
        since the engine keeps the rest in the global scope alone: `$local:ShellId` in a child scope
        is `Microsoft.PowerShell`, and `$local:ErrorActionPreference` there finds nothing. Which
        defaults every scope holds is `refinery.lib.scripts.ps1.data.ALL_SCOPE_VARIABLES`.
        """
        if var.scope in NARROWER_QUALIFIERS and key not in ALL_SCOPE_VARIABLES:
            return False
        return self.flow.ambient_value_survives(var)

    def binding_of(self, var: Ps1Variable) -> Binding | None:
        return self.flow.semantic.binding_of(var)

    @property
    def changes_an_object_in_place(self) -> bool:
        return self.flow.semantic.changes_an_object_in_place

    def installed(self, var: Ps1Variable, replacement: Node):
        binding = self.binding_of(var)
        if binding is not None:
            self.record.add(binding, replacement)


class Ps1ConstantInlining(Transformer):

    def __init__(self, max_expansion_ratio: float = 0.2, min_inlines_to_prune: int | None = 1):
        super().__init__()
        self.max_expansion_ratio = max_expansion_ratio
        self.min_inlines_to_prune = min_inlines_to_prune

    def visit(self, node: Node):
        # Captured once rather than re-read per reference: every substitution below marks the pass
        # changed, which drops the cache, so a per-site lookup would rebuild the control-flow graphs
        # of the whole script once per inlined variable. Nothing this pass adds or removes is a
        # statement, so the graphs it would rebuild are the graphs it already has.
        cache = model_cache(self, node)
        flow, faults = cache.variable_flow, cache.faults
        table = _ConstantTable(node)
        if not table:
            return None
        state = _Inlining(table, flow, self._blocked_by_expansion(node, table))
        self._substitute(node, state)
        self._remove_dead_assignments(table, state, faults, cache.error_state)
        return None

    def _blocked_by_expansion(self, root: Node, table: _ConstantTable) -> set[str]:
        """
        The keys whose substitution would grow the script past the expansion budget, estimated over
        every reference before any of them is installed. Purely a size heuristic: it withholds an
        inlining that is correct, and it is asked before the flow model so that a script full of
        references to one large array does not pay for a reaching-definition query per reference.

        The budget bounds *net* growth, so it credits the one definition inlining retires. When the
        walk's every reference to a key is installed, that key's read count reaches zero and the
        dead-store pass removes the assignment that held its value, so the first reference's growth
        is the definition moved to where it is read rather than a copy of it: the growth that
        remains is the duplication across the *further* references. Charging every reference and
        crediting the retired definition is what keeps a constant read once — a base64 blob that
        feeds a single `[Convert]::FromBase64String` — from being withheld on a small script, where
        inlining it is size-neutral and is what exposes the fold that collapses it.

        An engine default is not charged at all. The budget exists for a value the script defines,
        which can be as large as the script cares to make it; a default's spelling is bounded by
        the tables this module keeps, and what a small script full of preference reads paid for it
        was every fold on those reads — seven guards on `$VerbosePreference` were seven too many.
        """
        synth = Ps1Synthesizer()
        script_size = len(synth.convert(root))
        max_budget = max(_MIN_EXPANSION_BUDGET, int(script_size * self.max_expansion_ratio))

        budgeted = {
            key: values for key, values in table.values.items() if key not in table.ambient
        }
        value_lengths: dict[str, int] = {}
        array_literals: dict[str, Ps1ArrayLiteral | None] = {}
        for key, values in budgeted.items():
            value_lengths[key] = max(len(synth.convert(value)) for value in values)
            array_literals[key] = _get_array_literal(values[0])
        elem_lengths: dict[tuple[str, int], int] = {}

        expansion: defaultdict[str, int] = defaultdict(int)
        for node in _walk_outer_scope(root):
            if isinstance(node, Ps1IndexExpression):
                var = node.object
                if not isinstance(var, Ps1Variable):
                    continue
                key = _candidate_key(var)
                if key is None or key not in budgeted or node.index is None:
                    continue
                idx = integer_of(read(node.index))
                if idx is not None:
                    array = array_literals[key]
                    if array is None:
                        continue
                    if not 0 <= idx < len(array.elements):
                        continue
                    ref_len = 1 + len(var.name) + 1 + len(synth.convert(node.index)) + 1
                    cache_key = (key, idx)
                    if cache_key not in elem_lengths:
                        elem_lengths[cache_key] = len(synth.convert(array.elements[idx]))
                    expansion[key] += max(0, elem_lengths[cache_key] - ref_len)
                elif isinstance(budgeted[key][0], (Ps1StringLiteral, Ps1HereString)):
                    expansion[key] += max(0, value_lengths[key] - (1 + len(var.name)))
            elif isinstance(node, Ps1Variable):
                key = _candidate_key(node)
                if key is None or key not in budgeted or is_write_occurrence(node):
                    continue
                shape = _shape_member_of(node)
                array = array_literals[key] if shape is not None else None
                if array is not None:
                    count = 1 if shape == 'rank' else len(array.elements)
                    expansion[key] += max(0, len(str(count)) - (1 + len(node.name)))
                    continue
                expansion[key] += max(0, value_lengths[key] - (1 + len(node.name)))

        return {
            key for key in budgeted
            if expansion[key] - value_lengths[key] > max_budget
        }

    def _substitute(self, root: Node, state: _Inlining):
        """
        Replace every reference this pass can resolve with the value it observes.

        The walk stops at a function, class, or enum body. What a read inside one observes is a
        question about the call sites that reach it, which the flow model refuses rather than
        answers, so descending would only spend a query per reference to be told nothing; and a
        class body is opaque to the graphs, so a property initializer inside one locates to the
        class statement and would be ordered against code it does not run beside.

        Which positions may hold a value at all is
        `refinery.lib.scripts.ps1.analysis.model.is_substitutable_position`, asked once here rather
        than reassembled from the positional predicates it is made of. It is a fact about the
        *position*, not about the binding: a store through is a write occurrence carrying no value,
        so the flow model already names none for a read below one, but the ambient table answers
        with no binding at all and would otherwise install a constant where `$x[0] = 'z'` names a
        place rather than a value.
        """
        for node in list(_walk_outer_scope(root)):
            if isinstance(node, Ps1IndexExpression):
                var = node.object
                if not isinstance(var, Ps1Variable):
                    continue
                # Spoken for either way: the walk snapshot still holds this occurrence after the
                # index expression around it has been swapped out, and substituting it a second time
                # would install the whole value where an element of it now stands.
                state.handled.add(id(var))
                key = _candidate_key(var)
                if key is not None and is_substitutable_position(var):
                    self._substitute_index_reference(node, var, key, state)
            elif isinstance(node, Ps1Variable):
                if id(node) in state.handled or not is_substitutable_position(node):
                    continue
                key = _candidate_key(node)
                if key is not None and key not in state.blocked:
                    self._substitute_variable_reference(node, key, state)

    def _substitute_index_reference(
        self,
        node: Ps1IndexExpression,
        var: Ps1Variable,
        key: str,
        state: _Inlining,
    ) -> None:
        const_value = state.value_at(var, key)
        if const_value is None or not _preserves_sharing(var, const_value, state):
            return
        idx = integer_of(read(node.index))
        if idx is None:
            if key in state.blocked or not isinstance(const_value, Ps1StringLiteral):
                return
            replacement = _clone_constant(const_value)
            if substitute_field(node, 'object', replacement):
                self.mark_changed()
                state.installed(var, replacement)
            return
        if isinstance(const_value, Ps1StringLiteral):
            text = const_value.value
            if not 0 <= idx < len(text):
                return
            replacement = make_string_literal(text[idx])
        else:
            array = _get_array_literal(const_value)
            if array is None or not 0 <= idx < len(array.elements):
                return
            replacement = _clone_constant(array.elements[idx])
        if substitute(node, replacement):
            self.mark_changed()
            state.installed(var, replacement)

    def _substitute_variable_reference(
        self,
        node: Ps1Variable,
        key: str,
        state: _Inlining,
    ) -> None:
        const_value = state.value_at(node, key)
        if const_value is None or not _survives_this_position(const_value, node):
            return
        if not _preserves_sharing(node, const_value, state):
            return
        if isinstance(node.parent, Ps1ExpandableString):
            replacement = _interpolated(const_value, node, state.flow)
        else:
            replacement = _clone_constant(const_value)
        if replacement is None:
            return
        if substitute(node, replacement):
            self.mark_changed()
            state.installed(node, replacement)

    def _remove_dead_assignments(
        self,
        table: _ConstantTable,
        state: _Inlining,
        faults: Ps1FaultReach,
        error_state: Ps1ErrorStateReach,
    ):
        """
        Delete the constant writes of every binding whose value nothing observes any more.

        Removal is decided per binding, and counted against that binding's own reads rather than
        against the references this walk resolved. Every occurrence in `Binding.reads` observes the
        value, including the ones the walk cannot answer for — a read inside a function body, a read
        after a write whose value is not constant, an index this pass cannot evaluate — and each of
        them is a reader the write still has. Counting only what the walk replaced is what let
        `$x = 'a'; function f { Write-Host $x }; Write-Host $x; f` delete the assignment `f` reads.

        A write that observes the previous value is a read as much as a write, so a binding with one
        is never dead however many of its reads were substituted; and a write whose value this pass
        holds no constant for stays, because deleting it would drop whatever it does to produce that
        value.

        `Binding.reads` is the whole list of readers only when the binding ends with its own body.
        `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel` binds a bare write to the
        block it is written in, and `refinery.lib.scripts.ps1.analysis.blocks.Ps1BlockModel` is
        the layer that says a `. { }` or a `ForEach-Object` body performs that write on whoever runs
        it — where the readers are other bindings entirely, and `_block_kills` already honours the
        same fact on the read side. Deleting such a write leaves the caller reading the value from
        before the body.
        """
        plans = Ps1RemovalPlans(faults, error_state=error_state)
        for binding, replacements in state.record:
            if len(replacements) < len(binding.reads):
                continue
            if self._writes_leave_the_body(state.flow, binding):
                continue
            if any(write.role.observes for write in binding.writes):
                continue
            if self.min_inlines_to_prune is not None:
                if len(replacements) < self.min_inlines_to_prune:
                    continue
            for write in binding.writes:
                assignment = assignment_of(write.node)
                if assignment is None or id(write.node) not in table.by_write:
                    continue
                statement = self._find_removable_statement(assignment)
                if statement is not None:
                    plans.propose(statement)
        if plans.commit():
            self.mark_changed()

    @staticmethod
    def _writes_leave_the_body(flow: Ps1VariableFlow, binding: Binding) -> bool:
        """
        Whether *binding*'s writes land in the scope of whatever runs the body they are written in,
        rather than in a scope that ends with that body. True for every block but a proven child
        scope — see `refinery.lib.scripts.ps1.analysis.blocks` for why that asymmetry is the safe
        one.
        """
        node = binding.scope.node
        return isinstance(node, Ps1ScriptBlock) and flow.blocks.may_write_caller_scope(node)

    _find_removable_statement = staticmethod(_find_removable_statement)


class Ps1NullVariableInlining(Transformer):
    """
    Replace references to never-assigned variables with `$Null`. Only operates on variables that
    appear in expression contexts where null coercion enables further simplification (arithmetic,
    comparison, cast, assignment value).

    A never-assigned read is `$null` only under the default semantics; under strict mode it is a
    statement-terminating error instead, so giving it `$null` decides a branch the script never
    reaches. `refinery.lib.scripts.ps1.analysis.faults.Ps1FaultReach.strict_mode_may_be_in_force`
    is the one model of whether the script arms it, shared with the removal veto, and the whole
    pass stands down where it may be in force rather than every substitution deciding it again.

    A read is not worth `$null` either where the script runs code supplied as data — an
    `Invoke-Expression`, a dot-sourced file, an opaque dispatch — because that code can assign the
    name in the calling scope out of data this walk cannot read, so the pass stands down there too.
    The trusting model — `refinery.lib.scripts.ps1.options.eval_is_trusted` — trusts such code to
    touch nothing the script does not spell and restores it.

    A read that names its scope outright is never given `$null`, though it is given a value the
    script wrote. The pass rests on reading a name nobody writes as an accident of the obfuscation,
    and `$script:x` or `$global:x` is the opposite evidence: it asks for the variable of one scope
    by name, which is how a script reads what a profile, a session or a loader dot-sourcing it set
    up before it ran.

    A name is written by more than its spellings as a variable. `New-Variable q 5` and
    `-OutVariable q` assign `$q` as surely as `$q = 5` does, and the semantic model files those
    writes against the name; a command addressing a name this cannot read may write any of them,
    so the pass stands down wherever one does.
    """

    @staticmethod
    def _is_null_eligible(ref: Ps1Variable) -> bool:
        cursor = ref
        while cursor.parent is not None:
            parent = cursor.parent
            if isinstance(parent, Ps1BinaryExpression):
                return True
            if isinstance(parent, Ps1UnaryExpression):
                return True
            if isinstance(parent, Ps1CastExpression):
                cursor = parent
                continue
            if isinstance(parent, Ps1AssignmentExpression) and cursor is parent.value:
                return True
            if isinstance(parent, (Ps1ParenExpression, Ps1ArrayLiteral)):
                cursor = parent
                continue
            if isinstance(parent, (Ps1WhileLoop, Ps1DoLoop, Ps1ForLoop)) and cursor is parent.condition:
                return True
            if isinstance(parent, (Ps1IfStatement, Ps1SwitchStatement)):
                return any(cursor is cond for cond, _ in parent.clauses)
            return False
        return False

    def visit(self, node: Node):
        cache = model_cache(self, node)
        if cache.faults.strict_mode_may_be_in_force():
            return
        if runs_code_supplied_as_data(cache.world_measurement):
            return
        model = cache.model
        if model.writes_unreadable_names or any(
            unreadable_name_target(command) is not None
            for command in node.walk() if isinstance(command, Ps1CommandInvocation)
        ):
            return
        mutated = _collect_mutated_variables(node) | set(model.write_sites())
        for ref in list(node.walk()):
            if not isinstance(ref, Ps1Variable) or ref.scope in VARIABLE_QUALIFIERS:
                continue
            key = _candidate_key(ref)
            if key is None:
                continue
            if key in mutated:
                continue
            if key in PS1_KNOWN_VARIABLES:
                continue
            if key in _PS1_DEFAULT_VARIABLES:
                continue
            if key in PS1_AUTOMATIC_VARIABLES:
                continue
            if key.startswith('env:'):
                continue
            if is_assignment_write_target(ref):
                continue
            if not self._is_null_eligible(ref):
                continue
            if not substitute(ref, Ps1Variable(name='Null')):
                continue
            self.mark_changed()


class Ps1SuccessFlagInlining(Transformer):
    """
    Replace a read of the `$?` automatic variable with the `$true`/`$false` value it holds at that
    point, wherever the positional success-flag channel can prove it. `$?` reports whether the last
    statement succeeded and resets after every statement, so its value is a property of the read's
    position — decided by
    `refinery.lib.scripts.ps1.analysis.errorstate.Ps1ErrorStateReach.success_flag_at` — and not a
    fixed truth value. A read the channel cannot decide is left in place, which keeps the branch 5.1
    runs.

    It runs before every fold and every removal so the flag is frozen from what precedes the read
    while that predecessor is still in the tree. A statement that raises leaves `$?` at `$false`, and
    once its `$?` reader is a literal the raiser is unobserved and later removed as junk — so
    resolving must happen first, or the reader would read as the top of the script once the raiser is
    gone.

    Unlike `Ps1NullVariableInlining` this needs no strict-mode stand-down: `$?` is always defined, so
    reading it never throws, and the value substituted is the one 5.1 holds regardless of mode.
    """

    _SUCCESS_FLAG_KEY = '?'

    def visit(self, node: Node):
        # The error-state model is fetched on the first `$?` read rather than up front, so a script
        # that reads none never pays to build it. Substituting `$?` swaps one value node for another
        # and adds or removes no statement, so the control-flow graphs the model reads are unchanged
        # by it and the captured model stays valid across the walk — the same reasoning
        # `Ps1ConstantInlining.visit` rests on.
        error_state: Ps1ErrorStateReach | None = None
        for ref in list(node.walk()):
            if not isinstance(ref, Ps1Variable):
                continue
            if ref.scope is not Ps1ScopeModifier.NONE or ref.name != self._SUCCESS_FLAG_KEY:
                continue
            if is_assignment_write_target(ref):
                continue
            if isinstance(ref.parent, (Ps1ExpandableString, Ps1ExpandableHereString)):
                continue
            if error_state is None:
                error_state = model_cache(self, node).error_state
            decided = error_state.success_flag_at(ref)
            if decided is None:
                continue
            if substitute(ref, Ps1Variable(name='True' if decided else 'False')):
                self.mark_changed()
