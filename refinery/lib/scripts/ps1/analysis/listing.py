"""
The listings of the session a script can read: the command table through `Get-Command` and the
lookups of `$ExecutionContext.InvokeCommand`, the members of a value through `Get-Member` and its
`psobject`, and the variable table through `Get-Variable` and the `Variable:` drive. A listing fold
replaces such a lookup by the one name it yields, and the removal passes ask which of the script's
own functions a lookup may hand out; both read the listing through this module, so that the name a
fold writes and the names a removal keeps are one reading of the lookup.

Each listing is read in three parts. A *selection* is what the lookup itself asks for: the name or
pattern it is given, how it reads it, and whether anything else shapes the result. A *narrowing*
is a `Where-Object` filter on the name the lookup's output is piped into. The *guard* is what must
hold at the lookup for the collected surface to be what the session lists there: no command the
script defines or a writer of the table installs, no variable the script writes, matches what the
lookup asks for.

What each listing holds was measured on Windows PowerShell 5.1:

- `Get-Command` with a name returns one command by precedence, the name's escapes removed. With a
  pattern it lists every alias, function, filter and cmdlet matching it, a module's command once
  per module folder that ships the module, and every file on `PATH` whose full name matches and
  ends in a `PATHEXT` extension. With no name at all it lists the functions, filters, cmdlets and
  the aliases a module exports, and never one of the aliases the engine defines without a module.
- `GetCommandName` reads its name as a pattern where its second argument converts to `$true`;
  `GetCmdlet` and `GetCommand` take a literal, and `GetCmdlets` lists cmdlets alone.
- A literal lookup that finds nothing raises, and so does a malformed pattern; a well-formed pattern
  matching nothing does not.
- The member views are those of `refinery.lib.scripts.ps1.data.Ps1MemberView`.
- The variable table holds the session's variables, the script's own, and the automatic variables
  the engine creates while running, each only once the run has made it.
"""
from __future__ import annotations

import functools

from typing import Collection, Mapping, NamedTuple, Sequence

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1ObservedWrite
from refinery.lib.scripts.ps1.analysis.values import (
    Ps1VariableTyping,
    is_pipeline_variable,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.ast import (
    get_member_name,
    is_builtin_variable,
    is_piped_into,
    normalize_command_name,
    resolve_command_name,
    string_value,
    switch_setting,
    unwrap_parens,
    variable_table_name,
)
from refinery.lib.scripts.ps1.data import (
    ENGINE_COMMAND_NAMES,
    EVENT_ACTION_VARIABLES,
    KNOWN_CMDLET_NAMES,
    KNOWN_COMMAND_NAMES,
    MODULELESS_ALIASES,
    PROGRAM_EXTENSIONS,
    RUNTIME_VARIABLES,
    SESSION_VARIABLES,
    Ps1MemberView,
    abbreviated_parameter,
    is_assignable_to,
    is_enumerable,
    member_listing,
    resolve_type,
    value_parameters,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1BinaryExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1ScriptBlock,
    Ps1TypeExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.patterns import (
    is_wildcard_pattern,
    literal_name,
    wildcard_may_end_with,
    wildcard_regex,
)

_GET_COMMAND = 'get-command'
_GET_MEMBER = 'get-member'
_WHERE_OBJECT = 'where-object'

#: The commands that subscribe an action block to an event, inside which the engine binds the
#: variables of `refinery.lib.scripts.ps1.data.EVENT_ACTION_VARIABLES`.
_EVENT_SUBSCRIBERS = frozenset({
    'register-cimindicationevent',
    'register-engineevent',
    'register-objectevent',
    'register-wmievent',
})

#: The comparisons of a name narrowing, mapped to whether each compares case.
_LIKE_OPERATORS = {
    '-like': False,
    '-ilike': False,
    '-clike': True,
}

#: The members of `$_` a narrowing filters on, which is the name in every listing here.
_NARROWED_MEMBERS = frozenset({'name'})


class Ps1CommandSelection(NamedTuple):
    """
    What a lookup of the command table asks for: the `name` it is given as written, `None` where it
    is given none; whether it reads that name as a `pattern`; whether another entry `shaped` the
    listing beyond the name — a `-CommandType`, a `-Module`, an `-All`; and whether it lists only
    cmdlets, as the `GetCmdlet` lookups do.
    """
    name: str | None
    pattern: bool
    shaped: bool = False
    cmdlets_only: bool = False


class Ps1NameNarrowing(NamedTuple):
    """
    A `Where-Object { $_.Name -like 'P' }` stage a listing is piped into: the `pattern` and
    whether the comparison is `case_sensitive`, as `-clike` is.
    """
    pattern: str
    case_sensitive: bool


class Ps1MemberSelection(NamedTuple):
    """
    What a listing of members asks for: the type whose members it lists and the view it lists.
    """
    type_name: str
    view: Ps1MemberView


class Ps1Listed(NamedTuple):
    """
    The command names a lookup may list, as the removal passes read them: the `names` of a literal
    lookup, keyed through `refinery.lib.scripts.ps1.ast.normalize_command_name`, the `patterns` of
    one that lists what a pattern matches, or `every` name where the lookup cannot be read.
    """
    names: frozenset[str] = frozenset()
    patterns: tuple[str, ...] = ()
    every: bool = False

    def holds(self, key: str) -> bool:
        """
        Whether the command keyed *key* may be among what the lookup lists.
        """
        if self.every or key in self.names:
            return True
        for pattern in self.patterns:
            regex = wildcard_regex(pattern)
            if regex is None or regex.match(key):
                return True
        return False


def get_command_selection(invocation: Ps1CommandInvocation) -> Ps1CommandSelection | None:
    """
    The selection a `Get-Command` invocation makes, or `None` where it cannot be read: a splat,
    an argument the parser left in a shape no parameter reading accepts, a parameter that binds
    nothing unambiguously (`-N` is both `-Name` and `-Noun`), a name that is not a literal, a second
    free argument, or input piped into it, which binds `-Name` where the invocation stands.

    A parameter and the value written after it reach the tree as two arguments — a switch naming
    the parameter, then a positional holding the value — so the two are paired here; the colon
    spelling `-Name:'wr?te'` reaches it as one named argument with its value.
    """
    if is_piped_into(invocation):
        return None
    name: str | None = None
    named = False
    shaped = False
    expecting: str | None = None
    for argument in invocation.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            return None
        value = argument.value
        if isinstance(value, Ps1Variable) and value.splatted:
            return None
        if argument.kind is Ps1CommandArgumentKind.POSITIONAL:
            if expecting is None or expecting == 'Name':
                if named or (text := string_value(value)) is None:
                    return None
                name, named = text, True
            expecting = None
            continue
        if expecting is not None:
            return None
        parameter = abbreviated_parameter(_GET_COMMAND, argument.name)
        if parameter is None:
            return None
        if parameter == 'Name':
            if named:
                return None
            if argument.kind is Ps1CommandArgumentKind.NAMED:
                if (text := string_value(value)) is None:
                    return None
                name, named = text, True
            else:
                expecting = parameter
            continue
        shaped = True
        if (
            argument.kind is Ps1CommandArgumentKind.SWITCH
            and parameter.lower() in value_parameters(_GET_COMMAND)
        ):
            expecting = parameter
    if expecting is not None:
        return None
    return Ps1CommandSelection(name, name is not None and is_wildcard_pattern(name), shaped)


def _as_boolean(node: Node | None) -> bool | None:
    """
    What PowerShell's boolean conversion makes of the literal *node*, or `None` where it is no
    literal this reads: `$true` and `$false`, a decimal integer, which is true where it is not zero,
    and a string, which is true where it is not empty — measured, `'0'` is true and `0` is not.
    """
    if is_builtin_variable(node, {'true'}):
        return True
    if is_builtin_variable(node, {'false'}):
        return False
    if isinstance(node, Ps1IntegerLiteral):
        return int(node.raw) != 0 if node.raw.isdigit() else None
    text = string_value(node)
    return None if text is None else bool(text)


def lookup_selection(call: Ps1InvokeMember) -> Ps1CommandSelection | None:
    """
    The selection a command lookup of `CommandInvocationIntrinsics` makes, or `None` where *call*
    is none of them or an argument cannot be read. The method may be called through its `Invoke`,
    as `.GetCmdlets.Invoke('*w-*ct')` names it. The caller owes that the receiver is the engine's
    intrinsics: nothing about a method name says what it is a method of.

    Every argument is read, including the ones the selection does not carry: a fold replaces the
    whole call, and an argument that is not a literal may do something the replacement drops.
    """
    method = get_member_name(call.member)
    if method is None:
        return None
    method = method.lower()
    if method == 'invoke':
        receiver = call.object
        if not isinstance(receiver, Ps1MemberAccess):
            return None
        method = get_member_name(receiver.member)
        if method is None:
            return None
        method = method.lower()
    arguments = call.arguments
    if not arguments or (name := string_value(arguments[0])) is None:
        return None
    if method == 'getcommandname':
        if len(arguments) != 3:
            return None
        pattern = _as_boolean(arguments[1])
        if pattern is None or _as_boolean(arguments[2]) is None:
            return None
        return Ps1CommandSelection(name, pattern)
    if method == 'getcmdlets' and len(arguments) == 1:
        return Ps1CommandSelection(name, True, cmdlets_only=True)
    if method == 'getcmdlet' and len(arguments) == 1:
        return Ps1CommandSelection(name, False, cmdlets_only=True)
    if method == 'getcommand' and len(arguments) == 2:
        kind = _command_types_member(arguments[1])
        if kind is None:
            return None
        if kind.lower() == 'all':
            return Ps1CommandSelection(name, False)
        if kind.lower() == 'cmdlet':
            return Ps1CommandSelection(name, False, cmdlets_only=True)
    return None


#: The type a command lookup takes the kinds of command it finds as.
_COMMAND_TYPES = 'system.management.automation.commandtypes'


def _command_types_member(node: Node) -> str | None:
    """
    The `CommandTypes` member *node* spells: a literal name, which converts to the member, or a
    read of the member off the type itself, as `[Management.Automation.CommandTypes]::Cmdlet`.
    """
    text = string_value(node)
    if text is not None:
        return text
    if not isinstance(node, Ps1MemberAccess) or node.access is not Ps1AccessKind.STATIC:
        return None
    receiver = node.object
    if not isinstance(receiver, Ps1TypeExpression):
        return None
    resolved = resolve_type(receiver.name)
    if resolved is None or resolved.definition.lower() != _COMMAND_TYPES:
        return None
    return get_member_name(node.member)


def name_narrowing(element: Node) -> Ps1NameNarrowing | None:
    """
    The narrowing *element* applies to a listing piped into it, or `None` where it is no
    `Where-Object` stage whose one statement compares the name of the current object against a
    literal pattern. Only `$_` and `$PSItem` read the current object
    (`refinery.lib.scripts.ps1.analysis.values.is_pipeline_variable`), and only an instance member
    of it is its name: measured, `$_::Name` reads a static member of its type, which the listings
    here have not, and filters out every object.
    """
    invocation = element.expression if isinstance(element, Ps1PipelineElement) else element
    if not isinstance(invocation, Ps1CommandInvocation):
        return None
    if resolve_command_name(invocation) != _WHERE_OBJECT or len(invocation.arguments) != 1:
        return None
    argument = invocation.arguments[0]
    if isinstance(argument, Ps1CommandArgument):
        if argument.kind is not Ps1CommandArgumentKind.POSITIONAL:
            return None
        argument = argument.value
    if not isinstance(argument, Ps1ScriptBlock) or len(argument.body) != 1:
        return None
    statement = argument.body[0]
    if isinstance(statement, Ps1ExpressionStatement):
        expression = statement.expression
    elif isinstance(statement, Ps1Pipeline) and len(statement.elements) == 1:
        stage = statement.elements[0]
        expression = stage.expression if isinstance(stage, Ps1PipelineElement) else None
    else:
        return None
    if not isinstance(expression, Ps1BinaryExpression):
        return None
    case_sensitive = _LIKE_OPERATORS.get(expression.operator.lower())
    if case_sensitive is None:
        return None
    left = expression.left
    if (
        not isinstance(left, Ps1MemberAccess)
        or left.access is not Ps1AccessKind.INSTANCE
        or not is_pipeline_variable(left.object)
    ):
        return None
    member = get_member_name(left.member)
    if member is None or member.lower() not in _NARROWED_MEMBERS:
        return None
    pattern = string_value(expression.right)
    if pattern is None:
        return None
    return Ps1NameNarrowing(pattern, case_sensitive)


def _psobject_view(expression: Node) -> tuple[Node, Ps1MemberView] | None:
    """
    The value and the view of an `X.psobject.Methods` or `X.psobject.Properties` read.
    """
    if not isinstance(expression, Ps1MemberAccess):
        return None
    leaf = get_member_name(expression.member)
    views = {'methods': Ps1MemberView.METHODS, 'properties': Ps1MemberView.PROPERTIES}
    view = None if leaf is None else views.get(leaf.lower())
    inner = expression.object
    if view is None or not isinstance(inner, Ps1MemberAccess) or inner.object is None:
        return None
    psobject = get_member_name(inner.member)
    if psobject is None or psobject.lower() != 'psobject':
        return None
    return inner.object, view


def _get_member_view(invocation: Ps1CommandInvocation) -> Ps1MemberView | None:
    """
    The view a `Get-Member` invocation lists: `-Static` read through its switch setting, and a
    `-MemberType` that is the literal `Method` or `Property`. Any other argument shapes the listing
    in a way no view describes, and so does the two together.
    """
    static = switch_setting(invocation, 'static')
    if static is None:
        return None
    view: Ps1MemberView | None = None
    expecting = False
    for argument in invocation.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            return None
        if argument.kind is Ps1CommandArgumentKind.POSITIONAL:
            if not expecting:
                return None
            expecting = False
            view = _member_type_view(argument.value)
            if view is None:
                return None
            continue
        if expecting:
            return None
        parameter = abbreviated_parameter(_GET_MEMBER, argument.name)
        if parameter == 'Static':
            continue
        if parameter != 'MemberType':
            return None
        if argument.kind is Ps1CommandArgumentKind.NAMED:
            view = _member_type_view(argument.value)
            if view is None:
                return None
        else:
            expecting = True
    if expecting:
        return None
    if static:
        return None if view is not None else Ps1MemberView.STATIC
    return view or Ps1MemberView.INSTANCE


def _member_type_view(value: Node | None) -> Ps1MemberView | None:
    text = string_value(value)
    if text is None:
        return None
    return {'method': Ps1MemberView.METHOD, 'property': Ps1MemberView.PROPERTY}.get(text.lower())


def _member_listing(stages: Sequence[Node]) -> tuple[Node, Ps1MemberView, Ps1CommandInvocation | None] | None:
    """
    The value the pipeline *stages* list the members of, the view they list, and the `Get-Member`
    invocation that lists them where one does: a value piped into `Get-Member`, or the
    `psobject.Methods` or `psobject.Properties` of one, possibly inside parentheses.
    """
    if len(stages) == 1:
        stage = stages[0]
        expression = stage.expression if isinstance(stage, Ps1PipelineElement) else stage
        if expression is None:
            return None
        inner = unwrap_parens(expression)
        if isinstance(inner, Ps1Pipeline):
            return _member_listing(inner.elements)
        found = _psobject_view(expression)
        if found is None:
            return None
        value, view = found
        return value, view, None
    if len(stages) != 2:
        return None
    source, lister = stages
    if not isinstance(source, Ps1PipelineElement) or not isinstance(lister, Ps1PipelineElement):
        return None
    invocation = lister.expression
    if not isinstance(invocation, Ps1CommandInvocation) or resolve_command_name(invocation) != _GET_MEMBER:
        return None
    view = _get_member_view(invocation)
    if view is None or source.expression is None:
        return None
    return source.expression, view, invocation


def member_selection(
    stages: Sequence[Node],
    type_of_variable: Ps1VariableTyping | None = None,
) -> Ps1MemberSelection | None:
    """
    What the pipeline *stages* in front of a narrowing list, or `None` where they list no members
    of a type this can name: a value piped into `Get-Member`, or the `psobject.Methods` or
    `psobject.Properties` of one, possibly inside parentheses.

    Only a value the values layer types qualifies, and it types no command's output — measured, the
    output of `Get-Date`, `Get-Item` and `Get-Process` carries notes its type has not, which such a
    value would list beside the members of its type. A value the pipeline would unroll is refused,
    since its elements are listed rather than itself, and so is a type literal outside the static
    view: piped in, it is a `System.RuntimeType` whose own members no listing here holds.
    """
    found = _member_listing(stages)
    if found is None:
        return None
    value, view, _ = found
    return _typed_selection(value, view, type_of_variable)


def _typed_selection(
    value: Node,
    view: Ps1MemberView,
    type_of_variable: Ps1VariableTyping | None,
) -> Ps1MemberSelection | None:
    inner = unwrap_parens(value)
    if isinstance(inner, Ps1TypeExpression) and view is not Ps1MemberView.STATIC:
        return None
    if not isinstance(value, Expression):
        return None
    found = resolve_expression_type(value, type_of_variable)
    if found is None:
        return None
    type_name = str(found)
    if is_enumerable(type_name) is not False and is_assignable_to(
        type_name, 'System.Collections.IDictionary'
    ) is not True:
        return None
    if member_listing(type_name, view) is None:
        return None
    return Ps1MemberSelection(type_name, view)


def _the_one_match(names, pattern: str, case_sensitive: bool = False) -> str | None:
    regex = wildcard_regex(pattern, case_sensitive)
    if regex is None:
        return None
    matches = [name for name in names if regex.match(name)]
    return matches[0] if len(matches) == 1 else None


def _by_folded_name(names: frozenset[str]) -> Mapping[str, tuple[str, ...]]:
    found: dict[str, list[str]] = {}
    for name in names:
        found.setdefault(name.casefold(), []).append(name)
    return {folded: tuple(spellings) for folded, spellings in found.items()}


#: The vocabulary a literal lookup reads, keyed by the name it spells: what a lookup of commands
#: and one of cmdlets alone may find under each name.
_LISTED_BY_NAME = {
    False: _by_folded_name(KNOWN_COMMAND_NAMES),
    True: _by_folded_name(KNOWN_CMDLET_NAMES),
}

#: The vocabulary a lookup of no name lists, without the aliases no module defines: what a lookup
#: of commands and one of cmdlets alone lists.
_LISTED_WITHOUT_A_NAME = {
    False: KNOWN_COMMAND_NAMES - MODULELESS_ALIASES,
    True: KNOWN_CMDLET_NAMES - MODULELESS_ALIASES,
}


def listed_command(
    selection: Ps1CommandSelection,
    narrowing: Ps1NameNarrowing | None = None,
) -> str | None:
    """
    The one command name the lookup *selection* makes, piped through *narrowing* where one is
    given, lists, or `None` where it lists none, several, or one this cannot vouch for.

    A literal names the command of the session whose name it spells once its escapes are removed.
    A pattern or no name at all lists more than the collected vocabulary holds, so the one name
    that survives must be engine-owned (`refinery.lib.scripts.ps1.data.ENGINE_COMMAND_NAMES`),
    which no module folder of the machine lists twice, and a pattern that may end in an extension
    of `refinery.lib.scripts.ps1.data.PROGRAM_EXTENSIONS` may list a program on `PATH` beside it.
    """
    if selection.shaped:
        return None
    candidates = KNOWN_CMDLET_NAMES if selection.cmdlets_only else KNOWN_COMMAND_NAMES
    name = selection.name
    listed: Collection[str]
    if name is None:
        if narrowing is None:
            return None
        listed = _LISTED_WITHOUT_A_NAME[selection.cmdlets_only]
    elif not selection.pattern:
        literal = name if is_wildcard_pattern(name) else literal_name(name)
        found = _LISTED_BY_NAME[selection.cmdlets_only].get((literal or '').casefold(), ())
        if len(found) != 1:
            return None
        listed = found
        if narrowing is None:
            return found[0]
    else:
        if not selection.cmdlets_only and any(
            wildcard_may_end_with(name, extension) for extension in PROGRAM_EXTENSIONS
        ):
            return None
        regex = wildcard_regex(name)
        if regex is None:
            return None
        listed = [candidate for candidate in candidates if regex.match(candidate)]
    if narrowing is not None:
        regex = wildcard_regex(narrowing.pattern, narrowing.case_sensitive)
        if regex is None:
            return None
        listed = [candidate for candidate in listed if regex.match(candidate)]
    if len(listed) != 1:
        return None
    found_name, = listed
    if selection.pattern or name is None:
        if found_name not in ENGINE_COMMAND_NAMES:
            return None
    return found_name


def listed_member(selection: Ps1MemberSelection, narrowing: Ps1NameNarrowing) -> str | None:
    """
    The one member name the listing *selection* holds that *narrowing* passes, or `None`.
    """
    names = member_listing(selection.type_name, selection.view)
    if names is None:
        return None
    return _the_one_match(names, narrowing.pattern, narrowing.case_sensitive)


def listed_variable(pattern: str) -> str | None:
    """
    The one variable of the session *pattern* matches, spelled as the session spells it, or `None`
    where it matches none, several, or a variable the engine may create while the script runs.
    Whether the script itself wrote a matching name is `variable_listing_holds_at`'s question.
    """
    regex = wildcard_regex(pattern)
    if regex is None or any(regex.match(name) for name in RUNTIME_VARIABLES):
        return None
    return _the_one_match(SESSION_VARIABLES, pattern)


def lookup_may_raise(selection: Ps1CommandSelection) -> bool:
    """
    Whether the lookup *selection* may raise where it lists nothing: a literal does, as does a
    malformed pattern and a lookup shaped beyond its name; a well-formed pattern and a lookup of no
    name at all do not.
    """
    if selection.shaped:
        return True
    if selection.name is None:
        return False
    if not selection.pattern:
        return True
    return wildcard_regex(selection.name) is None


def functions_listed(
    selection: Ps1CommandSelection | None,
    narrowing: Ps1NameNarrowing | None = None,
) -> Ps1Listed:
    """
    The script's functions the lookup *selection* may list, piped through *narrowing* where one is
    given: the one a literal names, those a pattern matches, or every function where the lookup
    names none or cannot be read. A lookup of cmdlets lists no function.
    """
    if selection is not None and selection.cmdlets_only:
        return Ps1Listed()
    name = None if selection is None else selection.name
    if selection is None or name is None:
        if narrowing is not None:
            return Ps1Listed(patterns=(narrowing.pattern,))
        return Ps1Listed(every=True)
    if not selection.pattern:
        literal = name if is_wildcard_pattern(name) else literal_name(name)
        return Ps1Listed(names=frozenset({normalize_command_name(literal or name)}))
    return Ps1Listed(patterns=(name,))


def command_listing_holds_at(node: Node, patterns: Sequence[str], cache) -> bool:
    """
    Whether the collected vocabulary is what the session's command table lists at *node* for every
    pattern of *patterns*: a lookup invoked by name still runs the lookup command it names, and no
    writer of the table and no definition matching a pattern ran before it. *cache* is the
    `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` of the tree *node* stands in.
    """
    reach = cache.world_reach
    if isinstance(node, Ps1CommandInvocation) and not reach.may_trust_invocation(node):
        return False
    return reach.may_read_the_command_table_at(node, patterns)


def member_listing_holds_at(pipeline: Ps1Pipeline, cache) -> bool:
    """
    Whether the collected surface is what the member listing *pipeline* pipes into the narrowing
    at its end lists where it stands: the `Get-Member` it lists through, where it lists through
    one, still runs the command it names, and no code the analysis cannot read can have changed a
    type before it. *cache* is the `refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` of the
    tree *pipeline* stands in.
    """
    found = _member_listing(pipeline.elements[:-1])
    if found is None:
        return False
    reach = cache.world_reach
    lister = found[2]
    if lister is not None and not reach.may_trust_invocation(lister):
        return False
    return reach.closed_at(pipeline)


class Ps1VariableTableWrites:
    """
    What the guard of a variable listing reads of the whole script, read once per tree: every name
    the script writes into the variable table, each with the key its writes are filed under, and
    whether the script subscribes an event action. Which written names a pattern matches is
    answered once per pattern.
    """

    def __init__(self, keys: Mapping[str, str], subscribes_an_event_action: bool):
        self._keys = keys
        self._matched: dict[str, tuple[str, ...]] = {}
        self.subscribes_an_event_action = subscribes_an_event_action

    def matching(self, pattern: str) -> tuple[str, ...]:
        """
        The keys of the written names *pattern* matches; none for a pattern 5.1 rejects.
        """
        matched = self._matched.get(pattern)
        if matched is None:
            regex = wildcard_regex(pattern)
            matched = () if regex is None else tuple(
                key for name, key in self._keys.items() if regex.match(name))
            self._matched[pattern] = matched
        return matched


def variable_table_writes(root: Node, write_sites: Mapping[str, object]) -> Ps1VariableTableWrites:
    """
    The `Ps1VariableTableWrites` of *root*, whose writes are the keys of *write_sites* as
    `refinery.lib.scripts.ps1.analysis.model.Ps1SemanticModel.write_sites` files them. The key of
    an environment variable names nothing in the variable table and is left out.
    """
    keys: dict[str, str] = {}
    for key in write_sites:
        name = variable_table_name(key)
        if name is not None:
            keys[name] = key
    subscribes = any(
        isinstance(node, Ps1CommandInvocation) and resolve_command_name(node) in _EVENT_SUBSCRIBERS
        for node in root.walk()
    )
    return Ps1VariableTableWrites(keys, subscribes)


@functools.lru_cache(maxsize=1024)
def _session_keys_matching(pattern: str) -> frozenset[str]:
    regex = wildcard_regex(pattern)
    if regex is None:
        return frozenset()
    return frozenset(name.lower() for name in SESSION_VARIABLES if regex.match(name))


@functools.lru_cache(maxsize=1024)
def _matches_an_event_action_variable(pattern: str) -> bool:
    regex = wildcard_regex(pattern)
    return regex is not None and any(regex.match(name) for name in EVENT_ACTION_VARIABLES)


def variable_listing_holds_at(pattern: str, site: Node, cache) -> bool:
    """
    Whether the variables *pattern* matches at *site* are those the session started with: no write
    of the script to a name it matches — a session variable or one the script writes — and no write
    nobody can attribute to a name has run before *site*. Where the script writes a matching name,
    `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.write_observed_at` answers for each
    such name and for the writes nobody can attribute, in the script's own scope. Where it writes
    none, only a write nobody can attribute could add one, and
    `refinery.lib.scripts.ps1.analysis.dataflow.Ps1VariableFlow.unattributable_write_may_precede`
    orders those; in a script that holds none the listing holds anywhere, which keeps a listing
    inside a function body foldable.

    The names written are the names the variable table lists, read off the keys of the writes
    (`refinery.lib.scripts.ps1.ast.variable_table_name`), including those holding a colon: measured
    on 5.1, after `Set-Variable 'e:x' 1` a listing of `E*t` holds `e:x` beside `ExecutionContext`.

    A pattern matching a variable an event action binds is refused where the script subscribes one,
    since a listing in the action block, or in a function it calls, lists that variable as well.
    """
    if wildcard_regex(pattern) is None:
        return False
    writes = cache.variable_table_writes
    if writes.subscribes_an_event_action and _matches_an_event_action_variable(pattern):
        return False
    flow = cache.variable_flow
    written = writes.matching(pattern)
    if not written:
        if not flow.has_unattributable_writes:
            return True
        return not flow.unattributable_write_may_precede(site)
    keys = set(_session_keys_matching(pattern))
    keys.update(written)
    keys.add(pattern.lower())
    return all(flow.write_observed_at(key, site) is Ps1ObservedWrite.NOTHING for key in keys)
