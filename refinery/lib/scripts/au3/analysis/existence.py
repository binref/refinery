"""
The existence model: the names a global may take when the tree runs. The may-write summary
refinement asks it — a bare write inside a function creates a local when no global of the name
exists, so a summary may drop the write only when the census proves no channel can create that
global — and the interpreter's frame relies on the same fact the other way: the summary the
refinement emptied is what makes the frame's implicit local one AutoIt itself creates.

The census walks every channel that can create a global: the command-line constants AutoIt
defines before the first statement runs, a write at script level, a `Global` declaration
anywhere in the tree, an `Assign` with a literal name, an `Execute` payload or a computed `Call`
name resolved to the string it spells — a literal shape, or a call with literal arguments to a
script function probed through `refinery.lib.scripts.au3.analysis.interpreter.Au3Interpreter.probe`
— the variable names every call hands to a `ByRef` parameter, and the registrations whose
registered function receives arguments, which must name a script function literally. Source text
the parser could not read — an error node in the tree, or a payload this parser reads as
nothing — is read through `refinery.lib.scripts.au3.analysis.unparsed.read_unparsed`, and every
variable it spells may be a global. The parser's record list is not an input: its texts also
live in the tree — an error node is its own record, and a repair record names a token of a line
the parser went on to read — while the list itself outlives the edits that remove those lines,
so a census over it would stay poisoned over a tree its own transforms had cleaned. A channel
the census cannot read — an include it cannot see, a computed `Assign` name, an unresolvable
payload or `Call` name, an indirect callee, a forwarding `Call` of `Call`, a registration whose
name is not a literal script function, a registration or an option set through a `Call` whose
sole argument may be a `CallArgArray` expansion, an option setting that may expand variables,
macros, or
environment strings inside string literals, unread text that may call a channel or declare a
function, or a probe budget the tree exhausts — answers that any name may be a global, and that
the tree may set `MustDeclareVars`, which the unread channel may do as well. Every other callee
is covered by one closure claim: a name none of the channels above owns is an AutoIt builtin
that creates no script variable or a call AutoIt refuses to run, which is the one
documentation-sourced boundary of the census.

An `Opt` that may set `MustDeclareVars` — tree-level or inside a payload the census examines —
makes every implicit write fatal, so the model reports it and the summary refinement refuses to
lean on the census while it holds. The census does not see the order in which the settings run,
so a zero elsewhere clears nothing.

This module also owns what a dynamic-name channel writes: `execute_kills` and `assign_kills`,
the answers the constant-binding walk, the alias map, and the usage model read, over the one
payload parse they share — and `call_target`, the callee a computed `Call` invocation resolves
to, which the usage model's read-side channel walk reads beside it.

A census runs once per tree version, and a run holds one `Au3ProbeMemo` across its versions, so
a census asks the interpreter only for the probes no earlier census made.
"""
from __future__ import annotations

import functools

from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from refinery.lib.scripts import UnspellableNode
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import OPTION_SETTERS
from refinery.lib.scripts.au3.analysis.interpreter import Au3Interpreter, Au3Probe
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.unparsed import read_unparsed, spelled_name
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    literal_value,
    to_number,
    truthy,
)
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3EnumDeclaration,
    Au3ErrorNode,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3MemberAccess,
    Au3ScopeKind,
    Au3Script,
    Au3StringLiteral,
    Au3Variable,
    Au3VariableDeclaration,
    Expression,
)
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer

#: The globals every script holds before its first statement runs: the command-line constants
#: exist whether or not parameters are passed, so a bare write of either inside a function
#: reaches the constant — a fatal error — instead of creating a local.
_PREDEFINED_GLOBALS = frozenset({'cmdline', 'cmdlineraw'})

#: The registration builtins whose registered function receives arguments the registration
#: passes through, each mapped to the argument positions that hold the registered name: a name
#: registered there that is not a literal naming a script function may reach the builtin
#: `Assign` with arguments, so the census answers that any name may be a global. The
#: zero-argument registrations invoke an `Assign` shape with no arguments, which creates
#: nothing. `DllCallbackRegister` names its function first; its other leading position is the
#: return type, which names no function.
_REGISTRATION_NAME_POSITIONS: dict[str, frozenset[int]] = {
    'guiregistermsg'              : frozenset({1}),
    'guictrlregisterlistviewsort' : frozenset({1}),
    'dllcallbackregister'         : frozenset({0}),
    'objevent'                    : frozenset({1}),
}

#: The options under which a string literal expands the variables, macros, or environment
#: strings it spells when the tree runs: a literal the census reads as a name may then spell any
#: other, so a tree that may set one answers that any name may be a global.
_EXPANDING_OPTIONS = frozenset({'expandvarstrings', 'expandenvstrings'})

#: Every builtin whose call the census reads as a channel: source text the parser could not
#: read that names one may make a call the census can read only from a parsed tree.
_CHANNEL_BUILTINS = frozenset({
    'assign',
    'call',
    'execute',
    *_REGISTRATION_NAME_POSITIONS,
    *OPTION_SETTERS,
})

#: The total steps every probe the census makes may spend together: a tree that exhausts them
#: answers that any name may be a global. Roughly forty times what the a3x sample this model
#: was built over spends across all of its probes.
_MAX_CENSUS_PROBE_STEPS = 1_000_000


@functools.lru_cache(maxsize=None)
def parse_payload(text: str) -> Expression | None:
    """
    The expression an `Execute` payload spells, or `None` where the payload parses to nothing:
    AutoIt answers `""` there (probe3), and `""` writes nothing — only a call inside the parsed
    expression can. Every reader walks the parse, so one payload text parses once.
    """
    return Au3Parser(text).parse_expression()


def execute_kills(call: Au3Call) -> set[str] | None:
    """
    The names an `Execute` call may write: a constant argument spells one expression, so only a
    call inside it can write anything; a parse failure may still be a payload AutoIt runs — this
    parser's refusal is not AutoIt's — so it answers any name except the empty payload AutoIt
    answers `""` for (probe3). Any other argument can execute arbitrary code.
    """
    if len(call.arguments) != 1:
        return None
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    expression = parse_payload(literal.value)
    if expression is None:
        return set() if not literal.value.strip() else None
    if ast.contains_a_call(expression):
        return None
    return set()


def assign_kills(call: Au3Call) -> set[str] | None:
    """
    The names an `Assign` call may write: a constant first argument names one variable, anything
    else may name any.
    """
    if not call.arguments:
        return set()
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    return {spelled_name(literal.value)}


def call_target(
    name: str,
    passed: Sequence[Expression],
    function_names: frozenset[str],
) -> str | None:
    """
    The callee a computed `Call` invocation of *name* resolves to over *passed*, the arguments it
    forwards: the name the string spells, or `None` where the resolution refuses — a forwarding
    `Call` of `Call`, and a registration or option setter whose sole forwarded argument may be
    the array a `CallArgArray` expansion unpacks. Both read a position past the first, an element
    no walk sees.
    """
    target = spelled_name(name)
    if target == 'call':
        return None
    if (
        len(passed) == 1
        and (target in _REGISTRATION_NAME_POSITIONS or target in OPTION_SETTERS)
        and _may_expand(passed[0], function_names)
    ):
        return None
    return target


def _may_expand(argument: Expression, function_names: frozenset[str]) -> bool:
    """
    Whether *argument*, the sole one a computed `Call` passes on, may be the array a
    `CallArgArray` expansion unpacks: only a literal scalar is not.
    """
    value = literal_value(argument, function_names)
    return value is None or value.kind is Kind.ARRAY


@dataclass(frozen=True)
class Au3ExistenceModel:
    """
    What the census learned about one tree version: the names a global may take — `None` when
    any name may — and whether the tree may set `MustDeclareVars`, which makes every implicit
    write fatal; with both, which writes inside a function may target a global. Built once per
    tree version by `build_existence_model`.
    """
    possible_globals: frozenset[str] | None
    implicit_writes_are_fatal: bool

    def global_may_exist(self, name: str) -> bool:
        """
        Whether a global of *name* may exist when the tree runs.
        """
        return self.possible_globals is None or name in self.possible_globals

    def write_may_target_global(self, binding: Binding, name: str, creates_storage: bool) -> bool:
        """
        Whether a write of *name* inside a function, whose storage *binding* answers, may target
        a global. A provable local never does and a provable global always does. A write that
        proves nothing creates a local where no global of the name exists, so it may target one
        only where the census answers that one may exist, or where the tree may make every
        implicit write fatal. A write that creates no storage — a `ReDim`, which resizes an array
        that exists or ends the script — is outside that refinement and may target a global
        wherever no local provably holds the name.
        """
        if binding is Binding.LOCAL:
            return False
        if binding is Binding.GLOBAL or not creates_storage:
            return True
        return self.implicit_writes_are_fatal or self.global_may_exist(name)

    def write_is_fatal(self, name: str) -> bool:
        """
        Whether a store of *name* is a fatal error the tree runs into: one of the command-line
        constants every script starts with is read-only, so its store can never leave.
        """
        return name in _PREDEFINED_GLOBALS


_ProbeKey = tuple[str, frozenset[str], str]


class Au3ProbeMemo:
    """
    The probes the censuses of one run made, so a census over a later tree version answers a
    probe it asks again without running it. A probe reads the spelling of the function it runs,
    the names of the script functions — a nested call into one refuses — and its arguments, so
    its key holds all three, each argument by the exact spelling of its kind and payload; a
    function no text spells is probed afresh. A census charges the steps a remembered probe spent
    against its quota exactly as it would a fresh one, which keeps its answer a function of the
    tree alone. Only the probes the latest two censuses asked are held, so a function that a fold
    rewrites in every version costs no more memory than one census holds.
    """

    def __init__(self):
        self._held: dict[_ProbeKey, Au3Probe] = {}
        self._asked: dict[_ProbeKey, Au3Probe] = {}
        self._spellings: dict[int, str | None] = {}

    def renew(self) -> None:
        """
        Begin a census: the probes the previous census asked stay available, older ones drop.
        """
        self._held = self._asked
        self._asked = {}
        self._spellings = {}

    def probe(
        self,
        interpreter: Au3Interpreter,
        function: Au3FunctionDeclaration,
        arguments: Sequence[Au3Value],
    ) -> Au3Probe:
        spelling = self._spelling(function)
        if spelling is None:
            return interpreter.probe(function, arguments)
        key = (spelling, interpreter.function_names, repr(tuple(arguments)))
        probe = self._asked.get(key)
        if probe is None:
            probe = self._held.get(key)
        if probe is None:
            probe = interpreter.probe(function, arguments)
        self._asked[key] = probe
        return probe

    def _spelling(self, function: Au3FunctionDeclaration) -> str | None:
        """
        The source text of *function*, synthesized once per census: the tree does not change
        while a census runs.
        """
        key = id(function)
        if key not in self._spellings:
            try:
                self._spellings[key] = Au3Synthesizer().convert(function)
            except (UnspellableNode, RecursionError):
                self._spellings[key] = None
        return self._spellings[key]


class _Poison(Exception):
    """
    The signal that unwinds the census: a channel whose global creation the tree may spell
    without spelling its name, so the answer is that any name may be a global — and that the
    tree may set `MustDeclareVars`: the walk ends there, so a setter in that channel or past it
    goes unread.
    """


class _Census:
    """
    One walk over every global-creation channel of a tree, collecting the names a global may
    take. A channel the walk cannot read raises `_Poison`, and the answer becomes that any name
    may be a global and every implicit write may be fatal.
    """

    def __init__(self, scope_model: Au3ScopeModel, memo: Au3ProbeMemo):
        self.scope_model = scope_model
        self.functions = scope_model.functions
        self.function_names = scope_model.function_names
        self.interpreter = Au3Interpreter(scope_model, {})
        self.memo = memo
        self.probe_steps = 0
        self.names: set[str] = set(_PREDEFINED_GLOBALS)
        self.implicit_writes_are_fatal = False

    def collect(self, root: Au3Script) -> Au3ExistenceModel:
        try:
            if self.scope_model.holds_an_include:
                raise _Poison
            for node in root.walk_in_order():
                if isinstance(node, (Au3VariableDeclaration, Au3EnumDeclaration)):
                    if node.scope is Au3ScopeKind.GLOBAL:
                        for declarator in node.declarations:
                            if declarator.variable is not None:
                                self.names.add(declarator.variable.name)
                    continue
                if isinstance(node, Au3ErrorNode):
                    self._examine_unparsed(node.text)
                elif isinstance(node, Au3Call):
                    self._examine_call(node)
            for node in ast.scope_nodes(root.body):
                if isinstance(node, Au3Variable) and ast.is_write_occurrence(node):
                    self.names.add(node.name)
        except (_Poison, RecursionError):
            return Au3ExistenceModel(None, True)
        return Au3ExistenceModel(frozenset(self.names), self.implicit_writes_are_fatal)

    def _examine_call(self, call: Au3Call) -> None:
        callee = ast.unwrap_parens(call.callee)
        if isinstance(callee, Au3MemberAccess):
            return
        if not isinstance(callee, Au3Identifier):
            raise _Poison
        self._examine_target(callee.name, call.arguments)

    def _examine_target(self, name: str, arguments: Sequence[Expression]) -> None:
        """
        One call of *name* over *arguments*, as the tree spells it or as a computed `Call`
        resolves it: a script function receives its `ByRef` arguments, and a channel builtin is
        read over the arguments that reach it — after the name, where a `Call` spells one.
        """
        if name in self.functions:
            self._collect_byref(self.functions[name], arguments)
        elif name == 'assign':
            self._examine_assign(arguments)
        elif name == 'execute':
            self._examine_execute(arguments)
        elif name == 'call':
            self._examine_computed_call(arguments)
        elif name in _REGISTRATION_NAME_POSITIONS:
            for index in _REGISTRATION_NAME_POSITIONS[name]:
                if index < len(arguments):
                    self._examine_registered_name(arguments[index])
        elif name in OPTION_SETTERS:
            self._examine_option(arguments)

    def _collect_byref(
        self,
        function: Au3FunctionDeclaration,
        arguments: Sequence[Expression],
    ) -> None:
        """
        The variable names *arguments* hand into the `ByRef` parameters of *function*. Whether an
        undeclared name there is auto-created, fatal, or dead is unpinned, and spelling it is
        sound under every answer: an extra spelled name only keeps more writes in the summaries.
        """
        for variable in ast.byref_arguments(function, arguments):
            self.names.add(variable.name)

    def _examine_assign(self, arguments: Sequence[Expression]) -> None:
        if not arguments:
            return
        literal = ast.unwrap_parens(arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            raise _Poison
        self.names.add(spelled_name(literal.value))

    def _examine_execute(self, arguments: Sequence[Expression]) -> None:
        if not arguments:
            return
        payload = self._resolve_string(arguments[0])
        if payload is None:
            raise _Poison
        self._examine_payload(payload)

    def _examine_payload(self, payload: str) -> None:
        """
        One resolved `Execute` payload: only a call inside it can write (probe3), so every call
        in the parsed expression is examined by the same rules the tree-level calls follow — a
        nested payload resolving the same way, the structural recursion bounded by the
        `RecursionError` the collect walk catches. A payload this parser reads as nothing may
        still be one AutoIt runs, so its text is read token by token.
        """
        expression = parse_payload(payload)
        if expression is None:
            self._examine_unparsed(payload)
            return
        for node in expression.walk_in_order():
            if isinstance(node, Au3Call):
                self._examine_call(node)

    def _examine_computed_call(self, arguments: Sequence[Expression]) -> None:
        """
        A `Call` over a computed name: the name resolves to what it spells, and the target is
        examined over the arguments that follow it. A resolution `call_target` refuses poisons,
        and so does a name the census cannot read.
        """
        if not arguments:
            return
        name = self._resolve_string(arguments[0])
        if name is None:
            raise _Poison
        target = call_target(name, arguments[1:], self.function_names)
        if target is None:
            raise _Poison
        self._examine_target(target, arguments[1:])

    def _examine_registered_name(self, argument: Expression) -> None:
        literal = ast.unwrap_parens(argument)
        if (
            not isinstance(literal, Au3StringLiteral)
            or spelled_name(literal.value) not in self.functions
        ):
            raise _Poison

    def _examine_option(self, arguments: Sequence[Expression]) -> None:
        """
        One option setter: an option that may expand string literals is a channel the census
        cannot read, `MustDeclareVars` makes every implicit write fatal, and an option name the
        census cannot read may be either. A value may set an option unless it reads as zero both
        as a number and as a condition — which reading AutoIt takes is unpinned, and the two
        split on a non-empty string whose number is zero, such as `"0"`. The census does not see
        the order in which the settings run, so one that may set an option holds for the whole
        tree and no zero clears it. A setter of one argument only reads the option.
        """
        if len(arguments) < 2:
            return
        option = self._resolve_string(arguments[0])
        name = None if option is None else spelled_name(option)
        if name is not None and name not in _EXPANDING_OPTIONS and name != 'mustdeclarevars':
            return
        value = literal_value(arguments[1], self.function_names)
        if value is not None and to_number(value) == 0 and truthy(value) is False:
            return
        if name != 'mustdeclarevars':
            raise _Poison
        self.implicit_writes_are_fatal = True

    def _examine_unparsed(self, text: str) -> None:
        """
        Source text the parser could not read, which AutoIt may still run, read through
        `read_unparsed`: every variable it spells may be a global, and text that names a channel
        builtin, opens a call on a computed callee, or declares a function — whose `ByRef`
        positions only a parsed declaration shows — is a channel the census cannot read.
        """
        unparsed = read_unparsed(text)
        if (
            unparsed.computed_callee
            or unparsed.declares_function
            or unparsed.identifiers & _CHANNEL_BUILTINS
        ):
            raise _Poison
        self.names.update(unparsed.variables)

    def _resolve_string(self, expression: Expression | None) -> str | None:
        """
        The string *expression* spells where the census reads a payload or a name: a literal
        shape or the pieces one renders — `Chr(0)` standing alone spells the same string its `&`
        chain does — or a call with literal arguments to a script function, probed over the
        value domain. Anything else the census cannot read.
        """
        node = ast.unwrap_parens(expression)
        value: Au3Value | None = None
        if isinstance(node, Au3Call):
            callee = ast.direct_callee(node)
            if callee is not None and callee.name in self.functions:
                arguments: list[Au3Value] = []
                for argument in node.arguments:
                    value = literal_value(argument, self.function_names)
                    if value is None:
                        return None
                    arguments.append(value)
                probe = self.memo.probe(self.interpreter, self.functions[callee.name], arguments)
                self.probe_steps += probe.steps
                if self.probe_steps > _MAX_CENSUS_PROBE_STEPS:
                    raise _Poison
                value = probe.value
        if value is None:
            value = literal_value(cast(Expression | None, node), self.function_names)
        if value is not None and value.kind is Kind.STRING:
            return cast(str, value.payload)
        return None


def build_existence_model(
    root: Au3Script,
    scope_model: Au3ScopeModel,
    memo: Au3ProbeMemo | None = None,
) -> Au3ExistenceModel:
    """
    Walk every global-creation channel of *root* and collect the names a global may take, over
    the functions and the include answer of *scope_model*. A *memo* the run holds across its tree
    versions answers the probes an earlier census already made.
    """
    if memo is None:
        memo = Au3ProbeMemo()
    memo.renew()
    return _Census(scope_model, memo).collect(root)
