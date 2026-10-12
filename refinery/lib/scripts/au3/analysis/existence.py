"""
The existence model: the names a global may take when the tree runs. The may-write summary
refinement asks it — a bare write inside a function creates a local when no global of the name
exists, so a summary may drop the write only when the census proves no channel can create that
global — and the interpreter's frame relies on the same fact the other way: the summary the
refinement emptied is what makes the frame's implicit local one AutoIt itself creates.

The census walks every channel that can create a global: a write at script level, a `Global`
declaration anywhere in the tree, an `Assign` with a literal name, an `Execute` payload or a
computed `Call` name resolved to the string it spells — a literal shape, or a call with literal
arguments to a script function probed through
`refinery.lib.scripts.au3.analysis.interpreter.Au3Interpreter.probe` — the variable names every
call hands to a `ByRef` parameter, and the registrations whose registered function receives
arguments, which must name a script function literally. A channel the census cannot read — an
include it cannot see, a computed `Assign` name, an unresolvable payload or `Call` name, an
indirect callee, a forwarding `Call` of `Call`, a registration whose name is not a literal
script function, or a probe budget the tree exhausts — answers that any name may be a global.
Every other callee is covered by one closure claim: a name none of the channels above owns is
an AutoIt builtin that creates no script variable or a call AutoIt refuses to run, which is the
one documentation-sourced boundary of the census.

An `Opt` of `MustDeclareVars` with a truthy value — tree-level or inside a payload the census
examines, a literal zero clearing it again — makes every implicit write fatal, so the model
reports it and the summary refinement refuses to lean on the census while it holds.

This module also owns what a dynamic-name channel writes: `execute_kills` and `assign_kills`,
the answers the constant-binding walk, the alias map, and the usage model read, over the one
payload parse they share.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.interpreter import Au3Interpreter
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    literal_value,
    to_number,
)
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3EnumDeclaration,
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

#: The registration builtins whose registered function receives arguments the registration
#: passes through, each mapped to the argument positions that hold the registered name: a name
#: registered there that is not a literal naming a script function may reach the builtin
#: `Assign` with arguments, so the census answers that any name may be a global. The
#: zero-argument registrations invoke an `Assign` shape with no arguments, which creates
#: nothing. `DllCallbackRegister` names its function first; its other leading position is the
#: return type, which names no function.
_REGISTRATION_NAME_POSITIONS: dict[str, frozenset[int]] = {
    'guiregistermsg'     : frozenset({1}),
    'dllcallbackregister': frozenset({0}),
    'objevent'           : frozenset({1}),
}

#: The builtins that set an option, the positions a `MustDeclareVars` spelling of which makes
#: every implicit write in the tree fatal.
_OPTION_SETTERS = frozenset({'opt', 'autoitsetoption'})

#: The total steps every probe the census makes may spend together: a tree that exhausts them
#: answers that any name may be a global. Roughly forty times what the a3x sample this model
#: was built over spends across all of its probes.
_MAX_CENSUS_PROBE_STEPS = 1_000_000


def parse_payload(text: str) -> Expression | None:
    """
    The expression an `Execute` payload spells, or `None` where the payload parses to nothing:
    AutoIt answers `""` there (probe3), and `""` writes nothing — only a call inside the parsed
    expression can.
    """
    return Au3Parser(text).parse_expression()


def execute_kills(call: Au3Call) -> set[str] | None:
    """
    The names an `Execute` call may write: a constant argument spells one expression, so only a
    call inside it can write anything; a parse failure answers `""` and writes nothing. Any other
    argument can execute arbitrary code.
    """
    if len(call.arguments) != 1:
        return None
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    expression = parse_payload(literal.value)
    if expression is None:
        return set()
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
    return {literal.value.lstrip('$').lower()}


@dataclass(frozen=True)
class Au3ExistenceModel:
    """
    What the census learned about one tree version: the names a global may take — `None` when
    any name may — and whether the tree may set `MustDeclareVars`, which makes every implicit
    write fatal. Built once per tree version by `build_existence_model`.
    """
    possible_globals: frozenset[str] | None
    implicit_writes_are_fatal: bool

    def global_may_exist(self, name: str) -> bool:
        """
        Whether a global of *name* may exist when the tree runs.
        """
        return self.possible_globals is None or name in self.possible_globals


class _Poison(Exception):
    """
    The signal that unwinds the census: a channel whose global creation the tree may spell
    without spelling its name, so the answer is that any name may be a global.
    """


class _Census:
    """
    One walk over every global-creation channel of a tree, collecting the names a global may
    take. A channel the walk cannot read raises `_Poison`, and the answer becomes that any name
    may be a global.
    """

    def __init__(self, scope_model: Au3ScopeModel):
        self.scope_model = scope_model
        self.functions = scope_model.functions
        self.interpreter = Au3Interpreter(scope_model, {})
        self.names: set[str] = set()
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
                if isinstance(node, Au3Call):
                    self._examine_call(node)
            for node in ast.scope_nodes(root.body):
                if isinstance(node, Au3Variable) and ast.is_write_occurrence(node):
                    self.names.add(node.name)
        except (_Poison, RecursionError):
            return Au3ExistenceModel(None, self.implicit_writes_are_fatal)
        return Au3ExistenceModel(
            frozenset(self.names), self.implicit_writes_are_fatal)

    def _examine_call(self, call: Au3Call) -> None:
        callee = ast.unwrap_parens(call.callee)
        if isinstance(callee, Au3MemberAccess):
            return
        if not isinstance(callee, Au3Identifier):
            raise _Poison
        name = callee.name
        if name in self.functions:
            self._collect_byref(call, self.functions[name])
        elif name == 'assign':
            self._examine_assign(call)
        elif name == 'execute':
            self._examine_execute(call)
        elif name == 'call':
            self._examine_computed_call(call)
        elif name in _REGISTRATION_NAME_POSITIONS:
            for index in _REGISTRATION_NAME_POSITIONS[name]:
                if index < len(call.arguments):
                    self._examine_registered_name(call.arguments[index])
        elif name in _OPTION_SETTERS:
            if len(call.arguments) > 1:
                self._examine_option(call.arguments[0], call.arguments[1])

    def _collect_byref(
        self,
        call: Au3Call,
        function: Au3FunctionDeclaration,
        offset: int = 0,
    ) -> None:
        """
        The variable names *call* hands into the `ByRef` parameters of *function*, its arguments
        counted from *offset* — the one a computed `Call` shifts past the name it spells.
        Whether an undeclared name there is auto-created, fatal, or dead is unpinned, and
        spelling it is sound under every answer: an extra spelled name only keeps more writes
        in the summaries.
        """
        for index, parameter in enumerate(function.params):
            if not parameter.by_ref:
                continue
            position = index + offset
            if position >= len(call.arguments):
                continue
            node = ast.unwrap_parens(call.arguments[position])
            if isinstance(node, Au3Variable):
                self.names.add(node.name)

    def _examine_assign(self, call: Au3Call) -> None:
        if not call.arguments:
            return
        literal = ast.unwrap_parens(call.arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            raise _Poison
        self.names.add(literal.value.lstrip('$').lower())

    def _examine_execute(self, call: Au3Call) -> None:
        if not call.arguments:
            return
        payload = self._resolve_string(call.arguments[0])
        if payload is None:
            raise _Poison
        self._examine_payload(payload)

    def _examine_payload(self, payload: str) -> None:
        """
        One resolved `Execute` payload: only a call inside it can write (probe3), so every call
        in the parsed expression is examined by the same rules the tree-level calls follow —
        a nested payload resolving the same way, the structural recursion bounded by the
        `RecursionError` the collect walk catches.
        """
        expression = parse_payload(payload)
        if expression is None:
            return
        for node in expression.walk_in_order():
            if isinstance(node, Au3Call):
                self._examine_call(node)

    def _examine_computed_call(self, call: Au3Call) -> None:
        """
        A `Call` over a computed name: the name resolves to what it spells, and the target is
        examined over the arguments that follow it. A target of `Call` itself poisons — a
        forwarding chain is not examined recursively.
        """
        if not call.arguments:
            return
        name = self._resolve_string(call.arguments[0])
        if name is None:
            raise _Poison
        target = name.lstrip('$').lower()
        if target in self.functions:
            self._collect_byref(call, self.functions[target], offset=1)
        elif target == 'assign':
            if len(call.arguments) > 1:
                literal = ast.unwrap_parens(call.arguments[1])
                if not isinstance(literal, Au3StringLiteral):
                    raise _Poison
                self.names.add(literal.value.lstrip('$').lower())
        elif target == 'execute':
            if len(call.arguments) > 1:
                payload = self._resolve_string(call.arguments[1])
                if payload is None:
                    raise _Poison
                self._examine_payload(payload)
        elif target == 'call':
            raise _Poison
        elif target in _REGISTRATION_NAME_POSITIONS:
            if len(call.arguments) > 1:
                self._examine_registered_name(call.arguments[1])
        elif target in _OPTION_SETTERS:
            if len(call.arguments) > 2:
                self._examine_option(call.arguments[1], call.arguments[2])

    def _examine_registered_name(self, argument: Expression) -> None:
        literal = ast.unwrap_parens(argument)
        if (
            not isinstance(literal, Au3StringLiteral)
            or literal.value.lstrip('$').lower() not in self.functions
        ):
            raise _Poison

    def _examine_option(self, name: Expression, value: Expression) -> None:
        """
        One `Opt` of `MustDeclareVars`: an unresolvable option name answers fatal — the census
        cannot prove it is not the one — and the value a literal zero clears and anything else
        holds, a computed value included.
        """
        option = self._resolve_string(name)
        if option is None:
            self.implicit_writes_are_fatal = True
            return
        if option.lower() != 'mustdeclarevars':
            return
        resolved = literal_value(value, self.scope_model.function_names)
        number = None if resolved is None else to_number(resolved)
        self.implicit_writes_are_fatal = number != 0

    def _resolve_string(self, expression: Expression | None) -> str | None:
        """
        The string *expression* spells where the census reads a payload or a name: a literal
        shape, or a call with literal arguments to a script function, probed over the value
        domain. Anything else the census cannot read.
        """
        node = ast.unwrap_parens(expression)
        if isinstance(node, Au3Call):
            callee = ast.direct_callee(node)
            if callee is None or callee.name not in self.functions:
                return None
            arguments: list[Au3Value] = []
            for argument in node.arguments:
                value = literal_value(argument, self.scope_model.function_names)
                if value is None:
                    return None
                arguments.append(value)
            result = self.interpreter.probe(self.functions[callee.name], arguments)
            if self.interpreter.probe_steps > _MAX_CENSUS_PROBE_STEPS:
                raise _Poison
            if result is not None and result.kind is Kind.STRING:
                return cast(str, result.payload)
            return None
        value = literal_value(cast(Expression | None, node), self.scope_model.function_names)
        if value is not None and value.kind is Kind.STRING:
            return cast(str, value.payload)
        return None


def build_existence_model(root: Au3Script, scope_model: Au3ScopeModel) -> Au3ExistenceModel:
    """
    Walk every global-creation channel of *root* and collect the names a global may take, over
    the functions and the include answer of *scope_model*.
    """
    return _Census(scope_model).collect(root)
