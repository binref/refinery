"""
Dynamic-name flattening: replacing a `Call`, `Assign`, or `Eval` over a string-literal name with
the direct call, plain write, or plain read that name spells.

The three builtins are the language's computed-name primitives, and every rule here flattens only
where the pinned semantics prove the replacement indistinguishable. `Call("f", args…)` becomes
`f(args…)` over a declared function whose arguments fill its parameters, defaulted ones included
(probe9 A13), because the undeclared name and the wrong count are the failures `Call` answers
with `@error` while the direct call terminates the script (probe9 A13b). A statement-position
`Assign("x", v)` becomes `$x = v` — flag 0 is the plain write in every storage configuration
probed (probe9 A1-A5, A18-A20, A23, A24) — never over a constant, which the plain write refuses
fatally (probe9d A10), and never where `@error` is observable: a successful `Assign` clears a
previous `@error`/`@extended` while the plain write leaves both (probe9f A21). `Eval("x")`
becomes `$x` only behind a local that provably exists — every other read targets a global the
tree cannot prove exists, and the plain read of a missing name is a fatal refusal where `Eval`
answered `""` (probe9c A11) — and only behind a claim that strictly precedes the read:
`Local $x = $x` is an interpreter refusal (probe9g A29). A successful `Eval` clears
`@error`/`@extended` the same way (probe9f A22), so its rule carries the same observability gate.

Every rule shares three refusals: a script function of the builtin's name shadows it, an include
directive may declare storage and constants no tree declaration covers, and a name holding `$`
or any other character the synthesizer cannot spell back builds nothing this pass may write. The
pass holds its model snapshot for the visit — its edits introduce no declaration, remove no
declaration, and change no parameter list, so every fact the snapshot holds stays true mid-pass.
"""
from __future__ import annotations

import re

from dataclasses import dataclass

from refinery.lib.scripts import Node, Transformer, _replace_in_parent, set_child, set_child_list
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3BooleanLiteral,
    Au3Call,
    Au3DefaultLiteral,
    Au3ExpressionStatement,
    Au3FloatLiteral,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3Include,
    Au3IncludeOnce,
    Au3IntLiteral,
    Au3Macro,
    Au3NullLiteral,
    Au3ParenExpression,
    Au3Script,
    Au3StringLiteral,
    Au3Variable,
    Expression,
)

_ERROR_MACROS = frozenset({'error', 'extended'})

_NAME_SHAPE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

#: The literal shapes an argument position may hold: a `ByRef` parameter takes these unchanged,
#: discarding the mutation of the value (probe9h A30), and no literal can be the array a
#: `CallArgArray` expansion reads.
_ARGUMENT_LITERALS = (
    Au3BooleanLiteral,
    Au3DefaultLiteral,
    Au3FloatLiteral,
    Au3IntLiteral,
    Au3NullLiteral,
    Au3StringLiteral,
)

#: The literal shapes a `ByRef` parameter position flattens: plain values, whose mutation both
#: forms discard (probe9h A30). `Null` and `Default` are keyword arguments with passing rules no
#: probe pinned, so they refuse.
_BYREF_LITERALS = (
    Au3BooleanLiteral,
    Au3FloatLiteral,
    Au3IntLiteral,
    Au3StringLiteral,
)


@dataclass(frozen=True)
class _TreeFacts:
    """
    What the whole tree holds, read once per pass before any edit: an include directive, a read
    of `@error` or `@extended`, and a call to `Execute` or `AutoItSetOption`. The pass's edits
    rewrite and remove calls and add plain reads, so none of the four can become true mid-pass.
    """
    includes_a_directive: bool
    reads_an_error_macro: bool
    calls_execute: bool
    calls_autoit_set_option: bool


def _tree_facts(root: Au3Script) -> _TreeFacts:
    callees: set[str] = set()
    includes = False
    reads_error = False
    for node in root.walk():
        if isinstance(node, (Au3Include, Au3IncludeOnce)):
            includes = True
        elif isinstance(node, Au3Macro):
            reads_error = reads_error or node.name in _ERROR_MACROS
        elif isinstance(node, Au3Call):
            callee = ast.direct_callee(node)
            if callee is not None:
                callees.add(callee.name)
    return _TreeFacts(
        includes,
        reads_error,
        'execute' in callees,
        'autoitsetoption' in callees,
    )


def _in_callee_position(node: Node) -> bool:
    """
    Whether *node* is the callee of a call, through any number of parentheses: replacing it
    there rewrites the caller's shape — `Call("f")(1)` would collapse two calls into one — not
    only the occurrence's own.
    """
    cursor = node
    parent = cursor.parent
    while isinstance(parent, Au3ParenExpression):
        cursor = parent
        parent = cursor.parent
    return isinstance(parent, Au3Call) and parent.callee is cursor


def _arguments_fill(arguments: list[Expression], function: Au3FunctionDeclaration) -> bool:
    """
    Whether *arguments* fill *function*'s parameters: exactly as many, or fewer with every
    missing one defaulted (probe9 A13 — `Call` fills a default the direct call fills too). One
    argument too many refuses: `Call` answers that with `@error` (probe9 A13b) while the direct
    call terminates the script.
    """
    if len(arguments) > len(function.params):
        return False
    return all(parameter.default is not None for parameter in function.params[len(arguments):])


class Au3DynamicNameFlattening(Transformer):
    """
    Replaces a `Call`, `Assign`, or `Eval` whose name argument is a string literal with the
    direct call, plain write, or plain read that name spells, in every position the pinned
    semantics of the three builtins cover.
    """

    def __init__(self):
        super().__init__()
        self._scopes = Au3ScopeModel({})
        self._facts = _TreeFacts(False, False, False, False)

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._scopes = model_cache(self, node).scopes
            self._facts = _tree_facts(node)
        self.generic_visit(node)
        if not isinstance(node, Au3Call):
            return None
        callee = ast.direct_callee(node)
        if callee is None:
            return None
        if callee.name == 'call':
            self._flatten_call(node)
        elif callee.name == 'assign':
            self._flatten_assign(node)
        elif callee.name == 'eval':
            self._flatten_eval(node)
        return None

    def _literal_name(self, call: Au3Call, builtin: str) -> str | None:
        """
        The variable or function name the call's first argument spells, or `None` where a shared
        gate refuses the call: a script function of the builtin's name shadows it, the tree holds
        an include directive, the first argument is missing or not a string literal, or the name
        holds a character the synthesizer cannot spell back.
        """
        if builtin in self._scopes.functions:
            return None
        if self._facts.includes_a_directive:
            return None
        if not call.arguments:
            return None
        literal = ast.unwrap_parens(call.arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            return None
        name = literal.value.lower()
        if _NAME_SHAPE.fullmatch(name) is None:
            return None
        return name

    def _flatten_call(self, call: Au3Call) -> None:
        name = self._literal_name(call, 'call')
        if name is None or _in_callee_position(call):
            return
        target = self._scopes.functions.get(name)
        if target is None:
            return
        arguments = call.arguments[1:]
        if not _arguments_fill(arguments, target):
            return
        if any(ast.contains_an_array_literal(argument) for argument in arguments):
            return
        if len(arguments) == 1 and not isinstance(
            ast.unwrap_parens(arguments[0]),
            _ARGUMENT_LITERALS,
        ):
            return
        for parameter, argument in zip(target.params, arguments):
            if parameter.by_ref and not isinstance(
                ast.unwrap_parens(argument),
                (Au3Variable, *_BYREF_LITERALS),
            ):
                return
        set_child(call, 'callee', Au3Identifier(name=name, raw=name))
        set_child_list(call, 'arguments', list(arguments))
        self.mark_changed()

    def _flatten_assign(self, call: Au3Call) -> None:
        name = self._literal_name(call, 'assign')
        if name is None:
            return
        if name in self._scopes.constant_names:
            return
        if self._facts.reads_an_error_macro or self._facts.calls_execute:
            return
        arguments = call.arguments
        if len(arguments) not in (2, 3):
            return
        if len(arguments) == 3:
            flag = ast.unwrap_parens(arguments[2])
            if not isinstance(flag, Au3IntLiteral) or flag.value != 0:
                return
        value = arguments[1]
        if ast.contains_an_array_literal(value):
            return
        statement = ast.owning_statement(call)
        if not (
            isinstance(statement, Au3ExpressionStatement)
            and ast.unwrap_parens(statement.expression) is call
        ):
            return
        if self._facts.calls_autoit_set_option:
            scope = ast.enclosing_function(call)
            if self._scopes.binding(scope, statement, name) is not Binding.LOCAL:
                return
        assignment = Au3Assignment()
        set_child(assignment, 'target', Au3Variable(name=name, raw=F'${name}'))
        set_child(assignment, 'value', value)
        set_child(statement, 'expression', assignment)
        self.mark_changed()

    def _flatten_eval(self, call: Au3Call) -> None:
        name = self._literal_name(call, 'eval')
        if name is None:
            return
        if self._facts.reads_an_error_macro or self._facts.calls_execute:
            return
        if len(call.arguments) != 1 or _in_callee_position(call):
            return
        if not self._scopes.local_precedes_read(ast.enclosing_function(call), call, name):
            return
        variable = Au3Variable(name=name, raw=F'${name}')
        statement = ast.owning_statement(call)
        if (
            isinstance(statement, Au3ExpressionStatement)
            and ast.unwrap_parens(statement.expression) is call
        ):
            set_child(statement, 'expression', variable)
        elif not _replace_in_parent(call, variable):
            return
        self.mark_changed()
