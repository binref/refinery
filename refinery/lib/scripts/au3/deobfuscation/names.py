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
fatally (probe9d A10), never under a `MustDeclareVars` the tree may set without a declaration
backing the plain write — the option refusing the write to an undeclared name while its hold
over `Assign` is unpinned — and never where `@error` is observable: a successful `Assign` clears a
previous `@error`/`@extended` while the plain write leaves both (probe9f A21). `Eval("x")`
becomes `$x` only behind a local that provably exists — every other read targets a global the
tree cannot prove exists, and the plain read of a missing name is a fatal refusal where `Eval`
answered `""` (probe9c A11) — and only behind a claim that strictly precedes the read:
`Local $x = $x` is an interpreter refusal (probe9g A29). A successful `Eval` clears
`@error`/`@extended` the same way (probe9f A22), so its rule carries the same observability gate,
and one position refuses outright: a whole-argument slot an enclosing call passes by reference —
the callee's write reaches the temporary `Eval` answers, not the named variable the flatten would
put in its place, a variable `Call` mutates (probe9 A15). A statement whose whole expression is
an `=` comparison still flattens: the synthesizer brackets the printed line, because a plain `=`
comparison over a writable left operand re-parses as an assignment
(`refinery.lib.scripts.au3.precedence`).

Every rule shares four refusals: a script function of the builtin's name shadows it, an include
may declare storage and constants no tree declaration covers — read from the scope model, in
both spellings the parser answers with, the node and the directive an include line with trailing
text becomes — a tree whose parse failed anywhere is refused outright, and a name that is not a
shape the lexer reads back builds nothing this pass may write. The `MustDeclareVars` gate reads
every spelling the option answers to — `Opt` is the documented alias of `AutoItSetOption`, and a
computed callee may name either. The pass holds its model snapshot for the visit — its edits
introduce no declaration, remove no declaration, and change no parameter list, so every fact the
snapshot holds stays true mid-pass.
"""
from __future__ import annotations

from dataclasses import dataclass

from refinery.lib.scripts import Node, Transformer, _replace_in_parent, set_child, set_child_list
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import OPTION_SETTERS
from refinery.lib.scripts.au3.analysis.cache import Au3ModelCache, model_cache
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel
from refinery.lib.scripts.au3.analysis.usage import callee_census
from refinery.lib.scripts.au3.lexer import is_au3_identifier
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3BooleanLiteral,
    Au3Call,
    Au3DefaultLiteral,
    Au3ExpressionStatement,
    Au3FloatLiteral,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IntLiteral,
    Au3MemberAccess,
    Au3NullLiteral,
    Au3Script,
    Au3StringLiteral,
    Au3Variable,
    Au3WithMember,
    Expression,
)

#: The literal shapes a sole `Call` argument may hold: no literal can be the array a
#: `CallArgArray` expansion reads (probe9 A14c), so a sole argument of any other shape keeps
#: the call dynamic.
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
    What the whole tree holds, read once per pass before any edit: a possible read of the error
    state and a call to an option setter. The pass's edits rewrite and remove calls and add plain
    reads, so neither can become true mid-pass.
    """
    observes_error_state: bool
    calls_autoit_set_option: bool


def _tree_facts(cache: Au3ModelCache) -> _TreeFacts:
    """
    The facts the whole tree decides. The callee spellings are the census's to read — see
    `callee_census` — over the usage model's functions and error-node facts, and they answer the
    error-state and the option-setter questions. The spelling of the option the tree sets is
    unpinned either way — only that the tree may set `MustDeclareVars` is a fact here.
    """
    census = callee_census(cache.root, cache.usage.functions, cache.usage.unparsed)
    return _TreeFacts(
        census.observes_error_state(),
        census.computed_callee or not OPTION_SETTERS.isdisjoint(census.callees),
    )


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
        self._facts = _TreeFacts(False, False)

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            cache = model_cache(self, node)
            self._scopes = cache.scopes
            self._facts = _tree_facts(cache)
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
        The spelling the call's first argument holds, or `None` where a shared gate refuses the
        call: a script function of the builtin's name shadows it, the tree holds an include or a
        parse error, the first argument is missing or not a string literal, or the spelling is no
        shape the lexer reads back as one name.
        """
        if builtin in self._scopes.functions:
            return None
        if self._scopes.holds_an_include:
            return None
        if self._scopes.holds_a_parse_error:
            return None
        if not call.arguments:
            return None
        literal = ast.unwrap_parens(call.arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            return None
        if not is_au3_identifier(literal.value):
            return None
        return literal.value

    def _flatten_call(self, call: Au3Call) -> None:
        spelling = self._literal_name(call, 'call')
        if spelling is None or ast.in_callee_position(call):
            return
        name = spelling.lower()
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
                argument,
                (Au3Variable, *_BYREF_LITERALS),
            ):
                return
        set_child(call, 'callee', Au3Identifier(name=name, raw=spelling))
        set_child_list(call, 'arguments', list(arguments))
        self.mark_changed()

    def _flatten_assign(self, call: Au3Call) -> None:
        spelling = self._literal_name(call, 'assign')
        if spelling is None:
            return
        name = spelling.lower()
        if name in self._scopes.constant_names:
            return
        if self._facts.observes_error_state:
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
            if not self._scopes.declaration_backs_write(scope, statement, name):
                return
        assignment = Au3Assignment()
        set_child(assignment, 'target', Au3Variable(name=name, raw=F'${spelling}'))
        set_child(assignment, 'value', value)
        set_child(statement, 'expression', assignment)
        self.mark_changed()

    def _flatten_eval(self, call: Au3Call) -> None:
        spelling = self._literal_name(call, 'eval')
        if spelling is None:
            return
        name = spelling.lower()
        if self._facts.observes_error_state:
            return
        if len(call.arguments) != 1 or ast.in_callee_position(call):
            return
        if not self._scopes.local_precedes_read(ast.enclosing_function(call), call, name):
            return
        if self._in_byref_slot(call):
            return
        variable = Au3Variable(name=name, raw=F'${spelling}')
        statement = ast.owning_statement(call)
        if (
            isinstance(statement, Au3ExpressionStatement)
            and ast.unwrap_parens(statement.expression) is call
        ):
            set_child(statement, 'expression', variable)
        elif not _replace_in_parent(call, variable):
            return
        self.mark_changed()

    def _in_byref_slot(self, call: Au3Call) -> bool:
        """
        Whether *call* stands as a whole argument in a slot an enclosing call passes by
        reference. A function return value is an unnamed temporary the parameter may bind — the
        Func documentation names it a legal `ByRef` argument — so the callee's write reaches the
        temporary, while the flattened variable is the named variable `Call` into a `ByRef`
        parameter mutates (probe9 A15). A parenthesized argument stays a parenthesized expression
        after the flatten, so only the direct argument position refuses. The callee is read the
        way `_tree_facts` reads one: an identifier naming a script function checks its
        parameters — a `Call` invocation over a literal, offset by the name argument — any other
        identifier names a builtin, whose parameters are never `ByRef`, and a callee computed at
        run time could name a function whose parameter there is one, so it refuses; the include
        gate rules out the unseen script function either spelling could name.
        """
        parent = call.parent
        if not isinstance(parent, Au3Call):
            return False
        index = next(
            (position for position, argument in enumerate(parent.arguments) if argument is call),
            None,
        )
        if index is None:
            return False
        callee = ast.unwrap_parens(parent.callee)
        if not isinstance(callee, Au3Identifier):
            return not isinstance(callee, (Au3MemberAccess, Au3WithMember))
        offset = 0
        if callee.name == 'call' and callee.name not in self._scopes.functions:
            if not parent.arguments:
                return False
            literal = ast.unwrap_parens(parent.arguments[0])
            if not isinstance(literal, Au3StringLiteral):
                return True
            name = literal.value.lower()
            offset = 1
        else:
            name = callee.name
        target = self._scopes.functions.get(name)
        if target is None:
            return False
        position = index - offset
        if position < 0 or position >= len(target.params):
            return False
        return target.params[position].by_ref
