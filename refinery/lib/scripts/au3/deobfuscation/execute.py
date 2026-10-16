"""
`Execute` flattening: splicing the one expression a string-literal argument provably names into
the place of the call.

The interpreter evaluates exactly one expression there — an assignment inside the argument
parses as a *comparison* and writes nothing, declarations and statement sequences are parse errors
that answer `""` — so the literal is read with the parser's expression entry, where `=` climbs as
a comparison. A literal that parses to a bare identifier never splices, in any position: what the
name evaluates to is unpinned, and the alias map in
`refinery.lib.scripts.au3.analysis.aliases` owns the declaration instead. A literal that parses
to any other expression splices in expression position — including a top-level `=` comparison,
which assignment duality reads back exactly as `Execute` did — and in statement position every
shape splices except that comparison: the synthesized line would re-parse as an assignment.

Every call inside the spliced expression must be a direct call to a script function or a table
builtin: a call an unseen `#include` resolves, or one through a variable, leaves the `Execute`
alone, because an unknown function is one of `Execute`'s pinned failure modes and the spliced
form would make that error fatal where the original answered `""`. A literal that fails to parse
never ran at runtime, so it is left standing for the same reason, and so is one that parses to
an expression holding an array literal: an array literal is legal AutoIt only where a declaration
initializes, which no splice position is.

The splice also refuses wherever a read of `@error` or `@extended` may see the state the
`Execute` stood over: a successful `Call`, `Assign`, and `Eval` all clear both flags (probe9
A17, probe9f A21/A22), and whether a successful `Execute` clears them is unpinned, so a tree
that may read either — by macro, through a computed callee, through another `Execute`'s
payload, or through an include — keeps every wrapper standing rather than guess. The model
cache owns that question; the decode pass over script functions refuses on the same answer.

The accepted behavior change — a runtime error the original `Execute` would have swallowed
becoming fatal where it happens — is bounded by these gates and owned by the Phase 2 plan.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, _replace_in_parent, set_child
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.functions import AUTOIT_FUNCTION_NAMES
from refinery.lib.scripts.au3.model import (
    Au3BinaryExpression,
    Au3Call,
    Au3ExpressionStatement,
    Au3Identifier,
    Au3Script,
    Au3StringLiteral,
    Expression,
)
from refinery.lib.scripts.au3.parser import Au3Parser


class Au3ExecuteFlattening(Transformer):
    """
    Replaces an `Execute` call whose single argument is a string literal with the expression
    that literal parses to, in every position the pinned semantics of `Execute` cover.
    """

    def __init__(self):
        super().__init__()
        self._functions: frozenset[str] = frozenset()
        self._error_state_is_observable = False

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            cache = model_cache(self, node)
            self._functions = cache.scopes.function_names
            self._error_state_is_observable = cache.may_read_error_state
        self.generic_visit(node)
        if not isinstance(node, Au3Call):
            return None
        expression = self._flattenable_expression(node)
        if expression is None:
            return None
        return self._splice(node, expression)

    def _flattenable_expression(self, call: Au3Call) -> Expression | None:
        """
        The expression the call's literal argument names, or `None` where the call is not a
        flattenable `Execute`: a shadowed name, a non-literal or missing argument, a parse
        failure, a bare identifier, an array literal inside the parsed expression, a call
        inside it this pass cannot resolve, or a tree whose error state a read may observe.
        """
        callee = ast.direct_callee(call)
        if callee is None or callee.name != 'execute':
            return None
        if 'execute' in self._functions:
            return None
        if self._error_state_is_observable:
            return None
        if len(call.arguments) != 1:
            return None
        literal = ast.unwrap_parens(call.arguments[0])
        if not isinstance(literal, Au3StringLiteral):
            return None
        expression = Au3Parser(literal.value).parse_expression()
        if expression is None:
            return None
        if isinstance(expression, Au3Identifier):
            return None
        if ast.contains_an_array_literal(expression):
            return None
        if not self._calls_resolve(expression):
            return None
        return expression

    def _calls_resolve(self, expression: Expression) -> bool:
        """
        Whether every call in *expression* is a direct call to a script function or a table
        builtin.
        """
        for node in expression.walk():
            if not isinstance(node, Au3Call):
                continue
            callee = ast.direct_callee(node)
            if callee is None:
                return False
            if callee.name not in self._functions and callee.name not in AUTOIT_FUNCTION_NAMES:
                return False
        return True

    def _splice(self, call: Au3Call, expression: Expression) -> Node | None:
        """
        Put *expression* where *call* stands: directly in expression position, and in statement
        position as an expression statement — unless it is a top-level `=` comparison, which the
        parser would read back as an assignment.
        """
        statement = ast.owning_statement(call)
        if (
            isinstance(statement, Au3ExpressionStatement)
            and ast.unwrap_parens(statement.expression) is call
        ):
            if self._is_top_level_equality(expression):
                return None
            set_child(statement, 'expression', expression)
            self.mark_changed()
            return None
        if not _replace_in_parent(call, expression):
            return None
        self.mark_changed()
        return None

    @staticmethod
    def _is_top_level_equality(expression: Expression) -> bool:
        return (
            isinstance(expression, Au3BinaryExpression)
            and expression.operator == '='
        )
