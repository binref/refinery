"""
The Phase 3 transform: what a script-defined decoder function returns becomes the literal its
call site stands for. The interpreter runs the call over the value domain; the globals it may
read are the ones the propagation walk proved at that call site, and the gate that admits the
function is the walk's may-write summary, so a call this transform rewrites changed nothing the
walk learned and the models of the pass stay sound.

A call qualifies when its direct callee is a script function, every argument is a literal the
value domain reads, and the call stands where an expression belongs — a call that is itself the
whole statement produces no value, and a bare literal is not a statement, so that call stays for
the dead-code phase to remove. The visit is bottom-up, so a decoder fed by another decoder —
`nvb(sjw("…"), 8)` — resolves in one pass: the inner call is replaced before the outer one is
asked.

The literal it installs faces the same render gates the propagation pass obeys, including the
depth bound: a decoder whose result spells as a chain deeper than the recursive emitter prints
leaves the call standing.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.interpreter import Au3Interpreter
from refinery.lib.scripts.au3.analysis.propagation import Au3PropagationModel
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel
from refinery.lib.scripts.au3.analysis.values import literal_value, render_at
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3ExpressionStatement,
    Au3Script,
)


class Au3FunctionEvaluation(Transformer):
    """
    Replaces a call to a script function the interpreter runs with the literal of its result,
    wherever the position of the call accepts that literal.
    """

    def __init__(self):
        super().__init__()
        self._scopes: Au3ScopeModel | None = None
        self._propagation: Au3PropagationModel | None = None
        self._interpreter: Au3Interpreter | None = None

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            cache = model_cache(self, node)
            self._scopes = cache.scopes
            self._propagation = cache.propagation
            self._interpreter = Au3Interpreter(cache.scopes, cache.propagation.summaries)
        self.generic_visit(node)
        if not isinstance(node, Au3Call):
            return None
        if self._scopes is None or self._propagation is None or self._interpreter is None:
            return None
        statement = ast.owning_statement(node)
        if (
            isinstance(statement, Au3ExpressionStatement)
            and ast.unwrap_parens(statement.expression) is node
        ):
            return None
        callee = ast.direct_callee(node)
        if callee is None:
            return None
        function = self._scopes.functions.get(callee.name)
        if function is None:
            return None
        arguments = []
        for argument in node.arguments:
            value = literal_value(argument, self._scopes.function_names)
            if value is None:
                return None
            arguments.append(value)
        result = self._interpreter.call(
            function, arguments, self._propagation.entry_globals(node))
        if result is None:
            return None
        return render_at(node, result, self._scopes.function_names)
