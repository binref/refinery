"""
Constant propagation: replacing a variable read whose value the walk in
`refinery.lib.scripts.au3.analysis.propagation` proves with the literal that spells it.

The model is keyed by occurrence, so a substitution needs no position reasoning of its own: every
recorded read is one a replacement may stand in for, and the target positions the plan guards —
declaration variables, assignment targets, loop variables — are exactly the ones the walk never
records. The literal itself still faces the render gates in
`refinery.lib.scripts.au3.analysis.values`, which refuse a string no literal spells and a binary
whose builtin a script function shadows.

Two values refuse positions the render gates cannot see. An array spells only as an array
literal, which AutoIt accepts only where a declaration initializes — so an array replaces a read
only inside a declarator's initializer, through array literals alone. A binary spells as a call,
which an array literal initializer may not accept — so a binary never replaces a read inside one.
The model is held from the root visit on: replacing a read with its provable value changes no
value the walk learned, so the pass's own edits cannot make its snapshot wrong.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.propagation import Au3PropagationModel
from refinery.lib.scripts.au3.analysis.values import render_at
from refinery.lib.scripts.au3.model import (
    Au3Script,
    Au3Variable,
)


class Au3ConstantPropagation(Transformer):
    """
    Replaces a variable read the propagation model proves a value for with the literal of that
    value, wherever that literal is legal in the position the read occupies.
    """

    def __init__(self):
        super().__init__()
        self._model = Au3PropagationModel({}, {}, {})
        self._functions: frozenset[str] = frozenset()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            cache = model_cache(self, node)
            self._model = cache.propagation
            self._functions = cache.scopes.function_names
        self.generic_visit(node)
        if not isinstance(node, Au3Variable):
            return None
        value = self._model.value_at(node)
        if value is None:
            return None
        return render_at(node, value, self._functions)
