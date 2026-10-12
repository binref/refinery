"""
Constant propagation: replacing a variable read whose value the walk in
`refinery.lib.scripts.au3.analysis.propagation` proves with the literal that spells it.

The model is keyed by occurrence, so a substitution needs no position reasoning of its own: every
recorded read is one a replacement may stand in for, and the target positions the plan guards —
declaration variables, assignment targets, loop variables — are exactly the ones the walk never
records. The literal itself still faces the render gates in
`refinery.lib.scripts.au3.analysis.values`, which refuse a string no literal spells, a binary
whose builtin a script function shadows, and a render deeper than the renderer's bound: a chain
that deep would crash the recursive emitter every pass that prints the pipeline's own product.

Two values refuse positions the render gates cannot see. An array spells only as an array
literal, which AutoIt accepts only where a declaration initializes — so an array replaces a read
only inside a declarator's initializer, through array literals alone. A binary spells as a call,
which an array literal initializer may not accept — so a binary never replaces a read inside one.
The model is held from the root visit on: replacing a read with its provable value changes no
value the walk learned, so the pass's own edits cannot make its snapshot wrong.

Each definition — a name inside the scope that binds it — owns a growth budget: every read of it
may charge the rendered length of its replacement minus the spelling the read already occupies,
and a definition whose charges exceed `max(_MIN_GROWTH_BUDGET, _GROWTH_RATIO × script length)`
keeps its reads, because a payload spelled at every read multiplies the tree where the definition
it comes from already spells it once. No credit is given for a definition that stops being read —
removing the definition is the dead code elimination's to decide, not this pass's.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.propagation import Au3PropagationModel
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    render_at,
    render_literal,
)
from refinery.lib.scripts.au3.model import (
    Au3FunctionDeclaration,
    Au3Script,
    Au3Variable,
)
from refinery.lib.scripts.au3.synth import Au3Synthesizer

#: The share of the script's own length a single definition's inlined reads may add.
_GROWTH_RATIO = 0.2

#: The growth every definition is granted even in a script too small for the ratio to fund it.
_MIN_GROWTH_BUDGET = 256


class Au3ConstantPropagation(Transformer):
    """
    Replaces a variable read the propagation model proves a value for with the literal of that
    value, wherever that literal is legal in the position the read occupies and small enough to
    install.
    """

    def __init__(self):
        super().__init__()
        self._model = Au3PropagationModel({}, {}, {})
        self._functions: frozenset[str] = frozenset()
        self._blocked: frozenset[tuple[Au3FunctionDeclaration | None, str]] = frozenset()
        self._synthesizer = Au3Synthesizer()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            cache = model_cache(self, node)
            self._model = cache.propagation
            self._functions = cache.scopes.function_names
            self._blocked = self._names_past_budget(node)
        self.generic_visit(node)
        if not isinstance(node, Au3Variable):
            return None
        if (ast.enclosing_function(node), node.name) in self._blocked:
            return None
        value = self._model.value_at(node)
        if value is None:
            return None
        return render_at(node, value, self._functions)

    def _names_past_budget(
        self,
        root: Au3Script,
    ) -> frozenset[tuple[Au3FunctionDeclaration | None, str]]:
        """
        The definitions — a name inside the scope that binds it — whose recorded reads, each
        charged the rendered length of its replacement minus the length the read already spells,
        together exceed their budget of `max(_MIN_GROWTH_BUDGET, _GROWTH_RATIO × script length)`.
        """
        budget = max(
            _MIN_GROWTH_BUDGET,
            int(len(self._synthesizer.convert(root)) * _GROWTH_RATIO),
        )
        charges: dict[tuple[Au3FunctionDeclaration | None, str], int] = {}
        sizes: dict[Au3Value, int | None] = {}
        for occurrence, value in self._model.values.items():
            if value.kind is Kind.ARRAY and not ast.in_declaration_initializer(occurrence):
                continue
            if value not in sizes:
                rendered = render_literal(value, self._functions)
                sizes[value] = (
                    None if rendered is None else len(self._synthesizer.convert(rendered))
                )
            length = sizes[value]
            if length is None:
                continue
            key = (ast.enclosing_function(occurrence), occurrence.name)
            charges[key] = (
                charges.get(key, 0)
                + max(0, length - len(occurrence.raw))
            )
        return frozenset(key for key, total in charges.items() if total > budget)
