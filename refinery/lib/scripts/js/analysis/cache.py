"""
A per-run cache of the JavaScript analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the models
only after that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter — instead of each transform rebuilding from scratch on
every pass. The version tracking, invalidation, and transformer-reuse mechanism live in
`refinery.lib.scripts.modelcache.ModelCacheBase`; this module only declares the JavaScript model
slots and their `build_*` wiring.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.analysis.assignment import (
    DefiniteAssignmentModel,
    build_definite_assignment,
)
from refinery.lib.scripts.js.analysis.cfg import ControlFlowModel, build_control_flow_model
from refinery.lib.scripts.js.analysis.dominance import DominanceModel, build_dominance
from refinery.lib.scripts.js.analysis.effects import EffectModel, build_effects
from refinery.lib.scripts.js.analysis.liveness import LivenessModel, build_liveness
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.analysis.reaching import ReachingModel, build_reaching
from refinery.lib.scripts.js.model import JsCallExpression, JsIdentifier, JsNewExpression, JsScript
from refinery.lib.scripts.js.options import (
    host_environment,
    is_host_entrypoint,
    runs_as_module,
)
from refinery.lib.scripts.modelcache import ModelCacheBase


class ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the `refinery.lib.scripts.js.analysis.model.SemanticModel`, the
    `refinery.lib.scripts.js.analysis.effects.EffectModel`, the
    `refinery.lib.scripts.js.analysis.cfg.ControlFlowModel` shared by the
    `refinery.lib.scripts.js.analysis.liveness.LivenessModel` and
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel`, the
    `refinery.lib.scripts.js.analysis.reaching.ReachingModel` layered on them, and the
    `refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel` built under the run's
    execution model, for one root script.
    The memoized models are dropped whenever this root's AST-mutation counter advances past the
    value they were built at, so a transform that reads the cache after an earlier mutation in the
    same pass — even one not yet announced through `refinery.lib.scripts.Transformer.changed` —
    observes models consistent with the current tree. The derived models are always built on the
    current semantic model, so dropping them together keeps them consistent.

    A transform may hold the models for the length of one pass through `pinned`, which suppresses both
    drops until the pass ends. The obligation is the one
    `refinery.lib.scripts.modelcache.ModelCacheBase.pinned` states: the transform's own rewrites must
    never make the models it reads more permissive. A rewrite that only restricts what the models would
    answer makes the held answer the stricter one, so the pass declines where it could have proceeded;
    one that could reveal a fact the held models predate would act on the stale, more permissive answer
    and must not read them pinned. The `--no-pin` differential (`test/conftest.py`) is the mechanical
    check: the whole suite must pass identically with every pin neutralized.
    """

    _SLOTS = (
        '_model',
        '_control_flow',
        '_effects',
        '_liveness',
        '_dominance',
        '_reaching',
        '_assignment',
    )

    root: JsScript
    _model: SemanticModel | None
    _control_flow: ControlFlowModel | None
    _effects: EffectModel | None
    _liveness: LivenessModel | None
    _dominance: DominanceModel | None
    _reaching: ReachingModel | None
    _assignment: DefiniteAssignmentModel | None

    @property
    def model(self) -> SemanticModel:
        return self._lazy('_model', lambda: build_semantic_model(
            self.root,
            host_environment(self.options),
        ))

    @property
    def effects(self) -> EffectModel:
        return self._lazy('_effects', lambda: build_effects(self.model))

    @property
    def control_flow(self) -> ControlFlowModel:
        return self._lazy('_control_flow', lambda: build_control_flow_model(self.root))

    @property
    def liveness(self) -> LivenessModel:
        return self._lazy('_liveness', lambda: build_liveness(self.model, self.control_flow))

    @property
    def dominance(self) -> DominanceModel:
        return self._lazy('_dominance', lambda: build_dominance(self.model, self.control_flow))

    @property
    def reaching(self) -> ReachingModel:
        return self._lazy('_reaching', lambda: build_reaching(self.dominance, self.effects))

    @property
    def assignment(self) -> DefiniteAssignmentModel:
        """
        The `refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel` for this root,
        built under the execution model and the host entrypoints the run's options select. It is the
        one establishment answer for implicit-global reads: every consumer in a run reads this slot,
        so no tree is ever judged under two establishment answers at once.
        """
        return self._lazy('_assignment', lambda: build_definite_assignment(
            self.model,
            self.control_flow,
            module_scope=runs_as_module(self.options, self.root),
            host_entrypoint=lambda name: is_host_entrypoint(self.options, name),
        ))

    def call_established(self, call: JsCallExpression | JsNewExpression) -> bool:
        """
        Whether *call* may be cleared by the purity oracle at all: its callee is a trusted
        intrinsic, or a local function whose definition reaches the call, so a call textually before
        a not-yet-established function keeps its runtime throw. The callee's summary may also defer
        outer `let`/`const`/`class` bindings its body reads (`EffectSummary.dead_zone_reads`); the
        call keeps its throw unless each such binding's declaration is guaranteed to have run first,
        judged by the same dominance model. This is the one composition of the effect and dominance
        models every consumer shares, so no pass can pair a purity verdict with a weaker
        establishment reading than another.
        """
        return self.effects.call_clearable(
            call,
            lambda func: self.dominance.established_before(func, call),
            lambda binding: self.dominance.past_dead_zone(binding, call),
        )

    def read_established(self, node: JsIdentifier) -> bool:
        """
        Whether reading *node* cannot be the evaluation that raises a `ReferenceError`: the one
        composition of the establishment and dominance models every discarding context shares, so no
        pass drops a read another would keep. True when a creating write has certainly completed
        (`refinery.lib.scripts.js.analysis.assignment.DefiniteAssignmentModel.read_established`, the
        implicit-global case), or when *node* reads a `let`/`const`/`class` binding whose
        declaration is guaranteed to have run first, ending its temporal dead zone
        (`refinery.lib.scripts.js.analysis.dominance.DominanceModel.runs_before` over the binding's
        declarations). A lexical read the ordering cannot vouch for — one that may run in the dead
        zone, or one whose binding carries no declaration site to order against — is not
        established, so the sweep keeps the store and the throw with it. This generalizes the
        write-only proof the consumers threaded before: every context that dropped a read the moment
        a creating write reached it now keeps a lexical read the same context would move out of its
        dead zone.
        """
        binding = self.model.resolve(node)
        if self.assignment.definitely_assigned_at(binding, node):
            return True
        if binding is None or not binding.is_lexical:
            return False
        return self.dominance.past_dead_zone(binding, node)


def model_cache(transformer: Transformer, root: JsScript) -> ModelCache:
    """
    The pipeline's shared `ModelCache` for *root* when one is attached to *transformer* and built
    over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse within
    its single-pass lifetime. See `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return ModelCache.for_transformer(transformer, root)
