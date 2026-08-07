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
from refinery.lib.scripts.js.analysis.cfg import ControlFlowModel, build_control_flow_model
from refinery.lib.scripts.js.analysis.dominance import DominanceModel, build_dominance
from refinery.lib.scripts.js.analysis.effects import EffectModel, build_effects
from refinery.lib.scripts.js.analysis.liveness import LivenessModel, build_liveness
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.analysis.reaching import ReachingModel, build_reaching
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.modelcache import ModelCacheBase


class ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the `refinery.lib.scripts.js.analysis.model.SemanticModel`, the
    `refinery.lib.scripts.js.analysis.effects.EffectModel`, the
    `refinery.lib.scripts.js.analysis.cfg.ControlFlowModel` shared by the
    `refinery.lib.scripts.js.analysis.liveness.LivenessModel` and
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel`, and the
    `refinery.lib.scripts.js.analysis.reaching.ReachingModel` layered on them, for one root script.
    The memoized models are dropped whenever this root's AST-mutation counter advances past the
    value they were built at, so a transform that reads the cache after an earlier mutation in the
    same pass — even one not yet announced through `refinery.lib.scripts.Transformer.changed` —
    observes models consistent with the current tree. The derived models are always built on the
    current semantic model, so dropping them together keeps them consistent.

    A transform whose own rewrites cannot change the answers it reads may hold the models for the length
    of one pass through `pinned`, which suppresses both drops until the pass ends. See that method for
    the obligation this places on the caller.
    """

    _SLOTS = ('_model', '_control_flow', '_effects', '_liveness', '_dominance', '_reaching')

    root: JsScript
    _model: SemanticModel | None
    _control_flow: ControlFlowModel | None
    _effects: EffectModel | None
    _liveness: LivenessModel | None
    _dominance: DominanceModel | None
    _reaching: ReachingModel | None

    @property
    def model(self) -> SemanticModel:
        return self._lazy('_model', lambda: build_semantic_model(self.root))

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


def model_cache(transformer: Transformer, root: JsScript) -> ModelCache:
    """
    The pipeline's shared `ModelCache` for *root* when one is attached to *transformer* and built
    over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse within
    its single-pass lifetime. See `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return ModelCache.for_transformer(transformer, root)
