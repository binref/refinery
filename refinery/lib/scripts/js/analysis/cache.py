"""
A per-run cache of the JavaScript analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the models
only after that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter — instead of each transform rebuilding from scratch on
every pass.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer, tree_version
from refinery.lib.scripts.js.analysis.dominance import DominanceModel, build_dominance
from refinery.lib.scripts.js.analysis.effects import EffectModel, build_effects
from refinery.lib.scripts.js.analysis.liveness import LivenessModel, build_liveness
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.model import JsScript


class ModelCache:
    """
    Lazily builds and memoizes the `refinery.lib.scripts.js.analysis.model.SemanticModel` and the
    `refinery.lib.scripts.js.analysis.effects.EffectModel` and
    `refinery.lib.scripts.js.analysis.liveness.LivenessModel` and
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel` layered on it, for one root script.
    The memoized models are dropped whenever this root's AST-mutation counter
    (`refinery.lib.scripts.tree_version`) advances past the value they were built at, so a transform
    that reads the cache after an earlier mutation in the same pass — even one not yet announced
    through `refinery.lib.scripts.Transformer.changed` — observes models consistent with the current
    tree. `invalidate` forces the same drop explicitly. The derived models are always built on the
    current semantic model, so dropping them together keeps them consistent.
    """

    def __init__(self, root: JsScript):
        self.root = root
        self._version = tree_version(root)
        self._model: SemanticModel | None = None
        self._effects: EffectModel | None = None
        self._liveness: LivenessModel | None = None
        self._dominance: DominanceModel | None = None

    def invalidate(self) -> None:
        self._model = None
        self._effects = None
        self._liveness = None
        self._dominance = None

    def _ensure_fresh(self) -> None:
        version = tree_version(self.root)
        if version != self._version:
            self._version = version
            self.invalidate()

    @property
    def model(self) -> SemanticModel:
        self._ensure_fresh()
        if self._model is None:
            self._model = build_semantic_model(self.root)
        return self._model

    @property
    def effects(self) -> EffectModel:
        self._ensure_fresh()
        if self._effects is None:
            self._effects = build_effects(self.model)
        return self._effects

    @property
    def liveness(self) -> LivenessModel:
        self._ensure_fresh()
        if self._liveness is None:
            self._liveness = build_liveness(self.model)
        return self._liveness

    @property
    def dominance(self) -> DominanceModel:
        self._ensure_fresh()
        if self._dominance is None:
            self._dominance = build_dominance(self.model)
        return self._dominance


def model_cache(transformer: Transformer, root: JsScript) -> ModelCache:
    """
    The pipeline's shared `ModelCache` for *root* when one is attached to *transformer* and built over
    that same root, otherwise a fresh single-use cache. This lets a transform consume the shared models
    inside the pipeline yet still run standalone — in tests, or outside the pipeline — with no change in
    behavior, since a standalone transform simply builds its own models on demand as before.
    """
    cache = transformer.models
    if isinstance(cache, ModelCache) and cache.root is root:
        return cache
    return ModelCache(root)
