"""
A per-run cache of the JavaScript analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the models only
after a transform changes the tree (signalled through `refinery.lib.scripts.Transformer.changed`),
instead of each transform rebuilding from scratch on every pass.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.analysis.effects import EffectModel, build_effects
from refinery.lib.scripts.js.analysis.liveness import LivenessModel, build_liveness
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.model import JsScript


class ModelCache:
    """
    Lazily builds and memoizes the `refinery.lib.scripts.js.analysis.model.SemanticModel` and the
    `refinery.lib.scripts.js.analysis.effects.EffectModel` and
    `refinery.lib.scripts.js.analysis.liveness.LivenessModel` layered on it, for one root script.
    `invalidate` drops the memoized models so the next access rebuilds them; the effect and liveness
    models are always built on the current semantic model, so a single `invalidate` keeps the three
    consistent.
    """

    def __init__(self, root: JsScript):
        self.root = root
        self._model: SemanticModel | None = None
        self._effects: EffectModel | None = None
        self._liveness: LivenessModel | None = None

    def invalidate(self) -> None:
        self._model = None
        self._effects = None
        self._liveness = None

    @property
    def model(self) -> SemanticModel:
        if self._model is None:
            self._model = build_semantic_model(self.root)
        return self._model

    @property
    def effects(self) -> EffectModel:
        if self._effects is None:
            self._effects = build_effects(self.model)
        return self._effects

    @property
    def liveness(self) -> LivenessModel:
        if self._liveness is None:
            self._liveness = build_liveness(self.model)
        return self._liveness


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
