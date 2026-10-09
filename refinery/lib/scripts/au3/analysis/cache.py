"""
A per-run cache of the AutoIt3 analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the models
only after that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter. The version tracking, invalidation, and
transformer-reuse mechanism live in `refinery.lib.scripts.modelcache.ModelCacheBase`; this module
only declares the model slots and their build wiring.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3.analysis.aliases import Au3AliasModel, build_alias_model
from refinery.lib.scripts.au3.analysis.propagation import (
    Au3PropagationModel,
    build_propagation_model,
)
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, build_scope_model
from refinery.lib.scripts.au3.analysis.usage import Au3UsageModel, build_usage_model
from refinery.lib.scripts.au3.model import Au3Script
from refinery.lib.scripts.modelcache import ModelCacheBase


class Au3ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the analysis models for one root script — the scope model the
    transforms ask which storage a write targets and which names are constant, the alias map the
    indirection rewrite reads, the propagation model the constant substitution reads, and the
    usage model the dead-code elimination reads — each dropped, together, whenever this root's
    tree changes.
    """

    _SLOTS = (
        '_scopes',
        '_aliases',
        '_propagation',
        '_usage',
    )

    root: Au3Script
    _scopes: Au3ScopeModel | None
    _aliases: Au3AliasModel | None
    _propagation: Au3PropagationModel | None
    _usage: Au3UsageModel | None

    @property
    def scopes(self) -> Au3ScopeModel:
        return self._lazy('_scopes', lambda: build_scope_model(self.root))

    @property
    def aliases(self) -> Au3AliasModel:
        """
        The per-scope map of variables that provably name one function, cut by every name a
        rebinding write — an `Assign`, a code-running `Execute`, or a script function call — may
        cost, which the propagation summaries feed.
        """
        return self._lazy('_aliases', lambda: build_alias_model(
            self.root, self.scopes, self.propagation.summaries))

    @property
    def propagation(self) -> Au3PropagationModel:
        """
        The value at every variable read and the may-write summary of every script function, over
        the scope model's binding answers.
        """
        return self._lazy('_propagation', lambda: build_propagation_model(self.root, self.scopes))

    @property
    def usage(self) -> Au3UsageModel:
        """
        What the script does with its names — the call counts, purity, channels, spellings, and
        storage bindings the dead-code elimination asks — over the scope model's bindings and the
        propagation walk's may-write summaries.
        """
        return self._lazy('_usage', lambda: build_usage_model(
            self.root, self.scopes, self.propagation.summaries))


def model_cache(transformer: Transformer, root: Node) -> Au3ModelCache:
    """
    The pipeline's shared `Au3ModelCache` for *root* when one is attached to *transformer* and
    built over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse
    within its single-pass lifetime. See
    `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return Au3ModelCache.for_transformer(transformer, root)
