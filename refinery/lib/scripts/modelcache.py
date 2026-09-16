"""
Shared machinery for the per-run analysis model caches. A language builds one cache over the script
being transformed and shares it across every transform in a run, rebuilding its models only after
that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter — instead of each transform rebuilding from scratch on
every pass.

`refinery.lib.scripts.js.analysis.cache.ModelCache` and
`refinery.lib.scripts.ps1.analysis.cache.Ps1ModelCache` are the concrete caches: each subclass
declares its typed model slots in `_SLOTS` and exposes one lazy property per model built through
`_lazy`, and inherits the version tracking, edge-triggered invalidation, the `ModelCacheBase.pinned`
suspension of that invalidation, and the transformer-reuse stash from here. Keeping the mechanism in
one place is why a new language's cache cannot drift from the invalidation contract the base
establishes.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Generator, TypeVar

from refinery.lib.scripts import Node, Transformer, tree_root, tree_version

_T = TypeVar('_T')
_C = TypeVar('_C', bound='ModelCacheBase')


class ModelCacheBase:
    """
    The version-tracking, invalidation, and reuse mechanism shared by every language's model cache.
    A subclass lists its lazily-built model attributes in `_SLOTS`, reads each through `_lazy`, and
    re-declares `root` at the node type it builds its models from. The base nulls the slots on
    construction, drops them together whenever this root's AST-mutation counter
    (`refinery.lib.scripts.tree_version`) advances past the value they were built at, and rebuilds
    on next access. Dropping the models together keeps a derived model consistent with the base
    model it was layered on. Because the base owns the whole mechanism, `invalidate` — the one
    method the `refinery.lib.scripts.AnalysisCache` protocol requires — is defined once, not per
    language. `pinned` suspends that mechanism for the length of a block, and lives here for the
    same reason: it is the one thing that can hold a model across a mutation, so a language cache
    cannot be allowed to grow its own version of it.

    The run's caller-supplied `options` are held here rather than per language, because a model
    built differently under them is built once per cache and `for_transformer` is the one place a
    cache is created without a caller naming them. Taking them off the transformer there is what
    keeps the two from disagreeing: the pipeline sets the same object on both, and a cache that
    defaulted its own would answer under a configuration the transformer beside it does not hold.
    """

    _SLOTS: tuple[str, ...] = ()

    # The slots whose build reads the live tree (`root`), not only already-built base models — the
    # guard's refusal set. A model derived from held bases is safe to build late: it reads those
    # bases and yields the entry-version answer. One of these, built late, layers a tree-reading
    # model over held bases, so only these are refused. `None` from a cache that has not classified
    # its slots reads as the whole slot set — the conservative default refusing any late fill. It is
    # the complete backstop: every build-time tree reader, whether or not a pinned pass reads it.
    # `warm` builds only the `_WARM_SLOTS` subset the pinned passes actually read.
    _ROOT_SLOTS: tuple[str, ...] | None = None

    # The subset of `_ROOT_SLOTS` that `warm` builds at a pin's entry: the tree-reading models a
    # pinned pass reads, held from entry so no read of one falls past an edit. A tree reader outside
    # this subset is not pre-built — a pinned pass that reads one late trips the guard rather than
    # silently layering it over the moved tree. `None` falls back to the full `_ROOT_SLOTS`.
    _WARM_SLOTS: tuple[str, ...] | None = None

    # A class attribute rather than an assignment in `__init__`, because `__init__` calls
    # `invalidate`, which reads this: an instance attribute would not exist yet at that point.
    _pins = 0
    _pin_entry: int | None = None
    _fill_slot: str | None = None

    root: Node
    options: object | None

    def __init__(self, root: Node, options: object | None = None):
        # Normalized here and not only in `for_transformer`, because the version counter a mutation
        # advances is the one keyed on the tree: a cache holding a nested node as its root would
        # read a counter nothing ever bumps and never invalidate.
        root = tree_root(root)
        self.root = root
        self.options = options
        self._version = tree_version(root)
        self.invalidate()

    def invalidate(self) -> None:
        if self._pins:
            return
        for slot in self._SLOTS:
            setattr(self, slot, None)

    @contextmanager
    def pinned(self: _C) -> Generator[_C, None, None]:
        """
        Hold the models for the duration of the block: each is still built on first use, and
        afterwards the memoized instance is served even as the tree changes underneath it. On exit
        the pin is released and the models are dropped, so no stale model outlives the block.

        This exists because a transform that both rewrites the tree and consults a model on every
        rewrite otherwise rebuilds the model per rewrite — the cost is the product of the two, and
        it dominated deobfuscation runtime. Suppression is counted so that an inner pin cannot
        release an outer one.

        **The caller must know that its own rewrites cannot make the models it reads more
        permissive.** That is a property of the specific transform, not of pinning: a pass that
        could reveal a fact its held model predates would act on the stale, more permissive answer.
        A pass whose rewrites only ever make facts *more* restrictive is safe, because it then
        declines where it could have proceeded.

        The pin also records the tree version it was entered at, and the outermost exit raises when
        a root-reading model was first built after the tree had moved past that version. Such a model
        reads the live tree, so building it there layers it over base models the pin holds from the
        earlier tree — the one state no unpinned run builds (there, a version change drops every slot
        together). A model derived only from held bases is not such a case: built late, it reads those
        bases and yields the entry answer. A pass that trips this reads a root-reading model at a
        point its own edits ran ahead of, and fixing that pass — or `warm`-ing it at entry — is the
        response.
        """
        self._ensure_fresh()
        if not self._pins:
            self._pin_entry = self._version
        self._pins += 1
        block_raised = False
        try:
            yield self
        except BaseException:
            block_raised = True
            raise
        finally:
            self._pins -= 1
            if not self._pins:
                self._version = tree_version(self.root)
                offender = self._fill_slot
                self._pin_entry = None
                self._fill_slot = None
                self.invalidate()
                if not block_raised and offender is not None:
                    raise RuntimeError(
                        F'the root-reading model in slot {offender!r} was built at a tree version'
                        ' past the one the pin was entered at, layering it over models the pin held'
                        ' from an earlier tree'
                    )

    def _ensure_fresh(self) -> None:
        version = tree_version(self.root)
        if version != self._version:
            self._version = version
            self.invalidate()

    def _root_slots(self) -> tuple[str, ...]:
        return self._SLOTS if self._ROOT_SLOTS is None else self._ROOT_SLOTS

    def _warm_slots(self) -> tuple[str, ...]:
        return self._root_slots() if self._WARM_SLOTS is None else self._WARM_SLOTS

    def warm(self) -> None:
        """
        Build the tree-reading models a pinned block reads, at the current tree version. A block
        that both edits the tree and reads models calls this at its entry, so no such model is first
        built after an edit has moved the tree — the one state the pin's exit refuses. A model
        derived only from held bases needs no warming: built late, it reads those bases and yields
        the entry answer. The set is the cache's `_WARM_SLOTS`, declared once beside the model
        definitions, so a call site cannot drift from the models it must hold the way a hand-copied
        pre-build list did. A tree reader the pinned passes do not read is left out of it and out of
        this build; the guard still refuses it if some pass reads it late, so leaving it out of the
        warm set cannot go silently wrong.

        This holds only for models that read the tree at build. A model that reads the tree lazily
        at query time — its walk happening on first use, not on construction — is not made
        consistent by warming its slot, and a pass that queries such a model across its edits owns
        that consistency itself.
        """
        for slot in self._warm_slots():
            getattr(self, slot[1:])

    def _lazy(self, slot: str, build: Callable[[], _T]) -> _T:
        """
        The value memoized in *slot*, built through *build* on first access after construction or
        an invalidation. Every model property routes through here so freshness is checked and the
        slot is filled by the one accessor primitive rather than a hand-copied check-build-store
        per model. The first root-reading slot built while a pin holds the cache and the tree has
        already moved past the pin's entry is noted, for the refusal `pinned` performs on the
        outermost exit.
        """
        self._ensure_fresh()
        value = getattr(self, slot)
        if value is None:
            value = build()
            if (
                self._pins
                and self._fill_slot is None
                and self._pin_entry is not None
                and self._version > self._pin_entry
                and slot in self._root_slots()
            ):
                self._fill_slot = slot
            setattr(self, slot, value)
        return value

    @classmethod
    def for_transformer(cls: type[_C], transformer: Transformer, root: Node) -> _C:
        """
        The pipeline's shared cache for *root* when one of this exact class is attached to
        *transformer* and built over that same root, otherwise a fresh cache — stashed back onto
        *transformer* so later lookups within its single-pass lifetime reuse it instead of
        rebuilding the models per call. A transform still runs standalone (in tests, or outside the
        pipeline); freshness stays governed by the tree version, and a standalone mutation
        invalidates the stashed cache exactly as it would the shared one.

        *root* is normalized to the tree it belongs to — by the constructor, so the two entry points
        cannot disagree — and a transform that visits a nested body therefore means the same cache
        as one that visits the script. Skipping that leaves a whole-script model derived from a
        subtree: a leak sitting outside it becomes invisible and the world reads closed, which is
        the one direction that deletes code.

        A fresh cache takes the options the transformer is holding, which is the run's own
        configuration wherever the pipeline set it. Defaulting them here instead would let one
        transform in a run read a model built under a configuration the run never asked for, and
        stash that cache back for every transform after it.
        """
        root = tree_root(root)
        cache = transformer.models
        if isinstance(cache, cls) and cache.root is root:
            return cache
        cache = cls(root, transformer.options)
        transformer.models = cache
        return cache
