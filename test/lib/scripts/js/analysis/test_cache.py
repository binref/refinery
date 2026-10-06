from __future__ import annotations

import gc

from contextlib import contextmanager

from test import TestBase, a_property_of_the_batch_itself, a_property_of_the_pin_itself

from test.lib.scripts.js.analysis.differential import deobfuscate_source
from test.lib.scripts.js.analysis.jsgen import generate

import refinery.lib.scripts.js.analysis.cache as cache_module
from refinery.lib.scripts import Node, Transformer, _remove_from_parent, canonical, set_body, tree_version
from refinery.lib.scripts.analysis.cfg import ElementLocator
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
    JsIdentifier,
    JsVariableDeclaration,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.pipeline import PipelineObserver


@contextmanager
def _no_pin(self):
    """
    A pin that holds nothing, standing in for the unpinned cache in a comparison.
    """
    yield self


def _transform_root_builds(transform: type[Transformer], source: str) -> tuple[int, str]:
    """
    How many times the script's own semantic model is built during one pass of *transform*, with the
    resulting script. Builds over freshly parsed fragments are excluded by identity of the root node.
    """
    script = JsParser(source).parse()
    count = {'n': 0}
    real_model = cache_module.build_semantic_model

    def counting_model(root, *args, **kwargs):
        if root is script:
            count['n'] += 1
        return real_model(root, *args, **kwargs)

    cache_module.build_semantic_model = counting_model
    try:
        transform().visit(script)
    finally:
        cache_module.build_semantic_model = real_model
    return count['n'], JsSynthesizer().convert(script)


class TestModelCache(TestBase):

    @staticmethod
    def _script(source: str):
        return JsParser(source).parse()

    @staticmethod
    def _first_declaration(script) -> JsVariableDeclaration:
        return next(
            stmt for stmt in script.body if isinstance(stmt, JsVariableDeclaration)
        )

    def test_model_is_memoized_while_the_tree_is_unchanged(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.model
        self.assertIs(cache.model, first)

    def test_mutating_the_cached_tree_rebuilds_the_model(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        first = cache.model
        _remove_from_parent(self._first_declaration(script))
        self.assertIsNot(cache.model, first)

    def test_mutating_an_unrelated_tree_keeps_the_cached_model(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.model
        unrelated = self._script('var c = 3; var d = 4;')
        _remove_from_parent(self._first_declaration(unrelated))
        self.assertIs(cache.model, first)

    def test_control_flow_is_memoized_while_the_tree_is_unchanged(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        first = cache.control_flow
        self.assertIs(cache.control_flow, first)

    def test_mutating_the_cached_tree_rebuilds_the_control_flow(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        first = cache.control_flow
        _remove_from_parent(self._first_declaration(script))
        self.assertIsNot(cache.control_flow, first)

    def test_shared_control_flow_does_not_change_dominance_or_liveness(self):
        """
        The dominance and liveness models the cache builds share its one `ControlFlowModel`; their
        answers must match models built independently over their own graphs.
        """
        script = self._script(
            'var a = 1; function f(){ var x; x = 1; x = 2; return x; } if (a) { g(a); } f();')
        cache = ModelCache(script)
        model = cache.model
        dom_fresh = build_dominance(model)
        live_fresh = build_liveness(model)
        idents = [n for n in script.walk_in_order() if isinstance(n, JsIdentifier)]
        for p in idents:
            for q in idents:
                self.assertEqual(cache.dominance.dominates(p, q), dom_fresh.dominates(p, q))
        self.assertEqual(
            [id(n) for n in cache.liveness.dead_stores()],
            [id(n) for n in live_fresh.dead_stores()],
        )


@a_property_of_the_pin_itself
class TestPinnedModels(TestBase):
    """
    A pinned cache holds its models across tree mutations for the length of a block, which is what stops a
    transform that consults a model on every rewrite from rebuilding it on every rewrite. The pin must not
    outlive its block: a model served after the block would be stale for consumers that assert freshness.
    """

    @staticmethod
    def _script(source: str):
        return JsParser(source).parse()

    @staticmethod
    def _first_declaration(script) -> JsVariableDeclaration:
        return next(stmt for stmt in script.body if isinstance(stmt, JsVariableDeclaration))

    def test_pinned_model_survives_a_mutation(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            first = cache.model
            _remove_from_parent(self._first_declaration(script))
            self.assertIs(cache.model, first)

    def test_pinned_model_survives_an_explicit_invalidation(self):
        """
        `Transformer.changed` invalidates through this method rather than the version counter — the
        one channel a raw write has — so a pin that guarded only the version would miss every such
        announcement.
        """
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            first = cache.model
            cache.invalidate()
            self.assertIs(cache.model, first)

    def test_model_is_rebuilt_after_the_pin_is_released(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            first = cache.model
            _remove_from_parent(self._first_declaration(script))
        self.assertIsNot(cache.model, first)

    def test_a_pin_over_an_unchanged_tree_keeps_its_models_past_the_block(self):
        """
        A model is a function of the tree alone, so a block that leaves the tree as it found it
        leaves nothing for a rebuild to change; dropping the models there charges the next pass a
        full rebuild over a tree the cache has already analysed.
        """
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        held = None
        with cache.pinned():
            held = cache.model
        self.assertIs(cache.model, held)

    def test_an_invalidation_requested_under_a_pin_drops_the_models_on_exit(self):
        """
        The announcement is the only change channel a raw write has and it never moves the version
        counter, so an exit that read the counter alone would keep the models past the write.
        """
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        held = None
        with cache.pinned():
            held = cache.model
            cache.invalidate()
        self.assertIsNot(cache.model, held)

    def test_an_invalidation_requested_under_an_inner_pin_drops_the_models_at_the_outermost_exit(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        held = None
        with cache.pinned():
            held = cache.model
            with cache.pinned():
                cache.invalidate()
            self.assertIs(cache.model, held)
        self.assertIsNot(cache.model, held)

    def test_a_pin_that_raises_over_an_unchanged_tree_keeps_its_models(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        held = None
        with self.assertRaises(ValueError):
            with cache.pinned():
                held = cache.model
                raise ValueError
        self.assertIs(cache.model, held)

    def test_model_is_rebuilt_after_a_pin_that_raises(self):
        """
        A pin leaked by an exception would serve a stale model to every later transform in the run.
        """
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        first = None
        with self.assertRaises(ValueError):
            with cache.pinned():
                first = cache.model
                _remove_from_parent(self._first_declaration(script))
                raise ValueError
        self.assertIsNot(cache.model, first)

    def test_nested_pins_release_only_with_the_outermost(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            first = cache.model
            with cache.pinned():
                pass
            _remove_from_parent(self._first_declaration(script))
            self.assertIs(cache.model, first)
        self.assertIsNot(cache.model, first)

    def test_pinning_builds_nothing_on_entry(self):
        """
        Entering the pin must stay lazy: a transform that consults no model on a given script — the
        reflective inliner on a script with no reflective site — must still build none.
        """
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        with cache.pinned():
            self.assertIsNone(cache._model)

    def test_pinned_model_is_fresh_at_entry_after_an_earlier_mutation(self):
        """
        A mutation before the block must not be held over into it; the pin freezes the tree as it is when
        the block opens, not as it was at some earlier read.
        """
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        stale = cache.model
        _remove_from_parent(self._first_declaration(script))
        with cache.pinned():
            self.assertIsNot(cache.model, stale)

    def test_derived_models_are_held_together(self):
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            held = (cache.model, cache.effects, cache.control_flow, cache.dominance)
            _remove_from_parent(self._first_declaration(script))
            self.assertEqual(
                held, (cache.model, cache.effects, cache.control_flow, cache.dominance))

    def test_a_root_reading_model_first_built_after_an_edit_is_refused_on_exit(self):
        """
        A root-reading model first built after the tree has moved under a pin reads the moved tree and
        is layered over held base models from an earlier tree — the state no unpinned run builds, since
        there a version change drops every slot together. The exit refuses it, and the cache the
        refusal leaves behind serves a model of the current tree, not the layered one.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                held = cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow
        self.assertIsNot(cache.model, held)

    def test_a_pure_derived_model_first_built_after_an_edit_is_not_refused(self):
        """
        A model that builds purely from held base models — `dominance`, from the held `model`,
        `control_flow` and `intrinsic_writes` — reads those bases, not the tree, so building it
        after the tree has moved under a pin yields the entry-version answer and is no
        inconsistency, and is not refused.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.model
            cache.control_flow
            cache.intrinsic_writes
            _remove_from_parent(self._first_declaration(script))
            cache.dominance

    def test_a_late_read_that_forces_a_root_reading_build_is_refused(self):
        """
        Reading a model whose build pulls in a root-reading base after an edit builds that base late
        over the moved tree, and the exit refuses rather than let the derived answer layer over it.
        Here `reaching` pulls `effects`, which re-walks the tree at build.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                cache.model
                cache.control_flow
                _remove_from_parent(self._first_declaration(script))
                cache.reaching

    def test_the_refusal_comes_from_the_outermost_exit(self):
        """
        The recorded fill is shared by nested pins, and an inner exit releases nothing, so it must not
        judge the fill either. The block inside the inner pin completes; the outermost exit is where
        the refusal belongs.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        completed_the_inner_block = False
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                held = cache.model
                _remove_from_parent(self._first_declaration(script))
                with cache.pinned():
                    cache.control_flow
                completed_the_inner_block = True
        self.assertTrue(completed_the_inner_block)
        self.assertIsNot(cache.model, held)

    def test_a_block_that_raises_its_own_error_is_not_masked_by_the_refusal(self):
        """
        The refusal fires on the outermost exit, which is also where a block's own exception is
        passing through. Raising the refusal there unconditionally would replace that exception with
        the guard's, hiding the real failure; a block that both raises and leaves a late root-reading
        fill behind must surface its own error.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(ValueError):
            with cache.pinned():
                cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow
                raise ValueError('the block\'s own failure')

    def test_warm_builds_the_root_reading_models_and_no_others(self):
        """
        Warming builds exactly the slots the cache classifies as root-reading — those whose build
        walks the live tree — leaving every purely-derived slot unbuilt, to build lazily over the
        held roots. The one that comes with them is `dominance`: the effect model orders a
        function's own dead-zone reads through it at build, so warming `effects` warms its base —
        itself derived from the held roots, so building it there is the entry answer and not a
        layering over a moved tree.
        """
        cache = ModelCache(self._script('var a = 1; function f(){ var x = 1; return x; } f();'))
        with cache.pinned():
            cache.warm()
            self.assertIsNotNone(cache._model)
            self.assertIsNotNone(cache._control_flow)
            self.assertIsNotNone(cache._effects)
            self.assertIsNotNone(cache._assignment)
            self.assertIsNotNone(cache._dominance)
            self.assertIsNone(cache._reaching)
            self.assertIsNone(cache._liveness)
            self.assertIsNone(cache._tampering)

    def test_warming_at_entry_lets_a_later_derived_read_after_an_edit_stand(self):
        """
        The call-site contract: a block that warms the root-reading models at entry may first read a
        purely-derived model only after an in-block edit and the exit does not refuse it, because
        that model builds over the held roots.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.warm()
            _remove_from_parent(self._first_declaration(script))
            cache.dominance

    def test_effects_first_built_after_an_edit_over_warmed_roots_yields_the_entry_answer(self):
        """
        `effects` re-walks the live tree at build, so it is a root-reading slot: warmed at entry, a
        read of it after an in-pin edit serves the entry model. Were it left out of the warm set,
        the read would build over the moved tree and report a global write the edit removed as
        absent — the more-permissive direction the pin forbids.
        """
        script = self._script(
            'function r(){return leaked;} function f(){leaked=1;} f();r();')
        f = next(
            n for n in script.walk()
            if isinstance(n, JsFunctionDeclaration) and n.id is not None and n.id.name == 'f')
        block = f.body
        assert block is not None
        cache = ModelCache(script)
        with cache.pinned():
            cache.warm()
            _remove_from_parent(block.body[0])
            self.assertTrue(cache.effects.summary_of(f).writes_global)

    def test_a_tree_reader_the_warm_set_omits_is_still_refused_when_read_late(self):
        """
        `liveness` walks the tree at build like `effects`, so it is in the guard's refusal set; but
        no pinned pass reads it, so it is left out of the warm build. The guard is the backstop: a
        pass that does read it late after an edit trips the refusal rather than layering a liveness
        verdict over the moved tree, so leaving it unwarmed cannot go silently wrong.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        self.assertNotIn('_liveness', cache._warm_slots())
        self.assertIn('_liveness', cache._root_slots())
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                cache.warm()
                _remove_from_parent(self._first_declaration(script))
                cache.liveness

    def test_a_node_made_after_an_edit_has_no_scope_in_the_held_model(self):
        """
        A held model outlives the code an edit frees. A node made after the edit is not one the
        model was built over, wherever it is allocated.
        """
        statements = ' '.join(F'g.p{k}.q;' for k in range(300))
        script = self._script(F'function f() {{ var a = 1; {statements} }}')
        function = script.body[0]
        assert isinstance(function, JsFunctionDeclaration) and function.body is not None
        cache = ModelCache(script)
        with cache.pinned():
            model = cache.model
            set_body(function.body, [])
            list(script.walk())
            gc.collect()
            made = [JsIdentifier(name='a') for _ in range(20000)]
            self.assertTrue(all(model.scope_of(node) is None for node in made))
            self.assertFalse(any(model.knows(node) for node in made))


class TestSimplificationDoesNotRebuildPerFold(TestBase):
    """
    A simplification pass must not rebuild its analysis models once per rewrite. It consults the
    fold-admission gate on nearly every fold, and every fold mutates the tree, so an unpinned cache makes
    the model-build count scale with the number of folds and the cost of a run the product of tree size and
    fold count. That product is what made a 74 KB script take minutes.

    The shape matters more than the count. `String.fromCharCode` is used because it reaches the gate, so
    each fold consults the effect model; string concatenation folds without consulting it and is therefore
    flat whether or not the models are held. An earlier version of this test used concatenation and asserted
    a constant that was already constant — it would have passed against the very regression it was written
    to catch, so the concatenation case is kept below only as a labelled control.
    """

    @staticmethod
    def _gated(count: int) -> str:
        """
        A script with *count* folds that each consult the fold-admission gate.
        """
        body = '\n'.join(F'var g{i} = String.fromCharCode({65 + i % 26});' for i in range(count))
        return F'{body}\nSINK({", ".join(F"g{i}" for i in range(count))});'

    @staticmethod
    def _concat(count: int) -> str:
        """
        A script with *count* folds that never consult the gate — the control.
        """
        body = '\n'.join(F"var c{i} = 'a' + 'b' + '{i}';" for i in range(count))
        return F'{body}\nSINK({", ".join(F"c{i}" for i in range(count))});'

    def _builds(self, source: str) -> tuple[int, int, str]:
        """
        The semantic and effect model build counts for one simplification pass over *source*, with the
        resulting script, counted by intercepting the builders the cache calls.
        """
        counts = {'model': 0, 'effects': 0}
        real_model = cache_module.build_semantic_model
        real_effects = cache_module.build_effects

        def counting_model(root, *args, **kwargs):
            counts['model'] += 1
            return real_model(root, *args, **kwargs)

        def counting_effects(model, *args, **kwargs):
            counts['effects'] += 1
            return real_effects(model, *args, **kwargs)

        script = JsParser(source).parse()
        cache_module.build_semantic_model = counting_model
        cache_module.build_effects = counting_effects
        try:
            JsSimplifications().visit(script)
        finally:
            cache_module.build_semantic_model = real_model
            cache_module.build_effects = real_effects
        return counts['model'], counts['effects'], JsSynthesizer().convert(script)

    @a_property_of_the_pin_itself
    def test_gated_folds_do_not_multiply_model_builds(self):
        few = self._builds(self._gated(10))[:2]
        many = self._builds(self._gated(80))[:2]
        self.assertEqual(few, many)

    @a_property_of_the_pin_itself
    def test_gated_folds_build_each_model_once(self):
        self.assertEqual((1, 1), self._builds(self._gated(40))[:2])

    def test_ungated_folds_do_not_multiply_model_builds(self):
        """
        The control. This holds with or without the models held, which is precisely why it cannot stand in
        for the gated case above.
        """
        self.assertEqual(self._builds(self._concat(10))[:2], self._builds(self._concat(80))[:2])

    def test_holding_the_models_does_not_change_the_result(self):
        """
        The counts above are only worth having if the output is unchanged: a held model that suppressed a
        fold would also flatten the count. Compare against the same pass with pinning disabled.
        """
        source = self._gated(40)
        with_pin = self._builds(source)[2]
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            without_pin_builds, _, without_pin = self._builds(source)
        finally:
            ModelCache.pinned = original
        self.assertEqual(with_pin, without_pin)
        self.assertGreater(without_pin_builds, 1)


class TestReflectiveInliningDoesNotRebuildPerSite(TestBase):
    """
    The reflective inliner consults the script's semantic model to decide each inline, and each inline
    mutates the script, so an unpinned cache rebuilds the whole model once per site. On the sample that
    motivated this work it was the largest remaining cost after the simplifier was fixed.

    Only the *root* model is held. Every inlined body is a freshly parsed fragment that needs its own model,
    so the total build count necessarily grows with the number of sites; asserting on the total would be
    asserting that a required build does not happen. The assertion below therefore isolates builds over the
    script being transformed.

    A pass that consumed a separated `Function`-constructor temporary pays exactly one more build: whether
    the temporary is still named is a structural fact the splices themselves change, so the retirement
    decides on the model rebuilt after the pin is released, never on the pinned one. A pass with no
    retirement candidate — every `eval`-only script — never reads the post-pin model and stays at one.
    """

    @staticmethod
    def _sites(count: int) -> str:
        """
        A script with *count* reflective sites, each of which consults the model before inlining.
        """
        body = '\n'.join(F"eval('var v{i} = {i};');" for i in range(count))
        return F'{body}\nSINK({", ".join(F"v{i}" for i in range(count))});'

    @staticmethod
    def _temporaries(count: int) -> str:
        """
        A script with *count* separated `Function`-constructor temporaries, each consumed by one folded
        invocation, so each is a retirement candidate.
        """
        body = '\n'.join(F"var m{i} = Function('return {i}');" for i in range(count))
        return F'{body}\nSINK({" + ".join(F"m{i}()" for i in range(count))});'

    def _root_builds(self, source: str) -> tuple[int, str]:
        return _transform_root_builds(JsReflectionInlining, source)

    @a_property_of_the_pin_itself
    def test_root_model_is_built_once_regardless_of_site_count(self):
        self.assertEqual(self._root_builds(self._sites(2))[0], self._root_builds(self._sites(16))[0])

    @a_property_of_the_pin_itself
    def test_root_model_is_built_exactly_once(self):
        self.assertEqual(1, self._root_builds(self._sites(8))[0])

    @a_property_of_the_pin_itself
    def test_retirement_pays_one_rebuild_regardless_of_temporary_count(self):
        self.assertEqual(2, self._root_builds(self._temporaries(2))[0])
        self.assertEqual(2, self._root_builds(self._temporaries(16))[0])

    def test_sites_sharing_free_reads_all_inline_in_one_pass(self):
        """
        The stale-name veto is fed only by names a splice declares or writes, so sites whose bodies
        merely read the same free names defer nothing to the next pass: one pass inlines all of them.
        """
        body = '\n'.join(F"eval('SINK({i}, shared);');" for i in range(64))
        output = self._root_builds(body)[1]
        self.assertNotIn('eval', output)
        self.assertEqual(64, output.count('SINK('))

    def test_holding_the_model_does_not_change_the_result(self):
        """
        A held model that suppressed an inline would also flatten the count, so the output must match the
        unpinned pass exactly.
        """
        source = self._sites(8)
        with_pin = self._root_builds(source)[1]
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            without_pin_builds, without_pin = self._root_builds(source)
        finally:
            ModelCache.pinned = original
        self.assertEqual(with_pin, without_pin)
        self.assertGreater(without_pin_builds, 1)


class TestWrapperInliningDoesNotRebuildPerSite(TestBase):
    """
    The call-wrapper inliner holds the models for its pass because every replacement advances the
    tree's mutation counter and an unpinned read would rebuild them once per call site. Nothing its
    loop does makes a model it reads more permissive — a replaced call is gone and no declaration
    moves — so the held answers stay the stricter ones; the output comparison checks that the pinned
    pass writes exactly what the unpinned one does.
    """

    @staticmethod
    def _sites(count: int) -> str:
        """
        A script with one call wrapper and *count* call sites it reaches, each replaced in one pass.
        """
        calls = '\n'.join(F'var r{i} = w({i}, {i + 1});' for i in range(count))
        return (
            'function w(a, b) { return target(a, b); }\n'
            F'{calls}\nSINK({", ".join(F"r{i}" for i in range(count))});'
        )

    def _root_builds(self, source: str) -> tuple[int, str]:
        return _transform_root_builds(JsCallWrapperInliner, source)

    @a_property_of_the_pin_itself
    def test_root_model_is_built_once_regardless_of_site_count(self):
        self.assertEqual(1, self._root_builds(self._sites(2))[0])
        self.assertEqual(1, self._root_builds(self._sites(16))[0])

    def test_holding_the_model_does_not_change_the_result(self):
        source = self._sites(8)
        with_pin = self._root_builds(source)[1]
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            without_pin_builds, without_pin = self._root_builds(source)
        finally:
            ModelCache.pinned = original
        self.assertEqual(with_pin, without_pin)
        self.assertGreater(without_pin_builds, 1)


class TestDeadCodeRemovalDecidesOnOneModel(TestBase):
    """
    Dead-code removal takes every decision of a run before its first edit, so it reads the models
    of one tree however many branches it prunes. Taking each decision where the edit is made
    instead reads models rebuilt after every pruned branch.
    """

    @staticmethod
    def _bodies(count: int) -> str:
        """
        A script with *count* functions, each holding one branch that never runs.
        """
        functions = '\n'.join(
            F'function f{i}(a) {{ if (false) {{ a.x = {i}; }} return a; }}' for i in range(count)
        )
        names = ', '.join(F'f{i}' for i in range(count))
        return F'{functions}\nSINK({names});'

    @a_property_of_the_batch_itself
    def test_the_model_is_built_once_however_many_bodies_hold_a_dead_branch(self):
        self.assertEqual(1, _transform_root_builds(JsDeadCodeElimination, self._bodies(2))[0])
        self.assertEqual(1, _transform_root_builds(JsDeadCodeElimination, self._bodies(16))[0])

    def test_deciding_before_the_first_edit_does_not_change_the_result(self):
        class Unbatched(JsDeadCodeElimination):
            batching = False

        source = self._bodies(8)
        batched = _transform_root_builds(JsDeadCodeElimination, source)[1]
        unbatched_builds, unbatched = _transform_root_builds(Unbatched, source)
        self.assertNotIn('false', batched)
        self.assertEqual(batched, unbatched)
        self.assertGreater(unbatched_builds, 1)


class TestUnusedCodeRemovalHoldsTheModelsForASweep(TestBase):
    """
    Unused-code removal sweeps the script until a sweep changes nothing, and every sweep holds the
    models of the tree it started on. Released, each removal of a sweep moves the tree under the
    next read, and the models are rebuilt once per body that holds a dead local.
    """

    @staticmethod
    def _bodies(count: int) -> str:
        """
        A script with *count* functions, each holding one local nothing reads.
        """
        functions = '\n'.join(F'function f{i}() {{ var t = g; return {i}; }}' for i in range(count))
        calls = ', '.join(F'f{i}()' for i in range(count))
        return F'g = 1;\n{functions}\nSINK({calls});'

    @staticmethod
    def _released(source: str) -> tuple[int, str]:
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            return _transform_root_builds(JsUnusedCodeRemoval, source)
        finally:
            ModelCache.pinned = original

    @a_property_of_the_pin_itself
    def test_the_models_are_built_as_often_for_sixteen_bodies_as_for_two(self):
        self.assertEqual(
            _transform_root_builds(JsUnusedCodeRemoval, self._bodies(2))[0],
            _transform_root_builds(JsUnusedCodeRemoval, self._bodies(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_released_models_are_built_more_often_for_sixteen_bodies_than_for_two(self):
        self.assertLess(self._released(self._bodies(2))[0], self._released(self._bodies(16))[0])

    def test_holding_the_models_does_not_change_the_result(self):
        source = self._bodies(8)
        held = _transform_root_builds(JsUnusedCodeRemoval, source)[1]
        self.assertNotIn('var t', held)
        self.assertEqual(held, self._released(source)[1])


#: Programs that run every pinned or batched pass through its rewriting arm — a reflective site at
#: statement and at expression position, a string timer, a consumed `Function` temporary, a gated
#: fold, a string respelling, a call wrapper, a pruned branch whose kept test assigns what a later
#: test reads, a dead store, a discarded completion and a global only one function uses — beside a
#: few plain shapes and the generated corpus, which exercise the rest of the pipeline.
_CORPUS = tuple(generate(seed) for seed in range(16)) + (
    'var q = 1; var t = (q + 1) * 2; f(t);',
    'var x = 5; var t = delete x; g(); f(t);',
    'const a = [1, 2, 3]; console.log(a[1]);',
    'var q = 1; function g(){ return q + 1; } console.log(g());',
    'var x = 5; x = 6; console.log(x);',
    "SINK('\\x61');",
    "eval('var v = 1;'); SINK(v);",
    "var r = eval('1 + 2'); SINK(r);",
    "execScript('var v = 1;'); SINK(v);",
    "setTimeout('SINK(1);', 10);",
    "var m = Function('return 41'); SINK(m());",
    'var g = String.fromCharCode(65); SINK(g);',
    'function w(a, b) { return target(a, b); } var r = w(1, 2); SINK(r);',
    'function main(c) { var o; if (c) { if ([o = {}, f()]) { A(); } } if (o) { X(); } else { Y(); } } SINK(main);',
    'function f(a) { var x = [a]; x = a.c; return x; } SINK(f);',
    '(function () { function g() { h(); return 0; } g(); })();',
    'var t; function f(a) { t = a.b; SINK(t); } f(SRC);',
)


class TestPinnedAndUnpinnedRunsAgree(TestBase):
    """
    A pin can only defer work to a later invocation: a rewrite a held model declines reappears when
    the group loop re-runs the pass on the rebuilt model. Every sample must therefore reach the same
    final output with the pins held as without them — a sample that does not has a pass acting on a
    stale answer in the permissive direction, which is the one direction the pin contract refuses.
    """

    def _unpinned(self, source: str) -> str:
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            return deobfuscate_source(source)
        finally:
            ModelCache.pinned = original

    def test_the_corpus_reaches_the_same_final_output(self):
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                self.assertEqual(deobfuscate_source(source), self._unpinned(source))


class TestAnAnnouncedChangeMovesTheTree(TestBase):
    """
    A pass that reports a change edited the tree through a sited edit, which moved the version
    counter with it. A pinned block's exit reads that counter to decide whether the block changed
    the tree at all, so a pass that edited a list in place and only announced it would have the
    models it holds kept past its own edit — the reflective inliner's statement splice was such a
    write. Every announcement the corpus makes is checked against the counter.
    """

    class _Recorder(PipelineObserver):

        def __init__(self):
            self.entry = 0
            self.unsited: list[str] = []

        def before(self, group: str, transformer: type[Transformer], ast: Node) -> None:
            self.entry = tree_version(ast)

        def after(
            self, group: str, transformer: type[Transformer], ast: Node, changed: bool,
        ) -> None:
            if changed and tree_version(ast) == self.entry:
                self.unsited.append(transformer.__name__)

    def test_every_change_the_corpus_announces_moved_the_counter(self):
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                recorder = self._Recorder()
                deobfuscate(JsParser(source).parse(), observer=recorder)
                self.assertEqual([], recorder.unsited)


@a_property_of_the_pin_itself
class TestAKeptModelDescribesTheProgramItOutlivedThePinOn(TestBase):
    """
    A pin's exit keeps the models when neither change channel reported an edit. `canonical` reads
    the program the tree spells and answers the same question independently of both channels: a
    model kept past a block whose program changed is stale whatever the counters said, and the
    program is the models' only input beside the run's fixed options.
    """

    def _models_kept_past_a_changed_program(self, source: str) -> int:
        kept_stale = 0
        original = ModelCache.pinned

        @contextmanager
        def audited(self: ModelCache):
            nonlocal kept_stale
            outermost = not self._pins
            program = canonical(self.root) if outermost else None
            with original(self) as pinned:
                yield pinned
            if outermost and self._model is not None and canonical(self.root) != program:
                kept_stale += 1

        ModelCache.pinned = audited
        try:
            deobfuscate_source(source)
        finally:
            ModelCache.pinned = original
        return kept_stale

    def test_no_model_in_the_corpus_is_kept_past_a_program_change(self):
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                self.assertEqual(0, self._models_kept_past_a_changed_program(source))


@a_property_of_the_pin_itself
class TestAHeldModelPlacesEveryNodeWhereItWasBuilt(TestBase):
    """
    A held control-flow model answers where a node stands by climbing the parents the node has at
    the moment it is asked. A pass whose edit puts a node that was in the tree when the pin was
    entered under a node the pass creates would have that model place it somewhere it was never
    built for. Every such answer the corpus asks a held model for after the tree moved is compared
    with the answer the same model gives once the parents of the pin's entry are put back: the held
    answer is either unknown or the same place.
    """

    def _held_answers(self, source: str) -> tuple[int, list[str]]:
        entries: list[tuple[ModelCache, int, dict[int, tuple[Node, Node | None]]]] = []
        compared = 0
        misplaced: list[str] = []
        original_pinned = ModelCache.pinned
        original_locate = ElementLocator.locate

        @contextmanager
        def recorded(self: ModelCache):
            outermost = not self._pins
            if outermost:
                parents = {id(node): (node, node.parent) for node in self.root.walk()}
                entries.append((self, tree_version(self.root), parents))
            try:
                with original_pinned(self) as pinned:
                    yield pinned
            finally:
                if outermost:
                    entries.pop()

        def audited(self: ElementLocator, element: Node):
            nonlocal compared
            answer = original_locate(self, element)
            if not entries:
                return answer
            cache, version, parents = entries[-1]
            entry = parents.get(id(element))
            if entry is None or entry[0] is not element or tree_version(cache.root) == version:
                return answer
            compared += 1
            moved: list[tuple[Node, Node | None]] = []
            cursor: Node | None = element
            while cursor is not None and (held := parents.get(id(cursor))) is not None:
                moved.append((cursor, cursor.parent))
                cursor.parent = held[1]
                cursor = held[1]
            try:
                then = original_locate(self, element)
            finally:
                for node, parent in moved:
                    node.parent = parent
            if answer is not None and (then is None or then[1] is not answer[1]):
                misplaced.append(type(element).__name__)
            return answer

        ModelCache.pinned = recorded
        ElementLocator.locate = audited
        try:
            deobfuscate_source(source)
        finally:
            ModelCache.pinned = original_pinned
            ElementLocator.locate = original_locate
        return compared, misplaced

    def test_no_held_model_in_the_corpus_places_a_node_elsewhere(self):
        compared = 0
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                count, misplaced = self._held_answers(source)
                compared += count
                self.assertEqual([], misplaced)
        self.assertGreater(compared, 0)
