from __future__ import annotations

from contextlib import contextmanager

from test import TestBase, a_property_of_the_pin_itself

from test.lib.scripts.js.analysis.differential import deobfuscate_source
from test.lib.scripts.js.analysis.jsgen import generate

import refinery.lib.scripts.js.analysis.cache as cache_module
from refinery.lib.scripts import Transformer, _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.model import JsIdentifier, JsVariableDeclaration
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


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
        `Transformer.changed` invalidates through this method rather than the version counter, and
        `generic_visit` replaces children without advancing that counter at all — so a pin that guarded
        only the version would miss every such rewrite.
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

    def test_a_model_first_built_after_an_edit_is_refused_on_exit(self):
        """
        A slot first read after the tree has moved under a pin is layered over held base models from
        an earlier tree — the state no unpinned run builds, since there a version change drops every
        slot together. The exit refuses it, and the cache the refusal leaves behind serves a model of
        the current tree, not the layered one.
        """
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                held = cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.reaching
        self.assertIsNot(cache.model, held)

    def test_the_refusal_comes_from_the_outermost_exit(self):
        """
        The fill version is shared by nested pins, and an inner exit releases nothing, so it must not
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
                    cache.reaching
                completed_the_inner_block = True
        self.assertTrue(completed_the_inner_block)
        self.assertIsNot(cache.model, held)


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

        def counting_effects(model):
            counts['effects'] += 1
            return real_effects(model)

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





class TestPinnedAndUnpinnedRunsAgree(TestBase):
    """
    A pin can only defer work to a later invocation: a rewrite a held model declines reappears when
    the group loop re-runs the pass on the rebuilt model. Every sample must therefore reach the same
    final output with the pins held as without them — a sample that does not has a pass acting on a
    stale answer in the permissive direction, which is the one direction the pin contract refuses.
    """

    _SHAPES = (
        'var q = 1; var t = (q + 1) * 2; f(t);',
        'var x = 5; var t = delete x; g(); f(t);',
        'const a = [1, 2, 3]; console.log(a[1]);',
        'var q = 1; function g(){ return q + 1; } console.log(g());',
        'var x = 5; x = 6; console.log(x);',
    )

    def _unpinned(self, source: str) -> str:
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            return deobfuscate_source(source)
        finally:
            ModelCache.pinned = original

    def test_the_corpus_reaches_the_same_final_output(self):
        sources = [generate(seed) for seed in range(16)] + list(self._SHAPES)
        for index, source in enumerate(sources):
            with self.subTest(sample=index):
                self.assertEqual(deobfuscate_source(source), self._unpinned(source))
