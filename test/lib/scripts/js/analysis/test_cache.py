from __future__ import annotations

import gc
import inspect

from contextlib import contextmanager

from test import TestBase, a_property_of_the_batch_itself, a_property_of_the_pin_itself, todo

from test.lib.scripts.js.analysis.differential import deobfuscate_source
from test.lib.scripts.js.analysis.jsgen import generate
from test.lib.scripts.js.deobfuscation import test_cff_statemachine as generator_fixtures

import refinery.lib.scripts.js.analysis.cache as cache_module
from refinery.lib.scripts import Node, Transformer, _remove_from_parent, canonical, set_body, tree_version
from refinery.lib.scripts.analysis.cfg import ElementLocator
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.analysis.dominance import build_dominance
from refinery.lib.scripts.js.analysis.liveness import build_liveness
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.deobfuscation.cff import JsStateMachineUnflattening
from refinery.lib.scripts.js.deobfuscation.deadcode import JsDeadCodeElimination
from refinery.lib.scripts.js.deobfuscation.objectfold import JsObjectFold
from refinery.lib.scripts.js.deobfuscation.reflection import JsReflectionInlining
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.unused import JsUnusedCodeRemoval
from refinery.lib.scripts.js.deobfuscation.wrappers import JsCallWrapperInliner
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
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
    yield self


def _transform_root_builds(
    transform: type[Transformer],
    source: str,
    options: object | None = None,
) -> tuple[int, str]:
    script = JsParser(source).parse()
    count = {'n': 0}
    real_model = cache_module.build_semantic_model

    def counting_model(root, *args, **kwargs):
        if root is script:
            count['n'] += 1
        return real_model(root, *args, **kwargs)

    cache_module.build_semantic_model = counting_model
    try:
        transformer = transform()
        transformer.options = options
        transformer.visit(script)
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
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        held = None
        with cache.pinned():
            held = cache.model
        self.assertIs(cache.model, held)

    def test_an_invalidation_requested_under_a_pin_drops_the_models_on_exit(self):
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
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        with cache.pinned():
            self.assertIsNone(cache._model)

    def test_pinned_model_is_fresh_at_entry_after_an_earlier_mutation(self):
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
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                held = cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow
        self.assertIsNot(cache.model, held)

    def test_a_pure_derived_model_first_built_after_an_edit_is_not_refused(self):
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.model
            cache.control_flow
            cache.intrinsic_writes
            _remove_from_parent(self._first_declaration(script))
            cache.dominance

    def test_a_late_read_that_forces_a_root_reading_build_is_refused(self):
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                cache.model
                cache.control_flow
                _remove_from_parent(self._first_declaration(script))
                cache.reaching

    def test_the_refusal_comes_from_the_outermost_exit(self):
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
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with self.assertRaises(ValueError):
            with cache.pinned():
                cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow
                raise ValueError('the block\'s own failure')

    def test_warm_builds_the_root_reading_models_and_no_others(self):
        cache = ModelCache(self._script('var a = 1; function f(){ var x = 1; return x; } f();'))
        with cache.pinned():
            cache.warm()
            self.assertIsNotNone(cache._model)
            self.assertIsNotNone(cache._control_flow)
            self.assertIsNotNone(cache._effects)
            self.assertIsNotNone(cache._assignment)
            self.assertIsNone(cache._reaching)
            self.assertIsNone(cache._liveness)
            self.assertIsNone(cache._tampering)

    def test_warming_at_entry_lets_a_later_derived_read_after_an_edit_stand(self):
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.warm()
            _remove_from_parent(self._first_declaration(script))
            cache.dominance

    def test_effects_first_built_after_an_edit_over_warmed_roots_yields_the_entry_answer(self):
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
        The edit frees the nodes the held model was built over, so new nodes may be allocated where
        they stood; the model must not mistake one of them for a node it knows.
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

    def test_a_renewal_answers_about_the_edited_tree(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            self.assertIn('a', cache.model.root_scope.bindings)
            _remove_from_parent(self._first_declaration(script))
            cache.renew()
            self.assertNotIn('a', cache.model.root_scope.bindings)

    def test_a_renewal_builds_the_models_it_names_and_no_others(self):
        script = self._script('var a = 1; function f(){ var x = 1; return x; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.warm()
            _remove_from_parent(self._first_declaration(script))
            cache.renew('_model', '_intrinsic_writes')
            self.assertIsNotNone(cache._model)
            self.assertIsNotNone(cache._intrinsic_writes)
            self.assertIsNone(cache._control_flow)
            self.assertIsNone(cache._effects)
            self.assertIsNone(cache._dominance)

    def test_a_renewal_over_the_tree_the_pin_was_entered_on_keeps_the_held_models(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        with cache.pinned():
            held = cache.model
            cache.renew()
            self.assertIs(cache.model, held)

    def test_a_renewal_after_an_announced_change_builds_the_models_again(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        with cache.pinned():
            held = cache.model
            cache.invalidate()
            cache.renew()
            self.assertIsNot(cache.model, held)

    def test_a_renewal_outside_a_pin_builds_nothing(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        cache.renew()
        self.assertIsNone(cache._model)

    def test_a_renewal_under_a_nested_pin_is_refused(self):
        cache = ModelCache(self._script('var a = 1; var b = 2;'))
        with cache.pinned():
            held = cache.model
            with cache.pinned():
                with self.assertRaises(RuntimeError):
                    cache.renew()
            self.assertIs(cache.model, held)

    def test_a_model_read_after_a_renewal_and_before_the_next_edit_is_not_refused(self):
        script = self._script('var a = 1; var b = 2; function f(){ return b; } f();')
        cache = ModelCache(script)
        with cache.pinned():
            cache.warm()
            _remove_from_parent(self._first_declaration(script))
            cache.renew('_model')
            cache.control_flow

    def test_a_model_the_renewal_did_not_name_and_read_after_the_next_edit_is_refused(self):
        script = self._script('var a = 1; var b = 2; function f(){ return b; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                cache.warm()
                _remove_from_parent(self._first_declaration(script))
                cache.renew('_model')
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow

    def test_a_late_build_before_a_renewal_is_still_refused(self):
        script = self._script('var a = 1; var b = 2; function f(){ return b; } f();')
        cache = ModelCache(script)
        with self.assertRaises(RuntimeError):
            with cache.pinned():
                cache.model
                _remove_from_parent(self._first_declaration(script))
                cache.control_flow
                cache.renew()

    def test_a_renewal_over_the_final_tree_keeps_its_models_past_the_block(self):
        script = self._script('var a = 1; var b = 2;')
        cache = ModelCache(script)
        with cache.pinned():
            cache.model
            _remove_from_parent(self._first_declaration(script))
            cache.renew()
            renewed = cache.model
        self.assertIs(cache.model, renewed)


class TestSimplificationDoesNotRebuildPerFold(TestBase):

    @staticmethod
    def _gated(count: int) -> str:
        body = '\n'.join(F'var g{i} = String.fromCharCode({65 + i % 26});' for i in range(count))
        return F'{body}\nSINK({", ".join(F"g{i}" for i in range(count))});'

    @staticmethod
    def _concat(count: int) -> str:
        body = '\n'.join(F"var c{i} = 'a' + 'b' + '{i}';" for i in range(count))
        return F'{body}\nSINK({", ".join(F"c{i}" for i in range(count))});'

    def _builds(self, source: str) -> tuple[int, int, str]:
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

    @staticmethod
    def _revealing(count: int) -> str:
        return '\n'.join('f(String.fromCharCode(118, 97, 108, 117, 101, 79, 102));' for _ in range(count))

    @a_property_of_the_pin_itself
    def test_folds_spelling_a_key_the_models_read_do_not_multiply_model_builds(self):
        self.assertEqual(self._builds(self._revealing(10))[:2], self._builds(self._revealing(80))[:2])

    @staticmethod
    def _constructor_keys(count: int) -> str:
        key = 'String.fromCharCode(99, 111, 110, 115, 116, 114, 117, 99, 116, 111, 114)'
        return '\n'.join(F'f(o{i}[{key}]);' for i in range(count))

    @staticmethod
    def _caller_strings(count: int) -> str:
        return '\n'.join('f([String.fromCharCode(99, 97, 108, 108, 101, 114)]);' for _ in range(count))

    @a_property_of_the_pin_itself
    def test_folds_spelling_constructor_as_a_key_do_not_multiply_model_builds(self):
        self.assertEqual(self._builds(self._constructor_keys(10))[:2], self._builds(self._constructor_keys(80))[:2])

    @staticmethod
    def _constructor_names(count: int) -> str:
        return '\n'.join("f(''.constructor.name);" for _ in range(count))

    @a_property_of_the_pin_itself
    def test_constructor_names_no_write_reaches_do_not_multiply_model_builds(self):
        self.assertEqual(self._builds(self._constructor_names(10))[:2], self._builds(self._constructor_names(80))[:2])

    @a_property_of_the_pin_itself
    def test_a_number_fold_completing_a_key_read_as_naming_nothing_renews_the_models(self):
        completed = self._builds("window['a' + (1 + 1)] = 5;")[0]
        never = self._builds("window['a' + g()] = 5;")[0]
        self.assertGreater(completed, never)

    @a_property_of_the_pin_itself
    def test_folds_spelling_caller_in_an_array_do_not_multiply_model_builds(self):
        self.assertEqual(self._builds(self._caller_strings(10))[:2], self._builds(self._caller_strings(80))[:2])

    @a_property_of_the_pin_itself
    def test_gated_folds_build_each_model_once(self):
        self.assertEqual((1, 1), self._builds(self._gated(40))[:2])

    def test_ungated_folds_do_not_multiply_model_builds(self):
        self.assertEqual(self._builds(self._concat(10))[:2], self._builds(self._concat(80))[:2])

    def test_holding_the_models_does_not_change_the_result(self):
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

    @staticmethod
    def _sites(count: int) -> str:
        body = '\n'.join(F"eval('var v{i} = {i};');" for i in range(count))
        return F'{body}\nSINK({", ".join(F"v{i}" for i in range(count))});'

    @staticmethod
    def _temporaries(count: int) -> str:
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
        body = '\n'.join(F"eval('SINK({i}, shared);');" for i in range(64))
        output = self._root_builds(body)[1]
        self.assertNotIn('eval', output)
        self.assertEqual(64, output.count('SINK('))

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


class TestWrapperInliningDoesNotRebuildPerSite(TestBase):

    @staticmethod
    def _sites(count: int) -> str:
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

    @staticmethod
    def _bodies(count: int) -> str:
        functions = '\n'.join(
            F'function f{i}(a) {{ if (false) {{ a.x = {i}; }} return a; }}' for i in range(count)
        )
        names = ', '.join(F'f{i}' for i in range(count))
        return F'{functions}\nSINK({names});'

    @staticmethod
    def _block_functions(count: int) -> str:
        functions = '\n'.join(
            F'function f{i}(a) {{ if (false) {{ function h{i}() {{}} }} return a; }}'
            for i in range(count)
        )
        names = ', '.join(F'f{i}' for i in range(count))
        return F'{functions}\nSINK({names});'

    @a_property_of_the_batch_itself
    def test_the_model_is_built_once_however_many_bodies_hold_a_dead_branch(self):
        self.assertEqual(1, _transform_root_builds(JsDeadCodeElimination, self._bodies(2))[0])
        self.assertEqual(1, _transform_root_builds(JsDeadCodeElimination, self._bodies(16))[0])

    @a_property_of_the_batch_itself
    def test_dead_branches_declaring_functions_in_a_module_need_one_model(self):
        module = DeobfuscationOptions(execution=ExecutionModel.module)
        for count in (2, 16):
            builds, pruned = _transform_root_builds(
                JsDeadCodeElimination,
                self._block_functions(count),
                module,
            )
            with self.subTest(count=count):
                self.assertEqual(builds, 1)
                self.assertNotIn('false', pruned)

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

    @staticmethod
    def _bodies(count: int) -> str:
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


class TestGeneratorUnflatteningHoldsTheModelsForARun(TestBase):

    _MACHINE = inspect.cleandoc(
        """
        function fINDEX() {
          function* gen(a, b, scope = SCOPE, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    STATE
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    @classmethod
    def _machines(
        cls,
        count: int,
        state: str = 'scope.v = INDEX; return done = true, scope.v;',
        scope: str = '{}',
    ) -> str:
        return '\n'.join(
            cls._MACHINE.replace('SCOPE', scope).replace('STATE', state).replace('INDEX', str(index))
            for index in range(count)
        )

    @classmethod
    def _keeping_the_global_object_in_a_namespace(cls, count: int) -> str:
        return cls._machines(
            count,
            'scope.NS.g = globalThis; return done = true, scope.NS.g === globalThis;',
            '{NS: {}}',
        )

    @staticmethod
    def _held(source: str) -> tuple[int, str]:
        return _transform_root_builds(JsStateMachineUnflattening, source)

    @staticmethod
    def _released(source: str) -> tuple[int, str]:
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            return _transform_root_builds(JsStateMachineUnflattening, source)
        finally:
            ModelCache.pinned = original

    @a_property_of_the_pin_itself
    def test_the_models_are_built_as_often_for_sixteen_machines_as_for_two(self):
        self.assertEqual(
            self._held(self._machines(2))[0],
            self._held(self._machines(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_a_namespace_member_holding_the_global_object_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._keeping_the_global_object_in_a_namespace(2))[0],
            self._held(self._keeping_the_global_object_in_a_namespace(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_a_slot_holding_a_property_of_the_global_object_needs_no_new_models(self):
        state = 'scope.d = window.document; return done = true, scope.d.title;'
        self.assertEqual(
            self._held(self._machines(2, state))[0],
            self._held(self._machines(16, state))[0],
        )

    @a_property_of_the_pin_itself
    def test_released_models_are_built_more_often_for_sixteen_machines_than_for_two(self):
        self.assertLess(self._released(self._machines(2))[0], self._released(self._machines(16))[0])

    def test_holding_the_models_does_not_change_the_result(self):
        for source in (self._machines(8), self._keeping_the_global_object_in_a_namespace(8)):
            held = self._held(source)[1]
            self.assertNotIn('function*', held)
            self.assertEqual(held, self._released(source)[1])

    def test_a_write_through_a_name_from_outside_the_with_does_not_change_the_result(self):
        fixtures = generator_fixtures.TestGeneratorCFFUnflattening
        source = fixtures.PROTOTYPE_WRITTEN_THROUGH_A_NAME_FROM_OUTSIDE_BEFORE_A_SIBLING_READS_IT_CFF
        self.assertEqual(self._held(source)[1], self._released(source)[1])


class TestObjectFoldingHoldsTheModelsForARun(TestBase):

    @staticmethod
    def _scopes(count: int, declaration: str, value: str) -> str:
        functions = '\n'.join(
            F'function f{index}() {{ var O = {declaration}; return {value}; }}'.replace('INDEX', str(index))
            for index in range(count)
        )
        calls = ', '.join(F'f{index}()' for index in range(count))
        return F'{functions}\nconsole.log({calls});'

    @classmethod
    def _independent(cls, count: int) -> str:
        return cls._scopes(count, '{a: INDEX, b: 2}', 'O.a + O.b')

    @classmethod
    def _comparing_the_global_object(cls, count: int) -> str:
        return cls._scopes(
            count,
            '{eq: function (a, b) { return a === b; }}',
            'O.eq(this, window) || O.eq(globalThis, INDEX)',
        )

    @staticmethod
    def _reading_a_parameter(count: int, declarations: str, value: str) -> str:
        functions = '\n'.join(
            F'function f{index}(e) {{ {declarations} return {value}; }}'.replace('INDEX', str(index))
            for index in range(count)
        )
        calls = ', '.join(F'f{index}(1)' for index in range(count))
        return F'{functions}\nconsole.log({calls});'

    @classmethod
    def _holding_the_parameter(cls, count: int) -> str:
        return cls._reading_a_parameter(count, 'var O = {a: e, b: INDEX};', 'O.a + O.b')

    @classmethod
    def _holding_the_parameter_beside_an_array(cls, count: int) -> str:
        return cls._reading_a_parameter(
            count,
            'var A = {v: e}; var B = {w: e, z: [INDEX]};',
            'A.v + B.w + B.z[0]',
        )

    @staticmethod
    def _one_object_read(count: int) -> str:
        reads = ', '.join(['O.a'] * count)
        return F'function f() {{ var O = {{a: 1, b: "s"}}; console.log({reads}); }} f();'

    @classmethod
    def _handing_names_on_to_a_call(cls, count: int) -> str:
        return cls._reading_a_parameter(count, 'var O = {c: function (a, b) { return a(b); }};', 'O.c(g, e)')

    @classmethod
    def _copying_strings_into_keys(cls, count: int) -> str:
        return cls._reading_a_parameter(
            count,
            'var O = {k0: "log", k1: "info", k2: "warn", k3: "error"};',
            '[e[O.k0](0), e[O.k1](1), e[O.k2](2), e[O.k3](3)]',
        )

    @classmethod
    def _copying_strings_into_keys_between_inlined_calls(cls, count: int) -> str:
        literal = ', '.join(F'k{i}: "m{i}", w{i}: function (x, y) {{ return x + y; }}' for i in range(8))
        calls = ', '.join(F'e[O.k{i}](O.w{i}(e, {i}))' for i in range(8))
        return cls._reading_a_parameter(count, F'var O = {{{literal}}};', F'[{calls}]')

    @classmethod
    def _inlining_calls_that_read_members_under_handed_strings(cls, count: int) -> str:
        literal = '{get: function (x, y) { return x[y]; }, add: function (x, y) { return x + y; }}'
        calls = ', '.join(F'O.get(e, "m{i}"), O.add(e, {i})' for i in range(8))
        return cls._reading_a_parameter(count, F'var O = {literal};', F'[{calls}]')

    _FOLDS_THE_MODELS_READ = (
        'var A = {g: globalThis}; var C = {x: 1}; console.log(A.g.C.x); console.log(C.x);',
        'var A = {g: globalThis}; var C = {x: 1};'
        ' Object.defineProperty(A.g, "C", {value: {x: 5}}); console.log(C.x);',
        'var D = {g: globalThis}; var C = {x: 1};'
        ' function out(g) { g.C = {x: 5}; } out(D.g); console.log(C.x);',
        'var A = {g: globalThis}; A.g["ev" + "al"]("Object.prototype.k = 1");'
        ' var B = {x: 1}; console.log(B.k);',
        'var A = {o: Object}; Object.defineProperty(A.o.prototype, "k", {value: 1});'
        ' var B = {x: 1}; console.log(B.k);',
        'var A = {f: function (p) { return p; }}; A.f(Object).prototype.k = 1;'
        ' var B = {x: 1}; console.log(B.k);',
        'function f(p) { var A = {o: Object}; arguments[0] = A.o; p.prototype.k = 1;'
        ' var B = {x: 1}; return B.k; } console.log(f(0));',
        'var A = {k: "C"}; var C = {x: 1}; globalThis[A.k] = {x: 5}; console.log(C.x);',
        'var A = {k: "defineProperty"}; var B = {x: 1};'
        ' Object[A.k](Object.prototype, "k", {value: 1}); console.log(B.k);',
        'var A = {k: "eval"}; function G() { return this; } var B = {x: 1};'
        ' G()[A.k]("Object.prototype.k = 1"); console.log(B.k);',
        'var A = {t: setTimeout}; A.t("Object.prototype.k = 1", 0); var B = {x: 1};'
        ' setTimeout(function () { console.log(B.k); }, 10);',
        'var A = {f: function () { return B.x; }, c: 2}; var B = {x: g, y: 1};'
        ' console.log(A.c); console.log(B.y);',
        'var A = {f: function (cb) { return 1; }}; var B = {x: g, y: 2};'
        ' console.log(A.f(function () { return B.x; })); console.log(B.y);',
        'var A = {f: function () { var a = arguments; a[0].x = 5; return 1; }};'
        ' var C = {x: 1}; console.log(A.f(C), C.x);',
        'var B = {o: Object, f: function (p) { return 1; }}; function g() { return ({}).x; }'
        ' function run() { console.log(B.f(g())); } var q = B.o;'
        ' Object.defineProperty(q.prototype, "x", {get: function () { return 2; }}); run();',
        'var A = {k: "prototype"}; var K = A.k; Object[K].x = 1; var B = {y: 1}; console.log(B.x);',
        'var A = {k: "prototype"}; function f(K) { Object[K].x = 1; } f(A.k);'
        ' var B = {y: 1}; console.log(B.x);',
        'function main() { var A = {f: function (a, b) { return a(b); }}; A.f(out, globalThis); }'
        ' var C = {x: 1}; function out(g) { g.C = {x: 5}; } main(); console.log(C.x);',
        'var A = {a: "define", b: "Property"}; Object[A.a + A.b](Object.prototype, "q", {value: 1});'
        ' var B = {y: 1}; console.log(B.q);',
        'function polyfill() { var S = {a: "define", b: "Property"};'
        ' Object[S.a + S.b](Object.prototype, "q", {value: 7}); } polyfill();'
        ' function main() { var cfg = {y: 1}; console.log(cfg.q); } main();',
        'var A = {a: "define", b: "Property", f: function (x, y) { return x + y; }};'
        ' Object[A.f(A.a, A.b)](Object.prototype, "q", {value: 1}); var B = {y: 1}; console.log(B.q);',
        'var A = {a: "__define", b: "Getter__"};'
        ' Object.prototype[A.a + A.b]("q", function () { console.log("got"); return 3; });'
        ' var B = {y: 1}; console.log(B.q);',
        'var A = {k: "defineProperty"}; function later() { return A.q; }'
        ' Object[A.k](Object.prototype, "q", {value: 1}); console.log(later());',
        'var A = {k: "eval"}; function G() { return this; } function later() { return A.q; }'
        ' G()[A.k]("Object.prototype.q = 1"); console.log(later());',
        'function g() { return 2; } function main() { var A = {k: "g", f: function (a) { return 1; }};'
        ' function later() { return A.f(g()); }'
        ' globalThis[A.k] = function () { console.log("side"); return 1; }; return later(); }'
        ' console.log(main());',
        'var A = {k: "valueOf"}; class C { [A.k]() { console.log("conv"); return 1; } }'
        ' var c = new C(); var H = {s: c + 1, n: 2}; console.log(H.n);',
        'var A = {k: "defineProperty"}; var {[A.k]: d} = Object; d(Object.prototype, "q", {value: 1});'
        ' var B = {y: 1}; console.log(B.q);',
        'var o = {}; var A = {k: "toString"};'
        ' Reflect.set(o, A.k, function () { console.log("conv"); return "c"; });'
        ' var H = {s: o + "", n: 2}; console.log(H.n);',
        'var o = {}; var A = {k: "toString"};'
        ' var p = {[A.k]: function () { console.log("conv"); return "c"; }};'
        ' var H = {s: p + "", n: 2}; console.log(H.n);',
        'var A = {k: function () { return "defineProperty"; }};'
        ' Object[A.k()](Object.prototype, "q", {value: 1}); var B = {y: 1}; console.log(B.q);',
    )

    @staticmethod
    def _held(source: str) -> tuple[int, str]:
        return _transform_root_builds(JsObjectFold, source)

    @staticmethod
    def _released(source: str) -> tuple[int, str]:
        original = ModelCache.pinned
        ModelCache.pinned = _no_pin
        try:
            return _transform_root_builds(JsObjectFold, source)
        finally:
            ModelCache.pinned = original

    @a_property_of_the_pin_itself
    def test_the_models_are_built_as_often_for_sixteen_objects_as_for_two(self):
        self.assertEqual(self._held(self._independent(2))[0], self._held(self._independent(16))[0])

    @a_property_of_the_pin_itself
    def test_an_inlined_call_comparing_the_global_object_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._comparing_the_global_object(2))[0],
            self._held(self._comparing_the_global_object(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_a_name_each_function_binds_anew_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._holding_the_parameter(2))[0],
            self._held(self._holding_the_parameter(16))[0],
        )

    @todo
    @a_property_of_the_pin_itself
    def test_a_value_reading_a_name_nothing_declares_needs_no_new_models(self):
        declaration = '{a: FREE + "/INDEX", b: INDEX}'
        self.assertEqual(
            self._held(self._scopes(2, declaration, 'O.a + O.b'))[0],
            self._held(self._scopes(16, declaration, 'O.a + O.b'))[0],
        )

    @a_property_of_the_pin_itself
    def test_an_object_declined_for_a_value_it_allocates_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._holding_the_parameter_beside_an_array(2))[0],
            self._held(self._holding_the_parameter_beside_an_array(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_inlined_calls_handing_names_on_to_another_call_need_no_new_models(self):
        self.assertEqual(
            self._held(self._handing_names_on_to_a_call(2))[0],
            self._held(self._handing_names_on_to_a_call(16))[0],
        )

    @a_property_of_the_pin_itself
    def test_strings_copied_into_keys_renew_the_models_at_most_once_per_object(self):
        renewals = self._held(self._copying_strings_into_keys(16))[0] - 1
        self.assertLessEqual(renewals, 16)

    @a_property_of_the_pin_itself
    def test_strings_copied_into_keys_between_inlined_calls_renew_the_models_at_most_once_per_object(self):
        renewals = self._held(self._copying_strings_into_keys_between_inlined_calls(16))[0] - 1
        self.assertLessEqual(renewals, 16)

    @a_property_of_the_pin_itself
    def test_inlined_calls_reading_members_under_handed_strings_renew_the_models_at_most_once_per_object(self):
        renewals = self._held(self._inlining_calls_that_read_members_under_handed_strings(16))[0] - 1
        self.assertLessEqual(renewals, 16)

    @todo
    @a_property_of_the_pin_itself
    def test_a_parameter_copied_into_an_argument_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._reading_a_parameter(2, 'var O = {a: e, b: INDEX};', 'g(O.a, O.b)'))[0],
            self._held(self._reading_a_parameter(16, 'var O = {a: e, b: INDEX};', 'g(O.a, O.b)'))[0],
        )

    @todo
    @a_property_of_the_pin_itself
    def test_a_parameter_an_inlined_call_hands_into_a_variable_needs_no_new_models(self):
        declarations = 'var O = {or: function (a, b) { return a || b; }}; var x = O.or(e, INDEX);'
        self.assertEqual(
            self._held(self._reading_a_parameter(2, declarations, 'x'))[0],
            self._held(self._reading_a_parameter(16, declarations, 'x'))[0],
        )

    @todo
    @a_property_of_the_pin_itself
    def test_a_constant_string_joined_in_an_argument_needs_no_new_models(self):
        self.assertEqual(
            self._held(self._reading_a_parameter(2, 'var O = {a: "he", b: "llo", n: INDEX};', 'g(O.a + O.b, O.n)'))[0],
            self._held(self._reading_a_parameter(16, 'var O = {a: "he", b: "llo", n: INDEX};', 'g(O.a + O.b, O.n)'))[0],
        )

    @todo
    @a_property_of_the_pin_itself
    def test_numbers_copied_into_keys_of_a_parameter_need_no_new_models(self):
        self.assertEqual(
            self._held(self._reading_a_parameter(2, 'var O = {i: 0, j: INDEX};', 'e[O.i] + e[O.j]'))[0],
            self._held(self._reading_a_parameter(16, 'var O = {i: 0, j: INDEX};', 'e[O.i] + e[O.j]'))[0],
        )

    @todo
    @a_property_of_the_pin_itself
    def test_a_string_copied_into_a_key_beside_a_joining_call_renews_the_models_at_most_once_per_object(self):
        declarations = 'var O = {m: "log", add: function (a, b) { return a + b; }, k: INDEX};'
        renewals = self._held(self._reading_a_parameter(16, declarations, 'e[O.m](O.add("he", "llo"), O.k)'))[0] - 1
        self.assertLessEqual(renewals, 16)

    @a_property_of_the_pin_itself
    def test_released_models_are_built_more_often_for_sixteen_objects_than_for_two(self):
        self.assertLess(self._released(self._independent(2))[0], self._released(self._independent(16))[0])

    @a_property_of_the_pin_itself
    def test_released_an_object_read_eight_times_builds_the_models_more_often_than_one_read_once(self):
        self.assertLess(self._released(self._one_object_read(1))[0], self._released(self._one_object_read(8))[0])

    @a_property_of_the_pin_itself
    def test_an_object_read_eight_times_builds_the_models_as_often_as_one_read_once(self):
        self.assertEqual(self._held(self._one_object_read(1))[0], self._held(self._one_object_read(8))[0])

    def test_holding_the_models_does_not_change_the_result(self):
        for source in (self._independent(8), self._comparing_the_global_object(8)):
            held = self._held(source)[1]
            self.assertNotIn('var O', held)
            self.assertEqual(held, self._released(source)[1])

    def test_holding_the_models_does_not_change_the_result_of_a_fold_the_models_read(self):
        for source in self._FOLDS_THE_MODELS_READ:
            with self.subTest(source=source):
                self.assertEqual(self._held(source)[1], self._released(source)[1])


#: The generated corpus, and programs on which every pass that pins or batches the models makes at
#: least one rewrite.
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
    generator_fixtures.TestGeneratorCFFUnflattening.PROTOTYPE_KEPT_IN_A_SLOT_BEFORE_A_SIBLING_READS_IT_CFF,
    generator_fixtures.TestGeneratorCFFUnflattening.PROTOTYPE_WRITTEN_THROUGH_A_NAME_FROM_OUTSIDE_BEFORE_A_SIBLING_READS_IT_CFF,
    generator_fixtures.TestGeneratorCFFUnflattening.RECOVERED_FUNCTION_DECLARING_A_NAME_A_SIBLING_DECLARES_CFF,
    'var B = {f: function (p) { return p + 1; }}; var C = {y: 2}; console.log(B.f(C.y));',
    'var A = {g: globalThis}; var w = A.g; var C = {x: 1}; w.C = {x: 5}; console.log(C.x);',
    'var B = {x: 1}; function f() { var A = {b: B}; return A.b.x; } console.log(f(), B.x);',
    'var A = {g: globalThis}; var C = {x: 1}; console.log(A.g.C.x); console.log(C.x);',
    'var A = {o: Object}; Object.defineProperty(A.o.prototype, "k", {value: 1}); var B = {x: 1}; console.log(B.k);',
    'var A = {k: "C"}; var C = {x: 1}; globalThis[A.k] = {x: 5}; console.log(C.x);',
)


class TestPinnedAndUnpinnedRunsAgree(TestBase):

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

        def fork(self) -> PipelineObserver:
            return self

    def test_every_change_the_corpus_announces_moved_the_counter(self):
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                recorder = self._Recorder()
                deobfuscate(JsParser(source).parse(), observer=recorder)
                self.assertEqual([], recorder.unsited)


@a_property_of_the_pin_itself
class TestAKeptModelDescribesTheProgramItOutlivedThePinOn(TestBase):

    def _models_kept_past_a_changed_program(self, source: str) -> int:
        kept_stale = 0
        programs: dict[ModelCache, object] = {}
        original = ModelCache.pinned
        original_renew = ModelCache.renew

        @contextmanager
        def audited(self: ModelCache):
            nonlocal kept_stale
            outermost = not self._pins
            if outermost:
                programs[self] = canonical(self.root)
            with original(self) as pinned:
                yield pinned
            if outermost and self._model is not None and canonical(self.root) != programs.pop(self):
                kept_stale += 1

        def renewed(self: ModelCache, *slots: str):
            original_renew(self, *slots)
            if self._pins and self in programs:
                programs[self] = canonical(self.root)

        ModelCache.pinned = audited
        ModelCache.renew = renewed
        try:
            deobfuscate_source(source)
        finally:
            ModelCache.pinned = original
            ModelCache.renew = original_renew
        return kept_stale

    def test_no_model_in_the_corpus_is_kept_past_a_program_change(self):
        for index, source in enumerate(_CORPUS):
            with self.subTest(sample=index):
                self.assertEqual(0, self._models_kept_past_a_changed_program(source))


@a_property_of_the_pin_itself
class TestAHeldModelPlacesEveryNodeWhereItWasBuilt(TestBase):

    def _held_answers(self, source: str) -> tuple[int, list[str]]:
        entries: list[tuple[ModelCache, int, dict[int, tuple[Node, Node | None]]]] = []
        compared = 0
        misplaced: list[str] = []
        original_pinned = ModelCache.pinned
        original_renew = ModelCache.renew
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

        def renewed(self: ModelCache, *slots: str):
            original_renew(self, *slots)
            if self._pins and entries and entries[-1][0] is self:
                parents = {id(node): (node, node.parent) for node in self.root.walk()}
                entries[-1] = (self, tree_version(self.root), parents)

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
        ModelCache.renew = renewed
        ElementLocator.locate = audited
        try:
            deobfuscate_source(source)
        finally:
            ModelCache.pinned = original_pinned
            ModelCache.renew = original_renew
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
