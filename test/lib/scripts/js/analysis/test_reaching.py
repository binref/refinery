from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.model import JsIdentifier, JsVariableDeclarator
from refinery.lib.scripts.js.parser import JsParser


class TestReaching(TestBase):

    def _query(self, source: str, name: str = 'x') -> bool:
        """
        Whether the value of the first declarator named *name* reaches its first read unchanged, as
        `ReachingModel.value_preserved` reports it. Every case below is single-read, so the first read is
        the use under test.
        """
        ast = JsParser(source).parse()
        cache = ModelCache(ast)
        declarator = next(
            node for node in ast.walk_in_order()
            if isinstance(node, JsVariableDeclarator)
            and isinstance(node.id, JsIdentifier)
            and node.id.name == name
        )
        assert isinstance(declarator.id, JsIdentifier) and declarator.init is not None
        binding = cache.model.binding_of(declarator.id)
        assert binding is not None
        return cache.reaching.value_preserved(binding, declarator.init, binding.reads[0])

    def test_reaches_with_no_barrier(self):
        self.assertTrue(self._query('var x = 1; x;'))

    def test_does_not_reach_when_use_not_dominated(self):
        self.assertFalse(self._query('if (c) { var x = 1; } x;'))

    def test_does_not_reach_across_same_statement(self):
        """
        The use in `y = x` shares the definition's statement, which statement granularity cannot order,
        so the value is not reported as reaching it — the conservative verdict that keeps `var y = x,
        x = 1` from folding `y` to `1` when `x` is undefined at the read.
        """
        self.assertFalse(self._query('var y = x, x = 1;'))

    def test_does_not_reach_past_mutating_call(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } m(); x;'))

    def test_reaches_read_before_mutating_call(self):
        self.assertTrue(self._query('var x = 1; function m() { x = 2; } x; m();'))

    def test_does_not_reach_past_transitive_mutating_call(self):
        self.assertFalse(self._query(
            'var x = 1;'
            ' function inner() { x = 2; }'
            ' function outer() { inner(); }'
            ' outer(); x;'
        ))

    def test_does_not_reach_across_loop_back_edge_to_a_mutating_call(self):
        """
        `m()` runs at the end of each iteration and the loop edge carries control back to the read, so a
        later iteration sees the mutated value — the kill is on a path back to the use.
        """
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } while (c) { x; m(); }'))

    def test_reaches_across_sibling_branch_mutating_call(self):
        """
        `m()` is on the branch the read is not on and cannot reach it, so the value still holds at the
        read — a precision statement position could not express.
        """
        self.assertTrue(self._query('var x = 1; function m() { x = 2; } if (c) { m(); } else { x; }'))

    def test_does_not_reach_past_mutating_call_sharing_definition_statement(self):
        self.assertFalse(self._query('function m() { x = 2; } var x = 1, y = m(); x;'))

    def test_does_not_reach_past_mutating_call_sharing_use_statement(self):
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } foo(m(), x);'))

    def test_does_not_reach_past_mutating_call_on_exceptional_edge(self):
        """
        `m()` may throw after changing the value, and the only path from it to the catch-bound read is
        the exceptional edge, which the reachability follows — so the kill lies between.
        """
        self.assertFalse(self._query('var x = 1; function m() { x = 2; } try { m(); } catch (e) { x; }'))

    def test_reaches_past_call_that_does_not_mutate(self):
        self.assertTrue(self._query('var x = 1; function m() { y = 2; } m(); x;'))

    def test_does_not_reach_when_a_mutator_escapes(self):
        """
        `m` is aliased, so it can be invoked at a point no call site enumerates; the value of `x` it
        writes could change anywhere, so no read is reported as reached.
        """
        self.assertFalse(self._query(
            'var x = 1; function m() { x = 2; } var alias = m; x;'
        ))
