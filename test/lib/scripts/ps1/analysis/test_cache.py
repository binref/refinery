from __future__ import annotations

import ast as pyast

from test import TestBase

from refinery.lib.scripts import Transformer, _remove_from_parent, set_body, set_child_list
from refinery.lib.scripts.ps1.analysis import dataflow
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache, model_cache
from refinery.lib.scripts.ps1.analysis.model import is_write_occurrence
from refinery.lib.scripts.ps1.model import Ps1IfStatement, Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1ModelCache(TestBase):

    @staticmethod
    def _script(source: str):
        return Ps1Parser(source).parse()

    def test_model_is_memoized_while_the_tree_is_unchanged(self):
        cache = Ps1ModelCache(self._script("$a = 1\n$b = 2"))
        first = cache.model
        self.assertIs(cache.model, first)

    def test_mutating_the_cached_tree_rebuilds_the_model(self):
        script = self._script("$a = 1\n$b = 2")
        cache = Ps1ModelCache(script)
        first = cache.model
        _remove_from_parent(script.body[0])
        self.assertIsNot(cache.model, first)

    def test_cycles_are_memoized_while_the_tree_is_unchanged(self):
        cache = Ps1ModelCache(self._script("while ($x) { $a = 1 }"))
        first = cache.cycles
        self.assertIs(cache.cycles, first)

    def test_mutating_the_cached_tree_rebuilds_the_cycles(self):
        """
        The cycle sets are read off the control-flow graphs, which are keyed to node identity, so a
        model kept across a mutation would answer about statements the tree no longer holds.
        """
        script = self._script("while ($x) { $a = 1 }\n$b = 2")
        cache = Ps1ModelCache(script)
        first = cache.cycles
        _remove_from_parent(script.body[1])
        self.assertIsNot(cache.cycles, first)

    def test_dominance_is_memoized_while_the_tree_is_unchanged(self):
        cache = Ps1ModelCache(self._script("$a = 1\n$b = 2"))
        first = cache.dominance
        self.assertIs(cache.dominance, first)

    def test_mutating_the_cached_tree_rebuilds_the_dominance(self):
        """
        The dominator trees are computed over the control-flow graphs, which are keyed to node
        identity, so a model kept across a mutation would order statements the tree no longer holds.
        """
        script = self._script("$a = 1\n$b = 2")
        cache = Ps1ModelCache(script)
        first = cache.dominance
        _remove_from_parent(script.body[1])
        self.assertIsNot(cache.dominance, first)

    def test_variable_flow_from_the_cache_resolves_the_only_write(self):
        script = self._script("$x = 'a'; Write-Host $x")
        cache = Ps1ModelCache(script)
        occurrences = [
            node for node in script.walk()
            if isinstance(node, Ps1Variable) and node.name.lower() == 'x'
        ]
        write = next(node for node in occurrences if is_write_occurrence(node))
        read = next(node for node in occurrences if not is_write_occurrence(node))
        self.assertIs(cache.variable_flow.reaching_definition(read), write)

    def test_mutating_an_unrelated_tree_keeps_the_cached_model(self):
        cache = Ps1ModelCache(self._script("$a = 1\n$b = 2"))
        first = cache.model
        unrelated = self._script("$c = 3\n$d = 4")
        _remove_from_parent(unrelated.body[0])
        self.assertIs(cache.model, first)

    def test_body_splice_advances_the_version_and_rebuilds(self):
        # A whole-body rewrite through the counter-bumping splice helper must invalidate the
        # cache the same way a per-node removal does.
        script = self._script("$a = 1\n$b = 2")
        cache = Ps1ModelCache(script)
        first = cache.model
        set_body(script, list(script.body[:1]))
        self.assertIsNot(cache.model, first)

    def test_body_splice_keeps_the_list_object(self):
        # The splice is in place: a transform that kept a reference to the list it was handed
        # must go on observing the node's current children rather than a detached snapshot.
        script = self._script("$a = 1\n$b = 2")
        body = script.body
        set_body(script, list(script.body[:1]))
        self.assertIs(script.body, body)
        self.assertEqual(len(body), 1)

    def test_clause_splice_adopts_the_nodes_inside_tuples(self):
        # An if-statement clause is a (condition, block) tuple; both halves are children of the
        # statement and must be adopted by a splice of the clause list.
        script = self._script('if ($a) { $b = 1 } elseif ($c) { $d = 2 }')
        statement = script.body[0]
        assert isinstance(statement, Ps1IfStatement)
        condition, block = statement.clauses[1]
        set_child_list(statement, 'clauses', [(condition, block)])
        self.assertIs(condition.parent, statement)
        self.assertIs(block.parent, statement)

    def test_model_cache_reuses_the_stash_by_root_identity(self):
        script = self._script("$a = 1")
        transformer = Transformer()
        first = model_cache(transformer, script)
        self.assertIs(model_cache(transformer, script), first)

    def test_model_cache_rebuilds_for_a_different_root(self):
        transformer = Transformer()
        first = model_cache(transformer, self._script("$a = 1"))
        self.assertIsNot(model_cache(transformer, self._script("$b = 2")), first)


def _spelled_callee(call: pyast.Call) -> str | None:
    func = call.func
    if isinstance(func, pyast.Name):
        return func.id
    if isinstance(func, pyast.Attribute):
        return func.attr
    return None


class TestPs1DataflowDominanceWiring(TestBase):

    def test_dataflow_never_constructs_the_shared_dominator_model(self):
        """
        `Ps1VariableFlow` receives the run's dominator model from the cache, so every pass shares
        one instance; a `DominatorModel(...)` call inside the module would quietly hand it a private
        copy again. Importing the name for annotations is fine — the call is what may not reappear.
        """
        with open(dataflow.__file__, 'r', encoding='utf-8') as fd:
            tree = pyast.parse(fd.read(), filename=dataflow.__file__)
        constructions = [
            node.lineno for node in pyast.walk(tree)
            if isinstance(node, pyast.Call) and _spelled_callee(node) == 'DominatorModel'
        ]
        self.assertEqual(constructions, [])
