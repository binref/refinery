"""
Tests for the shared AST mutation surface: the version contract every structural edit owes the
analysis caches, and the batching primitive that keeps a multi-edit pass from advancing the counter
once per edit.
"""
from __future__ import annotations

import unittest

from dataclasses import dataclass, field
from refinery.lib.scripts import (
    BodyEdit,
    Node,
    Script,
    Statement,
    Transformer,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
    mutation_epoch,
    set_body,
    set_child,
    set_child_list,
    set_value,
    tree_version,
)


@dataclass(repr=False, eq=False)
class _Leaf(Statement):
    name: str = ''


@dataclass(repr=False, eq=False)
class _Holder(Node):
    child: Node | None = None
    items: list[Node] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class _LateHolder(Node):
    items: list[Node] | None = None


def _script(*names: str) -> Script:
    script = Script()
    set_child_list(script, 'body', [_Leaf(name=name) for name in names])
    return script


def _names(script: Script) -> list[str]:
    return [stmt.name for stmt in script.body]


class TestTreeVersionContract(unittest.TestCase):
    """
    Every structural edit has to advance the counter of the tree it edits, because
    `refinery.lib.scripts.modelcache.ModelCacheBase` reads that counter to decide whether the models
    it holds still describe the tree. An edit that leaves the counter alone hands the next consumer
    a model of a tree that no longer exists.
    """

    def test_replacing_a_child_node_advances_the_counter(self):
        holder = _Holder(child=_Leaf(name='a'))
        before = tree_version(holder)
        set_child(holder, 'child', _Leaf(name='b'))
        self.assertGreater(tree_version(holder), before)

    def test_clearing_a_child_node_advances_the_counter(self):
        holder = _Holder(child=_Leaf(name='a'))
        before = tree_version(holder)
        set_child(holder, 'child', None)
        self.assertIsNone(holder.child)
        self.assertGreater(tree_version(holder), before)

    def test_a_replaced_child_is_adopted(self):
        holder = _Holder(child=_Leaf(name='a'))
        replacement = _Leaf(name='b')
        set_child(holder, 'child', replacement)
        self.assertIs(replacement.parent, holder)

    def test_a_visitor_replacement_advances_the_counter(self):
        class _Rename(Transformer):
            def visit__Leaf(self, node: _Leaf):
                return _Leaf(name=node.name.upper())

        script = _script('a', 'b')
        before = tree_version(script)
        _Rename().visit(script)
        self.assertEqual(_names(script), ['A', 'B'])
        self.assertGreater(tree_version(script), before)

    def test_a_visitor_replacement_in_a_direct_field_advances_the_counter(self):
        class _Rename(Transformer):
            def visit__Leaf(self, node: _Leaf):
                return _Leaf(name=node.name.upper())

        holder = _Holder(child=_Leaf(name='a'))
        holder.child.parent = holder
        before = tree_version(holder)
        _Rename().visit(holder)
        self.assertEqual(holder.child.name, 'A')
        self.assertGreater(tree_version(holder), before)

    def test_a_visitor_that_changes_nothing_leaves_the_counter_alone(self):
        class _Nothing(Transformer):
            def visit__Leaf(self, node: _Leaf):
                return None

        script = _script('a', 'b')
        before = tree_version(script)
        _Nothing().visit(script)
        self.assertEqual(tree_version(script), before)

    def test_an_edit_leaves_an_unrelated_tree_alone(self):
        script = _script('a')
        other = _script('b')
        before = tree_version(other)
        set_child_list(script, 'body', [_Leaf(name='c')])
        self.assertEqual(tree_version(other), before)


class TestMutationEpochContract(unittest.TestCase):
    """
    The epoch is what a cache reads that holds answers about nodes rather than about one tree: such
    a cache cannot ask `tree_version` of a root it does not have, and an edit to a tree it never
    looked at can still be an edit to a node it answered for. It therefore has to move for every
    mutation made anywhere, which is the one way it differs from `tree_version`.
    """

    def test_replacing_a_child_node_advances_the_epoch(self):
        holder = _Holder(child=_Leaf(name='a'))
        before = mutation_epoch()
        set_child(holder, 'child', _Leaf(name='b'))
        self.assertGreater(mutation_epoch(), before)

    def test_replacing_a_child_list_advances_the_epoch(self):
        holder = _Holder()
        before = mutation_epoch()
        set_child_list(holder, 'items', [_Leaf(name='a')])
        self.assertGreater(mutation_epoch(), before)

    def test_replacing_a_body_advances_the_epoch(self):
        script = _script('a')
        before = mutation_epoch()
        set_body(script, [_Leaf(name='b')])
        self.assertEqual(_names(script), ['b'])
        self.assertGreater(mutation_epoch(), before)

    def test_replacing_a_value_field_advances_the_epoch(self):
        script = _script('a')
        before = mutation_epoch()
        set_value(script.body[0], 'name', 'b')
        self.assertEqual(_names(script), ['b'])
        self.assertGreater(mutation_epoch(), before)

    def test_a_batch_of_removals_advances_the_epoch_once(self):
        script = _script('a', 'b', 'c', 'd')
        before = mutation_epoch()
        edit = BodyEdit(script)
        edit.splice(script.body[0], [])
        edit.splice(script.body[2], [])
        self.assertTrue(edit.apply())
        self.assertEqual(_names(script), ['b', 'd'])
        self.assertEqual(mutation_epoch(), before + 1)

    def test_a_visitor_replacement_advances_the_epoch(self):
        class _Rename(Transformer):
            def visit__Leaf(self, node: _Leaf):
                return _Leaf(name=node.name.upper())

        script = _script('a', 'b')
        before = mutation_epoch()
        _Rename().visit(script)
        self.assertEqual(_names(script), ['A', 'B'])
        self.assertGreater(mutation_epoch(), before)

    def test_a_changed_announcement_advances_the_epoch(self):
        """
        A pass that writes a field directly and announces the fact through `changed` owes the
        per-node caches the same protection the announcement already owes the model caches.
        """
        class _Announce(Transformer):
            def visit__Leaf(self, node: _Leaf):
                self.mark_changed()
                return None

        script = _script('a')
        before = mutation_epoch()
        _Announce().visit(script)
        self.assertGreater(mutation_epoch(), before)

    def test_an_edit_to_one_tree_advances_the_epoch_of_a_reader_of_another(self):
        script = _script('a')
        other = _script('b')
        version = tree_version(other)
        epoch = mutation_epoch()
        set_child_list(script, 'body', [_Leaf(name='c')])
        self.assertEqual(tree_version(other), version)
        self.assertGreater(mutation_epoch(), epoch)

    def test_a_visitor_that_replaces_nothing_leaves_the_epoch_alone(self):
        class _Nothing(Transformer):
            def visit__Leaf(self, node: _Leaf):
                return None

        script = _script('a', 'b')
        before = mutation_epoch()
        _Nothing().visit(script)
        self.assertEqual(mutation_epoch(), before)

    def test_reading_a_tree_leaves_the_epoch_alone(self):
        script = _script('a', 'b')
        before = mutation_epoch()
        self.assertEqual(_names(script), ['a', 'b'])
        self.assertEqual(len(list(script.walk())), 3)
        self.assertEqual(script.children(), tuple(script.body))
        self.assertEqual(tree_version(script), tree_version(script))
        self.assertEqual(mutation_epoch(), before)

    def test_building_nodes_that_are_attached_to_nothing_leaves_the_epoch_alone(self):
        before = mutation_epoch()
        leaf = _Leaf(name='a')
        holder = _Holder(child=leaf, items=[_Leaf(name='b')])
        self.assertIs(holder.child, leaf)
        self.assertIsInstance(Script(), Script)
        self.assertEqual(mutation_epoch(), before)


class TestReplaceInParent(unittest.TestCase):
    """
    A caller that turns tree edits into a `Transformer.changed` flag needs to know whether the edit
    happened. Reporting nothing on success reads as "nothing moved", which leaves the pipeline
    calling a pass stable while the mutation counter has already advanced past it.
    """

    def test_replacing_a_direct_field_reports_success(self):
        holder = _Holder(child=_Leaf(name='a'))
        self.assertTrue(_replace_in_parent(holder.child, _Leaf(name='b')))
        self.assertEqual(holder.child.name, 'b')

    def test_replacing_a_list_item_reports_success(self):
        script = _script('a', 'b')
        self.assertTrue(_replace_in_parent(script.body[0], _Leaf(name='c')))
        self.assertEqual(_names(script), ['c', 'b'])

    def test_replacing_a_parentless_node_reports_failure(self):
        self.assertFalse(_replace_in_parent(_Leaf(name='a'), _Leaf(name='b')))

    def test_replacing_a_node_its_parent_no_longer_holds_reports_failure(self):
        script = _script('a')
        orphan = script.body[0]
        set_child_list(script, 'body', [_Leaf(name='b')])
        self.assertFalse(_replace_in_parent(orphan, _Leaf(name='c')))

    def test_a_successful_replacement_advances_the_counter(self):
        script = _script('a')
        before = tree_version(script)
        _replace_in_parent(script.body[0], _Leaf(name='b'))
        self.assertGreater(tree_version(script), before)


class TestBodyEdit(unittest.TestCase):

    def test_a_batch_of_removals_advances_the_counter_once(self):
        script = _script('a', 'b', 'c', 'd')
        before = tree_version(script)
        edit = BodyEdit(script)
        edit.splice(script.body[0], [])
        edit.splice(script.body[2], [])
        self.assertTrue(edit.apply())
        self.assertEqual(_names(script), ['b', 'd'])
        self.assertEqual(tree_version(script), before + 1)

    def test_a_replacement_expands_in_place(self):
        script = _script('a', 'b')
        edit = BodyEdit(script)
        edit.splice(script.body[0], [_Leaf(name='x'), _Leaf(name='y')])
        edit.apply()
        self.assertEqual(_names(script), ['x', 'y', 'b'])

    def test_replacements_are_adopted(self):
        script = _script('a')
        replacement = _Leaf(name='x')
        edit = BodyEdit(script)
        edit.splice(script.body[0], [replacement])
        edit.apply()
        self.assertIs(replacement.parent, script)

    def test_an_empty_batch_leaves_the_tree_and_the_counter_alone(self):
        script = _script('a', 'b')
        before = tree_version(script)
        self.assertFalse(BodyEdit(script).apply())
        self.assertEqual(_names(script), ['a', 'b'])
        self.assertEqual(tree_version(script), before)

    def test_a_batch_of_identity_splices_leaves_the_counter_alone(self):
        script = _script('a', 'b')
        before = tree_version(script)
        edit = BodyEdit(script)
        for stmt in script.body:
            edit.splice(stmt, [stmt])
        self.assertFalse(edit.apply())
        self.assertEqual(tree_version(script), before)

    def test_splices_are_keyed_by_identity_not_equality(self):
        twin = _Leaf(name='a')
        script = Script()
        set_child_list(script, 'body', [twin, _Leaf(name='a')])
        edit = BodyEdit(script)
        edit.splice(script.body[1], [])
        edit.apply()
        self.assertEqual(len(script.body), 1)
        self.assertIs(script.body[0], twin)

    def test_a_splice_for_a_foreign_node_is_ignored(self):
        script = _script('a', 'b')
        edit = BodyEdit(script)
        edit.splice(_Leaf(name='elsewhere'), [_Leaf(name='x')])
        self.assertFalse(edit.apply())
        self.assertEqual(_names(script), ['a', 'b'])

    def test_result_does_not_touch_the_tree(self):
        script = _script('a', 'b')
        before = tree_version(script)
        edit = BodyEdit(script)
        edit.splice(script.body[0], [])
        self.assertEqual([stmt.name for stmt in edit.result()], ['b'])
        self.assertEqual(_names(script), ['a', 'b'])
        self.assertEqual(tree_version(script), before)

    def test_the_later_splice_for_a_node_wins(self):
        script = _script('a', 'b')
        edit = BodyEdit(script)
        edit.splice(script.body[0], [])
        edit.splice(script.body[0], [_Leaf(name='x')])
        edit.apply()
        self.assertEqual(_names(script), ['x', 'b'])

    def test_the_spliced_list_object_is_the_one_the_tree_already_held(self):
        script = _script('a', 'b')
        held = script.body
        edit = BodyEdit(script)
        edit.splice(script.body[0], [])
        edit.apply()
        self.assertIs(script.body, held)


class TestChildrenMemo(unittest.TestCase):
    """
    `Node.children` is the reader every walker and every model descends through, so it owes each
    mutation the answer a fresh reflection over the node's fields would give. Each test populates
    the memo first — a mutation that arrives before any read has nothing to invalidate — and then
    asks again after the mutation.
    """

    def _names(self, script: Script) -> list[str]:
        return [stmt.name for stmt in script.children()]

    def test_a_replaced_body_is_answered_by_children(self):
        script = _script('a', 'b')
        self.assertEqual(self._names(script), ['a', 'b'])
        set_body(script, [_Leaf(name='c')])
        self.assertEqual(self._names(script), ['c'])

    def test_a_spliced_entry_is_answered_by_children(self):
        script = _script('a', 'b', 'c')
        self.assertEqual(self._names(script), ['a', 'b', 'c'])
        edit = BodyEdit(script)
        edit.splice(script.body[1], [_Leaf(name='x')])
        edit.apply()
        self.assertEqual(self._names(script), ['a', 'x', 'c'])

    def test_a_replaced_child_is_answered_by_children(self):
        holder = _Holder(child=_Leaf(name='a'))
        self.assertEqual(holder.children(), (holder.child,))
        set_child(holder, 'child', _Leaf(name='b'))
        self.assertEqual(holder.children(), (holder.child,))

    def test_a_replaced_list_item_is_answered_by_children(self):
        script = _script('a', 'b')
        self.assertEqual(self._names(script), ['a', 'b'])
        _replace_in_parent(script.body[0], _Leaf(name='c'))
        self.assertEqual(self._names(script), ['c', 'b'])

    def test_a_removed_child_is_answered_by_children(self):
        script = _script('a', 'b')
        self.assertEqual(self._names(script), ['a', 'b'])
        _remove_from_parent(script.body[0])
        self.assertEqual(self._names(script), ['b'])

    def test_a_raw_write_announced_through_changed_is_answered_by_children(self):
        """
        The dispatcher shape: a transform that writes a list directly and then announces the fact.
        `changed` has to cover the memo for exactly as long as it covers the model caches.
        """
        class _RawWrite(Transformer):
            def visit_Script(self, node: Script):
                node.body.pop()
                self.mark_changed()
                return None

        script = _script('a', 'b')
        self.assertEqual(self._names(script), ['a', 'b'])
        _RawWrite().visit(script)
        self.assertEqual(self._names(script), ['a'])

    def test_a_clone_answers_with_the_clones_children(self):
        script = _script('a')
        source_child = script.children()[0]
        clone = _clone_node(script)
        clone_child = clone.children()[0]
        self.assertIsNot(clone_child, source_child)
        self.assertIs(clone_child.parent, clone)
        set_body(clone, [_Leaf(name='z')])
        self.assertEqual([stmt.name for stmt in clone.children()], ['z'])

    def test_the_memo_is_not_mistaken_for_a_child_container(self):
        """
        The memo lives in the instance `__dict__` beside the node's fields, and the parent scanners
        read every list-valued attribute of a parent as a child container. A memo a scanner mistook
        for one would refuse every edit.
        """
        script = _script('a', 'b')
        self.assertEqual(self._names(script), ['a', 'b'])
        holder = _Holder(child=_Leaf(name='a'))
        self.assertEqual(holder.children(), (holder.child,))
        self.assertTrue(_replace_in_parent(holder.child, _Leaf(name='b')))
        self.assertTrue(_remove_from_parent(script.body[0]))
        self.assertEqual(self._names(script), ['b'])


class TestChildListOwnership(unittest.TestCase):
    """
    `set_child_list` splices the tree's own list object where it finds one, and installs a copy
    where it finds none. Either way, the caller that handed the list in keeps no handle on the
    tree: an append to the list a caller still holds must not appear among the node's children
    without a mutation.
    """

    def test_a_field_that_holds_no_list_yet_gets_a_copy_of_the_callers_list(self):
        holder = _LateHolder()
        items = [_Leaf(name='a')]
        set_child_list(holder, 'items', items)
        items.append(_Leaf(name='b'))
        self.assertEqual([stmt.name for stmt in holder.items], ['a'])
        self.assertEqual([stmt.name for stmt in holder.children()], ['a'])

    def test_an_existing_field_keeps_the_object_the_tree_held(self):
        script = _script('a')
        held = script.body
        set_child_list(script, 'body', [_Leaf(name='b')])
        self.assertIs(script.body, held)


class TestNullableChildList(unittest.TestCase):
    """
    A child list declared nullable — `list[Node] | None`, the shape of a `finally` body a `try` need
    not have — is a child list all the same: reflection classifies it, construction adopts into
    it, and cloning copies it rather than handing both trees the one list.
    """

    def test_the_nodes_of_a_nullable_list_belong_to_the_tree(self):
        holder = _LateHolder(items=[_Leaf(name='a')])
        self.assertEqual([stmt.name for stmt in holder.children()], ['a'])
        self.assertIs(holder.children()[0].parent, holder)

    def test_a_nullable_list_that_holds_nothing_is_nothing(self):
        holder = _LateHolder()
        self.assertEqual(holder.children(), ())
        self.assertIsNone(_clone_node(holder).items)

    def test_a_clone_of_a_nullable_list_holds_copies(self):
        holder = _LateHolder(items=[_Leaf(name='a')])
        clone = _clone_node(holder)
        self.assertIsNot(clone.items[0], holder.items[0])
        self.assertIs(clone.items[0].parent, clone)


if __name__ == '__main__':
    unittest.main()
