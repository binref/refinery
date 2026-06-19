from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.cfg import ControlFlowGraph, build_cfg, build_control_flow
from refinery.lib.scripts.js.model import (
    JsBreakStatement,
    JsCatchClause,
    JsContinueStatement,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsIfStatement,
    JsReturnStatement,
    JsWhileStatement,
)
from refinery.lib.scripts.js.parser import JsParser

_CORPUS = [
    'a; b; c;',
    'if (x) { a; } else { b; } c;',
    'if (x) a;',
    'while (x) { a; b; }',
    'do { a; } while (x); b;',
    'for (var i = 0; i < n; i++) { a; }',
    'for (;;) { a; if (x) break; }',
    'for (k in obj) { a; }',
    'for (var v of items) { a; }',
    'switch (x) { case 1: a; break; case 2: b; default: c; }',
    'try { a; } catch (e) { b; } finally { c; }',
    'try { a; } finally { b; }',
    'outer: for (;;) { inner: for (;;) { continue outer; break inner; } }',
    'function f() { a; return b; } g();',
    'while (x) { if (y) continue; a; }',
    'label: { a; if (x) break label; b; }',
    'return; dead;',
    'throw e; dead;',
    'with (o) { a; }',
]


class TestControlFlowGraph(TestBase):

    @staticmethod
    def _cfg(source: str):
        ast = JsParser(source).parse()
        return ast, build_cfg(ast)

    @staticmethod
    def _first(ast, kind):
        return next(n for n in ast.walk_in_order() if isinstance(n, kind))

    @staticmethod
    def _reachable(cfg: ControlFlowGraph):
        seen: set[int] = set()
        stack = [cfg.entry]
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(node.successors)
        return seen

    def _assert_consistent(self, cfg: ControlFlowGraph):
        identities = {id(node) for node in cfg.nodes}
        for node in cfg.nodes:
            for successor in node.successors:
                self.assertIn(id(successor), identities)
                self.assertIn(node, successor.predecessors)
            for predecessor in node.predecessors:
                self.assertIn(id(predecessor), identities)
                self.assertIn(node, predecessor.successors)

    def test_every_graph_is_internally_consistent(self):
        for source in _CORPUS:
            ast = JsParser(source).parse()
            for cfg in build_control_flow(ast).values():
                self._assert_consistent(cfg)

    def test_entry_has_no_predecessors_and_exit_no_successors(self):
        for source in _CORPUS:
            _, cfg = self._cfg(source)
            self.assertEqual(cfg.entry.predecessors, [])
            self.assertEqual(cfg.exit.successors, [])

    def test_sequential_statements_form_a_chain(self):
        ast, cfg = self._cfg('a; b;')
        a, b = (n for n in ast.walk_in_order() if isinstance(n, JsExpressionStatement))
        na, nb = cfg.node_of(a), cfg.node_of(b)
        assert na is not None and nb is not None
        self.assertIn(na, cfg.entry.successors)
        self.assertIn(nb, na.successors)
        self.assertIn(cfg.exit, nb.successors)

    def test_if_else_branches_rejoin(self):
        ast, cfg = self._cfg('if (x) { a; } else { b; } c;')
        node = cfg.node_of(self._first(ast, JsIfStatement))
        a, b, c = (n for n in ast.walk_in_order() if isinstance(n, JsExpressionStatement))
        assert node is not None
        succ = {id(s) for s in node.successors}
        self.assertEqual(succ, {id(cfg.node_of(a)), id(cfg.node_of(b))})
        self.assertIn(cfg.node_of(c), cfg.node_of(a).successors)
        self.assertIn(cfg.node_of(c), cfg.node_of(b).successors)

    def test_if_without_else_falls_through(self):
        ast, cfg = self._cfg('if (x) a; b;')
        node = cfg.node_of(self._first(ast, JsIfStatement))
        a, b = (n for n in ast.walk_in_order() if isinstance(n, JsExpressionStatement))
        assert node is not None
        self.assertIn(cfg.node_of(a), node.successors)
        self.assertIn(cfg.node_of(b), node.successors)
        self.assertIn(cfg.node_of(b), cfg.node_of(a).successors)

    def test_while_loop_has_back_edge(self):
        ast, cfg = self._cfg('while (x) { a; }')
        head = cfg.node_of(self._first(ast, JsWhileStatement))
        body = cfg.node_of(self._first(ast, JsExpressionStatement))
        assert head is not None and body is not None
        self.assertIn(body, head.successors)
        self.assertIn(head, body.successors)
        self.assertIn(cfg.exit, head.successors)

    def test_break_leaves_the_loop(self):
        ast, cfg = self._cfg('while (x) { break; } a;')
        head = cfg.node_of(self._first(ast, JsWhileStatement))
        brk = cfg.node_of(self._first(ast, JsBreakStatement))
        after = cfg.node_of(self._first(ast, JsExpressionStatement))
        assert head is not None and brk is not None and after is not None
        self.assertIn(after, brk.successors)
        self.assertNotIn(head, brk.successors)

    def test_continue_returns_to_loop_head(self):
        ast, cfg = self._cfg('while (x) { continue; }')
        head = cfg.node_of(self._first(ast, JsWhileStatement))
        cont = cfg.node_of(self._first(ast, JsContinueStatement))
        assert head is not None and cont is not None
        self.assertEqual(cont.successors, [head])

    def test_code_after_return_is_unreachable(self):
        ast, cfg = self._cfg('return; dead;')
        ret = cfg.node_of(self._first(ast, JsReturnStatement))
        dead = cfg.node_of(self._first(ast, JsExpressionStatement))
        assert ret is not None and dead is not None
        self.assertIn(cfg.exit, ret.successors)
        self.assertEqual(dead.predecessors, [])
        self.assertNotIn(id(dead), self._reachable(cfg))

    def test_try_block_has_exceptional_edge_to_handler(self):
        ast, cfg = self._cfg('try { a; } catch (e) { b; }')
        a = cfg.node_of(self._first(ast, JsExpressionStatement))
        handler = cfg.node_of(self._first(ast, JsCatchClause))
        assert a is not None and handler is not None
        self.assertIn(handler, a.successors)

    def test_nested_function_has_its_own_graph(self):
        ast = JsParser('function f() { a; return b; } g();').parse()
        graphs = build_control_flow(ast)
        func = self._first(ast, JsFunctionDeclaration)
        self.assertIn(id(func), graphs)
        script = graphs[id(ast)]
        body_stmt = func.body.body[0]
        self.assertIsNone(script.node_of(body_stmt))
        self.assertIsNotNone(graphs[id(func)].node_of(body_stmt))
