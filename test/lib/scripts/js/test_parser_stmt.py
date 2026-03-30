from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsBreakStatement,
    JsClassBody,
    JsClassDeclaration,
    JsContinueStatement,
    JsDebuggerStatement,
    JsDoWhileStatement,
    JsEmptyStatement,
    JsErrorNode,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsIfStatement,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsLabeledStatement,
    JsMethodDefinition,
    JsReturnStatement,
    JsScript,
    JsSwitchStatement,
    JsThrowStatement,
    JsTryStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    JsWithStatement,
)


class TestJsParserStatements(TestBase):

    def _parse_stmt(self, source: str):
        p = JsParser(source)
        script = p.parse()
        self.assertIsInstance(script, JsScript)
        self.assertTrue(len(script.body) > 0)
        return script.body[0]

    def _parse_all(self, source: str) -> JsScript:
        p = JsParser(source)
        return p.parse()

    def test_var_declaration(self):
        stmt = self._parse_stmt('var x = 1;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(stmt.kind, 'var')
        self.assertEqual(len(stmt.declarations), 1)

    def test_let_declaration(self):
        stmt = self._parse_stmt('let x = 1;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(stmt.kind, 'let')

    def test_const_declaration(self):
        stmt = self._parse_stmt('const x = 1;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(stmt.kind, 'const')

    def test_var_multiple(self):
        stmt = self._parse_stmt('var x = 1, y = 2;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(len(stmt.declarations), 2)

    def test_var_no_init(self):
        stmt = self._parse_stmt('var x;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        decl = stmt.declarations[0]
        self.assertIsInstance(decl, JsVariableDeclarator)
        self.assertIsNone(decl.init)

    def test_destructuring_array(self):
        stmt = self._parse_stmt('let [a, b] = arr;')
        self.assertIsInstance(stmt, JsVariableDeclaration)

    def test_destructuring_object(self):
        stmt = self._parse_stmt('const {x, y} = obj;')
        self.assertIsInstance(stmt, JsVariableDeclaration)

    def test_if_statement(self):
        stmt = self._parse_stmt('if (x) { y; }')
        self.assertIsInstance(stmt, JsIfStatement)
        self.assertIsNotNone(stmt.test)
        self.assertIsNotNone(stmt.consequent)
        self.assertIsNone(stmt.alternate)

    def test_if_else(self):
        stmt = self._parse_stmt('if (x) { 1; } else { 2; }')
        self.assertIsInstance(stmt, JsIfStatement)
        self.assertIsNotNone(stmt.alternate)

    def test_if_else_if(self):
        stmt = self._parse_stmt('if (a) { 1; } else if (b) { 2; } else { 3; }')
        self.assertIsInstance(stmt, JsIfStatement)
        self.assertIsInstance(stmt.alternate, JsIfStatement)

    def test_while(self):
        stmt = self._parse_stmt('while (x) { x--; }')
        self.assertIsInstance(stmt, JsWhileStatement)
        self.assertIsNotNone(stmt.test)
        self.assertIsNotNone(stmt.body)

    def test_do_while(self):
        stmt = self._parse_stmt('do { x++; } while (x < 10);')
        self.assertIsInstance(stmt, JsDoWhileStatement)

    def test_for_loop(self):
        stmt = self._parse_stmt('for (var i = 0; i < 10; i++) { }')
        self.assertIsInstance(stmt, JsForStatement)
        self.assertIsNotNone(stmt.init)
        self.assertIsNotNone(stmt.test)
        self.assertIsNotNone(stmt.update)

    def test_for_in(self):
        stmt = self._parse_stmt('for (var k in obj) { }')
        self.assertIsInstance(stmt, JsForInStatement)

    def test_for_of(self):
        stmt = self._parse_stmt('for (const x of arr) { }')
        self.assertIsInstance(stmt, JsForOfStatement)
        self.assertFalse(stmt.is_await)

    def test_for_await_of(self):
        stmt = self._parse_stmt('for await (const x of gen()) { }')
        self.assertIsInstance(stmt, JsForOfStatement)
        self.assertTrue(stmt.is_await)

    def test_switch(self):
        stmt = self._parse_stmt(
            'switch (x) { case 1: break; case 2: break; default: break; }')
        self.assertIsInstance(stmt, JsSwitchStatement)
        self.assertEqual(len(stmt.cases), 3)
        self.assertIsNone(stmt.cases[2].test)

    def test_try_catch(self):
        stmt = self._parse_stmt('try { } catch (e) { }')
        self.assertIsInstance(stmt, JsTryStatement)
        self.assertIsNotNone(stmt.block)
        self.assertIsNotNone(stmt.handler)
        self.assertIsNone(stmt.finalizer)

    def test_try_catch_finally(self):
        stmt = self._parse_stmt('try { } catch (e) { } finally { }')
        self.assertIsInstance(stmt, JsTryStatement)
        self.assertIsNotNone(stmt.handler)
        self.assertIsNotNone(stmt.finalizer)

    def test_try_finally(self):
        stmt = self._parse_stmt('try { } finally { }')
        self.assertIsInstance(stmt, JsTryStatement)
        self.assertIsNone(stmt.handler)
        self.assertIsNotNone(stmt.finalizer)

    def test_catch_no_binding(self):
        stmt = self._parse_stmt('try { } catch { }')
        self.assertIsInstance(stmt, JsTryStatement)
        self.assertIsNone(stmt.handler.param)

    def test_return(self):
        stmt = self._parse_stmt('return 42;')
        self.assertIsInstance(stmt, JsReturnStatement)
        self.assertIsNotNone(stmt.argument)

    def test_return_no_arg(self):
        stmt = self._parse_stmt('return;')
        self.assertIsInstance(stmt, JsReturnStatement)
        self.assertIsNone(stmt.argument)

    def test_throw(self):
        stmt = self._parse_stmt('throw new Error();')
        self.assertIsInstance(stmt, JsThrowStatement)
        self.assertIsNotNone(stmt.argument)

    def test_break(self):
        stmt = self._parse_stmt('break;')
        self.assertIsInstance(stmt, JsBreakStatement)
        self.assertIsNone(stmt.label)

    def test_break_label(self):
        stmt = self._parse_stmt('break outer;')
        self.assertIsInstance(stmt, JsBreakStatement)
        self.assertIsNotNone(stmt.label)
        self.assertEqual(stmt.label.name, 'outer')

    def test_continue(self):
        stmt = self._parse_stmt('continue;')
        self.assertIsInstance(stmt, JsContinueStatement)

    def test_function_declaration(self):
        stmt = self._parse_stmt('function foo(a, b) { return a + b; }')
        self.assertIsInstance(stmt, JsFunctionDeclaration)
        self.assertEqual(stmt.id.name, 'foo')
        self.assertEqual(len(stmt.params), 2)
        self.assertFalse(stmt.generator)
        self.assertFalse(stmt.is_async)

    def test_generator_declaration(self):
        stmt = self._parse_stmt('function* gen() { yield 1; }')
        self.assertIsInstance(stmt, JsFunctionDeclaration)
        self.assertTrue(stmt.generator)

    def test_async_function_declaration(self):
        stmt = self._parse_stmt('async function foo() { }')
        self.assertIsInstance(stmt, JsFunctionDeclaration)
        self.assertTrue(stmt.is_async)

    def test_class_declaration(self):
        stmt = self._parse_stmt('class Foo { }')
        self.assertIsInstance(stmt, JsClassDeclaration)
        self.assertEqual(stmt.id.name, 'Foo')
        self.assertIsNone(stmt.super_class)

    def test_class_extends(self):
        stmt = self._parse_stmt('class Bar extends Foo { }')
        self.assertIsInstance(stmt, JsClassDeclaration)
        self.assertIsNotNone(stmt.super_class)

    def test_class_methods(self):
        stmt = self._parse_stmt(
            'class C { constructor() {} get x() {} set x(v) {} static m() {} }')
        self.assertIsInstance(stmt, JsClassDeclaration)
        body = stmt.body
        self.assertIsInstance(body, JsClassBody)
        self.assertEqual(len(body.body), 4)
        self.assertIsInstance(body.body[0], JsMethodDefinition)
        self.assertEqual(body.body[0].kind, 'constructor')
        self.assertEqual(body.body[1].kind, 'get')
        self.assertEqual(body.body[2].kind, 'set')
        self.assertTrue(body.body[3].is_static)

    def test_import_default(self):
        stmt = self._parse_stmt("import foo from 'bar';")
        self.assertIsInstance(stmt, JsImportDeclaration)
        self.assertEqual(len(stmt.specifiers), 1)
        self.assertIsInstance(stmt.specifiers[0], JsImportDefaultSpecifier)

    def test_import_namespace(self):
        stmt = self._parse_stmt("import * as mod from 'mod';")
        self.assertIsInstance(stmt, JsImportDeclaration)
        self.assertIsInstance(stmt.specifiers[0], JsImportNamespaceSpecifier)

    def test_import_named(self):
        stmt = self._parse_stmt("import { a, b } from 'mod';")
        self.assertIsInstance(stmt, JsImportDeclaration)
        self.assertEqual(len(stmt.specifiers), 2)

    def test_import_side_effect(self):
        stmt = self._parse_stmt("import 'polyfill';")
        self.assertIsInstance(stmt, JsImportDeclaration)
        self.assertEqual(len(stmt.specifiers), 0)

    def test_export_named(self):
        stmt = self._parse_stmt('export { a, b };')
        self.assertIsInstance(stmt, JsExportNamedDeclaration)
        self.assertEqual(len(stmt.specifiers), 2)

    def test_export_declaration(self):
        stmt = self._parse_stmt('export const x = 1;')
        self.assertIsInstance(stmt, JsExportNamedDeclaration)
        self.assertIsInstance(stmt.declaration, JsVariableDeclaration)

    def test_export_default(self):
        stmt = self._parse_stmt('export default 42;')
        self.assertIsInstance(stmt, JsExportDefaultDeclaration)

    def test_export_all(self):
        stmt = self._parse_stmt("export * from 'mod';")
        self.assertIsInstance(stmt, JsExportAllDeclaration)

    def test_labeled_statement(self):
        stmt = self._parse_stmt('outer: for (;;) { break outer; }')
        self.assertIsInstance(stmt, JsLabeledStatement)
        self.assertEqual(stmt.label.name, 'outer')

    def test_with_statement(self):
        stmt = self._parse_stmt('with (obj) { x; }')
        self.assertIsInstance(stmt, JsWithStatement)

    def test_debugger(self):
        stmt = self._parse_stmt('debugger;')
        self.assertIsInstance(stmt, JsDebuggerStatement)

    def test_empty_statement(self):
        stmt = self._parse_stmt(';')
        self.assertIsInstance(stmt, JsEmptyStatement)

    def test_block_statement(self):
        stmt = self._parse_stmt('{ x; y; }')
        self.assertIsInstance(stmt, JsBlockStatement)
        self.assertEqual(len(stmt.body), 2)

    def test_asi_return_newline(self):
        script = self._parse_all('return\n42')
        self.assertEqual(len(script.body), 2)
        self.assertIsInstance(script.body[0], JsReturnStatement)
        self.assertIsNone(script.body[0].argument)
        self.assertIsInstance(script.body[1], JsExpressionStatement)

    def test_error_recovery(self):
        script = self._parse_all('@@@ var x = 1;')
        has_error = False
        has_var = False
        for stmt in script.body:
            if isinstance(stmt, JsExpressionStatement):
                if isinstance(stmt.expression, JsErrorNode):
                    has_error = True
            if isinstance(stmt, JsVariableDeclaration):
                has_var = True
        self.assertTrue(has_error or has_var)

    def test_for_empty_parts(self):
        stmt = self._parse_stmt('for (;;) { }')
        self.assertIsInstance(stmt, JsForStatement)
        self.assertIsNone(stmt.init)
        self.assertIsNone(stmt.test)
        self.assertIsNone(stmt.update)

    def test_for_in_no_var(self):
        stmt = self._parse_stmt('for (x in obj) { }')
        self.assertIsInstance(stmt, JsForInStatement)
