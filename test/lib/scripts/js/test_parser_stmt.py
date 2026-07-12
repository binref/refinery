from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsClassBody,
    JsClassDeclaration,
    JsContinueStatement,
    JsDebuggerStatement,
    JsDecorator,
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
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportExpression,
    JsImportNamespaceSpecifier,
    JsLabeledStatement,
    JsMetaProperty,
    JsMethodDefinition,
    JsMethodKind,
    JsPrivateIdentifier,
    JsPropertyDefinition,
    JsReturnStatement,
    JsScript,
    JsStaticBlock,
    JsSwitchStatement,
    JsThrowStatement,
    JsTryStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
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
        self.assertEqual(stmt.kind, JsVarKind.VAR)
        self.assertEqual(len(stmt.declarations), 1)

    def test_let_declaration(self):
        stmt = self._parse_stmt('let x = 1;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(stmt.kind, JsVarKind.LET)

    def test_const_declaration(self):
        stmt = self._parse_stmt('const x = 1;')
        self.assertIsInstance(stmt, JsVariableDeclaration)
        self.assertEqual(stmt.kind, JsVarKind.CONST)

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
        self.assertEqual(body.body[0].kind, JsMethodKind.CONSTRUCTOR)
        self.assertEqual(body.body[1].kind, JsMethodKind.GET)
        self.assertEqual(body.body[2].kind, JsMethodKind.SET)
        self.assertTrue(body.body[3].is_static)

    def test_class_private_field_and_method(self):
        ast = JsParser('class C { #x = 1; #m() { return this.#x; } }').parse()
        names = [n.name for n in ast.walk() if isinstance(n, JsPrivateIdentifier)]
        self.assertEqual(names, ['x', 'm', 'x'])

    def test_class_private_field_produces_no_error_node(self):
        ast = JsParser('class C { #x = 1; }').parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_class_static_block(self):
        ast = JsParser('class C { static { this.x = 1; } }').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsStaticBlock)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_class_static_field_named_static_still_parses(self):
        ast = JsParser('class C { static x = 1; }').parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsStaticBlock)], [])
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_class_field_named_contextual_keyword(self):
        for name in ('static', 'get', 'set', 'async'):
            with self.subTest(name=name):
                ast = JsParser(F'class C {{ {name} }}').parse()
                fields = [n for n in ast.walk() if isinstance(n, JsPropertyDefinition)]
                self.assertEqual([n for n in ast.walk() if isinstance(n, JsMethodDefinition)], [])
                self.assertEqual(len(fields), 1)
                key = fields[0].key
                assert isinstance(key, JsIdentifier)
                self.assertEqual(key.name, name)
                self.assertFalse(fields[0].is_static)
                self.assertIsNone(fields[0].value)

    def test_class_field_named_contextual_keyword_with_initializer(self):
        for name in ('static', 'get', 'set', 'async'):
            with self.subTest(name=name):
                ast = JsParser(F'class C {{ {name} = 1; }}').parse()
                fields = [n for n in ast.walk() if isinstance(n, JsPropertyDefinition)]
                self.assertEqual(len(fields), 1)
                key = fields[0].key
                assert isinstance(key, JsIdentifier)
                self.assertEqual(key.name, name)
                self.assertIsNotNone(fields[0].value)
                self.assertFalse(fields[0].is_static)

    def test_class_method_named_contextual_keyword(self):
        for name in ('static', 'get', 'set', 'async'):
            with self.subTest(name=name):
                ast = JsParser(F'class C {{ {name}() {{ return 1; }} }}').parse()
                methods = [n for n in ast.walk() if isinstance(n, JsMethodDefinition)]
                self.assertEqual([n for n in ast.walk() if isinstance(n, JsPropertyDefinition)], [])
                self.assertEqual(len(methods), 1)
                key = methods[0].key
                assert isinstance(key, JsIdentifier)
                self.assertEqual(key.name, name)
                self.assertEqual(methods[0].kind, JsMethodKind.METHOD)

    def test_class_static_modifier_with_field_named_static(self):
        ast = JsParser('class C { static static = 1; }').parse()
        fields = [n for n in ast.walk() if isinstance(n, JsPropertyDefinition)]
        self.assertEqual(len(fields), 1)
        key = fields[0].key
        assert isinstance(key, JsIdentifier)
        self.assertEqual(key.name, 'static')
        self.assertTrue(fields[0].is_static)

    def test_class_async_field_then_method_across_newline(self):
        ast = JsParser('class C { async\n m() {} }').parse()
        fields = [n for n in ast.walk() if isinstance(n, JsPropertyDefinition)]
        methods = [n for n in ast.walk() if isinstance(n, JsMethodDefinition)]
        self.assertEqual(len(fields), 1)
        self.assertEqual(len(methods), 1)
        field_key = fields[0].key
        assert isinstance(field_key, JsIdentifier)
        self.assertEqual(field_key.name, 'async')
        value = methods[0].value
        assert isinstance(value, JsFunctionExpression)
        self.assertFalse(value.is_async)

    def test_class_static_modifier_survives_newline(self):
        ast = JsParser('class C { static\n m() {} }').parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsPropertyDefinition)], [])
        methods = [n for n in ast.walk() if isinstance(n, JsMethodDefinition)]
        self.assertEqual(len(methods), 1)
        self.assertTrue(methods[0].is_static)

    def test_class_getter_named_x(self):
        ast = JsParser('class C { get x() { return 1; } }').parse()
        methods = [n for n in ast.walk() if isinstance(n, JsMethodDefinition)]
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].kind, JsMethodKind.GET)
        key = methods[0].key
        assert isinstance(key, JsIdentifier)
        self.assertEqual(key.name, 'x')

    def test_class_async_method_is_async(self):
        ast = JsParser('class C { async m() {} }').parse()
        methods = [n for n in ast.walk() if isinstance(n, JsMethodDefinition)]
        self.assertEqual(len(methods), 1)
        value = methods[0].value
        assert isinstance(value, JsFunctionExpression)
        self.assertTrue(value.is_async)

    def test_dynamic_import_expression(self):
        ast = JsParser("const p = import('m');").parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsImportExpression)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_dynamic_import_statement_with_postfix(self):
        ast = JsParser("import('m').then(f);").parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsImportExpression)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_import_meta(self):
        ast = JsParser('var u = import.meta.url;').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsMetaProperty)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_import_declaration_not_confused_with_expression(self):
        ast = JsParser("import x from 'm';").parse()
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsImportExpression)], [])
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsImportDeclaration)]), 1)

    def test_class_decorator(self):
        ast = JsParser('@dec class C {}').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsDecorator)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_member_decorators(self):
        ast = JsParser('class C { @a m() {} @b x = 1; }').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsDecorator)]), 2)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_export_decorated_class(self):
        ast = JsParser('export @dec class C {}').parse()
        self.assertEqual(len([n for n in ast.walk() if isinstance(n, JsDecorator)]), 1)
        self.assertEqual([n for n in ast.walk() if isinstance(n, JsErrorNode)], [])

    def test_jsx_element_fails_loud(self):
        ast = JsParser('var x = <div>hi</div>;').parse()
        self.assertGreater(len([n for n in ast.walk() if isinstance(n, JsErrorNode)]), 0)

    def test_jsx_fragment_fails_loud(self):
        ast = JsParser('var x = <>hi</>;').parse()
        self.assertGreater(len([n for n in ast.walk() if isinstance(n, JsErrorNode)]), 0)

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

    def test_export_async_function(self):
        stmt = self._parse_stmt('export async function f() {}')
        assert isinstance(stmt, JsExportNamedDeclaration)
        decl = stmt.declaration
        assert isinstance(decl, JsFunctionDeclaration)
        self.assertTrue(decl.is_async)

    def test_export_default_async_function(self):
        stmt = self._parse_stmt('export default async function () {}')
        assert isinstance(stmt, JsExportDefaultDeclaration)
        decl = stmt.declaration
        assert isinstance(decl, JsFunctionDeclaration)
        self.assertTrue(decl.is_async)

    def test_export_default_async_arrow(self):
        stmt = self._parse_stmt('export default async () => {};')
        assert isinstance(stmt, JsExportDefaultDeclaration)
        decl = stmt.declaration
        assert isinstance(decl, JsArrowFunctionExpression)
        self.assertTrue(decl.is_async)

    def test_export_default_async_call(self):
        stmt = self._parse_stmt('export default async(1, 2);')
        assert isinstance(stmt, JsExportDefaultDeclaration)
        decl = stmt.declaration
        assert isinstance(decl, JsCallExpression)
        callee = decl.callee
        assert isinstance(callee, JsIdentifier)
        self.assertEqual(callee.name, 'async')

    def test_function_name_contextual_keyword(self):
        for name in ('async', 'await', 'yield', 'as', 'from', 'of', 'let'):
            with self.subTest(name=name):
                stmt = self._parse_stmt(F'function {name}() {{ return 1; }}')
                assert isinstance(stmt, JsFunctionDeclaration)
                node_id = stmt.id
                assert isinstance(node_id, JsIdentifier)
                self.assertEqual(node_id.name, name)

    def test_class_name_contextual_keyword(self):
        for name in ('async', 'await', 'yield', 'as', 'from', 'of', 'let'):
            with self.subTest(name=name):
                stmt = self._parse_stmt(F'class {name} {{}}')
                assert isinstance(stmt, JsClassDeclaration)
                node_id = stmt.id
                assert isinstance(node_id, JsIdentifier)
                self.assertEqual(node_id.name, name)

    def test_break_label_contextual_keyword(self):
        stmt = self._parse_stmt('break of;')
        assert isinstance(stmt, JsBreakStatement)
        assert isinstance(stmt.label, JsIdentifier)
        self.assertEqual(stmt.label.name, 'of')

    def test_continue_label_contextual_keyword(self):
        stmt = self._parse_stmt('continue as;')
        assert isinstance(stmt, JsContinueStatement)
        assert isinstance(stmt.label, JsIdentifier)
        self.assertEqual(stmt.label.name, 'as')

    def test_import_default_contextual_keyword(self):
        stmt = self._parse_stmt("import async from 'm';")
        assert isinstance(stmt, JsImportDeclaration)
        specifier = stmt.specifiers[0]
        assert isinstance(specifier, JsImportDefaultSpecifier)
        local = specifier.local
        assert isinstance(local, JsIdentifier)
        self.assertEqual(local.name, 'async')

    def test_import_default_named_from(self):
        stmt = self._parse_stmt("import from from 'm';")
        assert isinstance(stmt, JsImportDeclaration)
        specifier = stmt.specifiers[0]
        assert isinstance(specifier, JsImportDefaultSpecifier)
        local = specifier.local
        assert isinstance(local, JsIdentifier)
        self.assertEqual(local.name, 'from')

    def test_decorator_contextual_keyword_name(self):
        stmt = self._parse_stmt('@async class C {}')
        assert isinstance(stmt, JsClassDeclaration)
        decorator = stmt.decorators[0]
        assert isinstance(decorator.expression, JsIdentifier)
        self.assertEqual(decorator.expression.name, 'async')

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
        self.assertTrue(has_error)
        self.assertTrue(has_var)

    def test_error_recovery_between_valid_statements(self):
        script = self._parse_all('var a = 1; ### var b = 2;')
        declarations = [s for s in script.body if isinstance(s, JsVariableDeclaration)]
        errors = [s for s in script.body if isinstance(s, JsExpressionStatement) and isinstance(s.expression, JsErrorNode)]
        self.assertEqual(len(declarations), 2)
        self.assertGreater(len(errors), 0)

    def test_error_recovery_inside_block(self):
        script = self._parse_all('function f() { var a = 1; @@@ var b = 2; }')
        self.assertIsInstance(script.body[0], JsFunctionDeclaration)
        block = script.body[0].body
        declarations = [s for s in block.body if isinstance(s, JsVariableDeclaration)]
        errors = [s for s in block.body if isinstance(s, JsExpressionStatement) and isinstance(s.expression, JsErrorNode)]
        self.assertEqual(len(declarations), 2)
        self.assertGreater(len(errors), 0)

    def test_error_recovery_all_garbage(self):
        script = self._parse_all('@@@')
        self.assertGreater(len(script.body), 0)
        for stmt in script.body:
            self.assertIsInstance(stmt, JsExpressionStatement)
            self.assertIsInstance(stmt.expression, JsErrorNode)

    def test_for_empty_parts(self):
        stmt = self._parse_stmt('for (;;) { }')
        self.assertIsInstance(stmt, JsForStatement)
        self.assertIsNone(stmt.init)
        self.assertIsNone(stmt.test)
        self.assertIsNone(stmt.update)

    def test_for_in_no_var(self):
        stmt = self._parse_stmt('for (x in obj) { }')
        self.assertIsInstance(stmt, JsForInStatement)

    def test_newline_before_paren_continues_call(self):
        """
        ASI does not insert a semicolon before `(`, so the string on the first line is called as a
        function: this parses as one statement (a runtime TypeError), matching V8.
        """
        source = 'global["VERSION"] = "9.4533"\n\n(async () => {\n  const c = global;\n})()'
        body = self._parse_all(source).body
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], JsExpressionStatement)

    def test_newline_before_bracket_continues_member(self):
        """
        ASI does not insert a semicolon before `[`, so `[0]` on the next line continues the array as a
        computed member access `[10, 20][0]`: one statement, matching V8.
        """
        body = self._parse_all('var a = [10, 20]\n[0]').body
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], JsVariableDeclaration)

    def test_newline_before_template_continues_tagged_template(self):
        """
        ASI does not insert a semicolon before a template literal, so the template on the next line
        continues `foo` as a tagged template: one statement, matching V8.
        """
        body = self._parse_all('var x = foo\n`template`').body
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], JsVariableDeclaration)
