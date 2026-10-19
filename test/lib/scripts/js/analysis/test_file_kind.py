from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.model import JsExpressionStatement, JsMemberExpression
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel, file_kind
from refinery.lib.scripts.js.parser import JsParser


def _model(source: str, kind: FileKind) -> SemanticModel:
    return build_semantic_model(JsParser(inspect.cleandoc(source)).parse(), file_kind=kind)


def _kind(source: str, execution: ExecutionModel) -> FileKind:
    root = JsParser(inspect.cleandoc(source)).parse()
    return file_kind(DeobfuscationOptions(execution=execution), root)


class TestWhatTheFileIs(TestBase):

    def test_each_execution_model_names_its_kind(self):
        self.assertEqual(
            {execution: _kind('var a = 1;', execution) for execution in ExecutionModel},
            {
                ExecutionModel.script: FileKind.script,
                ExecutionModel.commonjs: FileKind.commonjs,
                ExecutionModel.module: FileKind.commonjs_or_es_module,
            },
        )

    def test_a_file_spelling_module_syntax_is_an_es_module_under_every_model(self):
        self.assertEqual(
            {execution: _kind('export var a = 1;', execution) for execution in ExecutionModel},
            {execution: FileKind.es_module for execution in ExecutionModel},
        )

    def test_a_lexical_declaration_of_a_wrapper_parameter_makes_a_module_an_es_module(self):
        for declaration in ('let require = 0;', 'const exports = 0;', 'class module {}'):
            with self.subTest(declaration):
                self.assertEqual(
                    {execution: _kind(declaration, execution) for execution in ExecutionModel},
                    {
                        ExecutionModel.script: FileKind.script,
                        ExecutionModel.commonjs: FileKind.es_module,
                        ExecutionModel.module: FileKind.es_module,
                    },
                )

    def test_a_var_or_a_nested_lexical_declaration_of_a_wrapper_parameter_changes_nothing(self):
        for source in ('var require = 0;', 'function f() { let module = 0; }', '{ let exports; }'):
            with self.subTest(source):
                self.assertEqual(_kind(source, ExecutionModel.commonjs), FileKind.commonjs)

    def test_an_options_value_that_is_not_one_reads_a_script(self):
        self.assertEqual(file_kind(None, JsParser('var a;').parse()), FileKind.script)


class TestTheModelAnswersForTheFileKind(TestBase):

    def test_a_top_level_var_reaches_the_global_object_only_in_a_script(self):
        reached = {}
        for kind in FileKind:
            model = _model('var v = 1;', kind)
            reached[kind] = model.reaches_global_object(model.root_scope.bindings['v'])
        self.assertEqual(reached, {kind: kind is FileKind.script for kind in FileKind})

    def test_global_code_reaches_a_top_level_var_only_in_a_script(self):
        reached = {}
        for kind in FileKind:
            model = _model('var v = 1;\n(0, eval)(s);', kind)
            reached[kind] = model.reflection_can_reach(model.root_scope.bindings['v'])
        self.assertEqual(reached, {kind: kind is FileKind.script for kind in FileKind})

    def test_a_direct_eval_anywhere_in_the_file_reaches_a_top_level_var_in_every_kind(self):
        for kind in FileKind:
            with self.subTest(kind.name):
                model = _model('var v = 1;\nfunction f(c) { eval(c); }', kind)
                self.assertTrue(model.reflection_can_reach(model.root_scope.bindings['v']))

    def test_global_code_reaches_an_implicit_global_in_every_kind(self):
        for kind in FileKind:
            with self.subTest(kind.name):
                model = _model('g = 1;\n(0, eval)(s);', kind)
                g = model.root_scope.bindings['g']
                self.assertTrue(model.reflection_can_reach(g))
                self.assertTrue(model.reflection_can_reach_from_its_scope(g))
                self.assertNotEqual(model.reflection_surface_sites(g), [])

    def test_a_top_level_this_names_a_global_only_in_a_script(self):
        names = {}
        for kind in FileKind:
            model = _model('this.g;', kind)
            statement = model.root.body[0]
            assert isinstance(statement, JsExpressionStatement)
            member = statement.expression
            assert isinstance(member, JsMemberExpression)
            names[kind] = model.global_alias_member_name(member)
        expected = {kind: 'g' if kind is FileKind.script else None for kind in FileKind}
        self.assertEqual(names, expected)

    def test_a_write_through_a_top_level_this_creates_a_global_only_in_a_script(self):
        created = {}
        for kind in FileKind:
            created[kind] = 'g' in _model('this.g = 1;', kind).root_scope.bindings
        self.assertEqual(created, {kind: kind is FileKind.script for kind in FileKind})

    def test_code_the_text_leaves_sloppy_may_run_as_strict_where_the_file_may_be_an_es_module(self):
        strict = {}
        for kind in FileKind:
            model = _model('f();', kind)
            strict[kind] = model.may_run_as_strict(model.root.body[0])
        self.assertEqual(strict, {kind: kind.may_be_an_es_module for kind in FileKind})

    def test_code_the_text_makes_strict_may_run_as_strict_in_every_kind(self):
        for kind in FileKind:
            with self.subTest(kind.name):
                model = _model("'use strict';\nf();", kind)
                self.assertTrue(model.may_run_as_strict(model.root.body[1]))
