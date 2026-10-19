from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model
from refinery.lib.scripts.js.model import JsExpressionStatement, JsIdentifier, JsMemberExpression
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

    def test_an_es_module_makes_no_copy_of_a_function_declared_in_a_block(self):
        copies = {}
        for kind in FileKind:
            copies[kind] = 'f' in _model('{ function f() {} }', kind).root_scope.bindings
        self.assertEqual(copies, {kind: kind is not FileKind.es_module for kind in FileKind})

    def test_code_the_text_makes_strict_may_run_as_strict_in_every_kind(self):
        for kind in FileKind:
            with self.subTest(kind.name):
                model = _model("'use strict';\nf();", kind)
                self.assertTrue(model.may_run_as_strict(model.root.body[1]))


class TestTheTopOfACommonJsFileBindsTheWrapper(TestBase):

    def test_the_wrapper_binds_its_parameters_and_arguments_in_their_order(self):
        names = ('exports', 'require', 'module', '__filename', '__dirname', 'arguments')
        for kind in FileKind:
            with self.subTest(kind.name):
                bindings = _model('', kind).root_scope.bindings
                bound = tuple(name for name in bindings if name in names)
                self.assertEqual(bound, names if kind.may_be_commonjs else ())

    def test_each_binding_the_host_supplies_has_no_declaration_and_is_flagged(self):
        bindings = _model('', FileKind.commonjs).root_scope.bindings
        self.assertEqual(
            {
                name: (binding.supplied_by_host, binding.declarations, binding.may_be_absent)
                for name, binding in bindings.items()
            },
            {
                name: (True, [], False)
                for name in ('exports', 'require', 'module', '__filename', '__dirname', 'arguments')
            },
        )

    def test_a_binding_the_host_supplies_may_be_absent_where_the_file_may_be_an_es_module(self):
        bindings = _model('', FileKind.commonjs_or_es_module).root_scope.bindings
        self.assertTrue(all(binding.may_be_absent for binding in bindings.values()))

    def test_a_var_or_a_function_of_a_parameter_joins_it_and_is_bound_in_either_reading(self):
        for source in ('var require = 1;', 'function require() {}'):
            with self.subTest(source):
                model = _model(source, FileKind.commonjs_or_es_module)
                require = model.root_scope.bindings['require']
                self.assertTrue(require.supplied_by_host)
                self.assertEqual(len(require.declarations), 1)
                self.assertFalse(require.may_be_absent)

    def test_a_read_of_a_parameter_throws_only_where_the_file_may_be_an_es_module(self):
        throws = {}
        for kind in (FileKind.commonjs, FileKind.commonjs_or_es_module):
            model = _model('require;', kind)
            statement = model.root.body[0]
            assert isinstance(statement, JsExpressionStatement)
            identifier = statement.expression
            assert isinstance(identifier, JsIdentifier)
            throws[kind] = model.read_may_throw(identifier)
        self.assertEqual(throws, {FileKind.commonjs: False, FileKind.commonjs_or_es_module: True})

    def test_no_declaration_lands_on_a_name_the_host_supplies(self):
        for kind in (FileKind.commonjs, FileKind.commonjs_or_es_module):
            with self.subTest(kind.name):
                model = _model('', kind)
                self.assertFalse(model.declaration_may_land({'module'}, model.root_scope))
                self.assertTrue(model.declaration_may_land({'other'}, model.root_scope))

    def test_a_declaration_lands_on_a_wrapper_name_in_a_script(self):
        model = _model('', FileKind.script)
        self.assertTrue(model.declaration_may_land({'module'}, model.root_scope))

    def test_a_parameter_holds_what_the_host_passed_until_the_file_replaces_it(self):
        held = {}
        for source in ('require("a");', 'require = 1;', 'var require;', 'eval(s);'):
            model = _model(source, FileKind.commonjs)
            held[source] = model.holds_what_the_host_passed(model.root_scope.bindings['require'])
        self.assertEqual(held, {
            'require("a");': True,
            'require = 1;': False,
            'var require;': False,
            'eval(s);': False,
        })

    def test_a_callee_the_host_passed_is_supplied_from_outside(self):
        model = _model('require("a"); var own = function () {}; own();', FileKind.commonjs)
        bindings = model.root_scope.bindings
        self.assertTrue(model.supplied_from_outside(None))
        self.assertTrue(model.supplied_from_outside(bindings['require']))
        self.assertFalse(model.supplied_from_outside(bindings['own']))

    def test_a_block_function_at_the_top_named_like_a_parameter_gets_no_copy(self):
        for name in ('exports', 'require', 'module', '__filename', '__dirname', 'arguments'):
            with self.subTest(name):
                model = _model(F'{{ function {name}() {{}} }}', FileKind.commonjs)
                self.assertEqual(model.root_scope.bindings[name].declarations, [])

    def test_the_wrapper_arguments_aliases_the_parameters_in_their_order(self):
        model = _model('exports = 1;\nf(arguments[0], arguments[2]);', FileKind.commonjs)
        bindings = model.root_scope.bindings
        read = {
            name: any(isinstance(node, JsMemberExpression) for node in bindings[name].reads)
            for name in ('exports', 'require', 'module')
        }
        self.assertEqual(read, {'exports': True, 'require': False, 'module': True})
