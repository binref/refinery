"""
The analyses read every property key through `refinery.lib.scripts.js.keys`.

A reader that reads a key it cannot read as no match, and does so outside the key reader, records
nothing, so a fold that spells the name there leaves a held answer stale with no renewal due. The
guard below reads the source of every analysis module and of the syntax tree module and fails on
each way of reading a key around the key reader:

- a call of a function that reads a key's text without recording anything (`static_string`,
  `static_property_key`, `member_property_name`, `_property_key_name`, `_certain_key`,
  `_primitive_literal_text`, `static_concatenation`), except inside those functions themselves;
- the text of a literal read off a key (`member.property.value`, `prop.key.name`), also through a
  name holding the key, and a test of a key's literal type (`isinstance(member.property, ...)`);
- a comparison of the text the key reader gives (`key_text`) with a string or a table of names,
  which is what the questions `key_may_be` and `key_is` are for.
"""
from __future__ import annotations

import ast
import pathlib

from test import TestBase

import refinery.lib.scripts.js.analysis as analysis
import refinery.lib.scripts.js.model as js_model

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.keys import STRINGS_READ_ANYWHERE
from refinery.lib.scripts.js.parser import JsParser

_RAW_READERS = frozenset({
    'static_string',
    'static_property_key',
    'member_property_name',
    '_property_key_name',
    '_certain_key',
    '_primitive_literal_text',
    'static_concatenation',
})

_KEY_FIELDS = frozenset({'property', 'key'})

_TEXT_FIELDS = frozenset({'value', 'name', 'raw'})

_LITERAL_CLASSES = frozenset({
    'JsStringLiteral',
    'JsNumericLiteral',
    'JsTemplateLiteral',
    'JsBooleanLiteral',
    'JsNullLiteral',
})

_SYNTAX_READERS = {
    ('model.py', 'object_sets_prototype'): (
        'only the syntax `__proto__: p` sets a prototype, a computed key of that name does not'
    ),
}


def _is_key_field(node: ast.AST, held: set[str]) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'strip_parens' and node.args:
        node = node.args[0]
    if isinstance(node, ast.Attribute) and node.attr in _KEY_FIELDS:
        return True
    return isinstance(node, ast.Name) and node.id in held


def _class_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Tuple):
        return {name for element in node.elts for name in _class_names(element)}
    if isinstance(node, ast.Name):
        return {node.id}
    return set()


def _is_key_text(node: ast.AST, texts: set[str]) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'key_text':
        return True
    return isinstance(node, ast.Name) and node.id in texts


def _is_a_name_test(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, (ast.Tuple, ast.Set, ast.List)):
        return True
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ''
    return name.lstrip('_').isupper()


class _Reads(ast.NodeVisitor):

    def __init__(self, module: str):
        self.module = module
        self.found: list[str] = []
        self._function = '<module>'

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        outer = self._function
        self._function = node.name
        held: set[str] = set()
        texts: set[str] = set()
        for statement in ast.walk(node):
            if isinstance(statement, (ast.Assign, ast.NamedExpr)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if _is_key_field(statement.value, set()):
                        held.add(target.id)
                    if _is_key_text(statement.value, set()):
                        texts.add(target.id)
        self._check(node, held, texts)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)
        self._function = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check(self, function: ast.AST, held: set[str], texts: set[str]):
        if (self.module, self._function) in _SYNTAX_READERS or self._function in _RAW_READERS:
            return
        for node in ast.walk(function):
            where = F'{self.module}:{getattr(node, "lineno", 0)} in {self._function}'
            if isinstance(node, ast.Call):
                callee = node.func
                name = callee.id if isinstance(callee, ast.Name) else callee.attr if isinstance(callee, ast.Attribute) else ''
                if name in _RAW_READERS:
                    self.found.append(F'{where}: calls {name}')
                if name == 'isinstance' and len(node.args) == 2 and _is_key_field(node.args[0], held):
                    if _class_names(node.args[1]) & _LITERAL_CLASSES:
                        self.found.append(F'{where}: tests the literal type of a key')
            elif isinstance(node, ast.Attribute) and node.attr in _TEXT_FIELDS:
                if _is_key_field(node.value, held):
                    self.found.append(F'{where}: reads .{node.attr} off a key')
            elif isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                if not all(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
                    continue
                if any(_is_key_text(side, texts) for side in sides) and any(_is_a_name_test(side) for side in sides):
                    self.found.append(F'{where}: compares a key text with names')


def _reads_around_the_key_reader(path: pathlib.Path) -> list[str]:
    reads = _Reads(path.name)
    tree = ast.parse(path.read_text(encoding='utf8'))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            reads.visit(node)
    return reads.found


class TestEveryKeyIsReadThroughTheKeyReader(TestBase):

    def test_no_analysis_module_reads_a_key_around_the_key_reader(self):
        found = []
        for path in sorted(pathlib.Path(analysis.__file__).parent.glob('*.py')):
            found.extend(_reads_around_the_key_reader(path))
        self.assertEqual(found, [])

    def test_the_syntax_tree_module_reads_no_key_around_the_key_reader(self):
        self.assertEqual(_reads_around_the_key_reader(pathlib.Path(js_model.__file__)), [])

    def test_the_guard_finds_each_way_of_reading_a_key_around_the_key_reader(self):
        source = '\n'.join([
            'def a(member):',
            '    return static_property_key(member) == "eval"',
            'def b(member):',
            '    return member.property.value',
            'def c(member):',
            '    prop = member.property',
            '    return isinstance(prop, JsStringLiteral) and prop.value in NAMES',
            'def d(member):',
            '    return key_text(member) in REFLECTIVE_INTRINSICS',
            'def e(member):',
            '    key = key_text(member)',
            '    return key == "constructor"',
            'def f(member):',
            '    return key_text(member) is None or key_is(member, NAMES, assumptions)',
        ])
        reads = _Reads('example.py')
        for node in ast.parse(source).body:
            reads.visit(node)
        self.assertEqual(
            [entry.split(' in ')[1].split(':')[0] for entry in reads.found],
            ['a', 'b', 'c', 'c', 'd', 'e'],
            source,
        )


class TestTheStringsReadAnywhereAreTheOnesTheModelChecks(TestBase):

    def test_a_program_spelling_none_of_them_has_each_unseen(self):
        model = build_semantic_model(JsParser('var x = 1;').parse())
        self.assertEqual(model.strings_still_unseen(), STRINGS_READ_ANYWHERE)


class TestANumberKeyIsReadAsItsText(TestBase):

    def test_an_element_handed_to_a_call_keeps_the_dispatch_of_call_and_apply_trusted(self):
        model = build_semantic_model(JsParser('var a = [1, 2]; f(a[0]);').parse())
        self.assertTrue(model.intrinsic_dispatch_trusted())

    def test_an_element_read_under_a_key_not_known_does_not(self):
        model = build_semantic_model(JsParser('var a = [1, 2]; f(a[g()]);').parse())
        self.assertFalse(model.intrinsic_dispatch_trusted())
