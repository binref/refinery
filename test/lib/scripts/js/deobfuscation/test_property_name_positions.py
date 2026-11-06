"""
SECURITY: every program here is written out by this module and Node runs only those. Nothing from
`samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from typing import Iterable

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    before_and_after,
    each_program_still_prints,
    folded,
    printed,
)

from refinery.lib.scripts.js.analysis.model import build_semantic_model, is_use_position
from refinery.lib.scripts.js.deobfuscation.namespaces import JsNamespaceFlattening
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser


def rewritten(programs: Iterable[str]) -> dict[str, str]:
    return {program: folded(program) for program in programs}


def spelled(programs: Iterable[str]) -> dict[str, str]:
    return {program: printed(program) for program in programs}


def spelled_as_expected(rows: dict[str, str]) -> dict[str, str]:
    return {source: printed(expected) for source, expected in rows.items()}


def run_by_node(programs: Iterable[str]) -> dict[str, tuple[str, str | None]]:
    return {program: behavior(program) for program in programs}


def run_by_node_as_expected(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: behavior(expected) for source, expected in rows.items()}


def occurrences_of(name: str, source: str) -> tuple[int, int]:
    """
    How often *name* is written as an identifier in *source*, and how many of those occurrences read
    or write a binding. A walk reaches the single identifier of a shorthand property through both
    slots it fills, so occurrences are counted by node and not by visit.
    """
    occurrences: dict[int, JsIdentifier] = {}
    for node in JsParser(source).parse().walk():
        if isinstance(node, JsIdentifier) and node.name == name:
            occurrences[id(node)] = node
    reads = sum(1 for node in occurrences.values() if is_use_position(node))
    return len(occurrences), reads


A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE = {
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify({ a: { q } }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ a: { q: 1 } }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify([{ a: { q } }]));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify([{ a: { q: 1 } }]));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var w = 'x';
        console.log(JSON.stringify({ a: 0, b: { q, r: 2, c: { w } } }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ a: 0, b: { q: 1, r: 2, c: { w: 'x' } } }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var w = 2;
        var e = 3;
        console.log(JSON.stringify({ q, w, e }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 1, w: 2, e: 3 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        console.log(JSON.stringify({ q, r: q }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 1, r: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'k';
        console.log(JSON.stringify({ q, [q]: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 'k', k: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'q';
        console.log(JSON.stringify({ q }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 'q' }));
        """
    ),
    inspect.cleandoc(
        """
        var async = 1;
        console.log(JSON.stringify({ async }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ async: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        var o = { if: 1, q };
        console.log(o.if, JSON.stringify(o));
        """
    ): inspect.cleandoc(
        """
        var o = { if: 1, q: 1 };
        console.log(o.if, JSON.stringify(o));
        """
    ),
    inspect.cleandoc(
        """
        var q = 1;
        class C { f = { q }; }
        console.log(JSON.stringify(new C().f));
        """
    ): inspect.cleandoc(
        """
        class C { f = { q: 1 }; }
        console.log(JSON.stringify(new C().f));
        """
    ),
    inspect.cleandoc(
        """
        var q = void 0;
        var o = { q };
        console.log(JSON.stringify(o), JSON.stringify(Object.keys(o)));
        """
    ): inspect.cleandoc(
        """
        var o = { q: void 0 };
        console.log(JSON.stringify(o), JSON.stringify(Object.keys(o)));
        """
    ),
}


class TestAConstantReachingAShorthandPropertyIsWrittenBesideItsName(TestBase):

    def test_a_shorthand_below_the_top_of_a_literal_is_written_out_under_its_name(self):
        rows = A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_CONSTANT_REACHING_A_SHORTHAND_PROPERTY_BEYOND_THE_PLAINEST_SHAPE
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


THE_SPELLINGS_OF_A_PROTO_KEY = {
    inspect.cleandoc(
        """
        var __proto__ = { z: 9 };
        var o = { __proto__ };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{"__proto__":{"z":9}} undefined\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { __proto__: v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{} 9\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { '__proto__': v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{} 9\n',
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var o = { ['__proto__']: v };
        console.log(JSON.stringify(o), o.z);
        """
    ): '{"__proto__":{"z":9}} undefined\n',
    inspect.cleandoc(
        """
        var __proto__ = 5;
        var o = { __proto__ };
        console.log(JSON.stringify(o));
        """
    ): '{"__proto__":5}\n',
    inspect.cleandoc(
        """
        var v = 5;
        var o = { __proto__: v };
        console.log(JSON.stringify(o));
        """
    ): '{}\n',
    inspect.cleandoc(
        """
        var v = 5;
        var o = { ['__proto__']: v };
        console.log(JSON.stringify(o));
        """
    ): '{"__proto__":5}\n',
}


A_PROTO_SHORTHAND_IS_LEFT_STANDING = [
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log(JSON.stringify({ __proto__ }));
        """
    ),
    inspect.cleandoc(
        """
        var __proto__ = { z: 9 };
        var o = { __proto__ };
        console.log(JSON.stringify(o), o.z);
        """
    ),
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log(JSON.stringify({ a: { __proto__ } }));
        """
    ),
    inspect.cleandoc(
        """
        var v = { z: 9 };
        var __proto__ = 5;
        var a = { __proto__, __proto__: v };
        console.log(JSON.stringify(a), a.z);
        """
    ),
]


A_PROTO_SHORTHAND_WRITTEN_OUT_UNDER_A_COMPUTED_KEY = {
    A_PROTO_SHORTHAND_IS_LEFT_STANDING[0]: inspect.cleandoc(
        """
        console.log(JSON.stringify({ ['__proto__']: 5 }));
        """
    ),
    A_PROTO_SHORTHAND_IS_LEFT_STANDING[2]: inspect.cleandoc(
        """
        console.log(JSON.stringify({ a: { ['__proto__']: 5 } }));
        """
    ),
    A_PROTO_SHORTHAND_IS_LEFT_STANDING[3]: inspect.cleandoc(
        """
        var v = { z: 9 };
        var a = { ['__proto__']: 5, __proto__: v };
        console.log(JSON.stringify(a), a.z);
        """
    ),
}


A_PROTO_KEY_A_VALUE_MAY_REACH = {
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ __proto__: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ __proto__: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ ['__proto__']: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ ['__proto__']: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = '__proto__';
        var v = 5;
        console.log(JSON.stringify({ [k]: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ ['__proto__']: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = 'q';
        var v = 5;
        console.log(JSON.stringify({ [k]: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 5 }));
        """
    ),
    inspect.cleandoc(
        """
        var v = 5;
        console.log(JSON.stringify({ ['q']: v }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q: 5 }));
        """
    ),
}


THE_SAME_PROTO_DECLARATION_WITH_NO_SHORTHAND_READING_IT = {
    inspect.cleandoc(
        """
        var __proto__ = 5;
        console.log('done');
        """
    ): inspect.cleandoc(
        """
        console.log('done');
        """
    ),
}


class TestTheShorthandProtoIsADifferentProgramFromTheWrittenOutOne(TestBase):
    """
    `{ __proto__ }` and `{ ['__proto__']: v }` give the object an own property named `__proto__`,
    while `{ __proto__: v }` and `{ '__proto__': v }` hand `v` to the prototype slot, which ignores
    anything but an object or `null`. So a value reaching the shorthand may only be written out
    under a computed key, and a computed key spelling `__proto__` may not be collapsed into a
    written-out one.
    """

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_every_spelling_of_a_proto_key_still_prints_what_it_printed(self):
        rows = THE_SPELLINGS_OF_A_PROTO_KEY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_proto_shorthand_is_left_standing_or_written_out_under_a_computed_key(self):
        written_out = A_PROTO_SHORTHAND_WRITTEN_OUT_UNDER_A_COMPUTED_KEY
        for source, result in rewritten(A_PROTO_SHORTHAND_IS_LEFT_STANDING).items():
            with self.subTest(source=source):
                self.assertIn(result, {printed(source), printed(written_out.get(source, source))})

    @opportunity
    def test_a_number_reaching_a_proto_shorthand_is_written_out_under_a_computed_key(self):
        rows = A_PROTO_SHORTHAND_WRITTEN_OUT_UNDER_A_COMPUTED_KEY
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    def test_a_proto_key_a_value_reaches_keeps_the_spelling_it_was_written_in(self):
        rows = A_PROTO_KEY_A_VALUE_MAY_REACH
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_PROTO_KEY_A_VALUE_MAY_REACH
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))

    def test_the_same_declaration_goes_once_the_shorthand_reading_it_is_gone(self):
        rows = THE_SAME_PROTO_DECLARATION_WITH_NO_SHORTHAND_READING_IT
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))


A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME = {
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 1 };
        console.log(q, o.q);
        """
    ): inspect.cleandoc(
        """
        console.log('zz', 1);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 1 };
        console.log(q, o['q']);
        """
    ): inspect.cleandoc(
        """
        console.log('zz', 1);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        console.log(q, JSON.stringify({ q: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log('zz', JSON.stringify({ q: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { q() { return 1; } }
        console.log(q, new C().q());
        """
    ): inspect.cleandoc(
        """
        class C { q() { return 1; } }
        console.log('zz', new C().q());
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { q = 1; }
        console.log(q, new C().q);
        """
    ): inspect.cleandoc(
        """
        class C { q = 1; }
        console.log('zz', new C().q);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { static q = 1; }
        console.log(q, C.q);
        """
    ): inspect.cleandoc(
        """
        class C { static q = 1; }
        console.log('zz', C.q);
        """
    ),
    inspect.cleandoc(
        """
        var q = 5;
        console.log(JSON.stringify({ q() { return 1; } }), q);
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ q() { return 1; } }), 5);
        """
    ),
    inspect.cleandoc(
        """
        var q = 5;
        var o = { get q() { return 1; } };
        console.log(o.q, q);
        """
    ): inspect.cleandoc(
        """
        var o = { get q() { return 1; } };
        console.log(o.q, 5);
        """
    ),
}


class TestANamePositionNeverTakesAValue(TestBase):

    def test_a_property_keeps_its_name_where_a_constant_carries_the_same_one(self):
        rows = A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_CONSTANT_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


A_COMPUTED_KEY_IS_A_READ = {
    inspect.cleandoc(
        """
        var q = 'k';
        console.log(JSON.stringify({ [q]: 1 }));
        """
    ): inspect.cleandoc(
        """
        console.log(JSON.stringify({ k: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var q = 'k';
        var o = { k: 3 };
        console.log(o[q]);
        """
    ): inspect.cleandoc(
        """
        console.log(3);
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        class C { [q]() { return 1; } }
        console.log(new C().zz());
        """
    ): inspect.cleandoc(
        """
        class C { ['zz']() { return 1; } }
        console.log(new C().zz());
        """
    ),
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = {};
        o[q] = 1;
        console.log(JSON.stringify(o));
        """
    ): inspect.cleandoc(
        """
        var o = {};
        o.zz = 1;
        console.log(JSON.stringify(o));
        """
    ),
}


class TestAComputedKeyIsAnOrdinaryRead(TestBase):

    def test_a_computed_key_takes_the_value_it_reads(self):
        rows = A_COMPUTED_KEY_IS_A_READ
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_COMPUTED_KEY_IS_A_READ
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS = {
    inspect.cleandoc(
        """
        var q = 'zz';
        var o = { q: 4 };
        var { q: x } = o;
        console.log(q, x);
        """
    ): inspect.cleandoc(
        """
        var o = { q: 4 };
        var { q: x } = o;
        console.log('zz', x);
        """
    ),
    inspect.cleandoc(
        """
        var d = 'zz';
        function f(o) { var { q = d } = o; return q; }
        console.log(f({}), f({ q: 1 }));
        """
    ): inspect.cleandoc(
        """
        function f(o) { var { q = 'zz' } = o; return q; }
        console.log(f({}), f({ q: 1 }));
        """
    ),
    inspect.cleandoc(
        """
        var k = 'q';
        var o = { q: 4 };
        var { [k]: x } = o;
        console.log(x);
        """
    ): inspect.cleandoc(
        """
        var o = { q: 4 };
        var { q: x } = o;
        console.log(x);
        """
    ),
}


class TestADestructuringPatternBindsWhereALiteralReads(TestBase):

    def test_a_pattern_takes_a_value_into_its_default_and_its_computed_key_only(self):
        rows = A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_program_runs_the_way_the_program_it_replaces_does(self):
        rows = A_DESTRUCTURING_PATTERN_BINDS_WHERE_A_LITERAL_READS
        self.assertEqual(run_by_node(rows), run_by_node_as_expected(rows))


A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING = {
    inspect.cleandoc(
        """
        var q = { z: 1 };
        console.log(JSON.stringify({ q }));
        """
    ): '{"q":{"z":1}}\n',
    inspect.cleandoc(
        """
        var q = { z: 1 };
        var o = { q };
        console.log(JSON.stringify(o), o.q.z);
        """
    ): '{"q":{"z":1}} 1\n',
}


THE_SAME_DECLARATION_WITH_NO_SHORTHAND_READING_IT = {
    inspect.cleandoc(
        """
        var q = { z: 1 };
        console.log('done');
        """
    ): inspect.cleandoc(
        """
        console.log('done');
        """
    ),
}


class TestAShorthandKeepsTheDeclarationItReads(TestBase):

    def test_a_declaration_read_only_by_a_shorthand_stays(self):
        rows = A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_the_same_declaration_goes_with_the_shorthand_taken_out(self):
        rows = THE_SAME_DECLARATION_WITH_NO_SHORTHAND_READING_IT
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_program_read_only_by_a_shorthand_still_prints_what_it_printed(self):
        rows = A_SHORTHAND_IS_THE_ONLY_READ_OF_ITS_BINDING
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


def _a_module_reporting_it_loaded(module: str) -> str:
    return F"{inspect.cleandoc(module)}\nconsole.log('loaded');\n"


def rewritten_as_modules(programs: Iterable[str]) -> dict[str, str]:
    return {program: folded(program, module=True) for program in programs}


A_MODULE_READING_WHAT_IT_EXPORTS = inspect.cleandoc(
    """
    var a = 1;
    export { a };
    console.log(a);
    """
)

A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES = {
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        let a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        const a = 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        const a = () => 1;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        let a;
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a as b };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1, b = 2;
        export { a, b };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var a = 1;
        export { a as default };
        """
    ): 'loaded\n',
    A_MODULE_READING_WHAT_IT_EXPORTS: '1\n',
    _a_module_reporting_it_loaded(
        """
        function a() { return 1; }
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        class a {}
        export { a };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        import { format } from 'node:util';
        export { format };
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        var format = 1;
        export { format } from 'node:util';
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded('export var a = 1;'): 'loaded\n',
}

#: A list with a `from` clause names bindings of the module it imports from and none of its own, so
#: the local `format` beside it is unread and goes.
A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS = {
    A_MODULE_READING_WHAT_IT_EXPORTS: inspect.cleandoc(
        """
        var a = 1;
        export { a };
        console.log(1);
        """
    ),
    _a_module_reporting_it_loaded(
        """
        var format = 1;
        export { format } from 'node:util';
        """
    ): inspect.cleandoc(
        """
        export { format } from 'node:util';
        console.log('loaded');
        """
    ),
}


class TestAnExportListReadsTheBindingItNames(TestBase):

    def test_a_module_the_list_alone_reads_comes_back_as_it_was(self):
        rows = [
            source for source in A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
            if source not in A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        ]
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_a_substituted_read_and_a_far_side_name_leave_their_own_marks(self):
        rows = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    def test_every_rewritten_row_is_a_row_of_the_table(self):
        self.assertLessEqual(
            set(A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS),
            set(A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES),
        )

    def test_the_module_model_hands_back_the_same_modules(self):
        rows = A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
        rewrites = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(
            {source: printed(rewrites.get(source, source)) for source in rows},
            rewritten_as_modules(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_module_still_prints_what_it_printed(self):
        rows = A_MODULE_THAT_EXPORTS_A_BINDING_IT_DECLARES
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_module_runs_the_way_the_module_it_replaces_does(self):
        rows = A_MODULE_AN_EXPORT_LIST_DOES_NOT_KEEP_AS_IT_WAS
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: behavior(expected, module=True) for source, expected in rows.items()},
        )


WHAT_A_NAME_IN_AN_EXPORT_LIST_COUNTS_FOR = {
    inspect.cleandoc(
        """
        var a = 1;
        export { a };
        """
    ): (2, 2),
    inspect.cleandoc(
        """
        var a = 1;
        export { a as b };
        """
    ): (2, 2),
    inspect.cleandoc(
        """
        var a = 1, x = 2;
        export { x as a };
        """
    ): (2, 1),
    inspect.cleandoc(
        """
        var a = 1;
        export { a } from 'node:util';
        """
    ): (2, 1),
    inspect.cleandoc(
        """
        export * as a from 'node:util';
        var a = 1;
        """
    ): (2, 1),
}


class TestOnlyTheLocalHalfOfAnExportListReads(TestBase):
    """
    A list with a `from` clause names bindings of the module it imports from, so neither half of its
    specifiers reads a local binding.
    """

    def test_the_halves_of_a_specifier_are_counted_by_position(self):
        rows = WHAT_A_NAME_IN_AN_EXPORT_LIST_COUNTS_FOR
        self.assertEqual(
            rows,
            {source: occurrences_of('a', source) for source in rows},
        )


A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION = {
    _a_module_reporting_it_loaded('export let b = 5;'): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export function g() { return 3; }
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded('export class K {}'): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export default function h() { return 4; }
        """
    ): 'loaded\n',
    _a_module_reporting_it_loaded(
        """
        export var a;
        a = 1;
        """
    ): 'loaded\n',
    inspect.cleandoc(
        """
        export var a;
        function f() { a = 2; return a; }
        console.log(f());
        """
    ): '2\n',
    inspect.cleandoc(
        """
        export const c = 7;
        console.log(c);
        """
    ): '7\n',
    inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(f());
        """
    ): '4\n',
}

A_DECLARATION_EXPORT_INLINES_ITS_READERS = {
    inspect.cleandoc(
        """
        export const c = 7;
        console.log(c);
        """
    ): inspect.cleandoc(
        """
        export const c = 7;
        console.log(7);
        """
    ),
    inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(f());
        """
    ): inspect.cleandoc(
        """
        export const f = () => 4;
        console.log(4);
        """
    ),
}

A_MODULE_WHOSE_EXPORTED_WRITE_AN_IMPORTER_READS = inspect.cleandoc(
    """
    export var a;
    a = 1;
    console.log(1);
    """
)
AN_IMPORTER_READING_THE_EXPORTED_WRITE = inspect.cleandoc(
    """
    import { a } from './lib.mjs';
    console.log(a);
    """
)
A_MODULE_WHOSE_FUNCTION_WRITES_THE_EXPORT = inspect.cleandoc(
    """
    export var a;
    var f = function () { a = 2; return a; };
    console.log(f());
    """
)

MODULES_READING_AN_EXPORTED_TABLE = (
    inspect.cleandoc(
        """
        export const T = ['a'];
        function A(i) { return T[i]; }
        export function get() { return A(0); }
        """
    ),
    inspect.cleandoc(
        """
        export const T = ['a'];
        export function get() { return T[0]; }
        """
    ),
)
AN_IMPORTER_CHANGING_THE_EXPORTED_TABLE = inspect.cleandoc(
    """
    import { T, get } from './lib.mjs';
    T[0] = 'z';
    console.log(get());
    """
)


class TestAnExportDeclarationKeepsTheBindingItExports(TestBase):

    def test_a_module_that_only_exports_comes_back_as_it_was(self):
        rows = [
            source for source in A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
            if source not in A_DECLARATION_EXPORT_INLINES_ITS_READERS
        ]
        self.assertEqual(spelled(rows), rewritten(rows))

    def test_an_inlined_reader_leaves_the_export_declaration_standing(self):
        rows = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(spelled_as_expected(rows), rewritten(rows))

    def test_every_rewritten_row_is_a_row_of_the_table(self):
        self.assertLessEqual(
            set(A_DECLARATION_EXPORT_INLINES_ITS_READERS),
            set(A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION),
        )

    def test_the_module_model_hands_back_the_same_modules(self):
        rows = A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
        rewrites = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(
            {source: printed(rewrites.get(source, source)) for source in rows},
            rewritten_as_modules(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_module_still_prints_what_it_printed(self):
        rows = A_MODULE_THAT_EXPORTS_THROUGH_ITS_DECLARATION
        self.assertEqual(
            {source: before_and_after(source, module=True) for source in rows},
            each_program_still_prints(rows),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_expected_module_runs_the_way_the_module_it_replaces_does(self):
        rows = A_DECLARATION_EXPORT_INLINES_ITS_READERS
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            {source: behavior(expected, module=True) for source, expected in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_exported_write_is_read_by_an_importer_after_the_fold(self):
        module = A_MODULE_WHOSE_EXPORTED_WRITE_AN_IMPORTER_READS
        importer = AN_IMPORTER_READING_THE_EXPORTED_WRITE
        agreed = ('1\n1\n', None)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                module_graph_behavior(
                    {
                        'main.mjs': importer,
                        'lib.mjs': deobfuscate_source(module, execution=ExecutionModel.module),
                    },
                    'main.mjs',
                ),
            ),
            (agreed, agreed),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_function_writing_the_export_keeps_the_write_an_importer_reads(self):
        module = A_MODULE_WHOSE_FUNCTION_WRITES_THE_EXPORT
        importer = AN_IMPORTER_READING_THE_EXPORTED_WRITE
        agreed = ('2\n2\n', None)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                module_graph_behavior(
                    {
                        'main.mjs': importer,
                        'lib.mjs': deobfuscate_source(module, execution=ExecutionModel.module),
                    },
                    'main.mjs',
                ),
            ),
            (agreed, agreed),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_read_of_an_exported_table_answers_what_an_importer_wrote(self):
        importer = AN_IMPORTER_CHANGING_THE_EXPORTED_TABLE
        self.assertEqual(
            {
                module: (
                    module_graph_behavior({'main.mjs': importer, 'lib.mjs': module}, 'main.mjs'),
                    module_graph_behavior(
                        {
                            'main.mjs': importer,
                            'lib.mjs': deobfuscate_source(module, execution=ExecutionModel.module),
                        },
                        'main.mjs',
                    ),
                )
                for module in MODULES_READING_AN_EXPORTED_TABLE
            },
            {
                module: (('z\n', None), ('z\n', None))
                for module in MODULES_READING_AN_EXPORTED_TABLE
            },
        )

    def test_a_read_of_an_exported_table_is_left_a_read(self):
        through_the_accessor, direct = MODULES_READING_AN_EXPORTED_TABLE
        self.assertIn(
            deobfuscate_source(through_the_accessor, execution=ExecutionModel.module),
            (printed(through_the_accessor), printed(direct)),
        )
        self.assertEqual(deobfuscate_source(direct, execution=ExecutionModel.module), printed(direct))

    @opportunity
    def test_the_accessor_reading_an_exported_table_is_inlined_into_its_caller(self):
        through_the_accessor, direct = MODULES_READING_AN_EXPORTED_TABLE
        self.assertEqual(
            deobfuscate_source(through_the_accessor, execution=ExecutionModel.module),
            printed(direct),
        )


#: `export default foo;` exports the value `foo` holds when the statement runs, not the binding, so
#: it ties nothing to the outside.
WHICH_LOCAL_BINDINGS_AN_EXPORT_TIES_TO_THE_OUTSIDE = {
    'export var a;': {'a'},
    'export let b = 5;': {'b'},
    'export const c = 7;': {'c'},
    'export var a, b;': {'a', 'b'},
    'export function g() {}': {'g'},
    'export class K {}': {'K'},
    'export const { a, b } = o;': {'a', 'b'},
    'export const [x, , y] = o;': {'x', 'y'},
    'export const { p: { q }, ...r } = o;': {'q', 'r'},
    'export const [a = 1] = o;': {'a'},
    'export default function h() {}': {'h'},
    'export default class D {}': {'D'},
    'export default function () {}': set(),
    'export default class {}': set(),
    'var foo = 1;\nexport default foo;': set(),
    'export default 1 + 2;': set(),
    'var q = 1;\nexport { q };': {'q'},
    'var q = 1;\nexport { q as w };': {'q'},
    'var q = 1;\nexport { q as default };': {'q'},
    "export { a } from 'm';": set(),
    "export { a as b } from 'm';": set(),
    "export * from 'm';": set(),
    "export * as ns from 'm';": set(),
}


def exported_bindings(source: str) -> set[str]:
    model = build_semantic_model(JsParser(source).parse())
    names: set[str] = set()
    stack = [model.root_scope]
    while stack:
        scope = stack.pop()
        names |= {name for name, binding in scope.bindings.items() if binding.exported}
        stack.extend(scope.children)
    return names


class TestRecordExportsMarksTheBindingEachExportFormTies(TestBase):

    def test_each_export_form_ties_exactly_its_local_bindings(self):
        rows = WHICH_LOCAL_BINDINGS_AN_EXPORT_TIES_TO_THE_OUTSIDE
        self.assertEqual(
            rows,
            {source: exported_bindings(source) for source in rows},
        )


WHAT_A_NAME_IN_AN_IMPORT_ATTRIBUTE_COUNTS_FOR = {
    inspect.cleandoc(
        """
        var type = 1;
        import d from './x.json' with { type: 'json' };
        console.log(type, d);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        import d from './x.json' with { type: 'json' };
        console.log(d);
        """
    ): (1, 0),
    inspect.cleandoc(
        """
        var type = 1;
        import d from './x.json' assert { type: 'json' };
        console.log(type, d);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        var type = 1;
        sink({ type: 'json' });
        console.log(type);
        """
    ): (3, 2),
    inspect.cleandoc(
        """
        var type = 'k';
        sink({ [type]: 'json' });
        console.log(type);
        """
    ): (3, 3),
    inspect.cleandoc(
        """
        var type = 1;
        sink({ type });
        console.log(type);
        """
    ): (3, 3),
}


class TestAnImportAttributeKeyIsNotARead(TestBase):

    def test_an_attribute_key_is_counted_as_a_name_and_never_as_a_read(self):
        rows = WHAT_A_NAME_IN_AN_IMPORT_ATTRIBUTE_COUNTS_FOR
        self.assertEqual(
            rows,
            {source: occurrences_of('type', source) for source in rows},
        )


A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME = {
    inspect.cleandoc(
        """
        var o = JSON.parse('{"q":9}');
        var NS = {};
        NS.q = 1;
        console.log(NS.q, o['q']);
        """
    ): inspect.cleandoc(
        """
        var q;
        var o = JSON.parse('{"q":9}');
        q = 1;
        console.log(q, o['q']);
        """
    ),
    inspect.cleandoc(
        """
        class C { ['q']() { return 'm'; } }
        var NS = {};
        NS.q = 1;
        console.log(NS.q, new C()['q']());
        """
    ): inspect.cleandoc(
        """
        var q;
        class C { ['q']() { return 'm'; } }
        q = 1;
        console.log(q, new C()['q']());
        """
    ),
}


class TestRenamingAVariableLeavesASameNamedPropertyAlone(TestJsDeobfuscator):

    def _flatten(self, source: str) -> str:
        return self._run_transformer(source, JsNamespaceFlattening)

    def test_a_property_of_another_receiver_is_not_renamed_with_the_namespace(self):
        rows = A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(
            spelled_as_expected(rows),
            {source: self._flatten(source) for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_flattened_program_prints_what_the_program_printed(self):
        rows = A_FLATTENED_NAMESPACE_BESIDE_A_PROPERTY_OF_THE_SAME_NAME
        self.assertEqual(
            run_by_node(rows),
            {source: behavior(self._flatten(source)) for source in rows},
        )
