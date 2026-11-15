"""
SECURITY: Node runs every program here. Each is written by hand; never add one taken from a sample.
"""
from __future__ import annotations

import unittest

from test import TestBase, todo, wontfix
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    folded,
    node_prints_what_each_program_pins,
    printed,
    prints,
)

from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.modulemap import JsModuleMapUnwrapper
from refinery.lib.scripts.js.model import JsFunctionExpression, JsVariableDeclaration
from refinery.lib.scripts.js.options import DeobfuscationOptions, ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.js.values import function_source, recorded_function_name

FORTY_TWO = 'cmV0dXJuIDQyOw=='
COUNTER = 'dmFyIG4gPSAwOyByZXR1cm4geyBuZXh0OiBmdW5jdGlvbiAoKSB7IHJldHVybiArK247IH0gfTs='
SEVEN = 'cmV0dXJuIDc7'
THIS = 'cmV0dXJuIHRoaXMgPT09IGdsb2JhbFRoaXM7'
CALLEE_NAME = 'cmV0dXJuIGFyZ3VtZW50cy5jYWxsZWUubmFtZTs='
READS_E = 'cmV0dXJuIGU7'
TYPEOF_E = 'cmV0dXJuIHR5cGVvZiBlOw=='
EVAL_TYPEOF_E = 'cmV0dXJuIGV2YWwoInR5cGVvZiBlIik7'
NEW_TARGET = 'cmV0dXJuIG5ldy50YXJnZXQgPT09IHVuZGVmaW5lZDs='
ARGUMENT_COUNT = 'cmV0dXJuIGFyZ3VtZW50cy5sZW5ndGg7'
REQUIRE = 'cmV0dXJuIHR5cGVvZiByZXF1aXJlOw=='
WRITES_THE_PROTOTYPE = 'T2JqZWN0LnByb3RvdHlwZS5rID0gMTsgcmV0dXJuIDE7'
AWAIT = 'dmFyIGF3YWl0ID0gNTsgcmV0dXJuIGF3YWl0Ow=='
WRITES_ATOB = 'YXRvYiA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuICJyZXR1cm4gNzsiOyB9OyByZXR1cm4gMTs='
WRITES_A_FREE_NAME = 'cSA9IDE7IHJldHVybiBxOw=='
DIRECT_EVAL = 'cmV0dXJuIGV2YWwoIjEgKyAxIik7'
LISTS_GLOBALS = 'cmV0dXJuIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKGdsb2JhbFRoaXMpLmxlbmd0aCA+IDA7'
READS_K1 = 'cmV0dXJuIHR5cGVvZiBrMTs='

TRIES_EACH_KEY = (
    "for (var key of ['k1', 'toString']) {\n"
    "  try { console.log(key, load(key)); } catch (x) { console.log(key, x.name); }\n"
    "}"
)


def a_registry(
    entries: str,
    calls: str,
    *,
    cache: str = '{}',
    site: str = 'const I = atob(MM[M]);\n      e[M] = new Function(I)();',
    before: str = '',
    inside: str = '',
) -> str:
    """
    A loader holding the map *entries* and a getter `c` that builds an entry at its first call and
    hands out the one it built at every later call, followed by *calls* of the getter as `load`.
    """
    return a_program(F"""
        {before}
        var load = function () {{
          var MM = {{ {entries} }};
          var e = {cache};
          {inside}
          function c(M) {{
            if (M in e == false) {{
              if (M in MM != true) {{
                throw new Error('');
              }}
              {site}
            }}
            return e[M];
          }}
          return c;
        }}();
        {calls}
        """)


def unwrapped(source: str, execution: ExecutionModel = ExecutionModel.script) -> str:
    ast = JsParser(source).parse()
    transformer = JsModuleMapUnwrapper()
    transformer.options = DeobfuscationOptions(execution=execution)
    transformer.models = ModelCache(ast, transformer.options)
    transformer.visit(ast)
    return JsSynthesizer().convert(ast)


def functions_written_at_the_top(source: str) -> list[JsFunctionExpression]:
    ast = JsParser(source).parse()
    transformer = JsModuleMapUnwrapper()
    transformer.options = DeobfuscationOptions(execution=ExecutionModel.script)
    transformer.models = ModelCache(ast, transformer.options)
    transformer.visit(ast)
    functions: list[JsFunctionExpression] = []
    for statement in ast.body:
        if not isinstance(statement, JsVariableDeclaration):
            break
        for declarator in statement.declarations:
            if isinstance(declarator.init, JsFunctionExpression):
                functions.append(declarator.init)
    return functions


def builds_from_text(text: str) -> bool:
    return 'Function(' in text or 'atob(' in text


A_REGISTRY_THAT_FOLDS: dict[str, Program] = {
    'two entries, one holding state': Program(
        a_registry(
            F"k1: '{FORTY_TWO}', k2: '{COUNTER}'",
            "console.log(load('k1'), load('k1'));\nconsole.log(load('k2').next(), load('k2').next());",
        ),
        prints('42 42', '1 2'),
        Reading.SCRIPT,
    ),
    'a construction holding the decode in place': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'));",
            site='e[M] = new Function(atob(MM[M]))();',
        ),
        prints('42'),
        Reading.SCRIPT,
    ),
    'a getter testing with the not operator': Program(
        a_program(F"""
            var load = function () {{
              var MM = {{ k1: '{FORTY_TWO}' }};
              var e = {{}};
              function c(M) {{
                if (!(M in e)) {{
                  if (!(M in MM)) {{
                    throw new Error('');
                  }}
                  e[M] = new Function(atob(MM[M]))();
                }}
                return e[M];
              }}
              return c;
            }}();
            console.log(load('k1'));
            """),
        prints('42'),
        Reading.SCRIPT,
    ),
    'an entry reading the receiver it is called with': Program(
        a_registry(F"k1: '{THIS}'", "console.log(load('k1'));"),
        prints('true'),
        Reading.SCRIPT,
    ),
    'a construction called with an argument': Program(
        a_registry(
            F"k1: '{ARGUMENT_COUNT}'",
            "console.log(load('k1'));",
            site="e[M] = new Function(atob(MM[M]))(console.log('argument'));",
        ),
        prints('argument', '1'),
        Reading.SCRIPT,
    ),
    'a key that is no name': Program(
        a_registry(F"'57-x': '{SEVEN}'", "console.log(load('57-x'));"),
        prints('7'),
        Reading.SCRIPT,
    ),
    'an entry spelling await as a name, under an async function': Program(
        a_program(F"""
            async function main() {{
              var MM = {{ k1: '{AWAIT}' }};
              var e = {{}};
              function c(M) {{
                if (M in e == false) {{
                  if (M in MM != true) {{
                    throw new Error('');
                  }}
                  e[M] = new Function(atob(MM[M]))();
                }}
                return e[M];
              }}
              return c('k1');
            }}
            main().then(function (v) {{ console.log(v); }});
            """),
        prints('5'),
        Reading.SCRIPT,
    ),
    'a key the loader already names': Program(
        a_registry(
            F"k1: '{SEVEN}'",
            "console.log(load('k1'));",
            inside='var k1 = 3;\n  console.log(k1);',
        ),
        prints('3', '7'),
        Reading.SCRIPT,
    ),
    'an entry reading a global named like its key': Program(
        a_registry(F"k1: '{READS_K1}'", "console.log(load('k1'));"),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'an entry reading a name the loader binds': Program(
        a_registry(F"k1: '{READS_E}'", "try { console.log(load('k1')); } catch (x) { console.log(x.name); }"),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'an entry testing a name the loader binds': Program(
        a_registry(F"k1: '{TYPEOF_E}'", "console.log(load('k1'));"),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'an entry evaluating a text that names what the loader binds': Program(
        a_registry(F"k1: '{EVAL_TYPEOF_E}'", "console.log(load('k1'));"),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'an entry running a direct eval': Program(
        a_registry(F"k1: '{DIRECT_EVAL}'", "console.log(load('k1'));"),
        prints('2'),
        Reading.SCRIPT,
    ),
    'an entry reading new.target': Program(
        a_registry(F"k1: '{NEW_TARGET}'", "console.log(load('k1'));"),
        prints('true'),
        Reading.SCRIPT,
    ),
    'an entry writing a name nothing declares': Program(
        a_registry(F"k1: '{WRITES_A_FREE_NAME}'", "console.log(load('k1'), q);"),
        prints('1 1'),
        Reading.SCRIPT,
    ),
    'an entry reading a name the CommonJS wrapper binds': Program(
        a_registry(F"k1: '{REQUIRE}'", "console.log(load('k1'));"),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'an entry writing a prototype before another entry is built': Program(
        a_registry(
            F"k1: '{WRITES_THE_PROTOTYPE}', k2: '{SEVEN}'",
            "console.log(load('k1'), load('k2'), ({}).k);",
        ),
        prints('1 7 1'),
        Reading.SCRIPT,
    ),
    'an entry listing the globals': Program(
        a_registry(
            F"k1: '{LISTS_GLOBALS}', k2: '{FORTY_TWO}'",
            "console.log(load('k1'), load('k2'));",
        ),
        prints('true 42'),
        Reading.SCRIPT,
    ),
}

A_REGISTRY_THAT_STAYS: dict[str, Program] = {
    'a map holding the key __proto__': Program(
        a_registry(
            F"'__proto__': '{FORTY_TWO}', k1: '{SEVEN}'",
            "console.log(load('k1'), typeof load('__proto__'));",
        ),
        prints('7 object'),
        Reading.SCRIPT,
    ),
    'a construction not called in place': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1') === load('k1'), load('k1')());",
            site='e[M] = new Function(atob(MM[M]));',
        ),
        prints('true 42'),
        Reading.SCRIPT,
    ),
    'a getter guarded by the map alone': Program(
        a_program(F"""
            var MM = {{ k1: '{FORTY_TWO}' }};
            function c(M) {{
              if (M in MM != true) {{
                throw new Error('');
              }}
              return new Function(atob(MM[M]))();
            }}
            for (var key of ['k1', 'toString', 'valueOf', '__proto__', 'nope']) {{
              try {{ console.log(key, c(key)); }} catch (x) {{ console.log(key, x.name); }}
            }}
            """),
        prints(
            'k1 42',
            'toString InvalidCharacterError',
            'valueOf InvalidCharacterError',
            '__proto__ InvalidCharacterError',
            'nope Error',
        ),
        Reading.SCRIPT,
    ),
    'a cache made without a prototype': Program(
        a_registry(F"k1: '{FORTY_TWO}'", TRIES_EACH_KEY, cache='Object.create(null)'),
        prints('k1 42', 'toString InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a cache literal without a prototype': Program(
        a_registry(F"k1: '{FORTY_TWO}'", TRIES_EACH_KEY, cache='{ __proto__: null }'),
        prints('k1 42', 'toString InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a cache whose prototype the loader takes away': Program(
        a_registry(F"k1: '{FORTY_TWO}'", TRIES_EACH_KEY, inside='Object.setPrototypeOf(e, null);'),
        prints('k1 42', 'toString InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a decode the program replaced': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'));",
            before="var atob = function () { return 'return 1;'; };",
        ),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a decode the program replaced on the global object': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'));",
            before="globalThis.atob = function () { return 'return 1;'; };",
        ),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a constructor the program replaced': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'));",
            before='var Function = function () { return function () { return 1; }; };',
        ),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a map written after its declaration': Program(
        a_registry(F"k1: '{FORTY_TWO}'", "console.log(load('k1'));", inside=F"MM.k1 = '{SEVEN}';"),
        prints('7'),
        Reading.SCRIPT,
    ),
    'a map losing an entry': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "try { console.log(load('k1')); } catch (x) { console.log(x.name); }",
            inside='delete MM.k1;',
        ),
        prints('Error'),
        Reading.SCRIPT,
    ),
    'a map handed on': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'));",
            inside='console.log(Object.keys(MM).length);',
        ),
        prints('1', '42'),
        Reading.SCRIPT,
    ),
    'a key written between the test and the construction': Program(
        a_registry(
            F"k1: '{FORTY_TWO}'",
            "try { console.log(load('k1')); } catch (x) { console.log(x.name); }",
            site="M = 'toString';\n      e[M] = new Function(atob(MM[M]))();",
        ),
        prints('InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a decode read before the test of the map': Program(
        a_program(F"""
            var load = function () {{
              var MM = {{ k1: '{FORTY_TWO}' }};
              var e = {{}};
              function c(M) {{
                if (M in e == false) {{
                  const I = atob(MM[M]);
                  if (M in MM != true) {{
                    throw new Error('');
                  }}
                  e[M] = new Function(I)();
                }}
                return e[M];
              }}
              return c;
            }}();
            for (var key of ['k1', 'nope']) {{
              try {{ console.log(key, load(key)); }} catch (x) {{ console.log(key, x.name); }}
            }}
            """),
        prints('k1 42', 'nope InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a map with an entry that does not decode': Program(
        a_registry(
            F"k1: '{FORTY_TWO}', k2: 'not base64!'",
            "console.log(load('k1'));\ntry { load('k2'); } catch (x) { console.log(x.name); }",
        ),
        prints('42', 'InvalidCharacterError'),
        Reading.SCRIPT,
    ),
    'a map with an entry that does not parse': Program(
        a_registry(
            F"k1: '{FORTY_TWO}', k2: 'cmV0dXJuICg7'",
            "console.log(load('k1'));\ntry { load('k2'); } catch (x) { console.log(x.name); }",
        ),
        prints('42', 'SyntaxError'),
        Reading.SCRIPT,
    ),
    'a map declared under a with statement': Program(
        a_program(F"""
            var scope = {{ k1: 5, k2: 0 }};
            with (scope) {{
              var MM = {{ k2: '{READS_K1}' }};
              var e = {{}};
              var load = function (M) {{
                if (M in e == false) {{
                  if (M in MM != true) {{
                    throw new Error('');
                  }}
                  e[M] = new Function(atob(MM[M]))();
                }}
                return e[M];
              }};
            }}
            console.log(load('k2'));
            """),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'a strict script': Program(
        a_program(F"""
            'use strict';
            var load = function () {{
              var MM = {{ k1: '{WRITES_A_FREE_NAME}' }};
              var e = {{}};
              function c(M) {{
                if (M in e == false) {{
                  if (M in MM != true) {{
                    throw new Error('');
                  }}
                  e[M] = new Function(atob(MM[M]))();
                }}
                return e[M];
              }}
              return c;
            }}();
            console.log(load('k1'));
            """),
        prints('1'),
        Reading.SCRIPT,
    ),
    'a CommonJS file': Program(
        a_registry(F"k1: '{READS_E}'", "try { console.log(load('k1')); } catch (x) { console.log(x.name); }"),
        prints('ReferenceError'),
        Reading.COMMONJS,
    ),
}

AN_ENTRY_REPLACING_THE_DECODE = Program(
    a_registry(
        F"k1: '{WRITES_ATOB}', k2: '{FORTY_TWO}'",
        "console.log(load('k1'), load('k2'));",
    ),
    prints('1 7'),
    Reading.SCRIPT,
)

AN_ENTRY_READING_ITS_OWN_NAME = Program(
    a_registry(F"k1: '{CALLEE_NAME}'", "console.log(load('k1'));"),
    prints('anonymous'),
    Reading.SCRIPT,
)

EVERY_REGISTRY = {
    **A_REGISTRY_THAT_FOLDS,
    **A_REGISTRY_THAT_STAYS,
    'an entry replacing the decode before another entry is built': AN_ENTRY_REPLACING_THE_DECODE,
    'an entry reading the name of its own function': AN_ENTRY_READING_ITS_OWN_NAME,
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARegistryOfFunctionsKeptAsTextStillPrintsWhatItPrints(TestBase):

    def test_node_prints_what_each_program_pins(self):
        node_prints_what_each_program_pins(self, EVERY_REGISTRY)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in {**A_REGISTRY_THAT_FOLDS, **A_REGISTRY_THAT_STAYS}.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    @todo
    def test_an_entry_replacing_the_decode_still_prints_what_it_prints(self):
        self.assertEqual(AN_ENTRY_REPLACING_THE_DECODE.read(), AN_ENTRY_REPLACING_THE_DECODE.required())

    @wontfix('the name a deobfuscated function owns is the analyst\'s; a fold reads the recorded one')
    def test_an_entry_reading_its_own_name_still_prints_what_it_prints(self):
        self.assertEqual(AN_ENTRY_READING_ITS_OWN_NAME.read(), AN_ENTRY_READING_ITS_OWN_NAME.required())


class TestARegistryOfFunctionsKeptAsTextIsWrittenOut(TestBase):

    def test_every_registry_that_folds_builds_nothing_from_text(self):
        for label, row in A_REGISTRY_THAT_FOLDS.items():
            with self.subTest(label=label):
                self.assertEqual(builds_from_text(folded(row.text)), False)

    def test_every_registry_whose_fold_would_change_what_it_does_still_builds_from_text(self):
        for label, row in A_REGISTRY_THAT_STAYS.items():
            with self.subTest(label=label):
                text = deobfuscate_source(row.text, execution=ExecutionModel.commonjs) if (
                    row.reading is Reading.COMMONJS
                ) else folded(row.text)
                self.assertEqual(builds_from_text(text), True)

    def test_two_entries_become_two_functions_written_at_the_top(self):
        self.assertEqual(
            unwrapped(A_REGISTRY_THAT_FOLDS['two entries, one holding state'].text),
            printed(a_program("""
                const __inlined_fn_dd3ae856 = function () {
                  return 42;
                };
                const __inlined_fn_8f7c742e = function () {
                  var n = 0;
                  return { next: function () { return ++n; } };
                };
                var load = function () {
                  var MM = { k1: __inlined_fn_dd3ae856, k2: __inlined_fn_8f7c742e };
                  var e = {};
                  function c(M) {
                    if (M in e == false) {
                      if (M in MM != true) {
                        throw new Error('');
                      }
                      e[M] = (0, MM[M])();
                    }
                    return e[M];
                  }
                  return c;
                }();
                console.log(load('k1'), load('k1'));
                console.log(load('k2').next(), load('k2').next());
                """)),
        )

    def test_a_construction_called_with_an_argument_becomes_a_call_with_it(self):
        self.assertEqual(
            unwrapped(A_REGISTRY_THAT_FOLDS['a construction called with an argument'].text),
            printed(a_program("""
                const __inlined_fn_eb115a9e = function () {
                  return arguments.length;
                };
                var load = function () {
                  var MM = { k1: __inlined_fn_eb115a9e };
                  var e = {};
                  function c(M) {
                    if (M in e == false) {
                      if (M in MM != true) {
                        throw new Error('');
                      }
                      e[M] = (0, MM[M])(console.log('argument'));
                    }
                    return e[M];
                  }
                  return c;
                }();
                console.log(load('k1'));
                """)),
        )

    def test_an_entry_is_written_after_the_directives_of_the_script(self):
        registry = a_registry(F"k1: '{FORTY_TWO}'", "console.log(load('k1'));")
        source = F"'a directive';\n{registry}"
        self.assertEqual(
            unwrapped(source).splitlines()[:2],
            printed(a_program("""
                'a directive';
                const __inlined_fn_dd3ae856 = function () {
                  return 42;
                };
                """)).splitlines()[:2],
        )

    def test_a_name_the_file_spells_takes_a_suffix(self):
        source = a_registry(
            F"k1: '{FORTY_TWO}'",
            "console.log(load('k1'), '__inlined_fn_dd3ae856');",
        )
        self.assertEqual(
            unwrapped(source).splitlines()[0],
            printed('const __inlined_fn_dd3ae856_1 = function () {\n  return 42;\n};\n').splitlines()[0],
        )

    def test_a_commonjs_file_is_left_as_it_is(self):
        source = A_REGISTRY_THAT_STAYS['a CommonJS file'].text
        self.assertEqual(unwrapped(source, ExecutionModel.commonjs), printed(source))

    def test_a_written_function_answers_the_text_the_construction_builds(self):
        functions = functions_written_at_the_top(A_REGISTRY_THAT_FOLDS['two entries, one holding state'].text)
        self.assertEqual(
            [function_source(function) for function in functions],
            [
                'function anonymous(\n) {\nreturn 42;\n}',
                'function anonymous(\n) {\nvar n = 0; return { next: function () { return ++n; } };\n}',
            ],
        )

    def test_a_written_function_answers_the_name_the_construction_gives(self):
        functions = functions_written_at_the_top(A_REGISTRY_THAT_FOLDS['two entries, one holding state'].text)
        self.assertEqual([recorded_function_name(function) for function in functions], ['anonymous', 'anonymous'])

    @todo
    def test_a_fold_of_the_name_of_a_written_function_answers_anonymous(self):
        self.assertEqual(
            folded(a_registry(F"k1: '{CALLEE_NAME}'", "console.log(load('k1'));")),
            "console.log('anonymous');\n",
        )
