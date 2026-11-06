"""
Only `escape` writes the same text in every host. The default host covers the Windows Script Host,
which writes the tags of the HTML methods of `String.prototype` in upper case and has no array
iterators, and the text of `Date()` and of a regular expression is the engine's to write; these fold
only where the host is Node.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import printed

from refinery.units.scripting.djs import djs

#: A program mapped to what it prints, to the text the default deobfuscation writes for it, and to
#: the text the deobfuscation writes for it in Node.
_A_STRING_A_BUILT_IN_WRITES: dict[str, tuple[str, str, str]] = {
    "console.log(escape('<i></i>'));": (
        '%3Ci%3E%3C/i%3E\n',
        "console.log('%3Ci%3E%3C/i%3E');",
        "console.log('%3Ci%3E%3C/i%3E');",
    ),
    "console.log(escape(String.fromCharCode(0, 31, 32) + '@*_+-./' + String.fromCharCode(126, 255, 256, 0x1234, 0xD83D, 0xDE00)));": (
        '%00%1F%20@*_+-./%7E%FF%u0100%u1234%uD83D%uDE00\n',
        "console.log('%00%1F%20@*_+-./%7E%FF%u0100%u1234%uD83D%uDE00');",
        "console.log('%00%1F%20@*_+-./%7E%FF%u0100%u1234%uD83D%uDE00');",
    ),
    "console.log(''.fontcolor(), ''.italics());": (
        '<font color="undefined"></font> <i></i>\n',
        "console.log(''.fontcolor(), ''.italics());",
        """console.log('<font color="undefined"></font>', '<i></i>');""",
    ),
    "console.log('x'.italics(), 'x'.link('a\"b'), 'x'.small(), 'x'.strike(), 'x'.sub(), 'x'.sup());": (
        '<i>x</i> <a href="a&quot;b">x</a> <small>x</small> <strike>x</strike> <sub>x</sub> <sup>x</sup>\n',
        "console.log('x'.italics(), 'x'.link('a\"b'), 'x'.small(), 'x'.strike(), 'x'.sub(), 'x'.sup());",
        """console.log('<i>x</i>', '<a href="a&quot;b">x</a>', '<small>x</small>', '<strike>x</strike>', '<sub>x</sub>', '<sup>x</sup>');""",
    ),
    "console.log([].entries() + '', [].keys() + '', [].values() + '', typeof [].values());": (
        '[object Array Iterator] [object Array Iterator] [object Array Iterator] object\n',
        "console.log([].entries() + '', [].keys() + '', [].values() + '', typeof [].values());",
        "console.log('[object Array Iterator]', '[object Array Iterator]', '[object Array Iterator]', 'object');",
    ),
    'console.log((false + Date())[30], (true + Date())[30], (NaN + Date())[30]);': (
        'G M T\n',
        'console.log((false + Date())[30], (true + Date())[30], (NaN + Date())[30]);',
        "console.log('G', 'M', 'T');",
    ),
    "console.log(RegExp + '', RegExp() + '', new RegExp() + '', RegExp('/') + '', RegExp('a/b') + '', /false/ + '');": (
        'function RegExp() { [native code] } /(?:)/ /(?:)/ /\\// /a\\/b/ /false/\n',
        "console.log(RegExp + '', RegExp() + '', new RegExp() + '', RegExp('/') + '', RegExp('a/b') + '', /false/ + '');",
        "console.log('function RegExp() { [native code] }', '/(?:)/', '/(?:)/', '/\\\\//', '/a\\\\/b/', '/false/');",
    ),
    "console.log([][[] + 'constructor'].constructor('return escape')()([].at));": (
        'function%20at%28%29%20%7B%20%5Bnative%20code%5D%20%7D\n',
        "console.log([][[] + 'constructor'].constructor('return escape')()([].at));",
        "console.log('function%20at%28%29%20%7B%20%5Bnative%20code%5D%20%7D');",
    ),
}

_A_BUILT_IN_REACHED_THROUGH_A_CONSTRUCTED_FUNCTION: dict[str, str] = {
    "console.log([][[] + 'constructor'].constructor('return escape')()([].at));": (
        'console.log(escape([].at));'
    ),
}

_EVERY_HTML_METHOD: dict[str, str] = {
    "console.log('x'.anchor('a\"b'), 'x'.big(), 'x'.blink(), 'x'.bold(), 'x'.fixed(), 'x'.fontcolor('a\"b'), 'x'.fontsize('a\"b'));": (
        '<a name="a&quot;b">x</a> <big>x</big> <blink>x</blink> <b>x</b> <tt>x</tt> <font color="a&quot;b">x</font>'
        ' <font size="a&quot;b">x</font>\n'
    ),
}

_A_STRING_THE_PROGRAM_DECIDES: dict[str, str] = {
    "Object.prototype.toString = function () { return 'X'; }; console.log([].entries() + '');": 'X\n',
    "Iterator.prototype.toString = function () { return 'I'; }; console.log([].entries() + '');": 'I\n',
    "Object.getPrototypeOf([].entries()).toString = function () { return 'P'; }; console.log([].entries() + '');": 'P\n',
    "RegExp.prototype.toString = function () { return 'R'; }; console.log(/a/ + '');": 'R\n',
    "Object.defineProperty(RegExp.prototype, 'source', {get: function () { return 'S'; }}); console.log(/a/ + '');": '/S/\n',
    "Object.defineProperty(RegExp.prototype, 'flags', {get: function () { return 'g'; }}); console.log(/a/ + '');": '/a/g\n',
    "escape = function () { return 'E'; }; console.log(escape('<'));": 'E\n',
    "String.prototype.italics = function () { return 'I'; }; console.log(''.italics());": 'I\n',
}

#: Reads the engine decides from more than the language says: a position of `Date()` past its `GMT`,
#: where the time zone's offset stands, and the text of a regular expression whose pattern holds a
#: character with a meaning in a pattern, a flag, or a line break.
_A_STRING_LEFT_TO_THE_ENGINE = [
    'console.log((false + Date())[33]);',
    "console.log(RegExp('a.b') + '', /a/g + '', RegExp('\\n') + '');",
    "console.log(RegExp('(') + '');",
]

_A_STRING_NODE_WRITES: dict[str, tuple[str, str]] = {
    "console.log(RegExp('a.b') + '', /a/g + '', RegExp('\\n') + '');": (
        '/a.b/ /a/g /\\n/\n',
        "console.log('/a.b/', '/a/g', '/\\\\n/');",
    ),
}

#: A program mapped to what Node prints, to the text the default deobfuscation writes for it, and to
#: the text the deobfuscation writes for it in Node.
_A_METHOD_NOT_EVERY_HOST_ANSWERS_ALIKE: dict[str, tuple[str, str, str]] = {
    "console.log(typeof [].values, !![].entries, typeof ''.italics);": (
        'function true function\n',
        "console.log(typeof [].values, !![].entries, 'function');",
        "console.log('function', true, 'function');",
    ),
}

_A_READ_NAMED_LIKE_A_METHOD_OF_A_REGULAR_EXPRESSION: dict[str, tuple[str, str]] = {
    "var cp = require('child_process'); var run = require('util').promisify(cp.exec); console.log('abc'.nope, typeof run);": (
        'undefined function\n',
        "var cp = require('child_process');\nvar run = require('util').promisify(cp.exec);\nconsole.log(void 0, typeof run);",
    ),
}

_EVERY_MODE = [
    (False, 'universal'),
    (False, 'node'),
    (True, 'node'),
]


def _deobfuscated(source: str, strict: bool, environment: str) -> str:
    return source.encode('utf8') | djs(strict=strict, environment=environment) | str


class TestAStringABuiltInWrites(TestBase):

    def test_the_default_deobfuscation_folds_only_escape(self):
        named = _A_BUILT_IN_REACHED_THROUGH_A_CONSTRUCTED_FUNCTION
        for source, (_, universal, _) in _A_STRING_A_BUILT_IN_WRITES.items():
            with self.subTest(source=source):
                self.assertIn(
                    _deobfuscated(source, False, 'universal'),
                    (universal, named.get(source, universal)),
                )

    @opportunity
    def test_the_default_deobfuscation_names_a_built_in_reached_through_a_constructed_function(self):
        for source, named in _A_BUILT_IN_REACHED_THROUGH_A_CONSTRUCTED_FUNCTION.items():
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source, False, 'universal'), named)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_for_the_text_naming_the_built_in(self):
        for source, named in _A_BUILT_IN_REACHED_THROUGH_A_CONSTRUCTED_FUNCTION.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(named), behavior(source))

    def test_each_deobfuscation_in_node_folds_every_one(self):
        for source, (_, _, folded) in _A_STRING_A_BUILT_IN_WRITES.items():
            for strict in (False, True):
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(_deobfuscated(source, strict, 'node'), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records(self):
        rows = {source: prints for source, (prints, _, _) in _A_STRING_A_BUILT_IN_WRITES.items()}
        for source, prints in (rows | _EVERY_HTML_METHOD | _A_STRING_THE_PROGRAM_DECIDES).items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_prints_what_the_program_prints(self):
        rows = {source: prints for source, (prints, _, _) in _A_STRING_A_BUILT_IN_WRITES.items()}
        for source, prints in (rows | _EVERY_HTML_METHOD).items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))


class TestAStringTheProgramOrTheEngineDecides(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_read_it_writes_alike_records_and_so_does_its_text(self):
        for source, (prints, folded) in _A_STRING_NODE_WRITES.items():
            with self.subTest(source=source):
                self.assertEqual((behavior(source), behavior(folded)), ((prints, None), (prints, None)))

    def test_each_deobfuscation_leaves_the_read_standing(self):
        for source in [*_A_STRING_THE_PROGRAM_DECIDES, *_A_STRING_LEFT_TO_THE_ENGINE]:
            last = source.rpartition('console.log(')[2]
            modes = [
                (strict, environment)
                for strict, environment in _EVERY_MODE
                if environment != 'node' or source not in _A_STRING_NODE_WRITES
            ]
            for strict, environment in modes:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertIn(last, _deobfuscated(source, strict, environment))

    def test_each_deobfuscation_in_node_leaves_a_read_node_writes_alike_standing_or_writes_its_text(self):
        for source, (_, folded) in _A_STRING_NODE_WRITES.items():
            for strict in (False, True):
                with self.subTest(source=source, strict=strict):
                    self.assertIn(_deobfuscated(source, strict, 'node'), (printed(source), folded))

    @opportunity
    def test_each_deobfuscation_in_node_writes_the_text_of_a_read_node_writes_alike(self):
        for source, (_, folded) in _A_STRING_NODE_WRITES.items():
            for strict in (False, True):
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(_deobfuscated(source, strict, 'node'), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_does_what_the_program_does(self):
        for source in [*_A_STRING_THE_PROGRAM_DECIDES, *_A_STRING_LEFT_TO_THE_ENGINE]:
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), behavior(source))


class TestAMethodNotEveryHostAnswersAlike(TestBase):

    def test_the_default_deobfuscation_leaves_what_the_windows_script_host_answers_otherwise(self):
        for source, (_, universal, _) in _A_METHOD_NOT_EVERY_HOST_ANSWERS_ALIKE.items():
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source, False, 'universal'), universal)

    def test_the_deobfuscation_in_node_folds_it(self):
        for source, (_, _, folded) in _A_METHOD_NOT_EVERY_HOST_ANSWERS_ALIKE.items():
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source, False, 'node'), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records_for_the_program_and_its_folded_text(self):
        for source, (prints, _, folded) in _A_METHOD_NOT_EVERY_HOST_ANSWERS_ALIKE.items():
            with self.subTest(source=source):
                self.assertEqual((behavior(source), behavior(folded)), ((prints, None), (prints, None)))


class TestAReadNamedLikeAMethodOfARegularExpression(TestBase):

    def test_each_deobfuscation_still_folds_what_the_prototype_of_strings_answers(self):
        for source, (_, folded) in _A_READ_NAMED_LIKE_A_METHOD_OF_A_REGULAR_EXPRESSION.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(_deobfuscated(source, strict, environment), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records_for_the_program_and_its_folded_text(self):
        for source, (prints, folded) in _A_READ_NAMED_LIKE_A_METHOD_OF_A_REGULAR_EXPRESSION.items():
            with self.subTest(source=source):
                self.assertEqual((behavior(source), behavior(folded)), ((prints, None), (prints, None)))
