from __future__ import annotations

import inspect

from typing import NamedTuple

from test import TestBase

from refinery.lib.scripts import Expression, canonical, is_well_formed
from refinery.lib.scripts.guess import guess_language
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsFunctionDeclaration,
    JsScript,
    JsStringLiteral,
    JsTemplateLiteral,
    JsVariableDeclaration,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting.js import js


_TOP_LEVEL = inspect.cleandoc("""
    const registry = {};

    function register(name, handler) {
      registry[name] = handler;
      return handler;
    }

    register('alpha', function (input) {
      return input.split(',').map(function (part) {
        return part.trim();
      });
    });
""") + '\n'

_FUNCTION_BODY = _TOP_LEVEL + inspect.cleandoc("""
    function describe(name) {
      const handler = registry[name];
""") + '\n'

_STATEMENTS_BEFORE_THE_CUT = 3


class Truncation(NamedTuple):
    """
    A file that stops in the middle of one construct, together with the text that would have
    finished it. `cut` is what an analyst carves out of memory and `whole` is the file it was cut
    from, so a difference between the two is caused by the cut and nothing else.
    """
    head: str
    opened: str
    closing: str

    @property
    def cut(self) -> str:
        return F'{self.head}{self.opened}'

    @property
    def whole(self) -> str:
        return F'{self.head}{self.opened}{self.closing}'


_TRUNCATIONS = {
    'string_at_top_level': Truncation(
        _TOP_LEVEL,
        "const banner = 'loading the alpha module",
        "';\n",
    ),
    'template_at_top_level': Truncation(
        _TOP_LEVEL,
        'const banner = `loading ${registry.alpha} and everything after it',
        '`;\n',
    ),
    'template_hole_at_top_level': Truncation(
        _TOP_LEVEL,
        'const banner = `loading ${Object.keys(registry',
        ').length} modules`;\n',
    ),
    'regexp_at_top_level': Truncation(
        _TOP_LEVEL,
        'const pattern = /^alpha-[0-9]+',
        '$/;\n',
    ),
    'comment_at_top_level': Truncation(
        _TOP_LEVEL,
        '/* the registry maps each name to the handler that reads it',
        " */\nregister('beta', registry.alpha);\n",
    ),
    'string_in_function_body': Truncation(
        _FUNCTION_BODY,
        "  const label = 'describing the handler for ",
        "';\n}\n",
    ),
    'template_in_function_body': Truncation(
        _FUNCTION_BODY,
        '  const label = `handler ${handler} registered for ',
        '`;\n}\n',
    ),
    'template_hole_in_function_body': Truncation(
        _FUNCTION_BODY,
        '  const label = `handler ${handler.toString(',
        ')} for ${name}`;\n}\n',
    ),
    'regexp_in_function_body': Truncation(
        _FUNCTION_BODY,
        '  const clean = name.replace(/[^a-z0-9',
        "]+/g, '-');\n}\n",
    ),
    'comment_in_function_body': Truncation(
        _FUNCTION_BODY,
        '  /* the handler is the function that was registered under this name',
        ' */\n  return handler;\n}\n',
    ),
}


_FOLDS = {
    'template_at_top_level': Truncation(
        _TOP_LEVEL,
        'const banner = `loading ` + `the alpha module',
        '`;\nconsole.log(banner);\n',
    ),
    'argument_at_top_level': Truncation(
        _TOP_LEVEL,
        "console.log('loading ' + 'the alpha module",
        "');\n",
    ),
}
"""
Files whose last statement is a constant expression the tool computes, cut in the middle of one of
the literals that expression is built from. Node accepts every `whole` here and refuses every `cut`,
so the closing quote is the whole of the difference between a program and a buffer that is not one.
"""

FOLDS_ANSWERED_WITH_A_PROGRAM = {
    'concatenation_at_top_level': Truncation(
        _TOP_LEVEL,
        "const banner = 'loading ' + 'the alpha module",
        "';\nconsole.log(banner);\n",
    ),
    'array_at_top_level': Truncation(
        _TOP_LEVEL,
        "const parts = ['loading ', 'the alpha module",
        "'];\nconsole.log(parts.join(''));\n",
    ),
    'concatenation_in_function_body': Truncation(
        _FUNCTION_BODY,
        "  const label = 'describing ' + 'the handler",
        "';\n  return label;\n}\nconsole.log(describe('alpha'));\n",
    ),
    'call_result_in_function_body': Truncation(
        _FUNCTION_BODY,
        "  const label = 'describing the handler'.toUpperCase() + 'x",
        "';\n  return label;\n}\nconsole.log(describe('alpha'));\n",
    ),
}
"""
The same kind of file, cut the same way, where the literal the cut left open stands in a declaration
nothing goes on to read: the declaration is dropped before anything is printed, so the literal never
reaches the printer at all. Nothing here is a program either, and the answer these are given is
pinned in `test.lib.scripts.js.test_unfixed_defects`.
"""

_EVERY_FOLD = {**_FOLDS, **FOLDS_ANSWERED_WITH_A_PROGRAM}


def _string_continued_over(line_ending: str) -> str:
    return F"{_TOP_LEVEL}const banner = 'loading \\{line_ending}the alpha module';\n"


def _string_holding(separator: str) -> str:
    return F"{_TOP_LEVEL}const banner = 'loading{separator}the module';\n"


_INTACT = {
    'line_continuation_lf': _string_continued_over('\n'),
    'line_continuation_crlf': _string_continued_over('\r\n'),
    'line_continuation_cr': _string_continued_over('\r'),
    'line_separator_in_string': _string_holding(chr(0x2028)),
    'paragraph_separator_in_string': _string_holding(chr(0x2029)),
    'template_across_lines': _TOP_LEVEL + inspect.cleandoc("""
        const banner = `loading
        the alpha
        module`;
    """) + '\n',
    'slash_inside_character_class': F'{_TOP_LEVEL}const pattern = /^[/a-z]+$/;\n',
}


def _last_initializer(script: JsScript) -> Expression:
    """
    The value the last declaration of *script* is given, reached through the function body where the
    corpus put that declaration inside one.
    """
    statement = script.body[-1]
    if isinstance(statement, JsFunctionDeclaration):
        assert isinstance(statement.body, JsBlockStatement)
        statement = statement.body.body[-1]
    assert isinstance(statement, JsVariableDeclaration)
    initializer = statement.declarations[0].init
    assert initializer is not None
    return initializer


class TestTruncatedSource(TestBase):

    def _print(self, script: JsScript, unescape_strings: bool = False) -> str:
        return JsSynthesizer(unescape_strings=unescape_strings).convert(script)

    def _string_denoted_by(self, source: str) -> tuple[str, bool]:
        literal = _last_initializer(JsParser(source).parse())
        assert isinstance(literal, JsStringLiteral)
        return literal.value, literal.terminated

    def _template_runs_of(self, source: str) -> list[tuple[str | None, bool, bool]]:
        literal = _last_initializer(JsParser(source).parse())
        assert isinstance(literal, JsTemplateLiteral)
        return [(run.value, run.tail, run.terminated) for run in literal.quasis]

    def test_everything_before_the_cut_parses_to_what_the_whole_file_parses_to(self):
        for name, truncation in _TRUNCATIONS.items():
            with self.subTest(name):
                cut = JsParser(truncation.cut).parse()
                whole = JsParser(truncation.whole).parse()
                self.assertEqual(
                    [canonical(node) for node in cut.body[:_STATEMENTS_BEFORE_THE_CUT]],
                    [canonical(node) for node in whole.body[:_STATEMENTS_BEFORE_THE_CUT]],
                )

    def test_the_construct_the_cut_broke_still_becomes_a_statement_unless_it_was_a_comment(self):
        expected = {
            'string_at_top_level': 4,
            'template_at_top_level': 4,
            'template_hole_at_top_level': 4,
            'regexp_at_top_level': 4,
            'comment_at_top_level': 3,
            'string_in_function_body': 4,
            'template_in_function_body': 4,
            'template_hole_in_function_body': 4,
            'regexp_in_function_body': 4,
            'comment_in_function_body': 4,
        }
        for name, count in expected.items():
            with self.subTest(name):
                self.assertEqual(len(JsParser(_TRUNCATIONS[name].cut).parse().body), count)

    def test_a_string_the_cut_left_open_keeps_its_text_and_records_the_missing_quote(self):
        self.assertEqual(
            self._string_denoted_by(_TRUNCATIONS['string_at_top_level'].cut),
            ('loading the alpha module', False),
        )
        self.assertEqual(
            self._string_denoted_by(_TRUNCATIONS['string_at_top_level'].whole),
            ('loading the alpha module', True),
        )
        self.assertEqual(
            self._string_denoted_by(_TRUNCATIONS['string_in_function_body'].cut),
            ('describing the handler for ', False),
        )
        self.assertEqual(
            self._string_denoted_by(_TRUNCATIONS['string_in_function_body'].whole),
            ('describing the handler for ', True),
        )

    def test_a_template_the_cut_left_open_keeps_its_runs_and_records_the_missing_delimiter(self):
        expected = {
            'template_at_top_level': [
                ('loading ', False, True),
                (' and everything after it', True, False),
            ],
            'template_hole_at_top_level': [
                ('loading ', False, True),
                ('', True, False),
            ],
            'template_in_function_body': [
                ('handler ', False, True),
                (' registered for ', True, False),
            ],
            'template_hole_in_function_body': [
                ('handler ', False, True),
                ('', True, False),
            ],
        }
        for name, runs in expected.items():
            with self.subTest(name):
                self.assertEqual(self._template_runs_of(_TRUNCATIONS[name].cut), runs)

    def test_a_template_the_cut_completed_is_terminated(self):
        expected = {
            'template_at_top_level': [
                ('loading ', False, True),
                (' and everything after it', True, True),
            ],
            'template_hole_at_top_level': [
                ('loading ', False, True),
                (' modules', True, True),
            ],
            'template_in_function_body': [
                ('handler ', False, True),
                (' registered for ', True, True),
            ],
            'template_hole_in_function_body': [
                ('handler ', False, True),
                (' for ', False, True),
                ('', True, True),
            ],
        }
        for name, runs in expected.items():
            with self.subTest(name):
                self.assertEqual(self._template_runs_of(_TRUNCATIONS[name].whole), runs)

    def test_no_tree_is_well_formed_after_the_cut(self):
        """
        Whatever the cut ran into says so. A literal the cut ran into records the delimiter it is
        missing; a block the cut ran into records that nothing closed it; a comment the cut ran
        into is the last thing the file holds, and the file records that it ended inside one. Node
        refuses every cut file, and so every tree reports that it is no program.
        """
        names = list(_TRUNCATIONS)
        self.assertEqual(
            {name: is_well_formed(JsParser(_TRUNCATIONS[name].cut).parse()) for name in names},
            {name: False for name in names},
        )

    def test_only_a_cut_inside_a_comment_ends_the_file_inside_one(self):
        names = list(_TRUNCATIONS)
        self.assertEqual(
            {name: JsParser(_TRUNCATIONS[name].cut).parse().terminated for name in names},
            {name: name not in ('comment_at_top_level', 'comment_in_function_body') for name in names},
        )

    def test_every_whole_file_and_every_intact_file_is_well_formed(self):
        sources = {name: case.whole for name, case in _TRUNCATIONS.items()}
        sources.update(_INTACT)
        for name, source in sources.items():
            with self.subTest(name):
                self.assertEqual(is_well_formed(JsParser(source).parse()), True)

    def test_the_synthesizer_prints_the_literal_the_cut_left_open_and_the_file_ends_there(self):
        """
        The literal is written as the file wrote it, with no closing quote or backtick the file did
        not hold, and nothing is written behind it: the block a function body opened is not closed
        either, since the file did not close it.
        """
        expected = {
            'string_at_top_level': "const banner = 'loading the alpha module",
            'template_at_top_level': 'const banner = `loading ${registry.alpha} and everything after it',
            'template_hole_at_top_level': 'const banner = `loading ${Object.keys(registry',
            'string_in_function_body': "  const label = 'describing the handler for ",
            'template_in_function_body': '  const label = `handler ${handler} registered for ',
            'template_hole_in_function_body': '  const label = `handler ${handler.toString(',
        }
        for name, last_line in expected.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    script = JsParser(_TRUNCATIONS[name].cut).parse()
                    printed = self._print(script, unescape_strings)
                    self.assertEqual(printed.splitlines()[-1], last_line)
                    self.assertEqual(printed.endswith(last_line), True)

    def test_the_synthesizer_prints_the_cut_regexp_as_written(self):
        """
        A regular expression the cut left open is a slash that opens no literal, and the statement
        holding it is text the parser could not read: it is written as it was written, and the
        file ends there.
        """
        expected = {
            'regexp_at_top_level': 'const pattern = /^alpha-[0-9]+',
            'regexp_in_function_body': '  const clean = name.replace(/[^a-z0-9',
        }
        for name, last_line in expected.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    script = JsParser(_TRUNCATIONS[name].cut).parse()
                    printed = self._print(script, unescape_strings)
                    self.assertEqual(printed.splitlines()[-1], last_line)
                    self.assertEqual(printed.endswith(last_line), True)

    def test_printing_the_cut_regexp_again_is_a_fixed_point(self):
        for name in ('regexp_at_top_level', 'regexp_in_function_body'):
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    once = self._print(JsParser(_TRUNCATIONS[name].cut).parse(), unescape_strings)
                    twice = self._print(JsParser(once).parse(), unescape_strings)
                    self.assertEqual(twice, once)

    def test_the_comment_the_cut_left_open_is_the_last_line_of_the_output(self):
        """
        The comment runs to the end of the file and the file carries it, so the output is what the
        text before the comment prints, then the comment as it was written at the head of a line,
        and nothing behind it: no closing brace for the function body the second cut is inside of,
        which is where the file ended.
        """
        expected = {
            'comment_at_top_level': '\n/* the registry maps each name to the handler that reads it',
            'comment_in_function_body': (
                '\n/* the handler is the function that was registered under this name'
            ),
        }
        for name, tail in expected.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    truncation = _TRUNCATIONS[name]
                    without = self._print(JsParser(truncation.head).parse(), unescape_strings)
                    printed = self._print(JsParser(truncation.cut).parse(), unescape_strings)
                    self.assertEqual(printed, without + tail)

    def test_a_cut_file_prints_to_text_that_prints_and_parses_to_itself(self):
        for name, truncation in _TRUNCATIONS.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    script = JsParser(truncation.cut).parse()
                    printed = self._print(script, unescape_strings)
                    again = JsParser(printed).parse()
                    self.assertEqual(self._print(again, unescape_strings), printed)
                    self.assertEqual(canonical(again), canonical(script))

    def test_a_whole_file_prints_to_text_that_prints_and_parses_to_itself(self):
        for name, truncation in _TRUNCATIONS.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    script = JsParser(truncation.whole).parse()
                    printed = self._print(script, unescape_strings)
                    again = JsParser(printed).parse()
                    self.assertEqual(self._print(again, unescape_strings), printed)
                    self.assertEqual(canonical(again), canonical(script))

    def test_an_intact_file_prints_to_text_that_prints_and_parses_to_itself(self):
        for name, source in _INTACT.items():
            for unescape_strings in (False, True):
                with self.subTest(name, unescape_strings=unescape_strings):
                    script = JsParser(source).parse()
                    printed = self._print(script, unescape_strings)
                    again = JsParser(printed).parse()
                    self.assertEqual(self._print(again, unescape_strings), printed)
                    self.assertEqual(canonical(again), canonical(script))

    def test_a_line_continuation_contributes_nothing_to_the_string_it_breaks(self):
        for name in ('line_continuation_lf', 'line_continuation_crlf', 'line_continuation_cr'):
            with self.subTest(name):
                self.assertEqual(
                    self._string_denoted_by(_INTACT[name]),
                    ('loading the alpha module', True),
                )

    def test_a_line_separator_inside_a_string_is_one_more_character_of_it(self):
        self.assertEqual(
            self._string_denoted_by(_INTACT['line_separator_in_string']),
            (F'loading{chr(0x2028)}the module', True),
        )
        self.assertEqual(
            self._string_denoted_by(_INTACT['paragraph_separator_in_string']),
            (F'loading{chr(0x2029)}the module', True),
        )

    def test_a_template_may_span_lines_without_being_cut(self):
        self.assertEqual(
            self._template_runs_of(_INTACT['template_across_lines']),
            [('loading\nthe alpha\nmodule', True, True)],
        )

    def test_a_slash_inside_a_character_class_does_not_end_the_regexp(self):
        self.assertEqual(
            canonical(_last_initializer(JsParser(_INTACT['slash_inside_character_class']).parse())),
            ('JsRegExpLiteral', '^[/a-z]+$', ''),
        )

    def test_the_language_is_still_recognized_after_the_cut(self):
        sources = {F'{name}::cut': case.cut for name, case in _TRUNCATIONS.items()}
        sources.update({F'{name}::whole': case.whole for name, case in _TRUNCATIONS.items()})
        sources.update(_INTACT)
        for name, source in sources.items():
            with self.subTest(name):
                self.assertEqual(guess_language(source), 'js')


class TestAFoldOverALiteralTheCutLeftOpen(TestBase):
    """
    What the deobfuscator makes of a buffer that ends inside a literal a fold reaches. The buffer
    is not a program — Node refuses every `cut` in either table and accepts every `whole` — and
    the one thing the tool may not answer with is a program, because an analyst reading it has no
    way left to tell that the file they handed over was cut. The literal was never closed, so the
    fold does not reach it: the expression is written as the file wrote it and the file ends
    inside the literal, exactly as it was handed over.
    """

    def _deobfuscated(self, source: str) -> str:
        return source.encode('utf8') | js() | str

    def test_a_fold_that_reaches_a_literal_the_cut_left_open_leaves_the_file_cut(self):
        expected = {
            'template_at_top_level': 'const banner = `loading ` + `the alpha module',
            'argument_at_top_level': "console.log('loading ' + 'the alpha module",
        }
        for name, last_line in expected.items():
            with self.subTest(name):
                deobfuscated = self._deobfuscated(_FOLDS[name].cut)
                self.assertEqual(deobfuscated.splitlines()[-1], last_line)
                self.assertEqual(deobfuscated.endswith(last_line), True)

    def test_the_same_file_with_its_delimiter_restored_deobfuscates_to_a_program(self):
        """
        Each closed file differs from the carved one by the single character the carve took, so a
        corpus the tool refused for some other reason would leave the refusal above saying nothing.
        """
        for name, truncation in _EVERY_FOLD.items():
            with self.subTest(name):
                printed = self._deobfuscated(truncation.whole)
                self.assertEqual(is_well_formed(JsParser(printed).parse()), True)
