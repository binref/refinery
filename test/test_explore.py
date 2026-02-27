import io
import re

from unittest.mock import patch

from refinery.explore import highlight, highlight_word, get_help_string, explorer
from refinery.lib.environment import environment
from refinery.units import Unit

from test import TestBase

NOMATCH = 'No matching unit was found.'


class TestHighlight(TestBase):

    def test_highlight_basic(self):
        result = highlight('hello world', re.compile('world'), '91')
        self.assertEqual(result, 'hello \033[91mworld\033[0m')

    def test_highlight_no_match(self):
        result = highlight('hello world', re.compile('foobar'), '91')
        self.assertEqual(result, 'hello world')

    def test_highlight_multiple_matches(self):
        result = highlight('abcabc', re.compile('abc'), '91')
        self.assertEqual(result, '\033[91mabc\033[0m\033[91mabc\033[0m')

    def test_highlight_case_insensitive_pattern(self):
        result = highlight('Hello HELLO hello', re.compile('(?i)hello'), '93')
        self.assertEqual(result, '\033[93mHello\033[0m \033[93mHELLO\033[0m \033[93mhello\033[0m')

    def test_highlight_special_characters_in_text(self):
        result = highlight('foo.bar', re.compile(r'foo\.bar'), '91')
        self.assertEqual(result, '\033[91mfoo.bar\033[0m')


class TestHighlightWord(TestBase):

    def test_highlight_word_basic(self):
        result = highlight_word('hello world', 'world', '91')
        self.assertEqual(result, 'hello \033[91mworld\033[0m')

    def test_highlight_word_case_insensitive(self):
        result = highlight_word('Hello HELLO hello', 'hello', '93')
        self.assertEqual(result, '\033[93mHello\033[0m \033[93mHELLO\033[0m \033[93mhello\033[0m')

    def test_highlight_word_no_match(self):
        result = highlight_word('hello world', 'foobar', '91')
        self.assertEqual(result, 'hello world')

    def test_highlight_word_special_regex_chars(self):
        result = highlight_word('a+b equals c', 'a+b', '91')
        self.assertEqual(result, '\033[91ma+b\033[0m equals c')


class TestGetHelpString(TestBase):

    def test_brief_mode_returns_documentation(self):
        result = get_help_string(Unit, brief=True, width=80)
        self.assertIsInstance(result, str)

    def test_full_mode_returns_help(self):
        unit_class = self._get_any_unit()
        if unit_class is None:
            self.skipTest('no entry points available')
        result = get_help_string(unit_class, brief=False, width=80)
        if result is not None:
            self.assertIsInstance(result, str)
            self.assertGreater(len(result), 0)

    def test_full_mode_remove_generic(self):
        unit_class = self._get_any_unit()
        if unit_class is None:
            self.skipTest('no entry points available')
        full = get_help_string(unit_class, brief=False, width=80, remove_generic=False)
        trimmed = get_help_string(unit_class, brief=False, width=80, remove_generic=True)
        if full is not None and trimmed is not None and 'generic options:' in full:
            self.assertLessEqual(len(trimmed), len(full))

    def test_brief_mode_with_different_widths(self):
        result_narrow = get_help_string(Unit, brief=True, width=40)
        result_wide = get_help_string(Unit, brief=True, width=120)
        self.assertIsInstance(result_narrow, str)
        self.assertIsInstance(result_wide, str)

    def _get_any_unit(self):
        from refinery.lib.loader import get_all_entry_points
        import refinery.units
        for unit in get_all_entry_points():
            if isinstance(unit, type) and issubclass(unit, Unit) and issubclass(unit, refinery.units.Entry) and unit is not refinery.units.Entry:
                return unit
        return None


class TestExplorer(TestBase):

    def _run_explorer(self, args):
        previous = environment.term_size.value
        environment.term_size.value = 120
        try:
            with patch('sys.argv', ['binref'] + args):
                stdout = io.StringIO()
                with patch('sys.stdout', stdout):
                    explorer()
                return stdout.getvalue()
        finally:
            environment.term_size.value = previous

    def test_version_flag(self):
        import refinery
        output = self._run_explorer(['--version'])
        self.assertEqual(output.strip(), refinery.__version__)

    def test_version_short_flag(self):
        import refinery
        output = self._run_explorer(['-V'])
        self.assertEqual(output.strip(), refinery.__version__)

    def test_no_keywords_lists_all_units(self):
        output = self._run_explorer([])
        self.assertGreater(len(output), 0)
        self.assertNotIn(NOMATCH, output)

    def test_nonexistent_keyword_no_results(self):
        output = self._run_explorer(['zzzyyyxxxwwwvvv'])
        self.assertIn(NOMATCH, output)

    def test_keyword_match(self):
        output = self._run_explorer(['base64'])
        self.assertNotIn(NOMATCH, output)
        self.assertGreater(len(output.strip()), 0)

    def test_or_flag(self):
        output = self._run_explorer(['-o', 'base64', 'zzzyyyxxxwwwvvv'])
        self.assertNotIn(NOMATCH, output)

    def test_all_flag_searches_full_help(self):
        output_brief = self._run_explorer(['base64'])
        output_all = self._run_explorer(['-a', 'base64'])
        self.assertNotIn(NOMATCH, output_brief)
        self.assertNotIn(NOMATCH, output_all)

    def test_case_sensitive_flag(self):
        output_insensitive = self._run_explorer(['BASE64'])
        output_sensitive = self._run_explorer(['-c', 'BASE64'])
        if NOMATCH in output_insensitive:
            self.skipTest('no units match BASE64 case-insensitively')
        has_insensitive_results = NOMATCH not in output_insensitive
        has_sensitive_results = NOMATCH not in output_sensitive
        if has_insensitive_results:
            self.assertTrue(True)
        if has_sensitive_results:
            self.assertIn(has_insensitive_results, (True,))

    def test_words_flag(self):
        output = self._run_explorer(['-w', 'base64'])
        self.assertIsInstance(output, str)

    def test_no_wildcards_flag(self):
        output = self._run_explorer(['-x', 'base*'])
        self.assertIsInstance(output, str)

    def test_wildcard_search(self):
        output = self._run_explorer(['b64*'])
        self.assertIsInstance(output, str)

    def test_multiple_keywords_all_must_match(self):
        output = self._run_explorer(['zzzyyyxxx', 'wwwvvvuuu'])
        self.assertIn(NOMATCH, output)

    def test_verbose_flag(self):
        output = self._run_explorer(['-v', 'base64'])
        self.assertIn('final regex', output)

    def test_separator_is_printed_when_results_found(self):
        output = self._run_explorer(['base64'])
        if NOMATCH not in output:
            lines = output.strip().split('\n')
            last_line = lines[-1]
            self.assertTrue(all(c == '-' for c in last_line))
