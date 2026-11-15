from __future__ import annotations

import inspect

from test import TestBase, fastest_processor_time, lines_executed, processor_time_ratio

from refinery.lib.scripts.ps1 import patterns
from refinery.lib.scripts.ps1.patterns import (
    is_wildcard_pattern,
    literal_name,
    wildcard_may_end_with,
    wildcard_regex,
)


class TestPs1WildcardRegex(TestBase):

    def _matches(self, pattern: str, name: str, case_sensitive: bool = False) -> bool:
        regex = wildcard_regex(pattern, case_sensitive)
        assert regex is not None
        return regex.match(name) is not None

    def test_an_exclamation_mark_in_a_set_is_a_member_and_not_a_negation(self):
        self.assertFalse(self._matches('[!x]rite', 'write'))

    def test_a_range_a_set_member_and_an_escape_match_their_name(self):
        for pattern in ('[v-x]rite', 'w`rite', 'wr[i]te'):
            with self.subTest(pattern):
                self.assertTrue(self._matches(pattern, 'write'))

    def test_an_escaped_wildcard_character_matches_only_itself(self):
        self.assertFalse(self._matches('wr`?te', 'write'))
        self.assertTrue(self._matches('wr`?te', 'wr?te'))

    def test_case_is_ignored_unless_asked_for(self):
        self.assertTrue(self._matches('new-o*', 'New-Object'))
        self.assertFalse(self._matches('new-o*', 'New-Object', case_sensitive=True))
        self.assertTrue(self._matches('New-O*', 'New-Object', case_sensitive=True))

    def test_an_unterminated_set_is_no_pattern(self):
        for pattern in ('wr[ite', '[zz'):
            with self.subTest(pattern):
                self.assertIsNone(wildcard_regex(pattern))

    def test_a_final_line_break_is_a_character_of_the_name(self):
        self.assertFalse(self._matches('abc', 'abc\n'))
        self.assertFalse(self._matches('*c', 'abc\n'))
        self.assertTrue(self._matches('abc?', 'abc\n'))
        self.assertTrue(self._matches('a*c', inspect.cleandoc("""
            a
            c
        """)))

    def test_every_star_matches_as_little_or_as_much_as_the_name_needs(self):
        for pattern, name, expected in (
            ('*a*b', 'xaxxb', True),
            ('*a*b', 'xbxxa', False),
            ('a*b*c', 'abcbc', True),
            ('a*b*c', 'acb', False),
            ('*ab*ab*', 'abab', True),
            ('*ab*ab*', 'aba', False),
            ('**a**', 'a', True),
            ('*?*', '', False),
            ('*?*', 'x', True),
            ('*[xy]*z', 'aybz', True),
            ('*[xy]*z', 'abz', False),
        ):
            with self.subTest(pattern=pattern, name=name):
                self.assertEqual(self._matches(pattern, name), expected)

    def test_a_pattern_of_many_stars_is_matched_in_time_linear_in_the_name(self):
        name = 'a' * 150
        many = wildcard_regex('*a*a*a*a*b')
        literal = wildcard_regex(F'{name}b')
        assert many is not None and literal is not None
        starred = fastest_processor_time([lambda: many.match(name)] * 2)
        baseline = fastest_processor_time([lambda: [literal.match(name) for _ in range(1000000)]] * 2)
        self.assertLess(processor_time_ratio(starred, baseline), 1)

    def test_a_pattern_asked_for_twice_is_translated_once(self):
        wildcard_regex('w?[i-k]te*')
        self.assertEqual(lines_executed(lambda: wildcard_regex('w?[i-k]te*'), patterns), 0)


class TestPs1WildcardPatternRecognition(TestBase):

    def test_every_unescaped_wildcard_character_makes_a_pattern(self):
        for text in ('???t?', 'wr*', 'zz]x', 'zz[q]x', '[zz'):
            with self.subTest(text):
                self.assertTrue(is_wildcard_pattern(text))

    def test_an_escaped_wildcard_character_makes_no_pattern(self):
        for text in ('wr`?te', 'w`rite', 'write'):
            with self.subTest(text):
                self.assertFalse(is_wildcard_pattern(text))

    def test_the_literal_name_drops_every_escape(self):
        self.assertEqual(literal_name('w`rite'), 'write')
        self.assertEqual(literal_name('wrn`te'), 'wrnte')
        self.assertEqual(literal_name('wr`?te'), 'wr?te')

    def test_a_pattern_has_no_literal_name(self):
        self.assertIsNone(literal_name('wr?te'))


class TestPs1WildcardMayEndWith(TestBase):

    def test_a_trailing_star_may_end_in_any_extension(self):
        self.assertTrue(wildcard_may_end_with('hel?*', '.exe'))
        self.assertTrue(wildcard_may_end_with('curl*', '.EXE'))

    def test_a_pattern_of_fixed_length_ends_only_where_its_tokens_allow(self):
        self.assertFalse(wildcard_may_end_with('???t?', '.exe'))
        self.assertFalse(wildcard_may_end_with('wr?te', '.exe'))
        self.assertTrue(wildcard_may_end_with('wh?re.?x?', '.exe'))
        self.assertFalse(wildcard_may_end_with('wh?re.?x?', '.com'))
