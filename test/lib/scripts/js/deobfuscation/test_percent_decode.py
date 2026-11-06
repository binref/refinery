from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable
from test.lib.scripts.js.ledger import folded


_ASTRAL = chr(0x1F600)

_A_LONE_HIGH = chr(92) + 'uD800'

_A_REVERSED_PAIR = chr(92) + 'uDC00' + chr(92) + 'uD800'

#: A character the argument spells directly is copied through untouched, a lone or reversed
#: surrogate included; only a run of escaped octets has to be strict UTF-8.
_A_DECODE_THE_ARGUMENT_ANSWERS: dict[str, tuple[str, str]] = {
    'an astral character'            : (_ASTRAL, _ASTRAL),
    'an astral then an escape'       : (_ASTRAL + '%41', _ASTRAL + 'A'),
    'a lone high surrogate'          : (_A_LONE_HIGH, _A_LONE_HIGH),
    'a reversed surrogate pair'      : (_A_REVERSED_PAIR, _A_REVERSED_PAIR),
    'ascii escapes'                  : ('%41%42', 'AB'),
    'a two octet escape, lowercase'  : ('%c3%a9', chr(0xE9)),
    'a three octet escape'           : ('%E2%82%AC', chr(0x20AC)),
    'a four octet escape'            : ('%F0%9F%98%80', _ASTRAL),
}

_A_DECODE_THE_SPECIFICATION_REFUSES: dict[str, str] = {
    'a percent sign nothing follows'      : '100%',
    'an escape one digit short'           : '%4',
    'an escape with no digits'            : '%GG',
    'a lone continuation octet'           : '%80',
    'an overlong two octet run'           : '%C0%80',
    'an overlong three octet run'         : '%E0%80%80',
    'an encoded surrogate'                : '%ED%A0%80',
    'a code point past the last one'      : '%F4%90%80%80',
    'a five octet lead'                   : '%F8%88%80%80%80',
    'a run the argument ends inside'      : '%C3',
    'a continuation that is not escaped'  : '%C3A9',
    'a continuation outside its range'    : '%C3%41',
}


def _a_call_over(argument: str) -> str:
    return F"console.log(decodeURIComponent('{argument}'));"


class TestADecodeAnswersTheValueItsArgumentEncodes(TestBase):

    def test_the_call_folds_to_what_the_literal_of_its_value_folds_to(self):
        for shape, (argument, value) in _A_DECODE_THE_ARGUMENT_ANSWERS.items():
            with self.subTest(shape=shape):
                self.assertEqual(
                    folded(_a_call_over(argument)),
                    folded(F"console.log('{value}');"),
                )


class TestADecodeTheSpecificationRefusesIsAThrow(TestBase):

    def test_the_refused_call_comes_back_standing_where_the_file_wrote_it(self):
        for shape, argument in _A_DECODE_THE_SPECIFICATION_REFUSES.items():
            source = _a_call_over(argument)
            with self.subTest(shape=shape):
                self.assertEqual(folded(source), source)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeAnswersEachRowTheWayItIsPinned(TestBase):

    def test_each_answered_call_and_the_literal_of_its_value_are_one_string(self):
        rows = _A_DECODE_THE_ARGUMENT_ANSWERS.values()
        self.assertEqual(
            code_units([F"decodeURIComponent('{argument}')" for argument, _ in rows]),
            code_units([F"'{value}'" for _, value in rows]),
        )

    def test_each_refused_argument_throws_a_uri_error(self):
        for shape, argument in _A_DECODE_THE_SPECIFICATION_REFUSES.items():
            with self.subTest(shape=shape):
                self.assertEqual(behavior(_a_call_over(argument)), ('', 'URIError'))
