from __future__ import annotations

import unittest

from refinery.lib.scripts.au3.analysis.builtins import (
    AUTOIT_FUNCTION_NAMES,
    EMULATED_NAMES,
    NAME_PARAMETERS,
    call_is_bounded,
)


class TestAutoitFunctionNames(unittest.TestCase):

    def test_every_emulated_name_is_a_real_builtin(self):
        self.assertEqual(EMULATED_NAMES - AUTOIT_FUNCTION_NAMES.keys(), set())

    def test_every_name_with_argument_positions_is_a_real_builtin(self):
        self.assertEqual(NAME_PARAMETERS.keys() - AUTOIT_FUNCTION_NAMES.keys(), set())

    def test_a_lowercased_name_maps_to_its_official_spelling(self):
        self.assertEqual(AUTOIT_FUNCTION_NAMES['dllstructcreate'], 'DllStructCreate')

    def test_the_official_spelling_is_not_forced_into_pascal_case(self):
        self.assertEqual(AUTOIT_FUNCTION_NAMES['bitand'], 'BitAND')


class TestCallIsBounded(unittest.TestCase):

    def test_an_emulated_builtin_is_bounded(self):
        self.assertTrue(call_is_bounded('abs'))

    def test_a_real_but_unemulated_builtin_is_bounded(self):
        self.assertTrue(call_is_bounded('msgbox'))

    def test_call_is_not_bounded(self):
        self.assertFalse(call_is_bounded('call'))

    def test_execute_is_not_bounded(self):
        self.assertFalse(call_is_bounded('execute'))

    def test_assign_is_not_bounded(self):
        self.assertFalse(call_is_bounded('assign'))

    def test_a_name_outside_the_table_is_not_bounded(self):
        self.assertFalse(call_is_bounded('unknown'))
