"""
The builtin name tables and the boundedness predicate over them: which names are real AutoIt
functions, the official spelling each prints as, and which of them a call may do anything
through. The emulated subset and the argument-position table are both answerable from the wide
table's membership, so their consistency is asserted rather than re-listed.
"""
from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.au3.analysis.builtins import (
    EMULATED_NAMES,
    NAME_PARAMETERS,
    call_is_bounded,
)
from refinery.lib.scripts.au3.functions import AUTOIT_FUNCTION_NAMES


class TestAu3Builtins(TestBase):

    def test_every_emulated_name_is_a_real_builtin(self):
        self.assertEqual(EMULATED_NAMES - AUTOIT_FUNCTION_NAMES.keys(), set())

    def test_every_name_with_argument_positions_is_a_real_builtin(self):
        self.assertEqual(NAME_PARAMETERS.keys() - AUTOIT_FUNCTION_NAMES.keys(), set())

    def test_a_lowercased_name_maps_to_its_official_spelling(self):
        self.assertEqual(AUTOIT_FUNCTION_NAMES['dllstructcreate'], 'DllStructCreate')

    def test_the_official_spelling_is_not_forced_into_pascal_case(self):
        self.assertEqual(AUTOIT_FUNCTION_NAMES['bitand'], 'BitAND')

    def test_the_map_functions_are_core_builtins(self):
        """
        The docs' `functions.txt` omits the five experimental map functions, but each keeps its
        own per-function page, so they are core builtins a sample may call under any casing.
        """
        for name in ('IsMap', 'MapAppend', 'MapExists', 'MapKeys', 'MapRemove'):
            with self.subTest(name):
                self.assertEqual(AUTOIT_FUNCTION_NAMES[name.lower()], name)

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

    def test_a_registration_builtin_is_not_bounded(self):
        """
        A registration builtin runs a registered script function on its own trigger, which may
        write any global, so a call to it is not a bounded call.
        """
        for name in (
            'adlibregister',
            'onautoitexitregister',
            'dllcallbackregister',
            'hotkeyset',
            'guiregistermsg',
            'guictrlregisterlistviewsort',
            'guisetonevent',
            'guictrlsetonevent',
            'traysetonevent',
            'trayitemsetonevent',
            'objevent',
        ):
            with self.subTest(name):
                self.assertFalse(call_is_bounded(name))
