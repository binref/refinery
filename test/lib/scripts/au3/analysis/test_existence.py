"""
The existence census: the names a global may take when the tree runs. One test per creation
channel, one per unreadable channel — each of which answers that any name may be a global —
and the `MustDeclareVars` latch that makes every implicit write fatal.
"""
from __future__ import annotations

import inspect
from unittest.mock import patch

from test import TestBase

from refinery.lib.scripts.au3.analysis.existence import build_existence_model
from refinery.lib.scripts.au3.analysis.scopes import build_scope_model
from refinery.lib.scripts.au3.parser import Au3Parser


def _model(source: str):
    root = Au3Parser(inspect.cleandoc(source)).parse()
    return build_existence_model(root, build_scope_model(root))


def _names(source: str) -> frozenset[str] | None:
    """
    The names a global may take under *source*, `None` standing for any name.
    """
    return _model(source).possible_globals


class TestAu3Existence(TestBase):

    def test_every_creation_channel_spells_its_name(self):
        """
        One tree holding every channel the census reads: a script-level bare write, a `Global`
        declaration anywhere in the tree, a literal `Assign`, an `Execute` payload resolved
        through a probed script function, a computed `Call` to `Assign`, and a name handed to a
        `ByRef` parameter.
        """
        self.assertEqual(_names('''
            $w_script = 1
            Global $w_global

            Func payload()
                Return 'Assign("w_exec", 1)'
            EndFunc

            Func sink(ByRef $unused)
            EndFunc

            Assign("w_assign", 1)
            Execute(payload())
            Call("Assign", "w_call", 1)
            sink($w_byref)
            '''), frozenset({
                'w_script',
                'w_global',
                'w_assign',
                'w_exec',
                'w_call',
                'w_byref',
            }))

    def test_every_unreadable_channel_answers_any_name(self):
        for label, source in (
            ('an include', '#include <Array.au3>'),
            ('a computed Assign name', 'Assign($n, 1)'),
            ('an unresolvable Execute payload', 'Execute($p)'),
            ('an unresolvable Call name', 'Call($n)'),
            ('an indirect callee', '$f()'),
            ('a registration over a computed name', 'GUIRegisterMsg(0x001C, $n)'),
            ('a registration over a builtin name', 'GUIRegisterMsg(0x001C, "Assign")'),
            ('a registration over an unknown name', 'GUIRegisterMsg(0x001C, "nosuch")'),
            ('a forwarding Call of Call', 'Call("Call", "Assign", "w", 1)'),
        ):
            with self.subTest(label=label):
                self.assertIsNone(_names(source))

    def test_a_registration_over_a_script_function_name_answers_nothing(self):
        """
        The argument-passing registrations accept a literal script-function name — the
        zero-argument `AdlibRegister` shape included, which passes no arguments at all.
        """
        for source in (
            '''
            Func handler($a, $b)
            EndFunc

            GUIRegisterMsg(0x001C, "handler")
            DllCallbackRegister("handler", "none", "")
            ''',
            'AdlibRegister("Assign")',
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertEqual(_names(source), frozenset())

    def test_the_census_boundary_answers_nothing(self):
        """
        A builtin that creates no script variable — and a call AutoIt refuses to run — is the
        closure claim every other callee rests on; neither spells a name.
        """
        self.assertEqual(_names('''
            MsgBox(0, "", "x")
            DllCall("kernel32.dll", "none", "f")
            '''), frozenset())

    def test_a_probed_channel_past_the_quota_answers_any_name(self):
        """
        The probes share one step budget; a tree that exhausts it answers that any name may be a
        global rather than lean on an unbounded resolution.
        """
        with patch(
                'refinery.lib.scripts.au3.analysis.existence._MAX_CENSUS_PROBE_STEPS', 0):
            self.assertIsNone(_names('''
                Func payload()
                    Return 'Assign("w", 1)'
                EndFunc

                Execute(payload())
                '''))

    def test_the_mustdeclarevars_latch_follows_the_last_option(self):
        for source, expected in (
            ('', False),
            ('Opt("MustDeclareVars", 1)', True),
            ('AutoItSetOption("MustDeclareVars", 1)', True),
            ('Opt("MustDeclareVars", "1")', True),
            ('Opt("MustDeclareVars", $v)', True),
            ('Opt($n, 1)', True),
            ('Opt("RunErrorsFatal", 1)', False),
            ('Call("Opt", "MustDeclareVars", 1)', True),
            ('Opt("MustDeclareVars", 0)', False),
            ('Opt("MustDeclareVars", 1)\nOpt("MustDeclareVars", 0)', False),
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertEqual(_model(source).implicit_writes_are_fatal, expected)

    def test_a_script_level_write_of_the_declared_name_answers_the_global(self):
        """
        The load-bearing opposite of an implicit local (probe10): a bare write to a name a
        `Global` declaration spells reaches that global, so the census keeps answering that it
        may exist.
        """
        model = _model('''
            Global $q = "orig"

            Func load_bearing()
                $q = "written"
                Return $q
            EndFunc
            ''')
        self.assertTrue(model.global_may_exist('q'))

    def test_a_poison_still_answers_the_names_it_collected(self):
        """
        The census spells the names it reached before the channel it cannot read, so a tree with
        a `Global` declaration and an include answers both its own name and any other.
        """
        model = _model('''
            Global $w_global
            #include <Array.au3>
            ''')
        self.assertIsNone(model.possible_globals)
        self.assertTrue(model.global_may_exist('w_global'))
        self.assertTrue(model.global_may_exist('anything_else'))
