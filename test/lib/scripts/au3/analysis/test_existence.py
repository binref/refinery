"""
The existence census: the names a global may take when the tree runs. One test per creation
channel, one per unreadable channel — each of which answers that any name may be a global —
and the `MustDeclareVars` latch that makes every implicit write fatal.
"""
from __future__ import annotations

import inspect

from test import TestBase
from unittest.mock import patch

from refinery.lib.scripts.au3.analysis.existence import Au3ProbeMemo, build_existence_model
from refinery.lib.scripts.au3.analysis.interpreter import Au3Interpreter
from refinery.lib.scripts.au3.analysis.scopes import build_scope_model
from refinery.lib.scripts.au3.parser import Au3Parser

_COMMAND_LINE_CONSTANTS = frozenset({'cmdline', 'cmdlineraw'})


def _model(source: str, memo: Au3ProbeMemo | None = None):
    root = Au3Parser(inspect.cleandoc(source)).parse()
    return build_existence_model(root, build_scope_model(root), memo)


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
        names = _names('''
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
            ''')
        self.assertEqual(names, _COMMAND_LINE_CONSTANTS | {
            'w_script',
            'w_global',
            'w_assign',
            'w_exec',
            'w_call',
            'w_byref',
        })

    def test_the_command_line_constants_exist_in_every_script(self):
        """
        AutoIt defines `$CmdLine` and `$CmdLineRaw` whether or not parameters are passed, so a
        bare write of either inside a function reaches the constant instead of creating a local.
        """
        self.assertEqual(_names(''), frozenset({'cmdline', 'cmdlineraw'}))

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
            ('a list view sort over a builtin name', 'GUICtrlRegisterListViewSort($i, "Assign")'),
            ('a registration through Call', 'Call("GUIRegisterMsg", 0x001C, "Assign")'),
            (
                'a registration through Call whose message is a function name',
                'Func handler($a, $b)\nEndFunc\nCall("GUIRegisterMsg", "handler", "Assign")',
            ),
            ('a forwarding Call of Call', 'Call("Call", "Assign", "w", 1)'),
            (
                'an option set through a CallArgArray',
                'Global $a[3] = ["CallArgArray", "MustDeclareVars", 1]\nCall("Opt", $a)',
            ),
            (
                'a registration through a CallArgArray',
                'Global $a[3] = ["CallArgArray", 0x001C, "Assign"]\nCall("GUIRegisterMsg", $a)',
            ),
            ('an error node naming a channel', 'Assign("w", 1.)'),
            ('an error node calling a computed callee', '$f(1.)'),
            ('an error node declaring a function', 'Func f(ByRef $p, $q = 1.)\nEndFunc\nf($w)'),
            ('an unreadable payload naming a channel', 'Execute(\'Assign("w", 1.)\')'),
            ('a variable expansion setting', 'Opt("ExpandVarStrings", 1)'),
            ('an environment expansion setting', 'AutoItSetOption("ExpandEnvStrings", 1)'),
            ('an expansion setting through Call', 'Call("Opt", "ExpandVarStrings", 1)'),
            ('an expansion setting of a zero string', 'Opt("ExpandVarStrings", "0")'),
            ('an option name the census cannot read', 'Opt($n, 1)'),
        ):
            with self.subTest(label=label):
                self.assertIsNone(_names(source))

    def test_an_expansion_setting_that_sets_nothing_spells_no_name(self):
        for source in (
            'Opt("ExpandVarStrings", 0)',
            'Opt("ExpandEnvStrings", False)',
            'Opt("ExpandVarStrings")',
        ):
            with self.subTest(source=source):
                self.assertEqual(_names(source), _COMMAND_LINE_CONSTANTS)

    def test_a_string_spelled_as_rendered_pieces_resolves_like_its_chain(self):
        """
        The pieces a literal renders — `Chr(0)` standing where a string literal could — spell
        the same string their `&` chain does, so a payload of one writes nothing and an option
        named by one sets nothing.
        """
        self.assertEqual(_names('Execute(Chr(0))'), _COMMAND_LINE_CONSTANTS)
        self.assertFalse(_model('Opt(Chr(0), 1)').implicit_writes_are_fatal)

    def test_a_registration_over_a_script_function_name_spells_no_name(self):
        """
        The argument-passing registrations accept a literal script-function name — reached
        directly or through `Call`, which hands the registration the arguments after the name —
        and the zero-argument `AdlibRegister` shape passes no arguments at all.
        """
        for source in (
            '''
            Func handler($a, $b)
            EndFunc

            GUIRegisterMsg(0x001C, "handler")
            DllCallbackRegister("handler", "none", "")
            ''',
            '''
            Func handler($a, $b)
            EndFunc

            Call("GUIRegisterMsg", 0x001C, "handler")
            ''',
            'AdlibRegister("Assign")',
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertEqual(_names(source), _COMMAND_LINE_CONSTANTS)

    def test_the_census_boundary_spells_no_name(self):
        """
        A builtin that creates no script variable — and a call AutoIt refuses to run — is the
        closure claim every other callee rests on; neither spells a name.
        """
        names = _names('''
            MsgBox(0, "", "x")
            DllCall("kernel32.dll", "none", "f")
            ''')
        self.assertEqual(names, _COMMAND_LINE_CONSTANTS)

    def test_an_error_node_spells_every_variable_it_holds(self):
        """
        Text the parser could not read may be a declaration AutoIt runs, so every variable it
        spells may be a global.
        """
        self.assertEqual(_names('Global $x = 1.'), _COMMAND_LINE_CONSTANTS | {'x'})

    def test_a_probed_channel_past_the_quota_answers_any_name(self):
        """
        The probes share one step budget; a tree that exhausts it answers that any name may be a
        global rather than lean on an unbounded resolution.
        """
        with patch('refinery.lib.scripts.au3.analysis.existence._MAX_CENSUS_PROBE_STEPS', 0):
            self.assertIsNone(_names('''
                Func payload()
                    Return 'Assign("w", 1)'
                EndFunc

                Execute(payload())
                '''))

    def test_the_mustdeclarevars_latch_holds_once_any_setting_may_set_it(self):
        """
        The census does not see the order in which the settings run, so a zero elsewhere in the
        tree does not clear a setting that may run before an implicit write. Whether AutoIt reads
        the value as a number or as a condition is unpinned, so only a value both readings take
        as zero leaves the option unset, and a channel the census cannot read may be a setter.
        """
        for source, expected in (
            ('', False),
            ('Opt("MustDeclareVars", 1)', True),
            ('AutoItSetOption("MustDeclareVars", 1)', True),
            ('Opt("MustDeclareVars", "1")', True),
            ('Opt("MustDeclareVars", "0")', True),
            ('Opt("MustDeclareVars", False)', False),
            ('Opt("MustDeclareVars", $v)', True),
            ('Opt($n, 1)', True),
            ('Opt("RunErrorsFatal", 1)', False),
            ('Call("Opt", "MustDeclareVars", 1)', True),
            ('Opt("MustDeclareVars", 0)', False),
            ('Opt("MustDeclareVars")', False),
            ('Opt("MustDeclareVars", 1)\nOpt("MustDeclareVars", 0)', True),
            ('Func f()\n    Opt("MustDeclareVars", 1)\nEndFunc\nOpt("MustDeclareVars", 0)', True),
            ('$f()', True),
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertEqual(_model(source).implicit_writes_are_fatal, expected)

    def test_a_name_spelled_up_to_a_nul_still_names_its_channel(self):
        """
        Whether AutoIt reads a looked-up name past a NUL is unpinned, and only the reading that
        stops there can name anything, so the census reads the name up to the NUL.
        """
        self.assertEqual(
            _names('Call("Assign" & Chr(0), "w", 1)'),
            _COMMAND_LINE_CONSTANTS | {'w'},
        )
        self.assertTrue(_model('Opt("MustDeclareVars" & Chr(0), 1)').implicit_writes_are_fatal)

    def test_a_later_tree_version_answers_a_repeated_probe_without_running_it(self):
        """
        A run holds one memo across its tree versions, and a version that keeps the probed
        function and its call site answers without asking the interpreter again.
        """
        memo = Au3ProbeMemo()
        _model('''
            Func payload()
                Return 'Assign("w", 1)'
            EndFunc

            Execute(payload())
            ''', memo)
        with patch.object(Au3Interpreter, 'probe', side_effect=AssertionError):
            names = _model('''
                Func payload()
                    Return 'Assign("w", 1)'
                EndFunc

                Execute(payload())
                MsgBox(0, "", "x")
                ''', memo).possible_globals
        self.assertEqual(names, _COMMAND_LINE_CONSTANTS | {'w'})

    def test_a_remembered_probe_still_spends_the_quota(self):
        source = '''
            Func payload()
                Return 'Assign("w", 1)'
            EndFunc

            Execute(payload())
            '''
        memo = Au3ProbeMemo()
        _model(source, memo)
        with patch('refinery.lib.scripts.au3.analysis.existence._MAX_CENSUS_PROBE_STEPS', 0):
            self.assertIsNone(_model(source, memo).possible_globals)

    def test_a_remembered_probe_never_answers_other_arguments(self):
        memo = Au3ProbeMemo()
        _model('''
            Func payload($n)
                Return 'Assign("' & $n & '", 1)'
            EndFunc

            Execute(payload("w"))
            ''', memo)
        names = _model('''
            Func payload($n)
                Return 'Assign("' & $n & '", 1)'
            EndFunc

            Execute(payload("v"))
            ''', memo).possible_globals
        self.assertEqual(names, _COMMAND_LINE_CONSTANTS | {'v'})

    def test_a_remembered_probe_never_answers_once_a_script_function_shadows_its_builtin(self):
        """
        A probe refuses a nested call into a script function, so the same payload function
        answers differently once the tree declares a script function of a builtin's name.
        """
        memo = Au3ProbeMemo()
        resolved = _model('''
            Func payload()
                Return StringLower('ASSIGN("W", 1)')
            EndFunc

            Execute(payload())
            ''', memo)
        shadowed = _model('''
            Func payload()
                Return StringLower('ASSIGN("W", 1)')
            EndFunc

            Func StringLower($s)
                Return $s
            EndFunc

            Execute(payload())
            ''', memo)
        self.assertEqual(resolved.possible_globals, _COMMAND_LINE_CONSTANTS | {'w'})
        self.assertIsNone(shadowed.possible_globals)
