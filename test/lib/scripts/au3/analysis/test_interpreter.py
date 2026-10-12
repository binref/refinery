"""
The interpreter against the interpreter: every function below comes from the probe4 source
(`temp/au3_semantics_probe/probe4.au3`, AutoIt 3.3.18.0) and every expected answer is the
literal its output line printed. Where the probe read a value's type through `VarGetType` — a
builtin the table does not own — the return spells the value instead, and the type is asserted
on the result where it separates answers. The refusals at the end are each named by the rule
that refuses them.
"""
from __future__ import annotations

import inspect

from test import TestBase
from typing import cast

from refinery.lib.scripts.au3.analysis.existence import build_existence_model
from refinery.lib.scripts.au3.analysis.interpreter import Au3Interpreter
from refinery.lib.scripts.au3.analysis.propagation import build_propagation_model
from refinery.lib.scripts.au3.analysis.scopes import build_scope_model
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    literal_value,
    of_array,
    of_int,
    of_string,
    to_string,
)
from refinery.lib.scripts.au3.parser import Au3Parser

PROBE4 = '''
Func p_noreturn()
    Local $x = 1
EndFunc
Func p_bare_return()
    Return
EndFunc
Func p_default($a, $b = 5)
    Return $a & "," & $b
EndFunc
Func p_param_write($a)
    $a = 99
    Return $a
EndFunc
Func p_array_param($a)
    $a[0] = "changed"
    Return $a[0]
EndFunc
Func p_uninit()
    Local $x
    Return $x
EndFunc
Func p_uninit_element()
    Local $a[3]
    Return $a[1] & "," & UBound($a)
EndFunc
Func p_shadow()
    Local $r = $g_shadow
    Local $g_shadow = 2
    Return $r & "," & $g_shadow
EndFunc
Func p_local_write()
    Local $g_local_write = 5
    $g_local_write = 6
    Return $g_local_write
EndFunc
Func p_partial_init()
    Local $a[3] = [1, 2]
    Return $a[2]
EndFunc
Func p_open_dim()
    Local $a[] = [4, 5, 6]
    Return UBound($a)
EndFunc
Func p_redim()
    Local $a[2] = ["a", "b"]
    ReDim $a[4]
    Return $a[1] & "," & $a[3] & "," & UBound($a)
EndFunc
Func p_element_compound()
    Local $a[1] = ["x"]
    $a[0] &= "y"
    Return $a[0]
EndFunc
Func p_for_after()
    Local $i = 0
    For $i = 1 To 3
    Next
    Return $i
EndFunc
Func p_for_empty()
    Local $n = 0
    Local $i = 42
    For $i = 1 To 0
        $n += 1
    Next
    Return $n & "," & $i
EndFunc
Func p_for_down()
    Local $s = ""
    For $i = 3 To 1 Step -1
        $s &= $i
    Next
    Return $s
EndFunc
Func p_for_float()
    Local $s = ""
    For $i = 0 To 1 Step 0.25
        $s &= $i & ";"
    Next
    Return $s
EndFunc
Func p_for_limit_once()
    Local $n = 3
    Local $c = 0
    For $i = 1 To $n
        $n = 10
        $c += 1
    Next
    Return $c
EndFunc
Func p_for_step_once()
    Local $k = 1
    Local $s = ""
    For $i = 1 To 6 Step $k
        $k = 3
        $s &= $i
    Next
    Return $s
EndFunc
Func p_for_body_writes_var()
    Local $s = ""
    For $i = 1 To 5
        $s &= $i
        $i += 1
    Next
    Return $s
EndFunc
Func p_for_string_bounds()
    Local $s = ""
    For $i = "1" To "3"
        $s &= $i & ";"
    Next
    Return $s
EndFunc
Func p_for_float_limit()
    Local $s = ""
    For $i = 1 To 2.5
        $s &= $i
    Next
    Return $s
EndFunc
Func p_exit_two()
    Local $s = ""
    For $i = 1 To 3
        For $j = 1 To 3
            $s &= $i & $j & ";"
            If $j = 2 Then ExitLoop 2
        Next
    Next
    Return $s
EndFunc
Func p_continue_two()
    Local $s = ""
    For $i = 1 To 2
        For $j = 1 To 3
            If $j = 2 Then ContinueLoop 2
            $s &= $i & $j & ";"
        Next
        $s &= "after;"
    Next
    Return $s
EndFunc
Func p_exit_in_switch()
    Local $s = ""
    For $i = 1 To 3
        Switch $i
            Case 2
                ExitLoop
        EndSwitch
        $s &= $i
    Next
    Return $s
EndFunc
Func p_do_once()
    Local $n = 0
    Do
        $n += 1
    Until True
    Return $n
EndFunc
Func p_while_exit()
    Local $n = 0
    While 1
        $n += 1
        If $n = 4 Then ExitLoop
    WEnd
    Return $n
EndFunc
Func p_switch($v)
    Switch $v
        Case "A"
            Return "upper-a"
        Case 1 To 5
            Return "range"
        Case "x", "y"
            Return "list"
        Case Else
            Return "else"
    EndSwitch
EndFunc
Func p_switch_nomatch()
    Local $r = "untouched"
    Switch 9
        Case 1
            $r = "one"
    EndSwitch
    Return $r
EndFunc
Func p_continue_case()
    Local $s = ""
    Switch 1
        Case 1
            $s &= "one;"
            ContinueCase
        Case 2
            $s &= "two;"
        Case 3
            $s &= "three;"
    EndSwitch
    Return $s
EndFunc
Func p_select()
    Select
        Case 0
            Return "zero"
        Case "abc"
            Return "string"
        Case Else
            Return "else"
    EndSelect
EndFunc
Func p_switch_string_range($v)
    Switch $v
        Case "a" To "c"
            Return "in"
        Case Else
            Return "out"
    EndSwitch
EndFunc
Func p_forin()
    Local $a[3] = ["p", "q", "r"]
    Local $s = ""
    For $v In $a
        $s &= $v
        $v = "z"
    Next
    Return $s & "," & $a[0]
EndFunc
Func p_compound()
    Local $s = 5
    $s &= 1
    Local $n = 5
    $n += "2"
    Local $d = 5
    $d /= 2
    Return $s & ";" & $n & ";" & $d
EndFunc
Func p_fib($n)
    If $n < 2 Then Return $n
    Return p_fib($n - 1) + p_fib($n - 2)
EndFunc
Func sjwakhwbtxwwb($s)
    Local $r = ""
    For $i = 1 To StringLen($s) - 1 Step 2
        $r &= StringMid($s, $i + 1, 1) & StringMid($s, $i, 1)
    Next
    If Mod(StringLen($s), 2) = 1 Then $r &= StringRight($s, 1)
    Return $r
EndFunc
Func nvbjtycmyxlfrdbypxqk($s, $n)
    Local $r = ""
    For $i = 1 To StringLen($s) Step $n
        $r &= StringMid($s, $i, 1)
    Next
    Return $r
EndFunc
Func d_xor($s, $k)
    Local $r = ""
    For $i = 1 To StringLen($s)
        $r &= Chr(BitXOR(Asc(StringMid($s, $i, 1)), $k))
    Next
    Return $r
EndFunc
Func d_split($s)
    Local $a = StringSplit($s, ",")
    Local $r = ""
    For $i = 1 To $a[0]
        $r &= ChrW($a[$i] - 7)
    Next
    Return $r
EndFunc
Func d_split_nocount($s)
    Local $a = StringSplit($s, "|", 2)
    Local $r = ""
    For $i = 0 To UBound($a) - 1
        $r &= Chr(Number($a[$i]))
    Next
    Return $r
EndFunc
Func d_forin($s)
    Local $r = ""
    For $c In StringSplit($s, "", 2)
        $r = $c & $r
    Next
    Return $r
EndFunc
Func d_global($i)
    Return $g_table[$i]
EndFunc
Func d_nested($s)
    Return nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb($s), 2)
EndFunc
Func d_while($s)
    Local $r = ""
    While StringLen($s) > 0
        $r &= StringLeft($s, 1)
        $s = StringTrimLeft($s, 2)
    WEnd
    Return $r
EndFunc
Func d_do($n)
    Local $r = ""
    Do
        $r &= Mod($n, 10)
        $n = Int($n / 10)
    Until $n = 0
    Return $r
EndFunc
Func d_switch($s)
    Local $r = ""
    For $i = 1 To StringLen($s)
        Local $c = StringMid($s, $i, 1)
        Switch $c
            Case "a" To "m"
                $r &= Chr(Asc($c) + 13)
            Case "n" To "z"
                $r &= Chr(Asc($c) - 13)
            Case Else
                $r &= $c
        EndSwitch
    Next
    Return $r
EndFunc
Func d_reverse($s)
    If StringLen($s) <= 1 Then Return $s
    Return d_reverse(StringTrimLeft($s, 1)) & StringLeft($s, 1)
EndFunc
Func d_hex($s)
    Local $r = ""
    For $i = 1 To StringLen($s) Step 2
        $r &= Chr(Dec(StringMid($s, $i, 2)))
    Next
    Return $r
EndFunc
Func d_array()
    Local $a[3]
    For $i = 0 To 2
        $a[$i] = $i * $i
    Next
    Return $a
EndFunc
'''


def _value(source: str) -> Au3Value:
    value = literal_value(Au3Parser(source).parse_expression(), frozenset())
    if value is None:
        raise ValueError(F'the source spells no literal the table reads: {source}')
    return value


class TestAu3Interpreter(TestBase):

    def _result(
        self,
        name: str,
        arguments: tuple[Au3Value, ...] = (),
        source: str = PROBE4,
        globals: dict[str, Au3Value] | None = None,
    ) -> Au3Value | None:
        root = Au3Parser(inspect.cleandoc(source)).parse()
        scope_model = build_scope_model(root)
        existence = build_existence_model(root, scope_model)
        summaries = build_propagation_model(root, scope_model, existence).summaries
        return Au3Interpreter(scope_model, summaries).call(
            scope_model.functions[name], arguments, globals or {})

    def _called(
        self,
        name: str,
        *sources: str,
        globals: dict[str, Au3Value] | None = None,
    ) -> str | None:
        result = self._result(name, tuple(_value(source) for source in sources), globals=globals)
        return None if result is None else to_string(result)

    def test_the_return_values(self):
        for name, sources, expected in (
            ('p_noreturn', (), '0'),
            ('p_bare_return', (), '0'),
            ('p_default', ('1',), '1,5'),
            ('p_default', ('1', '2'), '1,2'),
            ('p_param_write', ('7',), '99'),
            ('p_array_param', ('["kept", "x"]',), 'changed'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_the_locals(self):
        for name, sources, globals, expected in (
            ('p_uninit', (), None, ''),
            ('p_uninit_element', (), None, ',3'),
            ('p_shadow', (), {'g_shadow': of_int(1)}, '1,2'),
            ('p_local_write', (), None, '6'),
            ('p_partial_init', (), None, ''),
            ('p_open_dim', (), None, '3'),
            ('p_redim', (), None, 'b,,4'),
            ('p_element_compound', (), None, 'xy'),
        ):
            with self.subTest(name=name):
                self.assertEqual(self._called(name, *sources, globals=globals), expected)

    def test_the_for_loops(self):
        for name, expected in (
            ('p_for_after', '4'),
            ('p_for_empty', '0,1'),
            ('p_for_down', '321'),
            ('p_for_float', '0;0.25;0.5;0.75;1;'),
            ('p_for_limit_once', '3'),
            ('p_for_step_once', '123456'),
            ('p_for_body_writes_var', '135'),
            ('p_for_string_bounds', '1;2;3;'),
            ('p_for_float_limit', '12'),
        ):
            with self.subTest(name=name):
                self.assertEqual(self._called(name), expected)

    def test_a_for_variable_ends_as_an_integer(self):
        result = self._result('p_for_after')
        assert result is not None
        self.assertIs(result.kind, Kind.INT)

    def test_the_loop_control(self):
        for name, expected in (
            ('p_exit_two', '11;12;'),
            ('p_continue_two', '11;21;'),
            ('p_exit_in_switch', '1'),
            ('p_do_once', '1'),
            ('p_while_exit', '4'),
        ):
            with self.subTest(name=name):
                self.assertEqual(self._called(name), expected)

    def test_the_switch_and_select(self):
        for name, sources, expected in (
            ('p_switch', ('"a"',), 'upper-a'),
            ('p_switch', ('"3"',), 'range'),
            ('p_switch', ('3.5',), 'range'),
            ('p_switch', ('"Y"',), 'list'),
            ('p_switch', ('True',), 'upper-a'),
            ('p_switch_nomatch', (), 'untouched'),
            ('p_continue_case', (), 'one;two;'),
            ('p_select', (), 'string'),
            ('p_switch_string_range', ('"B"',), 'in'),
            ('p_switch_string_range', ('"bb"',), 'in'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_the_forin_loop(self):
        self.assertEqual(self._called('p_forin'), 'pqr,p')

    def test_the_compound_assignments(self):
        self.assertEqual(self._called('p_compound'), '51;7;2.5')

    def test_the_compound_assignment_types(self):
        result = self._result('p_compound')
        assert result is not None
        self.assertIs(result.kind, Kind.STRING)

    def test_the_recursion(self):
        self.assertEqual(self._called('p_fib', '15'), '610')

    def test_the_resub_decoder_helpers(self):
        self.assertEqual(self._called('sjwakhwbtxwwb', '"Z3HQHwba"'), '3ZQHwHab')
        self.assertEqual(self._called('sjwakhwbtxwwb', '"abc"'), 'bac')
        swapped = self._result('sjwakhwbtxwwb', (_value('"Z3HQHwba"'),))
        thinned = self._result(
            'nvbjtycmyxlfrdbypxqk',
            (swapped, of_int(8)) if swapped is not None else ())
        self.assertEqual(None if thinned is None else to_string(thinned), '3')

    def test_the_decoder_shapes(self):
        for name, sources, expected in (
            ('d_xor', ('"Kfool#Tlqog"', '3'), 'Hello World'),
            ('d_split', ('"79,108,115,115,118"',), 'Hello'),
            ('d_split_nocount', ('"72|105|33"',), 'Hi!'),
            ('d_forin', ('"stressed"',), 'desserts'),
            ('d_nested', ('"badcfehg"',), 'aceg'),
            ('d_while', ('"hxexlxlxo"',), 'hello'),
            ('d_do', ('12345',), '54321'),
            ('d_switch', ('"uryyb, jbeyq"',), 'hello, world'),
            ('d_reverse', ('"drawer"',), 'reward'),
            ('d_hex', ('"48656C6C6F"',), 'Hello'),
            ('d_hex', ('"610D0A62"',), 'a\r\nb'),
            ('d_hex', ('"6100"',), 'a\x00'),
        ):
            with self.subTest(name=name, sources=sources):
                self.assertEqual(self._called(name, *sources), expected)

    def test_a_global_read_answers_the_table_the_call_proved(self):
        table = of_array(tuple(of_string(name) for name in ('zero', 'one', 'two', 'three')))
        self.assertEqual(
            self._called('d_global', '2', globals={'g_table': table}),
            'two')

    def test_an_array_result_carries_its_elements(self):
        result = self._result('d_array')
        assert result is not None
        self.assertIs(result.kind, Kind.ARRAY)
        self.assertEqual(
            tuple(to_string(element) for element in cast(tuple[Au3Value, ...], result.payload)),
            ('0', '1', '4'))

    def test_a_call_to_a_name_outside_the_script_and_table_refuses(self):
        for source in (
            '''
            Func f()
                Return Random(1, 1, 1)
            EndFunc
            ''',
            '''
            Func f()
                Return DllCall("kernel32.dll")
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, "", "x")
            EndFunc
            ''',
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertIsNone(self._result('f', source=source))

    def test_a_function_that_writes_an_implicit_local_runs(self):
        """
        A bare write inside a function creates a local of that function — nothing outside it
        can observe the name (probe10c) — so the call runs and the write answers the read.
        """
        result = self._result(
            'f',
            source='''
            Func f()
                $g = 1
                Return $g
            EndFunc
            ''')
        self.assertEqual(to_string(result), '1')

    def test_a_function_that_writes_a_declared_global_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Global $g
            Func f()
                $g = 1
            EndFunc
            '''))

    def test_a_byref_parameter_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f(ByRef $a)
                Return $a
            EndFunc
            '''))

    def test_a_static_declaration_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Static $x = 1
                Return $x
            EndFunc
            '''))

    def test_an_exit_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Exit 0
            EndFunc
            '''))

    def test_an_out_of_range_element_read_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Local $a[2]
                Return $a[5]
            EndFunc
            '''))

    def test_a_nested_array_refuses_wherever_it_reaches_the_run(self):
        """
        An array holding an array is the one array shape the run refuses wherever the
        evaluator's literal path hands one in — an argument a call evaluates, or the branch a
        ternary chooses — exactly as the array literal the run builds itself is refused.
        """
        for source in (
            '''
            Func g($p)
                Return $p
            EndFunc
            Func f()
                Return g([1, [2]])
            EndFunc
            ''',
            '''
            Func f()
                Return True ? [1, [2]] : 0
            EndFunc
            ''',
        ):
            with self.subTest(source=inspect.cleandoc(source).strip()):
                self.assertIsNone(self._result('f', source=source))

    def test_an_endless_loop_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                While 1
                WEnd
            EndFunc
            '''))

    def test_unbounded_recursion_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Return f()
            EndFunc
            '''))

    def test_a_continue_case_in_a_select_refuses(self):
        """
        `ContinueCase` belongs to a `Switch`; a `Select` never consumes it, so the signal reaches
        the function boundary and the call refuses.
        """
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Select
                    Case 1
                        ContinueCase
                    Case 2
                        Return 2
                EndSelect
            EndFunc
            '''))

    def test_a_continue_case_in_the_last_switch_case_refuses(self):
        """
        A `ContinueCase` in the last case has no next case to fall into, which AutoIt refuses to
        load, so the call refuses rather than ending the case run silently.
        """
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Switch 1
                    Case 1
                        ContinueCase
                EndSwitch
                Return 2
            EndFunc
            '''))

    def test_a_loop_level_past_the_enclosing_loops_refuses(self):
        """
        An `ExitLoop 2` inside one loop leaves the loop with its level still raised, so the
        signal reaches the function boundary and the call refuses.
        """
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                For $i = 1 To 3
                    ExitLoop 2
                Next
            EndFunc
            '''))

    def test_an_exit_outside_any_loop_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                ExitLoop
                Return 2
            EndFunc
            '''))

    def test_a_binary_past_the_payload_budget_refuses(self):
        """
        A binary compounds with `&=` the same way a string does, so it answers the same payload
        budget instead of doubling without bound.
        """
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Local $b = Binary("01")
                For $i = 1 To 21
                    $b &= $b
                Next
                Return $b
            EndFunc
            '''))

    def test_an_array_declaration_past_the_budget_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Local $a[2000001]
                Return UBound($a)
            EndFunc
            '''))

    def test_a_bare_enum_declaration_runs(self):
        """
        A bare `Enum` declares its entries into the local storage like a local `Const`, so the
        function writes no global and the interpreter runs it.
        """
        self.assertEqual(
            self._result(
                'f',
                source='''
                Func f()
                    Enum $e = 1, $d
                    Return $d
                EndFunc
                ''',
            ),
            of_int(2))

    def test_a_global_enum_declaration_refuses(self):
        self.assertIsNone(self._result(
            'f',
            source='''
            Func f()
                Global Enum $e = 1
                Return $e
            EndFunc
            '''))

    def _probed(
        self,
        name: str,
        source: str,
        *sources: str,
    ) -> Au3Value | None:
        root = Au3Parser(inspect.cleandoc(source)).parse()
        scope_model = build_scope_model(root)
        return Au3Interpreter(scope_model, {}).probe(
            scope_model.functions[name], tuple(_value(source) for source in sources))

    def test_a_probe_of_a_decoder_with_implicit_locals_answers(self):
        """
        The probe10 decoder, verbatim: every intermediate lives in an implicit local, and the
        probe — no summary gate, no globals — runs it and answers the pinned decodings.
        """
        decoder = '''
            Func decode10($hx, $ky)
                $d_bin = BinaryToString($hx, 1)
                $d_out = ""
                For $d_i = 1 To StringLen($d_bin)
                    $d_c = AscW(StringMid($d_bin, $d_i, 1))
                    $d_k = AscW(StringMid($ky, Mod($d_i - 1, StringLen($ky)) + 1, 1))
                    $d_out &= ChrW(BitXOR($d_c, $d_k))
                Next
                Return $d_out
            EndFunc
            '''
        self.assertEqual(
            to_string(self._probed(
                'decode10', decoder, '"0x31275C23300271"', '"AU3"')),
            'probe10')
        self.assertEqual(
            to_string(self._probed(
                'decode10', decoder, '"0x2530502E31563325412E3756"', '"AU3"')),
            'decoderprobe')

    def test_a_probe_of_a_nested_script_call_refuses(self):
        self.assertIsNone(self._probed(
            'f',
            '''
            Func g()
                Return 1
            EndFunc
            Func f()
                Return g()
            EndFunc
            '''))

    def test_a_probe_of_a_read_before_any_write_refuses(self):
        self.assertIsNone(self._probed(
            'f',
            '''
            Func f($p)
                Return $q & $p
            EndFunc
            ''',
            '"x"'))
