from __future__ import annotations

import unittest

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1ForEachPipeline,
    Ps1FunctionEvaluator,
)
from refinery.lib.scripts.ps1.deobfuscation.emulator import (
    _NO_OPERATOR_METHOD_ON_BOOLEAN,
    _NO_OPERATOR_METHOD_ON_CHAR,
    _Ps1Interpreter,
    evaluate_truthy,
)
from refinery.lib.scripts.ps1.model import Ps1ScriptBlock
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.units.scripting.ps1 import ps1

#: The Int32 that every measurement in `TestPs1WhichSideOfWhichOperatorABooleanMayStandOn` was taken
#: against, as the grid names its type.
INT32 = 'System.Int32'


def _boolean_cell(operator: str, right: str) -> data.OperatorOutcome:
    """
    The grid cell a Boolean left operand and `right` index. A cell the grid does not cover raises
    here, naming what was asked for, rather than answering `None`: an operator or a type the grid
    stopped covering has to fail the comparison it stands in and not drop out of it.
    """
    cell = data.binary_outcome(operator, 'System.Boolean', right)
    if cell is None:
        raise KeyError(F'the grid has no cell for a Boolean {operator} {right}')
    return cell


def _char_cell(operator: str, right: str) -> data.OperatorOutcome:
    """
    The grid cell a Char left operand and `right` index, raising for a cell the grid does not cover
    for the same reason `_boolean_cell` does.
    """
    cell = data.binary_outcome(operator, 'System.Char', right)
    if cell is None:
        raise KeyError(F'the grid has no cell for a Char {operator} {right}')
    return cell


class TestPs1FunctionEvaluator(TestPs1):

    def test_stride_extraction(self):
        data = (
            "Function F ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$x = F 'HaEbLcLdOeX'"
            "\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('abcde', result)
        self.assertNotIn('function', result.lower())

    def test_multiple_call_sites(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$a = D 'XaYbZcX'\n"
            "$b = D 'P1Q2R3X'\n"
            "Write-Output $a\nWrite-Output $b"
        )
        result = self._deobfuscate(data)
        self.assertIn('abc', result)
        self.assertIn('123', result)
        self.assertNotIn('function', result.lower())

    def test_nonconstant_arg_preserved(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$y = D $input"
        )
        result = self._deobfuscate(data)
        self.assertIn('$Input', result)
        self.assertIn('function', result.lower())

    def test_while_loop_variant(self):
        data = (
            "Function W ([String]$s){"
            "$i=0; $r=''; "
            "While($i -lt $s.Length){$r=$r+$s.Substring($i, 1); $i+=2};"
            "$r;}"
            "$x = W 'HEeLlLlOo'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_foreach_tochararray(self):
        data = (
            "Function Rev ([String]$s){"
            "$a = $s.ToCharArray(); $r = '';"
            "ForEach($c in $a){$r = $c + $r};"
            "$r;}"
            "$x = Rev 'olleH'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_if_inside_function(self):
        data = (
            "Function C ([String]$s){"
            "$r = '';"
            "For($i=0; $i -lt $s.Length; $i+=1){"
            "If ($i % 2 -eq 0){$r = $r + $s.Substring($i, 1)}"
            "}; $r;}"
            "$x = C 'HxExLxLxO'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_function_definition_kept_when_not_all_resolved(self):
        data = (
            "Function D ([String]$s){"
            "For($i=1; $i -lt $s.Length-1; $i+=2)"
            "{$r=$r+$s.Substring($i, 1)};$r;}"
            "$a = D 'XaYbX'\n"
            "$b = D $var"
        )
        result = self._deobfuscate(data)
        self.assertIn('ab', result)
        self.assertIn('function', result.lower())

    def test_return_statement(self):
        data = (
            "Function Dec ([String]$s){"
            "$r = '';"
            "For($i=0; $i -lt $s.Length; $i+=2){"
            "$r = $r + $s.Substring($i, 1)"
            "}; return $r;}"
            "$x = Dec 'HxExLxLxOx'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_do_while_loop(self):
        data = (
            "Function D ([String]$s){"
            "$i = 0; $r = '';"
            "Do{$r = $r + $s.Substring($i, 1); $i += 2}"
            "While($i -lt $s.Length);"
            "$r;}"
            "$x = D 'HxExLxLxOx'\nWrite-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('HELLO', result)

    def test_new_object_byte_array(self):
        data = (
            "Function F ([Int]$n){"
            "$a = New-Object byte[] $n;"
            "$r = '';"
            "For($i=0; $i -lt $n; $i+=1){$r = $r + $a[$i]};"
            "$r;}"
            "$x = F 3\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('000', result)

    def test_convert_tobyte_static(self):
        data = (
            "Function F ([String]$s){"
            "$r = [convert]::ToByte($s, 16);"
            "$r;}"
            "$x = F 'FF'\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('255', result)

    def test_encoding_getstring(self):
        data = (
            "Function F {"
            "$a = New-Object byte[] 3;"
            "$a[0] = 72; $a[1] = 105; $a[2] = 33;"
            "[System.Text.Encoding]::ASCII.GetString($a);}"
            "$x = F\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hi!', result)

    def test_hex_xor_decode_function(self):
        data = (
            "Function F ([String]$s){\n"
            "$a = New-Object byte[] ($s.Length / 2)\n"
            "For($i=0; $i -lt $s.Length; $i+=2){\n"
            "$a[$i/2] = [convert]::ToByte($s.Substring($i, 2), 16)\n"
            "$a[$i/2] = ($a[$i/2] -bxor 128)\n"
            "}\n"
            "[String][System.Text.Encoding]::ASCII.GetString($a)\n"
            "}\n"
            "$x = F 'C8E5ECECEF'\n"
            "Write-Output $x\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)
        self.assertNotIn('function', result.lower())

    def test_base64_xor_decode_function(self):
        data = (
            "Function F ([String]$s, [Byte]$k) {\n"
            "$a = [System.Convert]::FromBase64String($s)\n"
            "For ($i = 0; $i -lt $a.Length; $i++) {\n"
            "$a[$i] = $a[$i] -bxor $k\n"
            "}\n"
            "return [System.Text.Encoding]::ASCII.GetString($a)\n"
            "}\n"
            "$x = F 'aEVMTE8=' 0x20\n"
            "Write-Output $x\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)
        self.assertNotIn('function', result.lower())

    def test_named_parameters(self):
        data = (
            "function F { Param([string]$a, [string]$b); $a + $b }\n"
            "$x = F -a 'Hel' -b 'lo'\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)
        self.assertNotIn('function', result.lower())

    def test_named_parameters_unordered(self):
        data = (
            "function G { Param([string]$first, [string]$second); $second + $first }\n"
            "$x = G -second 'World' -first 'Hello'\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('WorldHello', result)
        self.assertNotIn('function', result.lower())

    def test_constant_inlining_respects_function_scope(self):
        data = (
            "$a = 'INLINED'\n"
            "function F { Param([string]$a); $a }\n"
            "$x = F -a 'Hello'\n"
            "Write-Output $x"
        )
        result = self._deobfuscate(data)
        self.assertIn('Hello', result)

    def test_iex_trampoline_function(self):
        data = (
            "function Wrapper { Param([string]$code); Invoke-Expression $code > $Null 2> $Null }\n"
            "function Builder { Param([string]$a, [string]$b); $r = $a + $b; Wrapper '$r' }\n"
            "Builder -a 'Write-Host ' -b 'Hello'"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertIn('Hello', result)
        self.assertNotIn('function Builder', result)

    def test_decoy_function_producing_garbage_is_pruned(self):
        data = (
            "function IexWrap { Param([string]$c); Invoke-Expression $c }\n"
            "function Decoy { Param([string]$a); IexWrap ($a + '!!!###@@@') }\n"
            "function Real { Param([string]$a, [string]$b); IexWrap ($a + $b) }\n"
            "Decoy -a '!!!###@@@'\n"
            "Real -a 'Write-Host ' -b 'OK'"
        )
        result = self._deobfuscate(data)
        self.assertNotIn('function Decoy', result)
        self.assertNotIn('Decoy', result.split('Write-Host')[0])
        self.assertIn('Write-Host', result)
        self.assertIn('OK', result)

    def test_helper_only_called_from_function_bodies_is_pruned(self):
        data = (
            "function Helper { Param([string]$x); Invoke-Expression $x }\n"
            "function Caller { Param([string]$s); Helper $s }\n"
            "Caller -s 'Write-Host Done'"
        )
        result = self._deobfuscate(data)
        self.assertNotIn('function Helper', result)
        self.assertNotIn('function Caller', result)
        self.assertIn('Write-Host', result)
        self.assertIn('Done', result)


class TestPs1ForEachPipeline(TestPs1):

    def test_foreach_pipeline_char_convert(self):
        data = "'72z101z108z108z111'.Split('z') | %{ ([Char]([Convert]::ToInt16(($_.ToString()), 10))) }"
        result = self._deobfuscate(data)
        self.assertEqual(result, '[char]72, [char]101, [char]108, [char]108, [char]111')

    def test_foreach_pipeline_negative_integers(self):
        data = "((-83,-71,-65,-75,-107,-70,-75,-64,-110,-83,-75,-72,-79,-80) | %{ [char]($_ + 180) }) -join ''"
        result = self._deobfuscate(data)
        self.assertEqual(result, "'amsiInitFailed'")

    def test_foreach_pipeline_mixed_sign_integers(self):
        data = "(-4, 1, -17) | %{ [char]($_ + 104) }"
        result = self._deobfuscate(data)
        self.assertEqual(result, '[char]100, [char]105, [char]87')

    def test_foreach_pipeline_expandable_string_hex_decode(self):
        data = "'46 75 6E' -split ' ' | %{[char][byte]\"0x$_\"}"
        result = self._deobfuscate(data)
        self.assertEqual(result, '[char]70, [char]117, [char]110')

    def test_foreach_pipeline_expandable_string_with_subexpr(self):
        data = "@('A','B','C') | %{\"item: $( $_ )\"}"
        result = self._deobfuscate(data)
        self.assertIn('item: A', result)

    def test_foreach_pipeline_split_join_chain(self):
        data = (
            "$s = '48 65 6C 6C 6F'\n"
            "$r = $s -split ' ' | ForEach-Object {[char][byte]\"0x$_\"}\n"
            "$r -join ''"
        )
        result = self._deobfuscate_iterative(data)
        self.assertIn('Hello', result)

    def test_foreach_pipeline_replace_operator(self):
        data = "@('Hello','World') | %{$_ -replace 'o','0'}"
        result = self._deobfuscate(data)
        self.assertIn('Hell0', result)
        self.assertIn('W0rld', result)

    def test_foreach_pipeline_array_expression(self):
        data = "@(65,66,67) | %{[char]$_}"
        result = self._deobfuscate(data)
        self.assertEqual(result, '[char]65, [char]66, [char]67')


class TestPs1EmulatorExtra(TestPs1):

    def test_a_string_cast_over_an_identity_xor_pipeline_joins_on_the_default_ofs(self):
        result = self._deobfuscate(
            "[String]([Char[]] (72,101,108,108,111) | "
            "ForEach-Object { [Char]($_ -BXor 0) })")
        self.assertEqual(result, "'H e l l o'")

    def test_a_string_cast_over_an_xor_pipeline_joins_on_the_default_ofs(self):
        result = self._deobfuscate("[String]([Char[]] (127,78,88,95) | % { [Char]($_ -BXor 0x2B) })")
        self.assertEqual(result, "'T e s t'")

    def test_function_multiple_outputs_form_array(self):
        result = self._apply("function f { 'a'; 'b' }; $x = f", Ps1FunctionEvaluator)
        self.assertEqual(result, "$x = 'a', 'b'")

    def test_function_trailing_assignment_emits_nothing(self):
        # g only assigns, so it returns $null; the call must not fold to the assigned value, so
        # `$y = g` is left as-is.
        result = self._apply("function g { $r = 'hidden' }; $y = g", Ps1FunctionEvaluator)
        self.assertEqual(result, cleandoc("""
            function g {
              $r = 'hidden'
            }
            $y = g
        """))

    def test_emulated_shift_uses_int32_semantics(self):
        # The emulator must shift with the same .NET semantics as constant folding; a raw Python
        # shift would evaluate `1 -shl 32` to 4294967296 instead of 1.
        result = self._apply(
            'function f ($n) { $n -shl 32 }\n$x = f 1', Ps1FunctionEvaluator)
        self.assertIn('$x = 1', result)
        self.assertNotIn('4294967296', result)

    def test_foreach_pipeline_yields_array_not_joined_string(self):
        # Multi-character results stay an array (so indexing selects an element), unlike the
        # single-character char-build case which is joined.
        result = self._apply("('foo','bar' | %{ $_ })[1]", Ps1ForEachPipeline)
        self.assertEqual(result, "('foo', 'bar')[1]")

    def test_nested_function_reads_enclosing_scope(self):
        # Plain reads are transitive through the scope chain: C sees A's $g via the call stack.
        # Verified against PowerShell (returns 'X').
        result = self._apply(
            "function A { $g = 'X'; B } function B { C } function C { return $g }; $o = A",
            Ps1FunctionEvaluator)
        self.assertEqual(result, cleandoc("""
            function C {
              return $g
            }
            $o = 'X'
        """))

    def test_compound_assignment_does_not_read_enclosing_scope(self):
        # `$acc += 'C'` reads only the local scope, so against an enclosing-scope $acc it starts
        # from $null. Verified against PowerShell: the result is 'C', not 'ABC'.
        result = self._apply(
            "function A { $acc = 'AB'; B } function B { $acc += 'C'; return $acc }; $o = A",
            Ps1FunctionEvaluator)
        self.assertEqual(result, "$o = 'C'")

    def test_psitem_is_pipeline_item(self):
        result = self._apply('(97,98,99) | % { [char]$PSItem }', Ps1ForEachPipeline)
        self.assertEqual(result, '[char]97, [char]98, [char]99')

    def test_foreach_over_string_is_scalar(self):
        # PowerShell iterates a foreach over a string exactly once (the string is a scalar).
        result = self._apply(
            "function f($s){ $n = 0; foreach($c in $s){ $n = $n + 1 }; return $n }; $r = f 'abc'",
            Ps1FunctionEvaluator)
        self.assertEqual(result, '$r = 1')

    def test_iex_in_foreach_pipeline_does_not_crash(self):
        # The InvokeExpression signal is caught rather than escaping the pipeline; the script is
        # left unchanged.
        result = self._deobfuscate("('calc','notepad') | % { iex $_ }")
        self.assertEqual(result, cleandoc("""
            ('calc', 'notepad') | ForEach-Object {
              Invoke-Expression $_
            }
        """))

    def test_recursive_function_does_not_crash(self):
        # Unbounded recursion converts to a graceful bail (no RecursionError); the script is left
        # unchanged.
        result = self._deobfuscate("function f($x){ f $x }; f 1")
        self.assertEqual(result, cleandoc("""
            function f {
              Param($x)
              f $x
            }
            f 1
        """))

    def test_a_loop_exit_with_no_loop_around_it_is_refused_rather_than_raised(self):
        # Regression: `break` and `continue` unwound straight past the interpreter and crashed the
        # whole pipeline, because `emit` caught only `_ReturnSignal`. An exit that left every loop
        # the emulation ran names a loop the fold does not hold, so the call is refused.
        for exit_name in ('break', 'continue'):
            with self.subTest(exit_name):
                source = cleandoc(F"""
                    function f {{
                      1
                      {exit_name}
                      2
                    }}
                    $x = f
                """)
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)

    def test_a_loop_exit_inside_a_nested_subexpression_still_exits_the_loop_it_sits_in(self):
        # The conversion at the `emit` boundary must not reach into the loops the interpreter runs
        # itself: a `break` inside a `$()` is measured to exit the enclosing loop on 5.1, and the
        # loop's own handler still catches it. The body emits 'x' on the first pass, exits on the
        # second, and finishes with 'y'.
        source = cleandoc("""
            function f {
              for($i = 0; $i -lt 5; $i++) {
                if($i -eq 1) {
                  $(break)
                }
                'x'
              }
              'y'
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'x', 'y'")

    def test_a_loop_exit_in_an_unfolded_condition_is_refused_rather_than_raised(self):
        # The `unflatten` pass hands conditions to the interpreter directly, past `emit`'s boundary,
        # so a loop exit in one reached no conversion at all before the boundary was closed there
        # too.
        parsed = Ps1Parser('$(if(1){break})').parse()
        condition = parsed.body[0].expression
        self.assertIsNone(evaluate_truthy(condition, {}))

    def test_a_redirected_call_is_not_folded_into_its_value(self):
        # Regression: the replacement is an expression and an expression carries no redirections,
        # so folding `f > C:\log` into the string `f` returns printed it to the console and left
        # the file unwritten. Every spelling is refused, including the merges that leave the output
        # stream alone, because none of them survives the substitution either.
        for redirection in (r'> C:\log.txt', r'>> C:\log.txt', '1>&2', '2>&1', r'*> C:\log.txt'):
            with self.subTest(redirection):
                source = F"function f {{ 'FOLDED' }}\n$x = f {redirection}"
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), cleandoc(F"""
                    function f {{
                      'FOLDED'
                    }}
                    $x = f {redirection}
                """))

    def test_a_body_that_opens_a_file_is_not_folded_into_the_value_it_returns(self):
        # The call site carries no redirection here; the body does. Folding the call deletes the
        # body, so the file the redirection names is never created although the value is right.
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > C:\\o.txt
              'V'
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)

    def test_a_body_discarding_to_null_is_still_folded(self):
        # `> $Null` is PowerShell's discard and creates nothing, so there is no work the value
        # failed to capture. Reading it as a file would switch the trampoline resolution off for
        # the spelling obfuscators use most.
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > $Null
              'V'
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'V'")

    def test_a_call_to_a_function_that_emitted_nothing_goes_with_its_definition(self):
        # The body hands out no code and produces no value, so the call is accounted for with
        # nothing installed in its place, and the definition it named is left uncalled.
        source = cleandoc("""
            function Silent {
              Invoke-Expression ''
            }
            Silent
            Write-Host 'after'
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "Write-Host 'after'")

    def test_an_exported_definition_is_not_removed_after_its_calls_are_folded(self):
        # Regression: folding a call into its value is safe whoever else can reach the name, but
        # deleting the definition afterwards is a name-keyed removal, and an exported name has a
        # caller this tree does not contain. A `.psm1` lost the definition here, and the value it
        # had been folded into was then a bare literal at the root that junk removal stripped as
        # console text — so the module's whole payload went, under the default model, with an export
        # statement standing right there saying it was reachable.
        for export in (
            'Export-ModuleMember -Function f',
            "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function f",
        ):
            with self.subTest(export):
                result = self._apply(
                    F"{export}\nfunction f {{ 'FOLDED' }}\n$x = f", Ps1FunctionEvaluator)
                self.assertIn('function f', result)
                self.assertIn('FOLDED', result)

    def test_a_definition_no_export_names_is_still_removed_after_folding(self):
        # The other four unknowns `is_readable` carries are risks this pass takes deliberately, so
        # gating on the whole verdict would stop it resolving the `iex` trampolines above. Only the
        # export withholds.
        for opener in ('', 'Invoke-Expression $code\n', '& $dispatch\n'):
            with self.subTest(opener or '(closed world)'):
                result = self._apply(
                    F"{opener}function f {{ 'FOLDED' }}\n$x = f", Ps1FunctionEvaluator)
                self.assertNotIn('function f', result)
                self.assertIn("$x = 'FOLDED'", result)


class TestPs1AnArgumentIsFoldedOnlyWhereItsTypeSurvivesTheInterpreter(TestPs1):
    """
    The interpreter's values are Python objects and carry no .NET type, so binding one is a claim
    that the object stands for the value the source wrote. Where it does not, the call is left
    alone: a fold that dropped the type would answer `[byte] 5` with the Int32 5, which is a
    different value in every place the difference shows.
    """

    def _identity_call(self, argument: str) -> str:
        return cleandoc(F"""
            function f {{
              Param($n)
              $n
            }}
            $x = f {argument}
        """)

    def test_a_numeral_written_wider_than_its_magnitude_is_not_bound(self):
        self._assertUnchanged(self._identity_call('1L'), Ps1FunctionEvaluator)
        self.assertEqual(self._apply(self._identity_call('1'), Ps1FunctionEvaluator), '$x = 1')

    def test_a_numeral_written_at_the_width_its_magnitude_takes_is_bound(self):
        self.assertEqual(
            self._apply(self._identity_call('2147483648L'), Ps1FunctionEvaluator),
            '$x = 2147483648L',
        )

    def test_a_width_cast_is_not_bound_as_the_numeral_written_inside_it(self):
        self._assertUnchanged(self._identity_call('([byte]5)'), Ps1FunctionEvaluator)
        self._assertUnchanged(self._identity_call('([uint32]7)'), Ps1FunctionEvaluator)
        self.assertEqual(self._apply(self._identity_call('(5)'), Ps1FunctionEvaluator), '$x = 5')

    def test_a_char_is_not_bound_as_the_string_that_carries_the_same_character(self):
        self._assertUnchanged(self._identity_call('([char]65)'), Ps1FunctionEvaluator)
        self.assertEqual(self._apply(self._identity_call("'A'"), Ps1FunctionEvaluator), "$x = 'A'")

    def test_a_boolean_is_bound_and_handed_back_as_the_boolean_it_is(self):
        self.assertEqual(
            self._apply(self._identity_call('$true'), Ps1FunctionEvaluator), '$x = $True')
        self.assertEqual(self._apply('$true | % { $_ }', Ps1ForEachPipeline), '$True')

    def test_a_pipeline_source_declines_the_same_values_a_parameter_declines(self):
        self._assertUnchanged(cleandoc("""
            [byte]5 | % {
              $_
            }
        """), Ps1ForEachPipeline)
        self._assertUnchanged(cleandoc("""
            ([char]65) | % {
              $_
            }
        """), Ps1ForEachPipeline)
        self.assertEqual(self._apply('5 | % { $_ }', Ps1ForEachPipeline), '5')


class TestPs1AHexadecimalArgumentDenotesThePatternItFills(TestPs1):
    """
    A hexadecimal numeral names a bit pattern in the width its digits fill, not the magnitude the
    digits read as: 5.1 makes `0xFFFFFFFF` the Int32 -1, so a body that adds one to it produces 0
    and never 4294967296.
    """

    def _call(self, argument: str, body: str = '$n') -> str:
        return cleandoc(F"""
            function f ($n) {{ {body} }}
            $x = f {argument}
        """)

    def test_a_pattern_that_fills_an_int32_binds_the_negative_it_denotes(self):
        self.assertEqual(self._apply(self._call('0xFFFFFFFF'), Ps1FunctionEvaluator), '$x = -1')
        self.assertEqual(
            self._apply(self._call('0xFFFFFFFF', '$n + 1'), Ps1FunctionEvaluator), '$x = 0')

    def test_a_pattern_narrower_than_the_width_it_fills_binds_its_magnitude(self):
        self.assertEqual(self._apply(self._call('0xFF'), Ps1FunctionEvaluator), '$x = 255')
        self.assertEqual(
            self._apply(self._call('0x7FFFFFFF', '$n + 1'), Ps1FunctionEvaluator),
            '$x = 2147483648L',
        )

    def test_the_long_suffix_binds_the_digits_read_as_a_number(self):
        self.assertEqual(
            self._apply(self._call('0xFFFFFFFFL'), Ps1FunctionEvaluator), '$x = 4294967295L')

    def test_a_pipeline_reads_a_pattern_the_same_way_a_parameter_does(self):
        self.assertEqual(self._apply('0xFFFFFFFF | % { $_ + 1 }', Ps1ForEachPipeline), '0')


class TestPs1AProducedValueIsWrittenAsTheExpressionThatSpellsIt(TestPs1):

    def _folded(self, body: str, arguments: str) -> str:
        return self._apply(cleandoc(F"""
            function f ($a, $b) {{ {body} }}
            $x = f {arguments}
        """), Ps1FunctionEvaluator)

    def test_a_body_that_compares_folds_to_the_boolean_it_produced(self):
        self.assertEqual(self._folded('$a -eq $b', '1 1'), '$x = $True')
        self.assertEqual(self._folded('$a -eq $b', '1 2'), '$x = $False')

    def test_a_body_that_divides_folds_to_the_fraction_it_produced(self):
        self.assertEqual(self._folded('$a / $b', '3 2'), '$x = 1.5')
        self.assertEqual(self._folded('$a / $b', '4 2'), '$x = 2')

    def test_a_block_writes_each_item_under_the_type_it_produced(self):
        self.assertEqual(
            self._apply('(1, 2) | % { $_ -eq 1 }', Ps1ForEachPipeline), '$True, $False')
        self.assertEqual(self._apply('(3, 2) | % { $_ / 2 }', Ps1ForEachPipeline), '1.5, 1')


class TestPs1AnEmissionThatDidNotHappenIsNotFoldedIntoOne(TestPs1):
    """
    Producing nothing is not producing `$null`: measured on 5.1, `@(g).Count` is 0 for a body that
    emits nothing and 1 for `@($null)`, and `g | %{ }` runs the block no times where `$null | %{ }`
    runs it once. So nothing may stand in the place of an emission that never happened, and the
    call is left where it is.
    """

    def test_a_body_that_emits_nothing_leaves_its_call_alone(self):
        self._assertUnchanged(cleandoc("""
            function f {}
            $x = f
        """), Ps1FunctionEvaluator)
        self.assertEqual(self._apply(cleandoc("""
            function f { 'v' }
            $x = f
        """), Ps1FunctionEvaluator), "$x = 'v'")

    def test_a_block_that_emits_nothing_for_every_item_leaves_its_pipeline_alone(self):
        self._assertUnchanged('(1, 2) | % {}', Ps1ForEachPipeline)

    def test_an_item_that_emitted_nothing_contributes_nothing_to_the_stream(self):
        self.assertEqual(
            self._apply('@(1, 2) | % { if ($_ -eq 1) { $_ } }', Ps1ForEachPipeline), '1')


class TestPs1APipelineOverAScalarRunsItsBlockOverThatOneItem(TestPs1):

    def test_a_number_is_one_item(self):
        self.assertEqual(self._apply('5 | % { $_ + 1 }', Ps1ForEachPipeline), '6')

    def test_a_string_is_one_item_and_not_a_run_of_its_characters(self):
        self.assertEqual(self._apply("'abc' | % { $_.Length }", Ps1ForEachPipeline), '3')
        self.assertEqual(self._apply("'abc' | % { $_ }", Ps1ForEachPipeline), "'abc'")

    def test_the_one_item_still_contributes_everything_its_block_emits(self):
        self.assertEqual(self._apply('5 | % { $_, $_ }', Ps1ForEachPipeline), '5, 5')

    def test_an_array_source_runs_the_block_over_each_of_its_items(self):
        self.assertEqual(self._apply('@(5, 6) | % { $_ + 1 }', Ps1ForEachPipeline), '6, 7')


class TestPs1AnArrayABlockHandsOutWholeIsNotTheValuesInsideIt(TestPs1):
    """
    Measured on 5.1: `@(1, 2) | %{ $_, $_ }` has `.Count` 4 with an `Int32` at each position, where
    `@(1, 2) | %{ ,($_, $_) }` has `.Count` 2 with an `Object[]` at each. The two are one pipeline
    apart and may not be spelled the same way.
    """

    def test_a_block_handing_out_an_array_per_item_is_not_one_handing_out_two_values(self):
        self.assertEqual(self._apply('@(1, 2) | % { $_, $_ }', Ps1ForEachPipeline), '1, 1, 2, 2')
        self.assertEqual(
            self._apply('@(1, 2) | % { ,($_, $_) }', Ps1ForEachPipeline), '(1, 1), (2, 2)')

    def test_a_source_of_one_item_whose_block_hands_out_one_value_folds_to_that_value(self):
        self.assertEqual(self._apply("@('a') | % { $_ }", Ps1ForEachPipeline), "'a'")


class TestPs1AReturnWritesTheStreamTheExpressionAloneWrites(TestPs1):
    """
    Both spellings of each shape are asserted together because the claim is that they agree, and
    two expectations written apart can drift into agreeing with the code instead: the signal used
    to carry the collapsed stream, so `return ,($_, $_)` handed out the two values inside the array
    where the bare expression handed out the array.
    """

    def _both(self, body: str) -> tuple[str, str]:
        return (
            self._apply(F'@(1, 2) | % {{ {body} }}', Ps1ForEachPipeline),
            self._apply(F'@(1, 2) | % {{ return {body} }}', Ps1ForEachPipeline),
        )

    def _both_values(self, body: str) -> tuple[str, str]:
        return (
            self._apply(F'function f {{ {body} }}\n$x = f', Ps1FunctionEvaluator),
            self._apply(F'function f {{ return {body} }}\n$x = f', Ps1FunctionEvaluator),
        )

    def test_an_array_handed_out_is_one_object_whichever_spelling_writes_it(self):
        self.assertEqual(self._both(',($_, $_)'), ('(1, 1), (2, 2)', '(1, 1), (2, 2)'))

    def test_values_handed_out_stay_as_many_as_they_were_whichever_spelling_writes_them(self):
        self.assertEqual(self._both('$_, $_'), ('1, 1, 2, 2', '1, 1, 2, 2'))
        self.assertEqual(self._both('$_'), ('1, 2', '1, 2'))

    def test_a_return_from_a_nested_block_hands_out_what_that_block_wrote(self):
        self.assertEqual(
            self._apply('@(1, 2) | % { if ($_ -eq 1) { return $_ } }', Ps1ForEachPipeline), '1')

    def test_a_bare_return_hands_out_nothing_and_leaves_the_pipeline_alone(self):
        self._assertUnchanged(cleandoc("""
            @(1, 2) | % {
              return
            }
        """), Ps1ForEachPipeline)

    def test_a_call_folds_to_the_same_value_whichever_spelling_produced_it(self):
        self.assertEqual(self._both_values('5'), ('$x = 5', '$x = 5'))
        self.assertEqual(self._both_values("'a', 'b'"), ("$x = 'a', 'b'", "$x = 'a', 'b'"))


class TestPs1TheStreamABlockWritesIsAskedForBesideTheValueItCollapsesTo(TestPs1):
    """
    `emit` answers with one entry per object a block hands out and `execute` with the value those
    objects collapse to, so the two come apart wherever the collapse loses something.
    """

    @staticmethod
    def _block(body: str) -> Ps1ScriptBlock:
        block, = (
            node
            for node in Ps1Parser(F'& {{ {body} }}').parse().walk()
            if isinstance(node, Ps1ScriptBlock)
        )
        return block

    def _emit(self, body: str) -> list:
        return _Ps1Interpreter().emit(self._block(body), {'_': 1})

    def _emitted(self, body: str) -> tuple[list, list]:
        return self._emit(body), self._emit(F'return {body}')

    def _execute(self, body: str):
        return _Ps1Interpreter().execute(self._block(body), {'_': 1})

    def test_an_array_handed_out_whole_is_one_entry_where_its_values_are_two(self):
        self.assertEqual(self._emit(',($_, $_)'), [[1, 1]])
        self.assertEqual(self._emit('$_, $_'), [1, 1])

    def test_the_value_both_blocks_produce_is_the_one_the_collapse_cannot_tell_apart(self):
        self.assertEqual(self._execute(',($_, $_)'), [1, 1])
        self.assertEqual(self._execute('$_, $_'), [1, 1])

    def test_one_object_handed_out_is_one_entry_and_that_object_is_the_value(self):
        self.assertEqual(self._emit('$_'), [1])
        self.assertEqual(self._execute('$_'), 1)

    def test_a_block_handing_out_nothing_has_an_empty_stream_and_no_value(self):
        self.assertEqual(self._emit('$x = 5'), [])
        self.assertIsNone(self._execute('$x = 5'))

    def test_a_return_writes_the_stream_the_expression_alone_writes(self):
        self.assertEqual(self._emitted(',($_, $_)'), ([[1, 1]], [[1, 1]]))
        self.assertEqual(self._emitted('$_, $_'), ([1, 1], [1, 1]))
        self.assertEqual(self._emitted('$_'), ([1], [1]))

    def test_a_return_keeps_what_the_block_wrote_before_it(self):
        self.assertEqual(self._emit("'a'; return $_"), ['a', 1])
        self.assertEqual(self._emit("'a'; return ,($_, $_)"), ['a', [1, 1]])


class TestPs1EmulatorRedirections(TestPs1):

    def test_a_redirected_foreach_pipeline_is_not_folded_into_its_value(self):
        self._assertUnchanged(
            "@('a', 'b') | ForEach-Object {\n  $_\n} > C:\\o.txt", Ps1ForEachPipeline)

    def test_a_merge_on_a_foreach_pipeline_is_refused_too(self):
        self._assertUnchanged(
            "@('a', 'b') | ForEach-Object {\n  $_\n} 2>&1", Ps1ForEachPipeline)

    def test_an_unredirected_foreach_pipeline_is_still_folded(self):
        self.assertEqual(
            self._apply("@('a', 'b') | ForEach-Object { $_ }", Ps1ForEachPipeline), "'a', 'b'")

    def test_a_definition_a_redirected_call_still_names_is_kept(self):
        # The redirected call cannot be folded, so the name still has a caller when the definition
        # removal reads the counter. Emitting the fold without the definition leaves the script
        # calling a function it no longer defines.
        result = self._apply(
            "function F { 'V' }\n$x = F\nF > C:\\o.txt", Ps1FunctionEvaluator)
        self.assertIn('function F', result)
        self.assertIn("$x = 'V'", result)

    def test_a_redirecting_call_to_a_function_that_emitted_nothing_is_kept(self):
        # PowerShell creates the target as it sets the redirection up, so the statement produces the
        # file although the body it names writes nothing into it; deleting it as observing nothing
        # loses the one thing it did. Every spelling is refused, including the merges that create no
        # file, because a merge still moves records the console would otherwise show.
        for redirection in (r'> C:\o.txt', r'>> C:\o.txt', '2>&1', '1>&2', r'*> C:\o.txt'):
            with self.subTest(redirection):
                self._assertUnchanged(cleandoc(F"""
                    function Silent {{
                      Invoke-Expression ''
                    }}
                    Silent {redirection}
                    Write-Host 'after'
                """), Ps1FunctionEvaluator)

    def test_a_value_a_discard_took_away_is_not_read_back(self):
        # `$a = j > $Null` binds `$a` to `$null`, so `$a.Length` is not 4.
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > $Null
              $a.Length
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)


class TestPs1APipelineSourceIsWhatTheCastAroundItMakesOfIt(TestPs1):
    """
    Measured on 5.1: `[char[]]'ab'` is two Chars where the string it was written around is one item,
    `[int[]]('1', '2')` is two Int32s where the strings inside it would concatenate, and
    `[string[]](1, 2)` is two Strings where the numbers inside it would add. A block run over what
    stands inside the cast therefore runs the wrong number of times or over the wrong values.
    """

    def test_a_cast_that_decides_how_many_items_there_are_is_not_read_past(self):
        self._assertUnchanged(cleandoc("""
            [char[]]'ab' | % {
              $_
            }
        """), Ps1ForEachPipeline)

    def test_a_cast_that_decides_what_the_items_are_worth_is_not_read_past(self):
        for source in [
            cleandoc("""
                [int[]]('1', '2') | % {
                  $_ + 1
                }
            """),
            cleandoc("""
                [string[]](1, 2) | % {
                  $_ + 1
                }
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ForEachPipeline)

    def test_a_cast_the_numbers_written_inside_it_already_answer_is_still_folded(self):
        self.assertEqual(
            self._apply('[Char[]](72, 73) | % { [char]($_ -bxor 0) }', Ps1ForEachPipeline),
            '[char]72, [char]73',
        )


class TestPs1AnArrayCastAnElementDoesNotFitIsAThrowAndNotARename(TestPs1):
    """
    Measured on 5.1: `[byte[]](300, 1)`, `[byte[]](-1, 1)`, `[char[]](-1)` and `[int[]](2147483648)`
    each raise `Value was either too large or too small`, and so does the pipeline written over
    them, which therefore runs its block no times and produces nothing. Reading the cast as a name
    for the numbers inside it hands back a collection the script never produces.
    """

    def test_a_pipeline_over_a_cast_no_element_of_which_fits_is_left_alone(self):
        for source in [
            cleandoc("""
                [byte[]](300, 1) | % {
                  $_
                }
            """),
            cleandoc("""
                [byte[]](-1, 1) | % {
                  $_
                }
            """),
            cleandoc("""
                [char[]](-1) | % {
                  $_
                }
            """),
            cleandoc("""
                [int[]](2147483648) | % {
                  $_
                }
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ForEachPipeline)

    def test_a_pipeline_over_a_cast_every_element_fits_is_still_folded(self):
        """
        The block's answer is spelled at the types it computes: a `[char]` inside it leaves as the
        `Char` the body produced. The cast on the *source* is a different reading, which hands the
        element on as the number written inside it: on 5.1 `[byte[]](5, 6)` carries two
        `System.Byte` and the numerals written back carry `System.Int32`, so what survives the
        dropped cast is the count and the magnitudes and not the element type — bounded by the
        range check the tests above pin.
        """
        self.assertEqual(self._apply('[byte[]](5, 6) | % { $_ }', Ps1ForEachPipeline), '5, 6')
        self.assertEqual(self._apply('[byte[]](255, 1) | % { $_ }', Ps1ForEachPipeline), '255, 1')
        self.assertEqual(
            self._apply('[Char[]](72, 73) | % { [char]($_ -bxor 0) }', Ps1ForEachPipeline),
            '[char]72, [char]73',
        )


class TestPs1AnArrayCastToATypeThatDoesNotResolveIsWhereTheScriptStops(TestPs1):
    """
    Windows PowerShell 5.1 has no `[short]`, `[ushort]`, `[uint]` or `[ulong]` accelerator — those
    arrived in later versions — so `[ushort[]](1, 2)` is `Unable to find type` and the pipeline
    written over it runs its block no times at all. The integer widths 5.1 does have name a type
    the numbers inside the cast survive, and those are the ones the fold stands on.
    """

    def test_a_pipeline_over_a_cast_5_1_has_no_type_for_is_left_alone(self):
        for spelling in ['short', 'ushort', 'uint', 'ulong']:
            with self.subTest(spelling):
                self._assertUnchanged(cleandoc(F"""
                    [{spelling}[]](1, 2) | % {{
                      $_ + 1
                    }}
                """), Ps1ForEachPipeline)

    def test_a_pipeline_over_a_width_5_1_resolves_is_still_folded(self):
        for spelling in [
            'byte',
            'sbyte',
            'int',
            'int16',
            'int32',
            'int64',
            'long',
            'uint16',
            'uint32',
            'uint64',
            'char',
        ]:
            with self.subTest(spelling):
                self.assertEqual(
                    self._apply(F'[{spelling}[]](1, 2) | % {{ $_ + 1 }}', Ps1ForEachPipeline),
                    '2, 3',
                )


class TestPs1ANullWrittenAmongThePipelineSourceIsOneOfItsItems(TestPs1):
    """
    Measured on 5.1: `1, $null, 2 | % { $_ }` produces three objects, the middle one `$null`. A
    source read as the two numbers it names runs the block twice and hands back a collection one
    item shorter than the one the script produces.
    """

    def test_a_null_between_two_numbers_is_not_dropped_from_the_source(self):
        self._assertUnchanged(cleandoc("""
            1, $null, 2 | % {
              $_
            }
        """), Ps1ForEachPipeline)

    def test_a_source_of_numbers_alone_is_still_folded(self):
        self.assertEqual(self._apply('1, 2 | % { $_ }', Ps1ForEachPipeline), '1, 2')


class TestPs1WhichSideOfWhichOperatorABooleanMayStandOn(TestPs1):
    """
    Measured on 5.1 against the Int32 `2`, for every binary arithmetic and bitwise operator it has,
    with `$true` and `$false` on each side. An operator dispatches to a method on its *left*
    operand's type, and the three that `Boolean` carries none of are `*`, `-shl` and `-shr`: each
    answers `The operation '[System.Boolean] * [System.Int32]' is not defined` for both Booleans, so
    which one stands there decides nothing. The other seven convert it and answer a number for both,
    the Boolean deciding only which number: `$true / 2` is the Double 0.5 where `$false / 2` is the
    Int32 0, since left of a division the Boolean is the dividend. A Boolean on the *right* is
    converted before any dispatch happens and is a value for all ten, except that there `$false` is
    the divisor zero, which makes `2 / $false` and `2 % $false` `Attempted to divide by zero`.
    """

    def _call(self, expression: str, argument: str) -> str:
        return cleandoc(F"""
            function f {{
              Param($n)
              {expression}
            }}
            $x = f {argument}
        """)

    def test_the_operators_a_boolean_left_operand_has_no_method_for_leave_their_call_alone(self):
        for operator in ['*', '-shl', '-shr']:
            for argument in ['$true', '$false']:
                with self.subTest(F'{argument} {operator} 2'):
                    self._assertUnchanged(
                        self._call(F'$n {operator} 2', argument), Ps1FunctionEvaluator)

    def test_the_operators_a_boolean_left_operand_has_a_method_for_fold_to_their_number(self):
        for operator, from_true, from_false in [
            ('+', '3', '2'),
            ('-', '-1', '-2'),
            ('/', '0.5', '0'),
            ('%', '1', '0'),
            ('-band', '0', '0'),
            ('-bor', '3', '2'),
            ('-bxor', '3', '2'),
        ]:
            for argument, expected in [('$true', from_true), ('$false', from_false)]:
                with self.subTest(F'{argument} {operator} 2'):
                    self.assertEqual(
                        self._apply(self._call(F'$n {operator} 2', argument), Ps1FunctionEvaluator),
                        F'$x = {expected}',
                    )

    def test_the_ones_complement_of_a_boolean_folds_to_the_number_it_converts_to(self):
        # 5.1 converts the Boolean to the Int32 it names before complementing `-bnot`, so `-bnot
        # $true` is -2 (the complement of 1) and `-bnot $false` is -1 (the complement of 0).
        for argument, expected in [('$true', '-2'), ('$false', '-1')]:
            with self.subTest(F'-bnot {argument}'):
                self.assertEqual(
                    self._apply(self._call('-bnot $n', argument), Ps1FunctionEvaluator),
                    F'$x = {expected}',
                )

    def test_a_boolean_right_operand_folds_for_every_one_of_the_ten_operators(self):
        for operator, expected in [
            ('+', '3'),
            ('-', '1'),
            ('*', '2'),
            ('/', '2'),
            ('%', '0'),
            ('-band', '0'),
            ('-bor', '3'),
            ('-bxor', '3'),
            ('-shl', '4'),
            ('-shr', '1'),
        ]:
            with self.subTest(operator):
                self.assertEqual(
                    self._apply(self._call(F'2 {operator} $n', '$true'), Ps1FunctionEvaluator),
                    F'$x = {expected}',
                )

    def test_a_false_right_operand_folds_for_every_operator_it_is_not_the_divisor_of(self):
        for operator, expected in [
            ('+', '2'),
            ('-', '2'),
            ('*', '0'),
            ('-band', '0'),
            ('-bor', '2'),
            ('-bxor', '2'),
            ('-shl', '2'),
            ('-shr', '2'),
        ]:
            with self.subTest(F'2 {operator} $false'):
                self.assertEqual(
                    self._apply(self._call(F'2 {operator} $n', '$false'), Ps1FunctionEvaluator),
                    F'$x = {expected}',
                )

    def test_the_false_standing_right_of_a_division_is_the_divisor_zero(self):
        for operator in ['/', '%']:
            with self.subTest(F'2 {operator} $false'):
                self._assertUnchanged(
                    self._call(F'2 {operator} $n', '$false'), Ps1FunctionEvaluator)

    def test_a_block_reads_a_boolean_operand_exactly_as_a_function_body_does(self):
        self.assertEqual(self._apply('$true | % { $_ -bor 2 }', Ps1ForEachPipeline), '3')
        self.assertEqual(self._apply('$false | % { $_ -bor 2 }', Ps1ForEachPipeline), '2')
        self.assertEqual(self._apply('$true | % { $_ / 2 }', Ps1ForEachPipeline), '0.5')
        self.assertEqual(self._apply('$false | % { $_ / 2 }', Ps1ForEachPipeline), '0')
        self.assertEqual(self._apply('$true | % { 2 -shl $_ }', Ps1ForEachPipeline), '4')
        for source in [
            cleandoc("""
                $true | % {
                  $_ -shr 2
                }
            """),
            cleandoc("""
                $false | % {
                  $_ -shr 2
                }
            """),
            cleandoc("""
                $false | % {
                  2 % $_
                }
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1ForEachPipeline)

    def test_the_operators_refused_are_the_ones_the_grid_says_always_throw_for_a_boolean(self):
        """
        The list is hand written and the grid is measured, so it is the measurement the list has to
        keep agreeing with: an operator whose Boolean cell stops always throwing, and one that
        becomes so, are both a row of the capture the refusal no longer follows. The whole operator
        axis is asked rather than the ten measured above, so an operator the grid does not cover
        cannot enter the list until a capture covers it either.
        """
        operators = list(data._OPERATORS['binary'])
        self.assertEqual(len(operators), 63)
        self.assertEqual(
            {operator for operator in operators if _boolean_cell(operator, INT32).always_throws},
            set(_NO_OPERATOR_METHOD_ON_BOOLEAN),
        )

    def test_the_boolean_row_reaches_past_the_int32_the_refusal_is_pinned_to(self):
        """
        The refusal is by operand where the grid answers by cell, so the two part company wherever
        the rest of the Boolean row disagrees with the column it was measured against. Every
        disagreement the capture holds is listed: `*` always throws for every right operand but a
        Decimal, `+` and `-` for a Decimal and for a collection, `/` and `%` add the two whose throw
        is the divisor rather than the Boolean standing left of it, and the bitwise three part
        company over a collection alone.
        """
        operators = list(data._OPERATORS['binary'])
        types = list(data._OPERATORS['witnesses'])
        self.assertEqual((len(operators), len(types)), (63, 16))
        disagreeing = {}
        for operator in operators:
            measured = _boolean_cell(operator, INT32).always_throws
            found = [one for one in types if _boolean_cell(operator, one).always_throws != measured]
            if found:
                disagreeing[operator] = found
        self.assertEqual(disagreeing, {
            '+': ['System.Decimal', 'System.Object[]'],
            '-': ['System.Decimal', 'System.Object[]'],
            '*': ['System.Decimal'],
            '/': ['System.Decimal', 'System.Object[]', 'System.Void'],
            '%': ['System.Decimal', 'System.Object[]', 'System.Void'],
            '-band': ['System.Object[]'],
            '-bor': ['System.Object[]'],
            '-bxor': ['System.Object[]'],
        })


class TestPs1WhichSideOfWhichOperatorACharMayStandOn(TestPs1):
    """
    Measured on 5.1 against the Int32 `2`, for every binary arithmetic and bitwise operator, with a
    `Char` on each side. An operator dispatches to a method on its *left* operand's type, and the
    three a `Char` carries none of are `*`, `-shl` and `-shr` — the same three a `Boolean` lacks:
    each answers `The operation '[System.Char] -shl [System.Int32]' is not defined`. The bitwise
    three convert it to its code point and answer a number, so `[char]65 -bor 2` is `67`. A `Char`
    on the *right* is converted before any dispatch and is a value there for every operator reading
    a number: it is the count `-shl` and `-shr` mask and the number the bitwise three fold against.
    """

    def _body(self, expression: str) -> str:
        return cleandoc(F"""
            function f {{
              {expression}
            }}
            $x = f
        """)

    def test_the_operators_a_char_left_operand_has_no_method_for_leave_their_call_alone(self):
        for operator in ['*', '-shl', '-shr']:
            with self.subTest(F'[char]65 {operator} 2'):
                self._assertUnchanged(self._body(F'[char]65 {operator} 2'), Ps1FunctionEvaluator)

    def test_the_bitwise_operators_a_char_left_operand_has_fold_to_its_code_point(self):
        for expression, expected in [
            ('[char]65 -band 15', '1'),
            ('[char]65 -bor 2', '67'),
            ('[char]65 -bxor 1', '64'),
        ]:
            with self.subTest(expression):
                self.assertEqual(
                    self._apply(self._body(expression), Ps1FunctionEvaluator), F'$x = {expected}')

    def test_a_char_right_operand_is_the_code_point_the_reading_operators_fold_against(self):
        for expression, expected in [
            ('1 -shl [char]65', '2'),
            ('256 -shr [char]66', '64'),
            ('3 -band [char]65', '1'),
        ]:
            with self.subTest(expression):
                self.assertEqual(
                    self._apply(self._body(expression), Ps1FunctionEvaluator), F'$x = {expected}')

    def test_the_operators_refused_are_the_ones_the_grid_says_always_throw_for_a_char(self):
        """
        The list is hand written and the grid is measured, so it is the measurement the list has to
        keep agreeing with: an operator whose Char cell stops always throwing, and one that becomes
        so, are both a row of the capture the refusal no longer follows.
        """
        operators = list(data._OPERATORS['binary'])
        self.assertEqual(len(operators), 63)
        self.assertEqual(
            {operator for operator in operators if _char_cell(operator, INT32).always_throws},
            set(_NO_OPERATOR_METHOD_ON_CHAR),
        )


class TestPs1AHexadecimalNumeralInsideABodyDenotesThePatternItFills(TestPs1):
    """
    The same reading as for an argument, measured at the position an emulated body writes it in:
    5.1 answers `0xFFFFFFFF` with the Int32 -1 in a function body and in a `%{ }` block alike, so
    adding one to it is 0 at both, and `0xFFFFFFFFL` is 4294967295 at both.
    """

    def _call(self, body: str) -> str:
        return cleandoc(F"""
            function f {{ {body} }}
            $x = f
        """)

    def test_a_function_body_reads_a_pattern_that_fills_an_int32_as_the_negative_it_names(self):
        self.assertEqual(self._apply(self._call('0xFFFFFFFF'), Ps1FunctionEvaluator), '$x = -1')
        self.assertEqual(self._apply(self._call('0xFFFFFFFF + 1'), Ps1FunctionEvaluator), '$x = 0')

    def test_a_function_body_reads_a_pattern_narrower_than_its_width_as_its_magnitude(self):
        self.assertEqual(self._apply(self._call('0xFF'), Ps1FunctionEvaluator), '$x = 255')

    def test_a_function_body_reads_the_long_suffix_as_the_digits_read_as_a_number(self):
        self.assertEqual(
            self._apply(self._call('0xFFFFFFFFL'), Ps1FunctionEvaluator), '$x = 4294967295L')

    def test_a_block_reads_a_numeral_exactly_as_a_function_body_does(self):
        self.assertEqual(self._apply('1 | % { 0xFFFFFFFF }', Ps1ForEachPipeline), '-1')
        self.assertEqual(self._apply('1 | % { 0xFFFFFFFF + 1 }', Ps1ForEachPipeline), '0')
        self.assertEqual(self._apply('1 | % { 0xFF }', Ps1ForEachPipeline), '255')
        self.assertEqual(self._apply('1 | % { 0xFFFFFFFFL }', Ps1ForEachPipeline), '4294967295L')


class TestPs1ANumeralWithAMultiplierSuffixIsAnIntegerAndNotAFraction(TestPs1):
    """
    Measured on 5.1: `1kb` is the Int32 1024 and `2gb` the Int64 2147483648, a magnitude no Int32
    holds, where `1.5` and `1e3` are Doubles and `1.5d` a Decimal. The parser files every one of
    them as a real literal, so what a body produced has to be written back at the type the numeral
    it was written as has, and not at the one the node is named after.
    """

    def _call(self, body: str) -> str:
        return cleandoc(F"""
            function f {{ {body} }}
            $x = f
        """)

    def test_a_multiplier_suffix_is_written_back_as_the_integer_numeral_it_names(self):
        self.assertEqual(self._apply(self._call('1kb'), Ps1FunctionEvaluator), '$x = 1024')
        self.assertEqual(self._apply(self._call('2gb'), Ps1FunctionEvaluator), '$x = 2147483648L')
        self.assertEqual(self._apply(self._call('1kb + 1'), Ps1FunctionEvaluator), '$x = 1025')

    def test_a_numeral_5_1_reads_as_a_double_is_written_back_as_a_real_numeral(self):
        self.assertEqual(self._apply(self._call('1.5'), Ps1FunctionEvaluator), '$x = 1.5')
        self.assertEqual(self._apply(self._call('1e3'), Ps1FunctionEvaluator), '$x = 1000.0')
        self.assertEqual(self._apply(self._call('2.5kb'), Ps1FunctionEvaluator), '$x = 2560.0')

    def test_a_decimal_is_declined_rather_than_handed_back_as_a_double(self):
        self._assertUnchanged(cleandoc("""
            function f {
              1.5d
            }
            $x = f
        """), Ps1FunctionEvaluator)
        self._assertUnchanged(cleandoc("""
            1 | % {
              1.5d
            }
        """), Ps1ForEachPipeline)

    def test_a_block_reads_a_real_literal_exactly_as_a_function_body_does(self):
        self.assertEqual(self._apply('1 | % { 1kb }', Ps1ForEachPipeline), '1024')
        self.assertEqual(self._apply('1 | % { 2gb }', Ps1ForEachPipeline), '2147483648L')
        self.assertEqual(self._apply('1 | % { 1kb + 1 }', Ps1ForEachPipeline), '1025')
        self.assertEqual(self._apply('1 | % { 1.5 }', Ps1ForEachPipeline), '1.5')
        self.assertEqual(self._apply('1 | % { 1e3 }', Ps1ForEachPipeline), '1000.0')


class TestPs1AnEmulatedBodyAnswersWithTheHostsRulesAndNotWithPythons(TestPs1):
    """
    Each answer below is reached only through a body the tool emulates, and each turns on a rule 5.1
    follows and Python does not: a size string that Python's integer syntax reads and .NET's
    converter throws on, a Double written the way `str` writes it rather than the way .NET writes it,
    and a name the body never binds, whose value 5.1 takes from the caller so the fold is declined
    rather than read as the `$null` an isolated body would read.
    """

    def test_a_new_object_size_that_cannot_convert_folds_to_a_null_count_of_zero(self):
        # A size 5.1's converter refuses is a non-terminating error and not a throw, so `New-Object`
        # writes `$null` and the body runs on. `$null.Count` is 0 wherever strict mode is not armed,
        # which is the value the whole body folds to.
        for size in ['0b10', '0o10']:
            source = cleandoc(F"""
                function f {{
                  $a = New-Object byte[] '{size}'
                  $a.Count
                }}
                Write-Output (f)
            """)
            with self.subTest(size):
                self.assertEqual(self._deobfuscate(source), 'Write-Output 0')

    def test_the_null_count_a_bad_size_folds_to_is_withheld_under_strict_mode_version_two(self):
        # `Set-StrictMode -Version 2` turns the faked `$null.Count` into a statement-terminating
        # error, so the body 5.1 aborts must not fold to the 0 it answers without strict mode.
        source = cleandoc("""
            Set-StrictMode -Version 2
            function f {
              $a = New-Object byte[] '0b10'
              $a.Count
            }
            Write-Output (f)
        """)
        self._assertKept(source)

    def test_a_read_of_an_unset_name_in_a_body_is_withheld_under_strict_mode(self):
        # `Set-StrictMode` turns a read of a never-assigned variable into a statement-terminating
        # error, so a body 5.1 aborts must not fold to the value an isolated body reads `$q` as the
        # `$null` for. The faked-member gate above answers this for `$null.Count`; a plain unset read
        # is the same host rule and the emulator still folds it.
        source = cleandoc("""
            Set-StrictMode -Version 1
            function f {
              $q + 1
            }
            Write-Output (f)
        """)
        self._assertKept(source)

    def test_an_array_size_5_1_can_convert_is_folded_to_the_count_it_names(self):
        source = cleandoc("""
            function f {
              $a = New-Object byte[] 2
              $a.Count
            }
            Write-Output (f)
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output 2')

    def test_a_char_new_object_size_is_read_as_its_code_point_element_count(self):
        # `[char]65` is the code point 65, so `New-Object byte[] ([char]65)` builds a 65-element
        # array where an unreadable String size would fold to the count-of-zero of a `$null`.
        source = cleandoc("""
            function f {
              $a = New-Object byte[] ([char]65)
              $a.Count
            }
            Write-Output (f)
        """)
        self._assertDeobfuscatesTo(source, 'Write-Output 65')

    def test_a_double_becomes_the_text_5_1_writes_it_as(self):
        # A `[string]` of a double *literal* is folded by the value domain before emulation; a double
        # the body is handed reaches the interpreter's own coercion, which now writes the same
        # .NET-Framework text the value domain does — `1E+20` and `1E-07`, not Python's `str`.
        for numeral, text in [
            ('1E20', '1E+20'),
            ('0.0000001', '1E-07'),
            ('1.5E-7', '1.5E-07'),
        ]:
            source = cleandoc(F"""
                function f {{
                  $a = {numeral}
                  [string]$a
                }}
                Write-Output (f)
            """)
            with self.subTest(numeral):
                self.assertEqual(self._deobfuscate(source), F"Write-Output '{text}'")

    def test_a_double_in_a_current_culture_context_is_kept_not_folded(self):
        # The `[string]` cast is culture-invariant, so the text a Double casts to is one this unit can
        # write. Its interpolation and its `.ToString()` render with the *current* culture instead —
        # a decimal comma writes `1,5` where the cast writes `1.5` — which is a text no session pins,
        # so the body is left standing rather than folded to the one culture Python happens to write.
        for body in ['"$a"', '$a.ToString()']:
            with self.subTest(body):
                self._assertKept(F"""
                    function f {{
                      $a = 1E20
                      {body}
                    }}
                    Write-Output (f)
                """)

    def test_an_expression_over_a_name_the_body_does_not_bind_is_not_folded(self):
        # The script writes `$q`, so a body that reads it takes the caller's value 5.1 gives it and
        # not the `$null` an isolated fold would read: `$env:Temp + 1` is a concatenation, `5 + 1` is
        # `6` and not the `1` a `$null` reads, and a read before the body's own write reaches the
        # caller too. Every one of these is a fold the reader of `$q` was never entitled to take.
        for source in [
            cleandoc("""
                $q = $env:Temp
                function f {
                  $q + 1
                }
                Write-Output (f)
            """),
            cleandoc("""
                $q = 5
                function f {
                  $q + 1
                }
                Write-Output (f)
            """),
            cleandoc("""
                $q = 5
                function f {
                  $y = $q
                  $q = 1
                  $y
                }
                Write-Output (f)
            """),
            # `$variable:q` addresses the Variable provider drive, which is the variable namespace
            # itself, so it writes the script-scope `$q` the body reads exactly as the bare form does.
            cleandoc("""
                $variable:q = 5
                function f {
                  $q + 1
                }
                Write-Output (f)
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._deobfuscate(source), source)

    def test_an_expression_over_a_name_the_body_binds_itself_is_folded(self):
        source = cleandoc("""
            $q = $env:Temp
            function f {
              $q = 1
              $q + 1
            }
            Write-Output (f)
        """)
        self.assertEqual(self._deobfuscate(source), 'Write-Output 2')


class TestPs1RuntimeSurfacesThatAnswerTheSameInEverySession(TestPs1):
    """
    5.1 answers each of these the same way in every session: `New-Object` builds a zero filled
    array of the type its name spells, a call fills `$args` with what it was given, a .NET regular
    expression captures a group under a name that `-replace` substitutes and that `-match` leaves
    behind in `$Matches`, `-split` reads a limit as its second right operand, and a comparison
    operator written with a `c` or an `i` compares the way that letter names. Each is asked inside
    a function body, since a body is what the tool emulates.
    """

    def test_new_object_builds_a_byte_array_whose_elements_start_at_zero(self):
        source = cleandoc("""
            function f {
              $a = New-Object byte[] 1
              $a[0]
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), '$x = 0')

    def test_the_args_a_call_fills_count_the_arguments_it_was_given(self):
        source = cleandoc("""
            function f {
              ,$args
            }
            $t = f 1 2
            $x = $t.Count
        """)
        self.assertEqual(self._deobfuscate(source), '$x = 2')

    def test_a_named_group_is_substituted_under_the_name_it_was_captured_with(self):
        source = cleandoc("""
            function f {
              'abc' -replace '(?<x>b)', '[${x}]'
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'a[b]c'")

    def test_the_quoted_spelling_of_a_named_group_is_substituted_the_same_way(self):
        source = cleandoc("""
            function f {
              'abc' -replace "(?'x'b)", '[${x}]'
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'a[b]c'")

    def test_a_lookbehind_is_not_read_as_a_named_group(self):
        source = cleandoc("""
            function f {
              'aXb' -replace '(?<=a)X', 'Y'
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'aYb'")

    def test_a_named_backreference_matches_what_its_group_captured(self):
        source = cleandoc(r"""
            function f {
              'abab' -replace '(?<c>a)b\k<c>', 'Z'
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'Zb'")

    def test_a_match_leaves_the_group_it_captured_in_the_matches_variable(self):
        source = cleandoc("""
            function f {
              $null = 'abc' -match '(b)'
              $Matches[1]
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'b'")

    def test_the_zero_key_of_the_matches_variable_is_the_whole_match(self):
        source = cleandoc("""
            function f {
              $null = 'abc' -match 'a(b)c'
              $Matches[0]
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'abc'")

    def test_a_notmatch_that_finds_the_pattern_fills_the_matches_variable(self):
        source = cleandoc("""
            function f {
              $null = 'abc' -notmatch 'a(b)c'
              $Matches[1]
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'b'")

    def test_a_group_after_a_skipped_one_keeps_its_own_number_in_the_matches_variable(self):
        source = cleandoc("""
            function f {
              $null = 'ac' -match 'a(b)?(c)'
              $Matches[2]
            }
            $x = f
        """)
        self.assertEqual(self._deobfuscate(source), "$x = 'c'")

    def test_a_split_limit_leaves_the_rest_of_the_string_in_the_final_element(self):
        for split, tail, expected in [
            ("'a,b,c' -split ',', 2", '$a.Count', '$x = 2'),
            ("'a,b,c' -split ',', 2", '$a[1]', "$x = 'b,c'"),
            ("'a,b,c,d' -split ',', 2", '$a[1]', "$x = 'b,c,d'"),
            ("'a,b,c' -split ',', 5", '$a.Count', '$x = 3'),
        ]:
            source = cleandoc(F"""
                function f {{
                  $a = {split}
                  {tail}
                }}
                $x = f
            """)
            with self.subTest(F'{split} {tail}'):
                self.assertEqual(self._deobfuscate(source), expected)

    def test_a_case_prefix_on_a_string_comparison_compares_the_way_it_names(self):
        for comparison, expected in [
            ("'A' -ceq 'a'", '$False'),
            ("'A' -ieq 'a'", '$True'),
        ]:
            source = cleandoc(F"""
                function f {{
                  {comparison}
                }}
                $x = f
            """)
            with self.subTest(comparison):
                self.assertEqual(self._deobfuscate(source), F'$x = {expected}')

    def test_a_case_prefix_on_a_comparison_of_numbers_compares_them_all_the_same(self):
        """
        The prefix names how *text* is compared, so it makes no difference between two numbers —
        `-ceq` answers what `-eq` answers — and two Chars an ordering reads by their code points are
        numbers here too.
        """
        for comparison, expected in [
            ('1 -ceq 1', '$True'),
            ('1 -ine 1', '$False'),
            ('2 -cgt 1', '$True'),
            ('1 -ilt 2', '$True'),
            ('[char]97 -clt [char]66', '$False'),
            ('[char]65 -ilt [char]97', '$True'),
        ]:
            source = cleandoc(F"""
                function f {{
                  {comparison}
                }}
                $x = f
            """)
            with self.subTest(comparison):
                self.assertEqual(self._deobfuscate(source), F'$x = {expected}')


class TestPs1WhatAnOperatorInAnEmulatedBodyEvaluatesConvertsAndMatches(TestPs1):
    """
    Measured on 5.1, each asked inside a function body since a body is what the tool emulates.
    `-and` and `-or` never evaluate the operand they short circuit past. A collection is converted
    to a Boolean by its count, except that a collection of one takes the truthiness of the single
    element it holds. `-contains` converts the value it is given to the element's type before it
    compares. A backtick makes the wildcard behind it literal, and a wildcard set has no negation,
    `!` inside one being an ordinary character. `-band` converts a string by .NET's rules, which
    read no digit group separator and answer InvalidCastFromStringToInteger instead.
    """

    def test_an_increment_the_short_circuit_skips_never_happens(self):
        for condition in ['$false -and ($i++)', '$true -or ($i++)']:
            source = cleandoc(F"""
                function f {{
                  $i = 0
                  if ({condition}) {{ }}
                  $i
                }}
                $x = f
            """)
            with self.subTest(condition):
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = 0')

    def test_a_collection_of_one_is_as_true_as_the_single_element_it_holds(self):
        for element, expected in [
            ('0', 'no'),
            ('1', 'yes'),
            ("''", 'no'),
            ("'x'", 'yes'),
        ]:
            source = cleandoc(F"""
                function f {{
                  $a = @({element})
                  if ($a) {{ 'yes' }} else {{ 'no' }}
                }}
                $x = f
            """)
            with self.subTest(element):
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), F"$x = '{expected}'")

    def test_a_collection_of_two_is_true_however_its_elements_read(self):
        source = cleandoc("""
            function f {
              $a = @(0, 0)
              if ($a) { 'yes' } else { 'no' }
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'yes'")

    def test_contains_converts_the_value_it_is_given_to_the_elements_type(self):
        for comparison, expected in [
            ("@('1') -contains 1", '$x = $True'),
            ("@(1) -contains '1'", '$x = $True'),
            ("@('1') -contains 2", '$x = $False'),
            ("1 -in @('1')", '$x = $True'),
            ("@('1') -notcontains 1", '$x = $False'),
            ("@(1) -contains 'abc'", '$x = $False'),
        ]:
            source = cleandoc(F"""
                function f {{
                  {comparison}
                }}
                $x = f
            """)
            with self.subTest(comparison):
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), expected)

    def test_a_backticked_asterisk_matches_the_one_character_it_spells(self):
        source = cleandoc("""
            function f {
              'a*' -like 'a`*'
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = $True')

    def test_a_backticked_asterisk_matches_nothing_a_bare_one_would(self):
        source = cleandoc("""
            function f {
              'ab' -like 'a`*'
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = $False')

    def test_a_wildcard_set_reads_an_exclamation_mark_as_no_negation(self):
        source = cleandoc("""
            function f {
              'b' -like '[!a]'
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = $False')

    def test_a_string_band_cannot_convert_is_a_throw_and_not_a_number(self):
        self._assertUnchanged(cleandoc("""
            function f {
              '1_0' -band 15
            }
            $x = f
        """), Ps1FunctionEvaluator)

    def test_a_string_band_can_convert_is_the_number_the_digits_spell(self):
        source = cleandoc("""
            function f {
              '10' -band 15
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = 10')


class TestPs1AFoldedBodyAnswersWhereTheHostAnswersAndNowhereElse(TestPs1):
    """
    Each of these is reached only inside a function body, since a body is what the tool folds.
    `System.Char` has no instance `ToUpper` and no multiplication, and a cast throws where the value
    does not fit the type, so all three are a script that stopped rather than a value. The
    `IgnoreCase` that a case insensitive `-match` means is .NET's culture `ToLower`, under which
    U+017F is no `s`, where Python's own folding makes it one. A sum too long for the interpreter's
    stack has to leave the unit with an answer and not with a `RecursionError`. An index written as
    a String is an index like any other and 5.1 answers the element it numbers, but `$null` is no
    index at all and 5.1 stops there rather than reading the element a zero would name.
    """

    @staticmethod
    def _sum_of_ones(terms: int) -> str:
        """
        A body adding `terms` ones, spelled one term to a line. A source of more than forty lines is
        one the redirection corpus in `test.units.test_style` leaves whole rather than reissuing it
        line by line, which would put this same fold in front of the same stack there.
        """
        chain = ' +\n  '.join(['1'] * terms)
        return F'function f {{\n  {chain}\n}}\n$x = f'

    def test_a_toupper_call_on_a_char_is_a_throw_and_not_the_char_it_was_called_on(self):
        self._assertUnchanged(cleandoc("""
            function f {
              ([char]65).ToUpper()
            }
            $x = f
        """), Ps1FunctionEvaluator)

    def test_a_tostring_call_on_a_char_is_the_string_that_char_spells(self):
        source = cleandoc("""
            function f {
              ([char]65).ToString()
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'A'")

    def test_a_char_times_a_number_is_a_throw_and_not_a_repeated_string(self):
        self._assertUnchanged(cleandoc("""
            function f {
              [char]65 * 2
            }
            $x = f
        """), Ps1FunctionEvaluator)

    def test_a_char_plus_a_string_is_the_text_the_two_concatenate_to(self):
        source = cleandoc("""
            function f {
              [char]65 + 'B'
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'AB'")

    def test_a_char_coerced_to_an_integer_in_a_body_is_its_code_point(self):
        source = cleandoc("""
            function f($n) {
              [int][char]$n
            }
            $x = f 53
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = 53')

    def test_a_byte_cast_the_value_does_not_fit_is_a_throw_and_not_a_masked_number(self):
        for cast in ['[byte]400', '[byte](200 * 2)']:
            source = cleandoc(F"""
                function f {{
                  {cast}
                }}
                $x = f
            """)
            with self.subTest(cast):
                self._assertUnchanged(source, Ps1FunctionEvaluator)

    def test_a_byte_cast_the_value_fits_folds_at_its_own_width(self):
        source = cleandoc("""
            function f {
              [byte]200
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = [byte]200')

    @unittest.expectedFailure
    def test_a_long_s_matches_no_s_under_the_culture_casing_ignorecase_means(self):
        for operator in ['-match', '-cmatch']:
            source = cleandoc(F"""
                function f {{
                  'ſ' {operator} 's'
                }}
                $x = f
            """)
            with self.subTest(operator):
                self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = $False')

    def test_the_unit_folds_a_sum_of_two_thousand_ones_to_the_number_they_add_up_to(self):
        # Both sums go through the unit and not the helper: raising the recursion limit is the
        # unit's own doing, so where a fold over a body runs out of stack is measurable only there.
        self.assertEqual(self._sum_of_ones(2000).encode('utf8') | ps1() | str, '$x = 2000')

    def test_the_unit_answers_a_sum_too_long_to_fold_rather_than_crashing_on_it(self):
        try:
            bytes(self._sum_of_ones(5000).encode('utf8') | ps1())
        except RecursionError:
            self.fail('a RecursionError escaped the unit, which has to decline a fold instead')

    def test_an_index_written_as_a_string_is_the_element_that_number_names(self):
        source = cleandoc("""
            function f {
              $a = 10, 20, 30
              $a['1']
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = 20')

    def test_a_null_index_is_a_throw_and_not_the_element_a_zero_would_name(self):
        self._assertUnchanged(cleandoc("""
            function f {
              $a = 10, 20, 30
              $a[$null]
            }
            $x = f
        """), Ps1FunctionEvaluator)

    def test_an_index_written_as_a_number_is_the_element_that_number_names(self):
        source = cleandoc("""
            function f {
              $a = 10, 20, 30
              $a[1]
            }
            $x = f
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), '$x = 20')


class TestPs1AFunctionBodyReadsWhatTheScriptScopeHolds(TestPs1):
    """
    A function body that names a variable the script assigned reads that variable when the call
    runs. Windows PowerShell 5.1 prints `v=6` for the script below, whose value comes from a command
    no fold can predict, so the call is left standing rather than folded as if `$g` were unset — and
    the store that feeds it survives with it.
    """

    def test_a_call_is_not_folded_as_if_the_script_variable_were_unset(self):
        result = self._deobfuscate(cleandoc(
            """
            $g = Get-Random -Minimum 5 -Maximum 6
            function zzqf { $g + 1 }
            Write-Host ('v=' + (zzqf))
            """
        ))
        self.assertEqual(result, cleandoc(
            """
            $g = Get-Random -Minimum 5 -Maximum 6
            function zzqf {
              $g + 1
            }
            Write-Host ('v=' + (zzqf))
            """
        ))


class TestPs1AFoldedCallKeepsItsPipelinePosition(TestPs1):
    """
    Only the first element of a pipeline may be an expression, so substituting a function's constant
    result into any later element writes a script 5.1 refuses with `ExpressionsMustBeFirstInPipeline`.
    Measured, the input prints `r=H` and the output runs nothing at all.
    """

    def test_a_function_in_a_later_pipeline_element_is_not_replaced_by_its_value(self):
        result = self._deobfuscate(cleandoc(
            """
            function zzqf { 'H' }
            $r = 'x' | zzqf
            Write-Host ('r=' + $r)
            """
        ))
        self.assertNotIn("| 'H'", result)
