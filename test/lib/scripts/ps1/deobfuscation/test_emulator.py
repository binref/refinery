from __future__ import annotations

from inspect import cleandoc

from test import backlog, todo, wontfix
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
from refinery.units.scripting.dps1 import dps1

INT32 = 'System.Int32'


def _boolean_cell(operator: str, right: str) -> data.OperatorOutcome:
    cell = data.binary_outcome(operator, 'System.Boolean', right)
    if cell is None:
        raise KeyError(F'the grid has no cell for a Boolean {operator} {right}')
    return cell


def _char_cell(operator: str, right: str) -> data.OperatorOutcome:
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

    def test_a_call_of_a_function_defined_alone_in_a_guarded_body_is_folded(self):
        source = """
            try {
              function f { 'a' }
            } catch {
              Write-Host 'caught'
            }
            Write-Host (f)
        """
        definition_kept = """
            try {
              function f { 'a' }
            } catch {
              Write-Host 'caught'
            }
            Write-Host 'a'
        """
        self._assertDeobfuscatesToOneOf(source, definition_kept, "Write-Host 'a'")

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
        self.assertIn("Write-Output 'Hello'", result)

    def test_iex_trampoline_function(self):
        data = (
            'function Wrapper { Param([string]$code); Invoke-Expression $code > $Null 2> $Null }\n'
            'function Builder { Param([string]$a, [string]$b); $r = $a + $b; Wrapper "$r" }\n'
            'Builder -a "Write-Host " -b "Hello"'
        )
        self.assertEqual(self._deobfuscate(data), 'Write-Host Hello')

    def test_iex_of_a_variable_the_caller_holds_yields_its_text_and_runs_nothing(self):
        source = cleandoc("""
            function W { Invoke-Expression '$r' }
            function B { $r = 'Write-Host Hello'; W }
            B
        """)
        self._assertDeobfuscatesToOneOf(source, source, "'Write-Host Hello'")

    def test_iex_of_a_local_variable_is_not_moved_out_of_its_function(self):
        source = """
            function B { $r = 'x'; Invoke-Expression '$r' }
            Write-Host (B)
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'x'", 'Write-Host x')

    def test_iex_of_a_local_variable_read_by_name_is_not_moved_out_of_its_function(self):
        source = """
            function B { $r = 'x'; Invoke-Expression '(Get-Variable r).Value' }
            $r = 'caller'
            Write-Host (B)
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'x'")

    def test_iex_calling_a_function_that_reads_a_local_is_not_moved_out_of_its_function(self):
        source = """
            function show { Write-Host $r }
            function W { $r = 'inner'; Invoke-Expression 'show' }
            $r = 'outer'
            W
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            function show { Write-Host $r }
            function W { $r = 'inner'; show }
            $r = 'outer'
            W
        """)

    def test_iex_joining_an_array_is_not_moved_away_from_the_separator_its_function_sets(self):
        source = """
            function B { $OFS = '-'; Invoke-Expression 'Write-Host ([string](1, 2))' }
            B
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            function B { $OFS = '-'; Write-Host ([string](1, 2)) }
            B
        """, "Write-Host '1-2'")

    def test_iex_trampoline_that_returns_what_the_iex_writes(self):
        self._assertDeobfuscatesTo("""
            function W { Param([string]$c); return Invoke-Expression $c }
            W 'Write-Host hi'
        """, 'Write-Host hi')

    def test_iex_trampoline_that_discards_a_value_first(self):
        self._assertDeobfuscatesTo("""
            function W { Param([string]$c); $null = $c.Length; Invoke-Expression $c }
            W 'Write-Host hi'
        """, 'Write-Host hi')

    @backlog
    def test_iex_trampoline_that_discards_the_output_keeps_discarding_it(self):
        source = """
            function W { Param([string]$c); Invoke-Expression $c > $Null }
            W 'Write-Output 1'
        """
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Output 1 > $Null', '$Null = Write-Output 1', '')

    def test_iex_whose_result_its_function_goes_on_to_use_is_not_the_value_of_the_call(self):
        source = """
            function f { $r = Invoke-Expression '1 + 1'; $r * 2 }
            Write-Host (f)
        """
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Host 4')

    def test_iex_trampoline_whose_payload_assigns_keeps_the_payload_in_a_scope_of_its_own(self):
        result = self._deobfuscate(cleandoc("""
            function W { Param([string]$c); Invoke-Expression $c }
            $u = 'caller'
            W '$u = "http://x/y"; Write-Host $u'
            Write-Host $u
        """))
        self.assertIn('http://x/y', result)
        self.assertNotIn("W '", result)
        self.assertIn("Write-Host 'caller'", result)

    def test_a_dot_sourced_call_writes_the_scope_of_its_caller(self):
        source = """
            function C { $q = 'x' }
            function B { . C; "[$q]" }
            Write-Host (B)
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host '[x]'")

    def test_a_dot_sourced_call_keeps_what_the_function_writes(self):
        source = """
            function f { $q = 'x'; 'r' }
            . f
            Write-Host "[$q]"
        """
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host '[x]'")

    def test_a_dot_sourced_trampoline_keeps_the_parameter_it_binds(self):
        source = """
            function W { Param([string]$c); Invoke-Expression $c }
            . W 'Write-Host hi'
            Write-Host "[$c]"
        """
        self._assertDeobfuscatesToOneOf(source, source, """
            Write-Host hi
            Write-Host '[Write-Host hi]'
        """)

    def test_iex_reading_a_local_through_a_session_state_it_keeps_is_not_moved_out(self):
        source = """
            function B { Param($c); $r = 'x'; Invoke-Expression $c }
            $r = 'caller'
            B '$v = $ExecutionContext.SessionState.PSVariable; Write-Host $v.GetValue(''r'')'
        """
        self._assertDeobfuscatesToOneOf(source, source)

    @wontfix('a working script does not call a function from outside the block that defines it')
    def test_a_function_defined_in_a_block_is_not_known_outside_it(self):
        source = """
            & { function g { 'in' } }
            Write-Host (g)
        """
        self._assertDeobfuscatesToOneOf(source, source)

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
        result = self._apply("function g { $r = 'hidden' }; $y = g", Ps1FunctionEvaluator)
        self.assertEqual(result, cleandoc("""
            function g {
              $r = 'hidden'
            }
            $y = g
        """))

    def test_emulated_shift_uses_int32_semantics(self):
        result = self._apply(
            'function f ($n) { $n -shl 32 }\n$x = f 1', Ps1FunctionEvaluator)
        self.assertIn('$x = 1', result)
        self.assertNotIn('4294967296', result)

    def test_foreach_pipeline_yields_array_not_joined_string(self):
        result = self._apply("('foo','bar' | %{ $_ })[1]", Ps1ForEachPipeline)
        self.assertEqual(result, "('foo', 'bar')[1]")

    def test_nested_function_reads_enclosing_scope(self):
        result = self._apply(
            "function A { $g = 'X'; B } function B { C } function C { return $g }; $o = A",
            Ps1FunctionEvaluator)
        self.assertIn("$o = 'X'", result)

    def test_compound_assignment_does_not_read_enclosing_scope(self):
        # On 5.1, `$acc += 'C'` reads only the local scope, so it starts from `$null` and not from
        # the caller's `'AB'`.
        result = self._apply(
            "function A { $acc = 'AB'; B } function B { $acc += 'C'; return $acc }; $o = A",
            Ps1FunctionEvaluator)
        self.assertEqual(result, "$o = 'C'")

    def test_psitem_is_pipeline_item(self):
        result = self._apply('(97,98,99) | % { [char]$PSItem }', Ps1ForEachPipeline)
        self.assertEqual(result, '[char]97, [char]98, [char]99')

    def test_foreach_over_string_is_scalar(self):
        result = self._apply(
            "function f($s){ $n = 0; foreach($c in $s){ $n = $n + 1 }; return $n }; $r = f 'abc'",
            Ps1FunctionEvaluator)
        self.assertEqual(result, '$r = 1')

    def test_iex_in_foreach_pipeline_does_not_crash(self):
        result = self._deobfuscate("('calc','notepad') | % { iex $_ }")
        self.assertEqual(result, cleandoc("""
            ('calc', 'notepad') | ForEach-Object {
              Invoke-Expression $_
            }
        """))

    def test_recursive_function_does_not_crash(self):
        result = self._deobfuscate("function f($x){ f $x }; f 1")
        self.assertEqual(result, cleandoc("""
            function f {
              Param($x)
              f $x
            }
            f 1
        """))

    def test_a_loop_exit_with_no_loop_around_it_is_refused_rather_than_raised(self):
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
        parsed = Ps1Parser('$(if(1){break})').parse()
        condition = parsed.body[0].expression
        self.assertIsNone(evaluate_truthy(condition, {}))

    def test_a_redirected_call_is_not_folded_into_its_value(self):
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
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > C:\\o.txt
              'V'
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)

    def test_a_body_discarding_to_null_is_still_folded(self):
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > $Null
              'V'
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "$x = 'V'")

    def test_a_call_to_a_function_that_emitted_nothing_goes_with_its_definition(self):
        source = cleandoc("""
            function Silent {
              Invoke-Expression ''
            }
            Silent
            Write-Host 'after'
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), "Write-Host 'after'")

    def test_an_exported_definition_is_not_removed_after_its_calls_are_folded(self):
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
        self.assertEqual(
            self._apply("function f { 'FOLDED' }\n$x = f", Ps1FunctionEvaluator),
            "$x = 'FOLDED'",
        )


class TestPs1ACallBelowCodeNobodyCanReadIsFoldedOnlyWhereThatCodeIsTrusted(TestPs1):

    _OPENERS = ('Invoke-Expression $code', '& $dispatch')

    @todo
    def test_a_call_below_an_unreadable_payload_leaves_the_script_as_written(self):
        for opener in self._OPENERS:
            with self.subTest(opener):
                self._assertKept(F"""
                    {opener}
                    function f {{ 'FOLDED' }}
                    Write-Host (f)
                """)

    def test_a_call_below_a_trusted_payload_is_folded_and_its_definition_removed(self):
        for opener in self._OPENERS:
            with self.subTest(opener):
                self._assertDeobfuscatesTo(
                    F"""
                        {opener}
                        function f {{ 'FOLDED' }}
                        Write-Host (f)
                    """,
                    F"""
                        {opener}
                        Write-Host 'FOLDED'
                    """,
                    trust_eval=True,
                )


class TestPs1AnArgumentIsFoldedOnlyWhereItsTypeSurvivesTheInterpreter(TestPs1):

    def _identity_call(self, argument: str) -> str:
        return cleandoc(F"""
            function f {{
              Param($n)
              $n
            }}
            $x = f {argument}
        """)

    def test_a_numeral_written_wider_than_its_magnitude_is_not_bound_as_a_narrower_one(self):
        source = self._identity_call('1L')
        self.assertIn(self._apply(source, Ps1FunctionEvaluator), (source, '$x = 1L'))
        self.assertEqual(self._apply(self._identity_call('1'), Ps1FunctionEvaluator), '$x = 1')

    def test_a_numeral_written_at_the_width_its_magnitude_takes_is_bound(self):
        self.assertEqual(
            self._apply(self._identity_call('2147483648L'), Ps1FunctionEvaluator),
            '$x = 2147483648L',
        )

    def test_a_width_cast_is_not_bound_as_the_numeral_written_inside_it(self):
        for argument, folded in [
            ('([byte]5)', '$x = [byte]5'),
            ('([uint32]7)', '$x = [uint32]7'),
        ]:
            with self.subTest(argument):
                source = self._identity_call(argument)
                self.assertIn(self._apply(source, Ps1FunctionEvaluator), (source, folded))
        self.assertEqual(self._apply(self._identity_call('(5)'), Ps1FunctionEvaluator), '$x = 5')

    def test_a_char_is_not_bound_as_the_string_that_carries_the_same_character(self):
        source = self._identity_call('([char]65)')
        self.assertIn(self._apply(source, Ps1FunctionEvaluator), (source, '$x = [char]65'))
        self.assertEqual(self._apply(self._identity_call("'A'"), Ps1FunctionEvaluator), "$x = 'A'")

    def test_a_boolean_is_bound_and_handed_back_as_the_boolean_it_is(self):
        self.assertEqual(
            self._apply(self._identity_call('$true'), Ps1FunctionEvaluator), '$x = $True')
        self.assertEqual(self._apply('$true | % { $_ }', Ps1ForEachPipeline), '$True')

    def test_a_pipeline_source_keeps_the_type_a_parameter_keeps(self):
        for source, folded in [
            (
                cleandoc("""
                    [byte]5 | % {
                      $_
                    }
                """),
                '[byte]5',
            ),
            (
                cleandoc("""
                    ([char]65) | % {
                      $_
                    }
                """),
                '[char]65',
            ),
        ]:
            with self.subTest(source):
                self.assertIn(self._apply(source, Ps1ForEachPipeline), (source, folded))
        self.assertEqual(self._apply('5 | % { $_ }', Ps1ForEachPipeline), '5')


class TestPs1AHexadecimalArgumentDenotesThePatternItFills(TestPs1):

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

    def test_a_block_handing_out_an_array_per_item_is_not_one_handing_out_two_values(self):
        self.assertEqual(self._apply('@(1, 2) | % { $_, $_ }', Ps1ForEachPipeline), '1, 1, 2, 2')
        self.assertEqual(
            self._apply('@(1, 2) | % { ,($_, $_) }', Ps1ForEachPipeline), '(1, 1), (2, 2)')

    def test_a_source_of_one_item_whose_block_hands_out_one_value_folds_to_that_value(self):
        self.assertEqual(self._apply("@('a') | % { $_ }", Ps1ForEachPipeline), "'a'")


class TestPs1AReturnWritesTheStreamTheExpressionAloneWrites(TestPs1):

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
        result = self._apply(
            "function F { 'V' }\n$x = F\nF > C:\\o.txt", Ps1FunctionEvaluator)
        self.assertIn('function F', result)
        self.assertIn("$x = 'V'", result)

    def test_a_redirecting_call_to_a_function_that_emitted_nothing_is_kept(self):
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
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 4 > $Null
              $a.Length
            }
            $x = F
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)

    def test_a_body_whose_expression_opens_a_file_is_not_folded_into_its_value(self):
        source = cleandoc("""
            function G {
              Param([int]$n)
              $v = ($n + 1) > C:\\o.txt
              'V'
            }
            $x = G 5
        """)
        self.assertEqual(self._apply(source, Ps1FunctionEvaluator), source)

    def test_a_discard_behind_an_expression_stores_the_zero_a_byte_slot_makes_of_null(self):
        source = cleandoc("""
            function F {
              $a = New-Object byte[] 2
              $a[0] = 65
              $a[1] = 66
              $a[1] = ($a[1] -bxor 1) > $Null
              [String][System.Text.Encoding]::ASCII.GetString($a)
            }
            $x = F
        """)
        self.assertIn(self._apply(source, Ps1FunctionEvaluator), (source, '$x = "A`0"'))

    def test_a_merge_on_the_value_an_assignment_takes_leaves_the_value_in_it(self):
        self.assertEqual(
            self._apply(cleandoc("""
                function G {
                  $v = (5 + 1) 2>&1
                  "v=$v"
                }
                $x = G
            """), Ps1FunctionEvaluator),
            "$x = 'v=6'",
        )


class TestPs1APipelineSourceIsWhatTheCastAroundItMakesOfIt(TestPs1):

    def test_a_cast_that_decides_how_many_items_there_are_is_not_read_past(self):
        source = cleandoc("""
            [char[]]'ab' | % {
              $_
            }
        """)
        self.assertIn(self._apply(source, Ps1ForEachPipeline), (source, '[char]97, [char]98'))

    def test_a_cast_that_decides_what_the_items_are_worth_is_not_read_past(self):
        for source, folded in [
            (
                cleandoc("""
                    [int[]]('1', '2') | % {
                      $_ + 1
                    }
                """),
                '2, 3',
            ),
            (
                cleandoc("""
                    [string[]](1, 2) | % {
                      $_ + 1
                    }
                """),
                "'11', '21'",
            ),
        ]:
            with self.subTest(source):
                self.assertIn(self._apply(source, Ps1ForEachPipeline), (source, folded))

    def test_a_cast_the_numbers_written_inside_it_already_answer_is_still_folded(self):
        self.assertEqual(
            self._apply('[Char[]](72, 73) | % { [char]($_ -bxor 0) }', Ps1ForEachPipeline),
            '[char]72, [char]73',
        )


class TestPs1AnArrayCastAnElementDoesNotFitIsAThrowAndNotARename(TestPs1):

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

    @backlog
    def test_a_pipeline_over_a_cast_every_element_fits_hands_on_the_element_type(self):
        for source, folded in [
            ('[byte[]](5, 6) | % { $_ }', '[byte]5, [byte]6'),
            ('[byte[]](255, 1) | % { $_ }', '[byte]255, [byte]1'),
        ]:
            with self.subTest(source):
                self.assertIn(
                    self._apply(source, Ps1ForEachPipeline), (self._apply(source), folded)
                )


class TestPs1AnArrayCastToATypeThatDoesNotResolveRunsNoBlock(TestPs1):

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
            'uint16',
        ]:
            with self.subTest(spelling):
                self.assertEqual(
                    self._apply(F'[{spelling}[]](1, 2) | % {{ $_ + 1 }}', Ps1ForEachPipeline),
                    '2, 3',
                )

    @backlog
    def test_a_sum_over_a_64_bit_element_is_an_int64(self):
        for spelling in ['int64', 'long']:
            with self.subTest(spelling):
                self.assertEqual(
                    self._apply(F'[{spelling}[]](1, 2) | % {{ $_ + 1 }}', Ps1ForEachPipeline),
                    '2L, 3L',
                )

    @backlog
    def test_a_sum_over_an_unsigned_32_or_64_bit_element_keeps_the_element_type(self):
        for spelling in ['uint32', 'uint64']:
            with self.subTest(spelling):
                source = F'[{spelling}[]](1, 2) | % {{ $_ + 1 }}'
                self.assertIn(
                    self._apply(source, Ps1ForEachPipeline),
                    (self._apply(source), F'[{spelling}]2, [{spelling}]3'),
                )

    @todo
    def test_a_sum_over_a_char_element_appends_the_number_as_text(self):
        source = '[char[]](1, 2) | % { $_ + 1 }'
        self.assertIn(
            self._apply(source, Ps1ForEachPipeline), (self._apply(source), "'\x011', '\x021'")
        )


class TestPs1ANullWrittenAmongThePipelineSourceIsOneOfItsItems(TestPs1):

    def test_a_null_between_two_numbers_is_not_dropped_from_the_source(self):
        source = '1, $null, 2 | % { $_ }'
        self.assertIn(
            self._apply(source, Ps1ForEachPipeline),
            (self._apply(source), '1, $Null, 2'),
        )

    def test_a_source_of_numbers_alone_is_still_folded(self):
        self.assertEqual(self._apply('1, 2 | % { $_ }', Ps1ForEachPipeline), '1, 2')


class TestPs1WhichSideOfWhichOperatorABooleanMayStandOn(TestPs1):

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
        operators = list(data._OPERATORS['binary'])
        self.assertEqual(len(operators), 63)
        self.assertEqual(
            {operator for operator in operators if _boolean_cell(operator, INT32).always_throws},
            set(_NO_OPERATOR_METHOD_ON_BOOLEAN),
        )

    def test_the_boolean_row_reaches_past_the_int32_the_refusal_is_pinned_to(self):
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
        operators = list(data._OPERATORS['binary'])
        self.assertEqual(len(operators), 63)
        self.assertEqual(
            {operator for operator in operators if _char_cell(operator, INT32).always_throws},
            set(_NO_OPERATOR_METHOD_ON_CHAR),
        )


class TestPs1AHexadecimalNumeralInsideABodyDenotesThePatternItFills(TestPs1):

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

    def test_a_decimal_is_not_handed_back_as_a_double(self):
        body = cleandoc("""
            function f {
              1.5d
            }
            $x = f
        """)
        self.assertIn(self._apply(body, Ps1FunctionEvaluator), (body, '$x = 1.5d'))
        block = cleandoc("""
            1 | % {
              1.5d
            }
        """)
        self.assertIn(self._apply(block, Ps1ForEachPipeline), (block, '1.5d'))

    def test_a_block_reads_a_real_literal_exactly_as_a_function_body_does(self):
        self.assertEqual(self._apply('1 | % { 1kb }', Ps1ForEachPipeline), '1024')
        self.assertEqual(self._apply('1 | % { 2gb }', Ps1ForEachPipeline), '2147483648L')
        self.assertEqual(self._apply('1 | % { 1kb + 1 }', Ps1ForEachPipeline), '1025')
        self.assertEqual(self._apply('1 | % { 1.5 }', Ps1ForEachPipeline), '1.5')
        self.assertEqual(self._apply('1 | % { 1e3 }', Ps1ForEachPipeline), '1000.0')


class TestPs1AnEmulatedBodyAnswersWithTheHostsRulesAndNotWithPythons(TestPs1):

    def test_a_new_object_size_that_cannot_convert_folds_to_a_null_count_of_zero(self):
        # On 5.1, a size `New-Object` cannot convert is a non-terminating error: `$a` is `$null` and
        # the body runs on.
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
        source = cleandoc("""
            function f {
              $a = New-Object byte[] ([char]65)
              $a.Count
            }
            Write-Output (f)
        """)
        self._assertDeobfuscatesTo(source, 'Write-Output 65')

    def test_a_double_becomes_the_text_5_1_writes_it_as(self):
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

    def test_a_double_rendered_by_its_own_to_string_is_kept_not_folded(self):
        self._assertKept("""
            function f {
              $a = 1E20
              $a.ToString()
            }
            Write-Output (f)
        """)

    def test_a_double_interpolated_into_a_string_is_the_text_the_cast_writes(self):
        source = cleandoc("""
            function f {
              $a = 1E20
              "$a"
            }
            Write-Output (f)
        """)
        self._assertDeobfuscatesToOneOf(source, source, "Write-Output '1E+20'")

    def test_an_expression_over_a_caller_value_no_fold_can_know_is_not_folded(self):
        source = cleandoc("""
            $q = $env:Temp
            function f {
              $q + 1
            }
            Write-Output (f)
        """)
        self.assertEqual(self._deobfuscate(source), source)

    def test_an_expression_over_a_name_the_body_does_not_bind_reads_the_callers_value(self):
        for source, folded in [
            (
                cleandoc("""
                    $q = 5
                    function f {
                      $q + 1
                    }
                    Write-Output (f)
                """),
                'Write-Output 6',
            ),
            (
                cleandoc("""
                    $q = 5
                    function f {
                      $y = $q
                      $q = 1
                      $y
                    }
                    Write-Output (f)
                """),
                'Write-Output 5',
            ),
            (
                cleandoc("""
                    $variable:q = 5
                    function f {
                      $q + 1
                    }
                    Write-Output (f)
                """),
                'Write-Output 6',
            ),
        ]:
            with self.subTest(source):
                self._assertDeobfuscatesToOneOf(source, source, folded)

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
        for comparison, expected in [
            ('1 -ceq 1', '$True'),
            ('1 -ine 1', '$False'),
            ('2 -cgt 1', '$True'),
            ('1 -ilt 2', '$True'),
            # 5.1 orders two Chars by their code points and not as text.
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

    @staticmethod
    def _sum_of_ones(terms: int) -> str:
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

    @wontfix(
        'neither an obfuscator nor a script author matches a letter like the long s or the Kelvin '
        'sign against its ASCII look-alike'
    )
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
        self.assertEqual(self._sum_of_ones(2000).encode('utf8') | dps1() | str, '$x = 2000')

    def test_the_unit_answers_a_sum_too_long_to_fold_rather_than_crashing_on_it(self):
        try:
            bytes(self._sum_of_ones(5000).encode('utf8') | dps1())
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

    def test_a_function_in_a_later_pipeline_element_is_not_replaced_by_its_value(self):
        result = self._deobfuscate(cleandoc(
            """
            function zzqf { 'H' }
            $r = 'x' | zzqf
            Write-Host ('r=' + $r)
            """
        ))
        self.assertNotIn("| 'H'", result)
