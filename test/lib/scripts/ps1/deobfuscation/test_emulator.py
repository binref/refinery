from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import (
    Ps1ForEachPipeline,
    Ps1FunctionEvaluator,
)


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
            "Function R ([String]$s){"
            "$a = $s.ToCharArray(); $r = '';"
            "ForEach($c in $a){$r = $c + $r};"
            "$r;}"
            "$x = R 'olleH'\nWrite-Output $x"
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
            "Function R ([String]$s){"
            "$r = '';"
            "For($i=0; $i -lt $s.Length; $i+=2){"
            "$r = $r + $s.Substring($i, 1)"
            "}; return $r;}"
            "$x = R 'HxExLxLxOx'\nWrite-Output $x"
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
        self.assertIn('Hello', result)

    def test_foreach_pipeline_negative_integers(self):
        data = "((-83,-71,-65,-75,-107,-70,-75,-64,-110,-83,-75,-72,-79,-80) | %{ [char]($_ + 180) }) -join ''"
        result = self._deobfuscate(data)
        self.assertIn('amsiInitFailed', result)

    def test_foreach_pipeline_mixed_sign_integers(self):
        data = "(-4, 1, -17) | %{ [char]($_ + 104) }"
        result = self._deobfuscate(data)
        self.assertIn('d', result)
        self.assertIn('i', result)
        self.assertIn('W', result)

    def test_foreach_pipeline_expandable_string_hex_decode(self):
        data = "'46 75 6E' -split ' ' | %{[char][byte]\"0x$_\"}"
        result = self._deobfuscate(data)
        self.assertIn('Fun', result)

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
        self.assertIn('A', result)
        self.assertIn('B', result)


class TestPs1EmulatorExtra(TestPs1):

    def test_cast_wrapped_array_pipeline(self):
        result = self._deobfuscate(
            "[String]([Char[]] (72,101,108,108,111) | "
            "ForEach-Object { [Char]($_ -BXor 0) })")
        self.assertIn('Hello', result)

    def test_char_array_xor_pipeline(self):
        result = self._deobfuscate("[String]([Char[]] (127,78,88,95) | % { [Char]($_ -BXor 0x2B) })")
        self.assertIn('Test', result)

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
        # $PSItem resolves like $_; the single-character results collapse to a joined string.
        result = self._apply("(97,98,99) | % { [char]$PSItem }", Ps1ForEachPipeline)
        self.assertEqual(result, "'abc'")

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
