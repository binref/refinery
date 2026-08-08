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
        # The other three unknowns `is_readable` carries are risks this pass takes deliberately, so
        # gating on the whole verdict would stop it resolving the `iex` trampolines above. Only the
        # export withholds.
        for opener in ('', 'Invoke-Expression $code\n', '& $dispatch\n'):
            with self.subTest(opener or '(closed world)'):
                result = self._apply(
                    F"{opener}function f {{ 'FOLDED' }}\n$x = f", Ps1FunctionEvaluator)
                self.assertNotIn('function f', result)
                self.assertIn("$x = 'FOLDED'", result)


class TestPs1EmulatorRedirections(TestPs1):

    def test_a_redirected_foreach_pipeline_is_not_folded_into_its_value(self):
        self._assertUnchanged(
            "@('a', 'b') | ForEach-Object {\n  $_\n} > C:\\o.txt", Ps1ForEachPipeline)

    def test_a_merge_on_a_foreach_pipeline_is_refused_too(self):
        self._assertUnchanged(
            "@('a', 'b') | ForEach-Object {\n  $_\n} 2>&1", Ps1ForEachPipeline)

    def test_an_unredirected_foreach_pipeline_is_still_folded(self):
        self.assertEqual(
            self._apply("@('a', 'b') | ForEach-Object { $_ }", Ps1ForEachPipeline), "'ab'")

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
