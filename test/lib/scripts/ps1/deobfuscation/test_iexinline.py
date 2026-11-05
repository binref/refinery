from __future__ import annotations

import inspect

from test import blocker, opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1IexInlining


class TestPs1InvokeScriptInlining(TestPs1):

    def test_invoke_script_basic(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.InvokeScript('Write-Host hello')"
        )
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('InvokeScript', result)

    def test_invoke_script_concat(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.InvokeScript('Write' + '-Host hi')"
        )
        self.assertIn('Write-Host', result)
        self.assertNotIn('InvokeScript', result)

    def test_invoke_script_case_insensitive(self):
        result = self._deobfuscate(
            "$executioncontext.invokecommand.invokescript('Write-Host test')"
        )
        self.assertIn('Write-Host', result)
        self.assertNotIn('invokescript', result.lower())


class TestPs1InvokeCommandInlining(TestPs1):

    def test_scriptblock_literal(self):
        result = self._deobfuscate('Invoke-Command -ScriptBlock { Write-Host hello }')
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Command', result)

    def test_icm_alias(self):
        result = self._deobfuscate('icm -ScriptBlock { Write-Host test }')
        self.assertIn('Write-Host', result)
        self.assertNotIn('icm', result.lower())

    def test_remoting_not_inlined(self):
        result = self._deobfuscate(
            'Invoke-Command -ComputerName server -ScriptBlock { Get-Process }'
        )
        self.assertIn('Invoke-Command', result)

    @blocker
    def test_an_assignment_in_the_block_does_not_reach_the_variable_of_the_caller(self):
        source = "$x = 'a'\nInvoke-Command -ScriptBlock { $x = 'b' }\nWrite-Host $x"
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'a'")

    @blocker
    def test_a_return_in_the_block_ends_only_the_block(self):
        source = "Invoke-Command -ScriptBlock { return }\nWrite-Host 'after'"
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'after'")

    @blocker
    def test_the_argument_list_binds_to_the_parameters_of_the_block(self):
        source = 'Invoke-Command -ScriptBlock { param($a) Write-Host $a } -ArgumentList 5'
        self._assertDeobfuscatesToOneOf(source, source, 'Write-Host 5')


class TestPs1IexInlining(TestPs1):

    def test_iex_single_statement(self):
        result = self._deobfuscate("IEX 'Write-Host hello'")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result.upper().split('WRITE')[0])

    def test_iex_multi_statement(self):
        result = self._deobfuscate("IEX '$a = 1; $b = 2'")
        self.assertIn('$a = 1', result)
        self.assertIn('$b = 2', result)
        self.assertNotIn('IEX', result)

    def test_iex_variable_not_inlined(self):
        result = self._deobfuscate('IEX $var')
        self.assertIn('Invoke-Expression', result)
        self.assertIn('$var', result)

    def test_iex_after_constant_inlining(self):
        result = self._deobfuscate("$x = 'Write-Host hi'; IEX $x")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('$x', result)

    def test_iex_inside_function_body(self):
        data = (
            "function F {\n"
            "IEX '$y = 42'\n"
            "}\n"
        )
        result = self._deobfuscate(data)
        self.assertIn('$y = 42', result)
        self.assertNotIn('IEX', result)

    def test_invoke_expression_long_form(self):
        result = self._deobfuscate("Invoke-Expression 'Write-Host hello'")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_piped_string(self):
        result = self._deobfuscate("'Write-Host hello' | IEX")
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('|', result)

    def test_iex_piped_variable_not_inlined(self):
        result = self._deobfuscate('$var | IEX')
        self.assertIn('Invoke-Expression', result)
        self.assertIn('$var', result)

    def test_invoke_expression_piped_long_form(self):
        result = self._deobfuscate("'Write-Host hello' | Invoke-Expression")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('|', result)

    def test_iex_piped_deflate_pipeline(self):
        b64 = 'Cy/KLEnV9cgvLlHISM3JyQcA'
        data = (
            "(New-Object IO.Compression.DeflateStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            " [IO.Compression.CompressionMode]::Decompress)"
            " | %{ New-Object System.IO.StreamReader($_, [Text.Encoding]::ASCII) }"
            " | %{ $_.ReadToEnd() })"
            " | Invoke-Expression"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('FromBase64String', result)

    def test_iex_expression_position_inlined(self):
        result = self._deobfuscate("$x = Invoke-Expression \"'hello'\"")
        self.assertIn("$x = 'hello'", result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_of_two_statements_in_a_value_slot_assigns_both_values(self):
        source = "$x = Invoke-Expression \"'a'; 'b'\"\nWrite-Host $x"
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            "$x = 'a', 'b'\nWrite-Host $x",
            "Write-Host ('a', 'b')",
        )

    def test_iex_via_env_comspec_indexing(self):
        data = "& ($env:ComSpec[4,26,25] -Join '') 'Write-Host hello'"
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('ComSpec', result)

    def test_iex_piped_via_env_comspec(self):
        data = "'Write-Host hello' | & ($env:ComSpec[4,26,25] -Join '')"
        result = self._deobfuscate(data)
        self.assertNotIn('ComSpec', result)
        self.assertIn('Write-Host', result)
        self.assertIn('hello', result)

    def test_iex_deflate_byte_array(self):
        data = (
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.DeflateStream("
            "[IO.MemoryStream]@("
            "0x0B, 0x2F, 0xCA, 0x2C, 0x49, 0xD5, 0xF5, 0xC8,"
            " 0x2F, 0x2E, 0x51, 0xC8, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00),"
            " [IO.Compression.CompressionMode]::Decompress)),"
            " [Text.Encoding]::ASCII)).ReadToEnd() | IEX"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('IEX', result)
        self.assertNotIn('DeflateStream', result)

    def test_scriptblock_create_ampersand(self):
        result = self._deobfuscate("&([scriptblock]::Create('Write-Host hello'))")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_scriptblock_create_invoke(self):
        result = self._deobfuscate("[scriptblock]::Create('Write-Host hello').Invoke()")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_scriptblock_create_fqn(self):
        result = self._deobfuscate(
            "&([System.Management.Automation.ScriptBlock]::Create('Write-Host hello'))"
        )
        self.assertIn('Write-Host', result)
        self.assertNotIn('ScriptBlock', result)

    def test_scriptblock_create_deflate(self):
        b64 = 'Cy/KLEnV9cgvLlHISM3JyQcA'
        data = (
            "&([scriptblock]::Create("
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.DeflateStream("
            F"[IO.MemoryStream][Convert]::FromBase64String('{b64}'),"
            " [IO.Compression.CompressionMode]::Decompress)),"
            " [Text.Encoding]::ASCII)).ReadToEnd()))"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())
        self.assertNotIn('FromBase64String', result)

    def test_scriptblock_create_gzip_new_object_memorystream(self):
        b64 = 'H4sIAP7802kC/wsvyixJ1fXILy5RyEjNyckHAA2QLxEQAAAA'
        data = (
            "&([scriptblock]::Create("
            "(New-Object IO.StreamReader("
            "(New-Object IO.Compression.GzipStream("
            "(New-Object IO.MemoryStream(,"
            F"[Convert]::FromBase64String('{b64}'))),"
            " [IO.Compression.CompressionMode]::Decompress)))"
            ".ReadToEnd()))"
        )
        result = self._deobfuscate(data)
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())
        self.assertNotIn('FromBase64String', result)

    def test_scriptblock_create_variable_not_inlined(self):
        result = self._deobfuscate('&([scriptblock]::Create($var))')
        self.assertIn('scriptblock', result.lower())
        self.assertIn('$var', result)

    @blocker
    def test_scriptblock_create_multi_statement_inlines_into_a_block_the_call_operator_runs(self):
        self._assertDeobfuscatesTo("&([scriptblock]::Create('$a = 1; $b = 2'))", """
            & {
              $a = 1
              $b = 2
            }
        """)

    def test_scriptblock_create_invoke_return_as_is(self):
        result = self._deobfuscate("[scriptblock]::Create('Write-Host hello').InvokeReturnAsIs()")
        self.assertIn('Write-Host', result)
        self.assertNotIn('scriptblock', result.lower())

    def test_iex_inside_subexpression(self):
        result = self._deobfuscate_iterative("$('\"hello\"' | Invoke-Expression)")
        self.assertIn('hello', result)
        self.assertNotIn('Invoke-Expression', result)

    def test_iex_piped_inside_assignment(self):
        result = self._deobfuscate("$x = 'Write-Host hello' | Invoke-Expression")
        self.assertIn('Write-Host', result)
        self.assertNotIn('Invoke-Expression', result)
        self.assertNotIn('|', result)

    def test_piped_iex_keeps_assignment_target(self):
        result = self._apply("$x = 'Get-Date' | iex", Ps1IexInlining)
        self.assertEqual(result, '$x = Get-Date')


class TestPs1IexRedirections(TestPs1):

    def test_a_redirected_iex_statement_is_not_replaced_by_the_code_it_holds(self):
        self._assertUnchanged(
            "Invoke-Expression 'Write-Host hello' > C:\\o.txt", Ps1IexInlining)

    def test_a_redirected_iex_in_a_value_slot_is_not_replaced_by_its_value(self):
        self._assertUnchanged("$a = (Invoke-Expression '42' > C:\\o.txt)", Ps1IexInlining)

    def test_a_refused_inlining_leaves_every_parent_pointer_true(self):
        source = "$a = (Invoke-Expression '42' > C:\\o.txt)"
        self._assertTreeIsIntact(source, source, Ps1IexInlining)

    def test_a_refused_inlining_does_not_report_a_change_it_did_not_make(self):
        transform = Ps1IexInlining()
        transform.visit(self._transform("Invoke-Expression 'Write-Host hi' > C:\\o.txt"))
        self.assertFalse(transform.changed)

    def test_an_unredirected_iex_statement_is_still_inlined(self):
        self.assertEqual(
            self._apply("Invoke-Expression 'Write-Host hello'", Ps1IexInlining),
            'Write-Host hello')


class TestPs1AShadowedForeachStageIsNotDecoded(TestPs1):

    _PIPELINE = (
        "(New-Object IO.Compression.DeflateStream("
        "[IO.MemoryStream][Convert]::FromBase64String('Cy/KLEnV9cgvLlHISM3JyQcA'),"
        " [IO.Compression.CompressionMode]::Decompress)"
        " | %{ New-Object System.IO.StreamReader($_, [Text.Encoding]::ASCII) }"
        " | %{ $_.ReadToEnd() })"
        " | Invoke-Expression"
    )

    def test_an_unshadowed_decode_pipeline_is_still_inlined(self):
        result = self._deobfuscate(self._PIPELINE)
        self.assertIn('Write-Host', result)
        self.assertNotIn('FromBase64String', result)

    def test_a_redefined_foreach_object_leaves_the_decode_pipeline_alone(self):
        result = self._deobfuscate(inspect.cleandoc(
            F"function ForEach-Object {{ 'HIJACK' }}\n{self._PIPELINE}"))
        self.assertNotIn('Write-Host', result)
        self.assertIn('ReadToEnd', result)

    def test_a_redefinition_an_earlier_inline_installs_is_seen_by_the_later_decode(self):
        source = "Invoke-Expression 'function ForEach-Object { \"HIJACK\" }'\n" + self._PIPELINE
        result = self._deobfuscate(source)
        self.assertNotIn('Write-Host', result)
        self.assertIn('ReadToEnd', result)


class TestPs1IexInliningOfAnEmptyBlock(TestPs1):

    def test_an_empty_scriptblock_resolves_to_nothing_rather_than_to_a_removal(self):
        self._assertUnchanged('Invoke-Command -ScriptBlock {}', Ps1IexInlining)

    def test_an_empty_scriptblock_does_not_abort_the_pipeline(self):
        source = "Invoke-Command -ScriptBlock {}\nWrite-Host 'go'"
        self._assertDeobfuscatesToOneOf(source, source, "Write-Host 'go'")

    @opportunity
    def test_an_empty_scriptblock_run_through_invoke_command_is_removed(self):
        self.assertEqual(
            self._deobfuscate("Invoke-Command -ScriptBlock {}\nWrite-Host 'go'"),
            "Write-Host 'go'",
        )

    def test_a_scriptblock_holding_a_statement_is_still_inlined(self):
        self.assertEqual(
            self._apply("Invoke-Command -ScriptBlock { Write-Host 'x' }", Ps1IexInlining),
            "Write-Host 'x'")
