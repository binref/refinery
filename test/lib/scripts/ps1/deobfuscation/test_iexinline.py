from __future__ import annotations

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
        # Base64-encoded raw deflate of "Write-Host hello"
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

    def test_iex_expression_multi_statement_not_inlined(self):
        result = self._deobfuscate("$x = Invoke-Expression \"'a'; 'b'\"")
        self.assertIn('Invoke-Expression', result)

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

    def test_scriptblock_create_multi_statement(self):
        result = self._deobfuscate("&([scriptblock]::Create('$a = 1; $b = 2'))")
        self.assertIn('$a = 1', result)
        self.assertIn('$b = 2', result)
        self.assertNotIn('scriptblock', result.lower())

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
