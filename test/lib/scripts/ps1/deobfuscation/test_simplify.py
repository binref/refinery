from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1Simplifications


class TestPS1BracketRemoval(TestPs1):

    def test_string_literal_01(self):
        result = self._deobfuscate('("{0}{2}{1}")')
        self.assertIn('"{0}{2}{1}"', result)

    def test_string_literal_02(self):
        result = self._deobfuscate('( ((    \n( "Test")))')
        self.assertIn('"Test"', result)

    def test_string_literal_03(self):
        result = self._deobfuscate('(((\n( "Tes""t")\n)) )')
        self.assertIn('"Tes""t"', result)

    def test_numeric_literal_01(self):
        result = self._deobfuscate('(0x12)')
        self.assertIn('0x12', result)

    def test_numeric_literal_02(self):
        result = self._deobfuscate('( ((    \n( 0x12)  ))')
        self.assertIn('0x12', result)

    def test_numeric_literal_03(self):
        result = self._deobfuscate('((31337) )')
        self.assertIn('31337', result)


class TestPs1NameNormalization(TestPs1):

    def test_wmi_class_name_normalized(self):
        result = self._deobfuscate(
            'Get-WmiObject wIn32_oPErATinGsYsteM'
        )
        self.assertIn('Win32_OperatingSystem', result)
        self.assertNotIn('wIn32_oPErATinGsYsteM', result)

    def test_env_variable_name_normalized(self):
        result = self._deobfuscate('${env:aPpdatA}')
        self.assertIn('AppData', result)
        self.assertNotIn('aPpdatA', result)


class TestPs1SubExpressionSimplification(TestPs1):

    def test_subexpression_scalar_simplified(self):
        result = self._deobfuscate("$('hello')")
        self.assertEqual(result.strip(), "'hello'")

    def test_replace_on_subexpression(self):
        result = self._deobfuscate("$('hello world').Replace('world', 'there')")
        self.assertIn('hello there', result)
        self.assertNotIn('$(', result)

    def test_subexpression_member_access(self):
        result = self._deobfuscate('$K[$i % $K.$($p) * $f]')
        self.assertIn('$K.$p', result)
        self.assertNotIn('\n*\n', result)

    def test_chained_replace_across_subexpression(self):
        result = self._deobfuscate(
            "$('aXb'.Replace('X', 'Y')).Replace('Y', 'Z')"
        )
        self.assertNotIn('aXb', result)
        self.assertIn('aZb', result)


class TestPs1SimplifyExtra(TestPs1):

    def test_bracket_removal_string(self):
        data = '("hello")'
        result = self._deobfuscate(data)
        self.assertNotIn('(', result)
        self.assertIn('hello', result)

    def test_bracket_removal_integer(self):
        data = '(42)'
        result = self._deobfuscate(data)
        self.assertEqual(result.strip(), '42')

    def test_uncurly_variable(self):
        data = '${variable}'
        result = self._deobfuscate(data)
        self.assertEqual(result.strip(), '$variable')

    def test_case_normalize_invoke_expression(self):
        data = "iNVokE-exPreSSion"
        result = self._deobfuscate(data)
        self.assertIn('Invoke-Expression', result)

    def test_case_normalize_get_variable(self):
        data = 'gEt-VaRIAblE'
        result = self._deobfuscate(data)
        self.assertIn('Get-Variable', result)

    def test_case_normalize_set_variable(self):
        data = 'sEt-VarIAbLE'
        result = self._deobfuscate(data)
        self.assertIn('Set-Variable', result)

    def test_invoke_simplification_member(self):
        data = '$x.ToString.Invoke()'
        result = self._deobfuscate(data)
        self.assertIn('$x.ToString()', result)

    def test_invoke_simplification_quoted_member(self):
        data = '$x."ToString"()'
        result = self._deobfuscate(data)
        self.assertIn('$x.ToString()', result)

    def test_command_invocation_ampersand(self):
        data = '& ("Invoke-Expression")'
        result = self._deobfuscate(data)
        self.assertIn('Invoke-Expression', result)
        self.assertNotIn('&', result)

    def test_command_invocation_dot(self):
        data = ". ('Set-Variable') foo 42"
        result = self._deobfuscate(data)
        self.assertIn('$foo', result)
        self.assertIn('42', result)

    def test_param_block(self):
        result = self._deobfuscate('param($qu, $sec=0, $iv=0)')
        self.assertIn('Param($qu, $sec = 0, $iv = 0)', result)

    def test_backtick_removal_in_variable(self):
        result = self._deobfuscate('${ex`ecu`tion}')
        self.assertNotIn('`', result)
        self.assertNotIn('{', result)
        self.assertEqual(result.strip(), '$execution')

    def test_backtick_variable_with_known_name(self):
        result = self._deobfuscate('${eXeC`uTi`oNCon`tEXt}')
        self.assertNotIn('`', result)
        self.assertNotIn('{', result)
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_normalize_true_false(self):
        result = self._deobfuscate('$tRUe, $fAlSE')
        self.assertIn('$True', result)
        self.assertIn('$False', result)

    def test_backtick_member_access(self):
        result = self._deobfuscate('$x."me`Th`od"')
        self.assertNotIn('`', result)
        self.assertIn('.meThod', result)

    def test_backtick_function_name_stripped(self):
        result = self._deobfuscate("function tR`iomE { Param($x); return $x }")
        self.assertNotIn('`', result)
        self.assertIn('function tRiomE', result)

    def test_backtick_in_command_name(self):
        result = self._deobfuscate("i`EX 'Write-Host hello'")
        self.assertNotIn('`', result)
        self.assertIn('Write-Host', result)

    def test_backtick_in_parameter_name(self):
        result = self._deobfuscate("Get-WmiObject -w`mI`InS`tAnCe foo")
        self.assertNotIn('`', result)

    def test_gcm_wildcard_not_substituted_as_name(self):
        # `gcm` normalizes to `Get-Command`, but a wildcard pattern must not become the command
        # name verbatim.
        result = self._apply("& (gcm i*e-e*) 'hi'", Ps1Simplifications)
        self.assertEqual(result, "& (Get-Command i*e-e*) 'hi'")

    def test_gcm_concrete_name_resolved(self):
        result = self._apply("& (gcm Write-Output) 'hi'", Ps1Simplifications)
        self.assertEqual(result, "Write-Output 'hi'")
