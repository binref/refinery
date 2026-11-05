from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"
_ANCHOR_TOKEN = 'ANCHOR_SURVIVES'

_RANDOM = ('$Null = Get-Random -Maximum 88175', '88175')
_DATE = ("$Null = Get-Date -Format 'Zqxwmp'", 'Zqxwmp')
_MEASURE = ('$Null = Measure-Object -InputObject 90210', '90210')
_SELECT = ("[Void](Select-Object -First 3 -InputObject 'Kdwlrp')", 'Kdwlrp')
_CHILDITEM = ("$Null = Get-ChildItem 'Vbnmqz'", 'Vbnmqz')
_SORT = ("Sort-Object -InputObject 'Rtyplo' | Out-Null", 'Rtyplo')

_PURE_COMMANDS = (_RANDOM, _DATE, _MEASURE, _SELECT, _CHILDITEM, _SORT)


class _Ps1CommandTrustFlow(TestPs1):

    def _assertPureCommandRemoved(self, source: str, token: str, acting: str) -> None:
        result = self._deobfuscate(source)
        self.assertNotIn(token, result)
        self.assertIn(acting, result)
        self.assertIn(_ANCHOR_TOKEN, result)

    def _assertPureCommandKept(self, source: str, token: str, acting: str) -> None:
        result = self._deobfuscate(source)
        self.assertIn(token, result)
        self.assertIn(acting, result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1APureCommandBeforeTheOnlyLeakIsRemoved(_Ps1CommandTrustFlow):

    def test_a_pure_command_before_the_only_invoke_expression_is_removed(self):
        source, token = _RANDOM
        self._assertPureCommandRemoved(
            F'{source}\nInvoke-Expression $enc\n{_ANCHOR}', token, 'Invoke-Expression')

    def test_a_pure_command_before_the_only_opaque_call_is_removed(self):
        source, token = _CHILDITEM
        self._assertPureCommandRemoved(
            F'{source}\n& $dispatch\n{_ANCHOR}', token, '$dispatch')

    def test_a_pure_command_before_the_only_import_module_is_removed(self):
        source, token = _SELECT
        self._assertPureCommandRemoved(
            F'{source}\nImport-Module .\\mod.psm1\n{_ANCHOR}', token, 'Import-Module')

    def test_a_pure_command_before_its_own_function_redefinition_is_removed(self):
        self._assertPureCommandRemoved(
            F'$Null = Get-Random -Maximum 88175\n'
            F'function Get-Random {{ Start-Process calc }}\n'
            F'Get-Random\n{_ANCHOR}',
            '88175', 'Start-Process calc')

    def test_a_pure_command_before_its_own_set_alias_is_removed(self):
        source, token = _DATE
        self._assertPureCommandRemoved(
            F'{source}\nSet-Alias Get-Date i*x\n{_ANCHOR}', token, 'Set-Alias')


class TestPs1APureCommandALeakCanPrecedeIsKept(_Ps1CommandTrustFlow):

    def test_a_pure_command_after_an_invoke_expression_is_kept(self):
        source, token = _RANDOM
        self._assertPureCommandKept(
            F'Invoke-Expression $enc\n{source}\n{_ANCHOR}', token, 'Invoke-Expression')

    def test_a_pure_command_after_an_opaque_call_is_kept(self):
        source, token = _MEASURE
        self._assertPureCommandKept(
            F'& $dispatch\n{source}\n{_ANCHOR}', token, '$dispatch')

    def test_a_pure_command_after_an_import_module_is_kept(self):
        source, token = _SELECT
        self._assertPureCommandKept(
            F'Import-Module .\\mod.psm1\n{source}\n{_ANCHOR}', token, 'Import-Module')

    def test_a_pure_command_after_its_own_function_redefinition_is_kept(self):
        self._assertPureCommandKept(
            F'function Get-Random {{ Start-Process calc }}\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}',
            '88175', 'Start-Process calc')

    def test_a_pure_command_after_its_own_set_alias_is_kept(self):
        source, token = _DATE
        self._assertPureCommandKept(
            F'Set-Alias Get-Date i*x\n{source}\n{_ANCHOR}', token, 'Set-Alias')

    def test_a_pure_command_looping_with_an_invoke_expression_is_kept(self):
        source, token = _MEASURE
        result = self._deobfuscate(F'while ($True) {{ {source}; Invoke-Expression $enc }}')
        self.assertIn(token, result)
        self.assertIn('Invoke-Expression', result)

    def test_a_pure_command_looping_with_an_opaque_call_is_kept(self):
        source, token = _RANDOM
        self._assertPureCommandKept(
            F'foreach ($i in 1..4) {{ {source}; & $dispatch }}\n{_ANCHOR}', token, '$dispatch')

    def test_a_pure_command_looping_with_an_import_module_is_kept(self):
        source, token = _CHILDITEM
        self._assertPureCommandKept(
            F'while ($True) {{ {source}; Import-Module .\\mod.psm1 }}\n{_ANCHOR}',
            token, 'Import-Module')


class TestPs1CommandTrustPolesWithAndWithoutALeak(_Ps1CommandTrustFlow):

    def test_a_pure_command_with_no_identity_leak_anywhere_is_removed(self):
        for source, token in _PURE_COMMANDS:
            with self.subTest(source):
                self._assertPureCommandRemoved(F'{source}\n{_ANCHOR}', token, _ANCHOR_TOKEN)

    def test_a_pure_command_with_an_identity_leak_reachable_before_it_is_kept(self):
        source, token = _RANDOM
        for leak, acting in (
            ('Invoke-Expression $enc', 'Invoke-Expression'),
            ('& $dispatch', '$dispatch'),
            ('Import-Module .\\mod.psm1', 'Import-Module'),
            ('function Get-Random { Start-Process calc }', 'Start-Process calc'),
            ('Set-Alias Get-Random i*x', 'Set-Alias'),
        ):
            with self.subTest(leak):
                self._assertPureCommandKept(F'{leak}\n{source}\n{_ANCHOR}', token, acting)


class TestPs1AFunctionRedefinitionSplitsItsNameIntoTwoEras(_Ps1CommandTrustFlow):

    def test_the_discarded_call_before_the_definition_goes_and_the_bare_call_after_it_stays(self):
        result = self._deobfuscate(
            F'$Null = Get-Random -Maximum 88175\n'
            F'function Get-Random {{ Start-Process calc }}\n'
            F'Get-Random -Maximum 70223\n{_ANCHOR}')
        self.assertNotIn('88175', result)
        self.assertIn('70223', result)
        self.assertIn('Start-Process calc', result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1APureCommandLoopingWithItsOwnRedefinitionIsKept(_Ps1CommandTrustFlow):

    def test_a_pure_command_alone_in_a_loop_body_is_removed(self):
        source, token = _RANDOM
        self._assertPureCommandRemoved(
            F'while ($True) {{ {source}; {_ANCHOR} }}', token, _ANCHOR_TOKEN)

    def test_a_pure_command_looping_with_its_own_function_redefinition_is_kept(self):
        source, token = _RANDOM
        self._assertPureCommandKept(
            F'while ($True) {{ {source}; function Get-Random {{ Start-Process calc }} }}\n{_ANCHOR}',
            token, 'Start-Process calc')

    def test_a_pure_command_looping_with_its_own_set_alias_is_kept(self):
        source, token = _DATE
        self._assertPureCommandKept(
            F'foreach ($i in 1..4) {{ {source}; Set-Alias Get-Date i*x }}\n{_ANCHOR}',
            token, 'Set-Alias')


class TestPs1ARedefinitionSiteTheGraphCannotPlaceIsAlwaysAhead(_Ps1CommandTrustFlow):

    def test_a_pure_command_after_a_param_default_redefinition_of_its_own_name_is_kept(self):
        self._assertPureCommandKept(
            F'function f {{ param($p = $(function global:Get-Random {{ Start-Process calc }})) }}\n'
            F'f\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}',
            '88175', 'Start-Process calc')

    def test_an_unplaceable_site_keeps_a_call_an_ordinary_later_redefinition_alone_would_shed(self):
        self._assertPureCommandKept(
            F'function f {{ param($p = $(function global:Get-Random {{ Start-Process calc }})) }}\n'
            F'f\n'
            F'$Null = Get-Random -Maximum 88175\n'
            F'function Get-Random {{ Start-Process iexplore }}\n{_ANCHOR}',
            '88175', 'iexplore')


class TestPs1BothPipedDiscardSinksFollowTheTrustVerdict(_Ps1CommandTrustFlow):

    _SINKS = ('| Out-Null', '| ForEach-Object { [Void]$_ }')

    def test_a_piped_discard_with_no_rebinder_of_its_name_anywhere_is_removed(self):
        for sink in self._SINKS:
            with self.subTest(sink):
                self._assertPureCommandRemoved(
                    F'Get-Random -Maximum 88175 {sink}\n{_ANCHOR}', '88175', _ANCHOR_TOKEN)

    def test_a_piped_discard_after_a_rebinder_of_its_own_name_is_kept(self):
        for sink in self._SINKS:
            for rebinder, acting in (
                ('Set-Alias Get-Random i*x', 'Set-Alias'),
                ('function Get-Random { Start-Process calc }', 'Start-Process calc'),
                ('Invoke-Expression $enc', 'Invoke-Expression'),
            ):
                with self.subTest(F'{rebinder} {sink}'):
                    self._assertPureCommandKept(
                        F'{rebinder}\nGet-Random -Maximum 88175 {sink}\n{_ANCHOR}', '88175', acting)


class TestPs1AWholeRunRefusalOverridesThePositionalGrant(_Ps1CommandTrustFlow):

    _REMOVABLE = (
        F'$Null = Get-Random -Maximum 88175\n'
        F'function Get-Random {{ Start-Process calc }}\n'
        F'Get-Random -Maximum 70223\n{_ANCHOR}')

    def test_running_the_own_script_path_keeps_a_call_its_position_alone_would_shed(self):
        self._assertPureCommandRemoved(self._REMOVABLE, '88175', 'Start-Process calc')
        self._assertPureCommandKept(
            F'{self._REMOVABLE}\n& $PSCommandPath', '88175', 'Start-Process calc'
        )

    def test_a_root_process_block_keeps_a_call_its_position_alone_would_shed(self):
        self._assertPureCommandRemoved(self._REMOVABLE, '88175', 'Start-Process calc')
        self._assertPureCommandKept(
            F'process {{\n{self._REMOVABLE}\n}}', '88175', 'Start-Process calc')


class TestPs1AnOpenerRefusesACallItsOwnDefinitionSitesWouldGrant(_Ps1CommandTrustFlow):

    def test_a_call_between_an_opener_and_its_own_later_redefinition_is_kept(self):
        self._assertPureCommandKept(
            F'Invoke-Expression $enc\n'
            F'$Null = Get-Random -Maximum 88175\n'
            F'function Get-Random {{ Start-Process calc }}\n{_ANCHOR}',
            '88175', 'Invoke-Expression')
