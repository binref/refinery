from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"
_ANCHOR_TOKEN = 'ANCHOR_SURVIVES'


class _Ps1CommandDefinitionKeyword(TestPs1):

    def _assertDiscardedCallRemoved(self, source: str, token: str) -> None:
        result = self._deobfuscate(source)
        self.assertNotIn(token, result)
        self.assertIn(_ANCHOR_TOKEN, result)

    def _assertDiscardedCallKept(self, source: str, token: str, acting: str) -> None:
        result = self._deobfuscate(source)
        self.assertIn(token, result)
        self.assertIn(acting, result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1ADiscardedPureCommandWithNoDefinitionOfItsNameIsRemoved(_Ps1CommandDefinitionKeyword):

    def test_a_null_assigned_pure_command_with_no_definition_is_removed(self):
        self._assertDiscardedCallRemoved(
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}', '88175')

    def test_a_void_cast_pure_command_with_no_definition_is_removed(self):
        self._assertDiscardedCallRemoved(
            F"[Void](Get-Date -Format 'Zqxwmp')\n{_ANCHOR}", 'Zqxwmp')

    def test_an_out_null_piped_pure_command_with_no_definition_is_removed(self):
        self._assertDiscardedCallRemoved(
            F"Get-ChildItem 'Vbnmqz' | Out-Null\n{_ANCHOR}", 'Vbnmqz')

    def test_a_workflow_defining_a_different_name_does_not_keep_the_discarded_call(self):
        self._assertDiscardedCallRemoved(
            F'workflow Do-Thing {{ Start-Process calc }}\n'
            F'$Null = Get-Random -Maximum 44011\n{_ANCHOR}', '44011')

    def test_a_configuration_defining_a_different_name_does_not_keep_the_discarded_call(self):
        self._assertDiscardedCallRemoved(
            F'configuration Set-Thing {{ Start-Process notepad }}\n'
            F"[Void](Get-Date -Format 'Wmzqxp')\n{_ANCHOR}", 'Wmzqxp')


class TestPs1ACallAfterAWorkflowDefiningItsNameIsKept(_Ps1CommandDefinitionKeyword):

    def test_a_null_assigned_call_after_a_workflow_of_its_name_is_kept(self):
        self._assertDiscardedCallKept(
            F'workflow Get-Random {{ Start-Process calc }}\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}', '88175', 'Start-Process calc')

    def test_an_out_null_piped_call_after_a_workflow_of_its_name_is_kept(self):
        self._assertDiscardedCallKept(
            F'workflow Get-Date {{ Start-Process notepad }}\n'
            F"Get-Date -Format 'Zqxwmp' | Out-Null\n{_ANCHOR}", 'Zqxwmp', 'Start-Process notepad')


class TestPs1ACallAfterAConfigurationDefiningItsNameIsKept(_Ps1CommandDefinitionKeyword):

    def test_a_void_cast_call_after_a_configuration_of_its_name_is_kept(self):
        self._assertDiscardedCallKept(
            F'configuration Get-Random {{ Start-Process calc }}\n'
            F'[Void](Get-Random -Maximum 44011)\n{_ANCHOR}', '44011', 'Start-Process calc')

    def test_an_out_null_piped_call_after_a_configuration_of_its_name_is_kept(self):
        self._assertDiscardedCallKept(
            F'configuration Get-ChildItem {{ Start-Process notepad }}\n'
            F"Get-ChildItem 'Vbnmqz' | Out-Null\n{_ANCHOR}", 'Vbnmqz', 'Start-Process notepad')
