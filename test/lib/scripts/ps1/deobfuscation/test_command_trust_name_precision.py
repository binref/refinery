from __future__ import annotations

from test import opportunity
from test.lib.scripts.ps1.deobfuscation import TestPs1

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"
_ANCHOR_TOKEN = 'ANCHOR_SURVIVES'

_DISCARDED_TOKEN = '88175'
_DISCARDS = (
    '$Null = Get-Random -Maximum 88175',
    '[Void](Get-Random -Maximum 88175)',
    'Get-Random -Maximum 88175 | Out-Null',
)

_ALIAS_OF_ANOTHER_NAME = 'Set-Alias Some-Other-Name i*x'
_OTHER_NAME_TOKEN = 'Some-Other-Name'

_ALIAS_OF_OWN_NAME = 'Set-Alias Get-Random i*x'

_FUNCTION_OF_ANOTHER_NAME = 'function Some-Other-Name { Start-Process calc }'
_CALL_OF_ANOTHER_NAME = 'Some-Other-Name'
_FUNCTION_LEAK_TOKEN = 'Start-Process calc'

_DISCARDED_READ = '$Null = [System.Guid]::NewGuid()'
_DISCARDED_READ_TOKEN = 'NewGuid'


class TestPs1DiscardedPureCallNamePrecisionControls(TestPs1):

    def test_a_discarded_pure_call_with_no_rebinder_anywhere_is_removed(self):
        for discard in _DISCARDS:
            with self.subTest(discard):
                result = self._deobfuscate(F'{discard}\n{_ANCHOR}')
                self.assertNotIn(_DISCARDED_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)

    def test_a_discarded_pure_call_after_a_set_alias_of_its_own_name_is_kept(self):
        for discard in _DISCARDS:
            with self.subTest(discard):
                result = self._deobfuscate(F'{_ALIAS_OF_OWN_NAME}\n{discard}\n{_ANCHOR}')
                self.assertIn(_DISCARDED_TOKEN, result)
                self.assertIn('Set-Alias', result)
                self.assertIn(_ANCHOR_TOKEN, result)

    def test_a_wildcard_set_alias_of_another_name_survives_deobfuscation(self):
        result = self._deobfuscate(F'{_ALIAS_OF_ANOTHER_NAME}\n{_ANCHOR}')
        self.assertIn(_OTHER_NAME_TOKEN, result)
        self.assertIn('Set-Alias', result)
        self.assertIn(_ANCHOR_TOKEN, result)

    def test_a_discarded_pure_call_after_a_function_redefinition_of_another_name_is_removed(self):
        result = self._deobfuscate(
            F'{_FUNCTION_OF_ANOTHER_NAME}\n{_CALL_OF_ANOTHER_NAME}\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
        self.assertNotIn(_DISCARDED_TOKEN, result)
        self.assertIn(_FUNCTION_LEAK_TOKEN, result)
        self.assertIn(_OTHER_NAME_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)

    def test_an_invoked_alias_of_a_harmless_command_is_inlined_and_frees_the_discard(self):
        result = self._deobfuscate(
            F'Set-Alias Some-Other-Name Get-Date\nWrite-Host ({_CALL_OF_ANOTHER_NAME})\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
        self.assertIn('Get-Date', result)
        self.assertNotIn(_OTHER_NAME_TOKEN, result)
        self.assertNotIn(_DISCARDED_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1DiscardedPureCallAfterASetAliasOfAnotherNameIsRemoved(TestPs1):

    def test_a_discarded_pure_call_after_a_set_alias_of_another_name_is_removed(self):
        for discard in _DISCARDS:
            with self.subTest(discard):
                result = self._deobfuscate(F'{_ALIAS_OF_ANOTHER_NAME}\n{discard}\n{_ANCHOR}')
                self.assertIn(_OTHER_NAME_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)
                self.assertNotIn(_DISCARDED_TOKEN, result)

    def test_every_defining_spelling_of_an_uninvoked_name_is_as_inert(self):
        for definer in ('Set-Alias', 'sal', 'New-Alias', 'nal', 'Set-Alias -Name', 'Set-Alias -Na'):
            with self.subTest(definer):
                result = self._deobfuscate(
                    F'{definer} Some-Other-Name i*x\n$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
                self.assertIn(_OTHER_NAME_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)
                self.assertNotIn(_DISCARDED_TOKEN, result)

    def test_a_discarded_member_read_after_a_set_alias_of_another_name_is_removed(self):
        result = self._deobfuscate(F'{_ALIAS_OF_ANOTHER_NAME}\n{_DISCARDED_READ}\n{_ANCHOR}')
        self.assertIn(_OTHER_NAME_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)
        self.assertNotIn(_DISCARDED_READ_TOKEN, result)


class TestPs1DiscardedPureCallAfterASetAliasOfAnInvokedNameIsKept(TestPs1):

    _INVOKED_BINDINGS = (
        'Set-Alias Some-Other-Name i*x\nSome-Other-Name',
        'Set-Alias Get-ChildItem i*x\ngci $payload',
        'Set-Alias X Invoke-Command\nX $payload',
        'Set-Alias global:X iex\nX $payload',
        'Set-Alias global:X iex\nglobal:X $payload',
        'Set-Alias Get-Frob iex\nFrob $payload',
        'Set-Alias Some-Other-Name i*x\nfunction f { Some-Other-Name }\nf',
    )

    def test_the_discarded_call_below_an_invoked_binding_is_kept(self):
        for binding in self._INVOKED_BINDINGS:
            with self.subTest(binding):
                result = self._deobfuscate(
                    F'{binding}\n$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
                self.assertIn(_DISCARDED_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)

    def test_the_discarded_member_read_below_an_invoked_binding_is_kept(self):
        result = self._deobfuscate(
            F'{_ALIAS_OF_ANOTHER_NAME}\n{_CALL_OF_ANOTHER_NAME}\n{_DISCARDED_READ}\n{_ANCHOR}')
        self.assertIn(_DISCARDED_READ_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)

    @opportunity
    def test_a_call_below_the_discard_does_not_keep_it(self):
        result = self._deobfuscate(
            F'{_ALIAS_OF_ANOTHER_NAME}\n$Null = Get-Random -Maximum 88175\n'
            F'{_CALL_OF_ANOTHER_NAME}\n{_ANCHOR}')
        self.assertNotIn(_DISCARDED_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1DiscardedPureCallAfterABindingTheWalkCannotRead(TestPs1):

    _UNREADABLE_BINDINGS = (
        'Set-Alias Some-Other-Name $target',
        "Set-Alias Some-Other-Name 'dI6tW'.Remove(3, 3)",
        'Set-Alias Some-Other-Name i*x -Force',
        'Set-Alias -Scope Global Some-Other-Name i*x',
        'Set-Alias Some-Other-Name i*x extra',
        'Set-Item alias:Some-Other-Name i*x',
    )

    @opportunity
    def test_the_discarded_call_below_an_unreadable_binding_of_another_name_is_removed(self):
        for binding in self._UNREADABLE_BINDINGS:
            with self.subTest(binding):
                result = self._deobfuscate(
                    F'{binding}\n$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
                self.assertNotIn(_DISCARDED_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)

    def test_a_script_that_redefines_set_alias_itself_keeps_the_discard(self):
        result = self._deobfuscate(
            'function Set-Alias { iex $x }\nSet-Alias Some-Other-Name WhatEver\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
        self.assertIn(_DISCARDED_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)
