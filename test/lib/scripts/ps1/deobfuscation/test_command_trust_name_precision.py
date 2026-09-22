from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

#: An acting statement that is never a removal candidate, so its survival only says the pass did not
#: empty the script wholesale. A `Write-Host` writes to the host and can never be dropped.
_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"
_ANCHOR_TOKEN = 'ANCHOR_SURVIVES'

#: The discarded side-effect-free command whose survival every test turns on. Its distinctive
#: literal `88175` is in the source and gone once the statement is removed, and the three spellings
#: sink the value the same way (`$Null =`, `[Void](...)`, `| Out-Null`), so a verdict depends on the
#: trust decision rather than on one discard idiom.
_DISCARDED_TOKEN = '88175'
_DISCARDS = (
    '$Null = Get-Random -Maximum 88175',
    '[Void](Get-Random -Maximum 88175)',
    'Get-Random -Maximum 88175 | Out-Null',
)

#: A surviving statement that rebinds a command name OTHER than the discarded call's. `Set-Alias`
#: opens the command table for the whole run, and the wildcard target keeps the binding from being
#: inlined away, so `Some-Other-Name` genuinely stays in the output. The name it rebinds is
#: `Some-Other-Name`, never `Get-Random`, so the discarded `Get-Random` call still runs the built-in
#: the metadata describes and is safe to drop.
_ALIAS_OF_ANOTHER_NAME = 'Set-Alias Some-Other-Name i*x'
_OTHER_NAME_TOKEN = 'Some-Other-Name'

#: The same aliaser pointed at the discarded call's OWN name, which genuinely rebinds `Get-Random`,
#: so keeping the call is correct here and both the coarse and a name-precise verdict agree.
_ALIAS_OF_OWN_NAME = 'Set-Alias Get-Random i*x'

#: A `function` redefinition of another name, called so it is a real surviving leak and not dead
#: code the pass sheds. Its `Start-Process calc` body cannot be dropped, so that token in the output
#: proves the redefinition stayed. A `function` is a per-name redefinition, so it leaves
#: `Get-Random` trustworthy — the behavior the aliaser above shares.
_FUNCTION_OF_ANOTHER_NAME = 'function Some-Other-Name { Start-Process calc }'
_CALL_OF_ANOTHER_NAME = 'Some-Other-Name'
_FUNCTION_LEAK_TOKEN = 'Start-Process calc'

#: A discarded static call whose removal needs the .NET type world to be closed at the call — the
#: other axis a rebinder could be thought to open — since nothing folds a fresh GUID away. A
#: `Set-Alias` touches no type, so a binding that no call reaches leaves the call as removable as
#: it is with no rebinder at all.
_DISCARDED_READ = '$Null = [System.Guid]::NewGuid()'
_DISCARDED_READ_TOKEN = 'NewGuid'


class TestPs1DiscardedPureCallNamePrecisionControls(TestPs1):
    """
    The discarded pure call is dropped only while its bareword still names the built-in the metadata
    describes. These controls pin the verdict at both poles and for the rebinder families the tool
    reads name-precisely, so the name-precise verdict on an aliaser beside them is not vacuous: with
    a clean command table the call goes; with a rebinder of the call's own name reaching it the call
    stays; and a `function` redefinition of a different name — a per-name redefinition the model
    trusts around — leaves the call removable although the redefinition itself survives.
    """

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


class TestPs1DiscardedPureCallAfterASetAliasOfAnotherNameIsRemoved(TestPs1):
    """
    A surviving `Set-Alias` of a name the script never invokes rebinds nothing any call reaches and
    runs nothing itself, so the discarded `Get-Random` call beside it still runs the built-in and is
    as removable as it is with no rebinder at all — the verdict a `function` redefinition of the
    other name gets. The aliaser survives, proving the world is not emptied. The command table
    still reads open for the whole run, so the removal is a positional grant and not a change to
    the whole-run verdict.
    """

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
    """
    A binding the script invokes may run anything — a leak that rebinds `Get-Random` among it — so
    it distrusts every name below it the way any opener does, and the discarded call stays. The
    bound name is matched the way a deny-list matches: one hop through the built-in alias table
    and the scope qualifier stripped, so no spelling of the call slips past the binding. Measured
    on 5.1, `Set-Alias global:x` binds a command that the spelling `global:x` does run. The
    payloads are variables so that no earlier pass can inline the call away before the trust
    decision is made.
    """

    _INVOKED_BINDINGS = (
        'Set-Alias Some-Other-Name i*x\nSome-Other-Name',
        'Set-Alias Get-ChildItem i*x\ngci $payload',
        'Set-Alias gci Foo\ngci $payload',
        'Set-Alias X Start-Job\nX { }',
        'Set-Alias global:X iex\nX $payload',
        'Set-Alias global:X iex\nglobal:X $payload',
        'Set-Alias Some-Other-Name i*x\nfunction f { Some-Other-Name }',
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

    def test_a_call_below_the_discard_still_keeps_it(self):
        result = self._deobfuscate(
            F'{_ALIAS_OF_ANOTHER_NAME}\n$Null = Get-Random -Maximum 88175\n'
            F'{_CALL_OF_ANOTHER_NAME}\n{_ANCHOR}')
        self.assertIn(_DISCARDED_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)


class TestPs1DiscardedPureCallAfterABindingTheWalkCannotReadIsKept(TestPs1):
    """
    A binding with an unreadable half is not one the flood may leave out: which name it takes over,
    or what that name will run, is exactly what the suspecting model refuses to assume. Removing
    the discard below one is what `trust_eval` buys and only it may, so the default keeps it.
    """

    _UNREADABLE_BINDINGS = (
        'Set-Alias Some-Other-Name $target',
        "Set-Alias Some-Other-Name 'dI6tW'.Remove(3, 3)",
        'Set-Alias Some-Other-Name i*x -Force',
        'Set-Alias -Scope Global Some-Other-Name i*x',
        'Set-Alias Some-Other-Name i*x extra',
        'Set-Item alias:Some-Other-Name i*x',
    )

    def test_the_discarded_call_below_an_unreadable_binding_is_kept(self):
        for binding in self._UNREADABLE_BINDINGS:
            with self.subTest(binding):
                result = self._deobfuscate(
                    F'{binding}\n$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
                self.assertIn(_DISCARDED_TOKEN, result)
                self.assertIn(_ANCHOR_TOKEN, result)

    def test_a_script_that_redefines_set_alias_itself_keeps_the_discard(self):
        """
        The binding is read by spelling, so a `Set-Alias` the script has taken over with a function
        still reads as a binding of the name it spells. What runs is the function body, and the
        body is the leak that keeps the discard.
        """
        result = self._deobfuscate(
            'function Set-Alias { iex $x }\nSet-Alias Some-Other-Name WhatEver\n'
            F'$Null = Get-Random -Maximum 88175\n{_ANCHOR}')
        self.assertIn(_DISCARDED_TOKEN, result)
        self.assertIn(_ANCHOR_TOKEN, result)
