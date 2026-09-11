from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

#: An acting statement that is never a removal candidate; a `Write-Host` writes to the host and can
#: never be dropped, so its survival says only that the pass did not empty the script wholesale.
_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

#: A discarded pure member read on the result of a pure typed cmdlet: `(Get-Date)` yields a `DateTime`
#: and `.Ticks` is a plain property read with no side effect, so `$Null =` sinks a value nothing
#: observes. Neither `Get-Date` nor `Ticks` occurs in the anchor or the leak, so the rendered read is
#: a distinctive marker whose absence from the output means the whole statement was removed.
_MEMBER_READ = '$Null = (Get-Date).Ticks'

#: An opaque rebinder of any command name. Placed after the read, it cannot have run at the read's
#: position and so cannot change what `(Get-Date)` resolves to before the read executes.
_LEAK = 'Invoke-Expression $enc'

#: Rebinders of the receiver's own name rather than of every name. The `function` takes `Get-Date`
#: over with a body that starts a process, and the `Set-Alias` points the name at a wildcard target
#: the aliaser cannot resolve away, so under either one `(Get-Date).Ticks` is no longer a pure read.
_FUNCTION_LEAK = 'function Get-Date { Start-Process calc }'
_ALIAS_LEAK = 'Set-Alias Get-Date i*x'

#: A call of the taken-over name, so that a `function` leak written below the read is referenced and
#: the asserted remainder cannot shrink because the definition itself went unused.
_REDEFINED_CALL = 'Get-Date'


class _Ps1MemberReadTrustFlow(TestPs1):

    def _assertDeobfuscatesTo(self, source: str, expected: str) -> None:
        """
        `expected` is written as ordinary PowerShell and rendered through the synthesizer before the
        comparison, so that brace layout cannot be mistaken for a statement having been removed.
        """
        self.assertEqual(self._deobfuscate(source), self._apply(expected))

    def _assertKept(self, source: str) -> None:
        self._assertDeobfuscatesTo(source, source)


class TestPs1APureMemberReadFollowsTheSamePositionalTrust(_Ps1MemberReadTrustFlow):
    """
    A discarded pure member read on a pure typed cmdlet result is junk when nothing that could
    change the command world has run before it. Trust is positional: a leak that only follows the
    read cannot have run at the read's position, so it cannot make `(Get-Date)` resolve to anything
    other than the built-in whose result carries the side-effect-free `.Ticks` property. With the
    leak ahead of the read instead, the read may observe a rebound world and is soundly kept.
    """

    def test_a_pure_member_read_with_no_leak_anywhere_is_removed(self):
        self.assertEqual(self._deobfuscate(F'{_MEMBER_READ}\n{_ANCHOR}'), _ANCHOR)

    def test_a_pure_member_read_after_a_leak_reachable_before_it_is_kept(self):
        source = F'{_LEAK}\n{_MEMBER_READ}\n{_ANCHOR}'
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1APureMemberReadBeforeTheOnlyLeakIsRemoved(_Ps1MemberReadTrustFlow):
    """
    The command-name trust pass removes a discarded pure command placed before the only later leak,
    because the leak cannot have run at that position. A member read's purity depends in addition
    on resolving the receiver's type, and that resolution asks the same positional question, so the
    read is removed on the same terms: nothing that could change what `Get-Date` denotes has run
    before it.
    """

    def test_a_pure_member_read_before_the_only_later_leak_is_removed(self):
        self.assertEqual(
            self._deobfuscate(F'{_MEMBER_READ}\n{_LEAK}\n{_ANCHOR}'),
            F'{_LEAK}\n{_ANCHOR}')


class TestPs1APureMemberReadBeforeARebinderOfItsOwnNameIsRemoved(_Ps1MemberReadTrustFlow):
    """
    A statement that takes the receiver's own command name over binds it only from where it runs
    onwards, so a read written above it still resolves `Get-Date` to the built-in and still yields a
    `DateTime` whose `.Ticks` nothing observes. Both spellings of such a takeover, the `function`
    and the `Set-Alias`, leave the read removable when they follow it.
    """

    def test_a_pure_member_read_before_the_only_function_redefinition_is_removed(self):
        self._assertDeobfuscatesTo(
            F'{_MEMBER_READ}\n{_FUNCTION_LEAK}\n{_REDEFINED_CALL}\n{_ANCHOR}',
            F'{_FUNCTION_LEAK}\n{_REDEFINED_CALL}\n{_ANCHOR}')

    def test_a_pure_member_read_before_the_only_set_alias_is_removed(self):
        self._assertDeobfuscatesTo(
            F'{_MEMBER_READ}\n{_ALIAS_LEAK}\n{_ANCHOR}',
            F'{_ALIAS_LEAK}\n{_ANCHOR}')


class TestPs1APureMemberReadAfterARebinderOfItsOwnNameIsKept(_Ps1MemberReadTrustFlow):
    """
    Once the receiver's own name has been taken over, `(Get-Date)` runs the redefinition instead of
    the built-in, so the call can start a process and `.Ticks` no longer names a known plain
    property. The read is then not provably unobservable and must survive, under either spelling of
    the takeover.
    """

    def test_a_pure_member_read_after_a_function_redefinition_is_kept(self):
        self._assertKept(F'{_FUNCTION_LEAK}\n{_MEMBER_READ}\n{_ANCHOR}')

    def test_a_pure_member_read_after_a_set_alias_is_kept(self):
        self._assertKept(F'{_ALIAS_LEAK}\n{_MEMBER_READ}\n{_ANCHOR}')


class TestPs1APureMemberReadSharingALoopBodyWithALeakIsKept(_Ps1MemberReadTrustFlow):
    """
    Inside a loop body, source order does not decide what has run: the back edge places a leak
    written below the read before the read of every iteration but the first, so the read is kept
    although no leak precedes it on the page. The same read alone in the same loop is removed, so
    a loop body is not itself a sanctuary and the three kept cases cannot pass by the pass
    declining to enter loops.
    """

    def test_a_pure_member_read_alone_in_a_loop_body_is_removed(self):
        self._assertDeobfuscatesTo(
            F'while ($True) {{ {_MEMBER_READ}; {_ANCHOR} }}',
            F'while ($True) {{ {_ANCHOR} }}')

    def test_a_pure_member_read_looping_with_an_opaque_leak_below_it_is_kept(self):
        self._assertKept(F'while ($True) {{ {_MEMBER_READ}; {_LEAK} }}\n{_ANCHOR}')

    def test_a_pure_member_read_looping_with_a_function_redefinition_below_it_is_kept(self):
        self._assertKept(F'while ($True) {{ {_MEMBER_READ}; {_FUNCTION_LEAK} }}\n{_ANCHOR}')

    def test_a_pure_member_read_looping_with_a_set_alias_below_it_is_kept(self):
        self._assertKept(F'while ($True) {{ {_MEMBER_READ}; {_ALIAS_LEAK} }}\n{_ANCHOR}')
