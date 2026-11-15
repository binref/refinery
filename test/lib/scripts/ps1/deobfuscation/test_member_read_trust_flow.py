from __future__ import annotations

import inspect

from test.lib.scripts.ps1.deobfuscation import TestPs1

_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

_MEMBER_READ = '$Null = (Get-Date).Ticks'

_LEAK = 'Invoke-Expression $enc'

_FUNCTION_LEAK = 'function Get-Date { Start-Process calc }'
_ALIAS_LEAK = 'Set-Alias Get-Date i*x'

_REDEFINED_CALL = 'Get-Date'


class TestPs1APureMemberReadFollowsTheSamePositionalTrust(TestPs1):

    def test_a_pure_member_read_with_no_leak_anywhere_is_removed(self):
        self.assertEqual(self._deobfuscate(inspect.cleandoc(F"""
            {_MEMBER_READ}
            {_ANCHOR}
        """)), _ANCHOR)

    def test_a_pure_member_read_after_a_leak_reachable_before_it_is_kept(self):
        source = inspect.cleandoc(F"""
            {_LEAK}
            {_MEMBER_READ}
            {_ANCHOR}
        """)
        self.assertEqual(self._deobfuscate(source), source)


class TestPs1APureMemberReadBeforeTheOnlyLeakIsRemoved(TestPs1):

    def test_a_pure_member_read_before_the_only_later_leak_is_removed(self):
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(F"""
                {_MEMBER_READ}
                {_LEAK}
                {_ANCHOR}
            """)),
            inspect.cleandoc(F"""
                {_LEAK}
                {_ANCHOR}
            """))


class TestPs1APureMemberReadBeforeARebinderOfItsOwnNameIsRemoved(TestPs1):

    def test_a_pure_member_read_before_the_only_function_redefinition_is_removed(self):
        self._assertDeobfuscatesTo(
            inspect.cleandoc(F"""
                {_MEMBER_READ}
                {_FUNCTION_LEAK}
                {_REDEFINED_CALL}
                {_ANCHOR}
            """),
            inspect.cleandoc(F"""
                {_FUNCTION_LEAK}
                {_REDEFINED_CALL}
                {_ANCHOR}
            """))

    def test_a_pure_member_read_before_the_only_set_alias_is_removed(self):
        self._assertDeobfuscatesTo(
            inspect.cleandoc(F"""
                {_MEMBER_READ}
                {_ALIAS_LEAK}
                {_ANCHOR}
            """),
            inspect.cleandoc(F"""
                {_ALIAS_LEAK}
                {_ANCHOR}
            """))


class TestPs1APureMemberReadAfterARebinderOfItsOwnNameIsKept(TestPs1):

    def test_a_pure_member_read_after_a_function_redefinition_is_kept(self):
        self._assertKept(inspect.cleandoc(F"""
            {_FUNCTION_LEAK}
            {_MEMBER_READ}
            {_ANCHOR}
        """))

    def test_a_pure_member_read_after_a_set_alias_is_kept(self):
        self._assertKept(inspect.cleandoc(F"""
            {_ALIAS_LEAK}
            {_MEMBER_READ}
            {_ANCHOR}
        """))


class TestPs1APureMemberReadSharingALoopBodyWithALeakIsKept(TestPs1):

    def test_a_pure_member_read_alone_in_a_loop_body_is_removed(self):
        self._assertDeobfuscatesTo(
            F'while ($True) {{ {_MEMBER_READ}; {_ANCHOR} }}',
            F'while ($True) {{ {_ANCHOR} }}')

    def test_a_pure_member_read_looping_with_an_opaque_leak_below_it_is_kept(self):
        self._assertKept(inspect.cleandoc(F"""
            while ($True) {{ {_MEMBER_READ}; {_LEAK} }}
            {_ANCHOR}
        """))

    def test_a_pure_member_read_looping_with_a_function_redefinition_below_it_is_kept(self):
        self._assertKept(inspect.cleandoc(F"""
            while ($True) {{ {_MEMBER_READ}; {_FUNCTION_LEAK} }}
            {_ANCHOR}
        """))

    def test_a_pure_member_read_looping_with_a_set_alias_below_it_is_kept(self):
        self._assertKept(inspect.cleandoc(F"""
            while ($True) {{ {_MEMBER_READ}; {_ALIAS_LEAK} }}
            {_ANCHOR}
        """))
