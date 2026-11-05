from __future__ import annotations

from test import TestBase, opportunity

from inspect import cleandoc

from refinery.lib.scripts.ps1.analysis.world import (
    Ps1TypeWorld,
    WorldRole,
    _opens_command_namespace,
    _opens_type_system,
    assigns_an_alias_name,
    build_closed_world,
    command_role,
    measure_world,
    opens_command_table_only_by_binding,
    touches_identity_provider,
)
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser


class Ps1TypeWorldTest(TestBase):

    @staticmethod
    def _closed(source: str) -> bool:
        script = Ps1Parser(source).parse()
        return build_closed_world(script).closed_for_the_whole_run

    @staticmethod
    def _closed_but_for_aliases(source: str) -> bool:
        script = Ps1Parser(source).parse()
        return build_closed_world(script).closed_but_for_alias_bindings


class TestPs1WorldOpeners(Ps1TypeWorldTest):

    def test_invoke_expression_opens_the_world(self):
        for source in (
            'iex $x',
            "Invoke-Expression 'Update-TypeData -TypeName System.String -MemberType NoteProperty "
            "-MemberName M -Value 1'",
            'Invoke-Expression (-Join $chars)',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_opaque_dispatch_opens_the_world(self):
        for source in ('& $f', '. $f', '& (Get-Command $n)', '. $env:x'):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_type_system_mutation_opens_the_world(self):
        for source in (
            'Update-TypeData -TypeName System.String -MemberName M -MemberType ScriptProperty -Value { 1 }',
            '$x | Add-Member -MemberType ScriptProperty -Name M -Value { 1 }',
            'Import-Module Foo',
            'ipmo Foo',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_reflective_type_mutation_opens_the_world(self):
        for source in (
            "[System.Management.Automation.PSObject+TypeAccelerators]::Add('x', [int])",
            "[System.Management.Automation.PSObject+TypeAccelerators]::Remove('x')",
            '$obj.PSObject.Members.Add($member)',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_command_identity_mutation_opens_the_world(self):
        for source in (
            "Set-Alias utd Update-TypeData",
            "New-Alias utd Update-TypeData",
            "Set-Item alias:utd Update-TypeData",
            "New-Item function:foo -Value { 1 }",
            '$alias:x = 1',
            '${function:Get-Date} = $blk',
            '${function:Get-Date} = (Get-Content f.ps1)',
            '${function:Get-Date} += { 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_command_lookup_hook_opens_the_world(self):
        for source in (
            '$ExecutionContext.InvokeCommand.PreCommandLookupAction = { 1 }',
            '$ExecutionContext.InvokeCommand.PostCommandLookupAction = { 1 }',
            '$ExecutionContext.InvokeCommand.CommandNotFoundAction = { 1 }',
            '$ExecutionContext.InvokeCommand.set_PreCommandLookupAction({ 1 })',
            '$ic = $ExecutionContext.InvokeCommand; $ic.CommandNotFoundAction = { 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_member_named_by_a_value_may_be_a_command_lookup_hook(self):
        for source in (
            '$ExecutionContext.InvokeCommand.($n) = { 1 }',
            '$ic = $ExecutionContext.InvokeCommand; $ic.($n)({ 1 })',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_scriptblock_execution_opens_the_world(self):
        for source in (
            '[scriptblock]::Create($s)',
            '$sb.Invoke()',
            '$sb.InvokeReturnAsIs()',
            '$sb.InvokeWithContext($f, $v)',
            '@(1).ForEach($sb)',
            '$ExecutionContext.InvokeCommand.InvokeScript($s)',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_dot_sourcing_a_file_opens_the_world(self):
        for source in (". 'helper.ps1'", '. .\\helper.ps1'):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_mutation_hidden_in_a_function_body_opens_the_world(self):
        source = 'function Reset { Update-TypeData -TypeName System.String -MemberName M }\nGet-Date'
        self.assertFalse(self._closed(source))


class TestPs1WorldClosed(Ps1TypeWorldTest):

    def test_an_ordinary_script_is_closed(self):
        for source in (
            "$x = 1\nWrite-Output $x",
            "$Null = [Environment]::UserName",
            "'abcdef'.Length",
            '[Math]::Max(1, 2)',
            'Get-ChildItem -Recurse | Where-Object { $_.Name }',
            '&{ 42 }',
            'New-Object System.Net.WebClient',
        ):
            with self.subTest(source):
                self.assertTrue(self._closed(source))


class TestPs1ShadowedCommands(Ps1TypeWorldTest):

    def test_a_redefinition_shadows_its_name(self):
        world = build_closed_world(Ps1Parser(
            "function Get-Date { 1 }\n"
            "filter Out-Null { $_ }\n"
            "${function:New-Object} = { 2 }\n"
            "$alias:gc = 'Get-Content'\n"
        ).parse())
        for name in ('get-date', 'out-null', 'new-object', 'gc'):
            with self.subTest(name):
                self.assertTrue(world.command_shadowed(name))
        self.assertFalse(world.command_shadowed('get-childitem'))

    def test_an_item_cmdlet_writing_a_provider_path_shadows_the_name_it_binds(self):
        for source in (
            'Set-Item function:Get-Date { 1 }',
            'Set-Item function:Get-Date -Value { 1 }',
            'New-Item function:Get-Date -Value { 1 }',
            "Set-Item 'Microsoft.PowerShell.Core\\Function::Get-Date' -Value { 1 }",
            'Set-Item Function:\\Get-Date -Value { 1 }',
            'Set-Item alias:Get-Date Stop-Process',
        ):
            with self.subTest(source):
                self.assertTrue(
                    build_closed_world(Ps1Parser(source).parse()).command_shadowed('get-date'))

    def test_a_provider_path_that_is_read_or_ordinary_shadows_nothing(self):
        for source in (
            'Get-Item function:Get-Date',
            'Write-Output function:Get-Date',
            'Set-Item C:\\tmp\\Get-Date.txt -Value 1',
        ):
            with self.subTest(source):
                self.assertFalse(
                    build_closed_world(Ps1Parser(source).parse()).command_shadowed('get-date'))

    def test_a_defined_function_does_not_open_the_world(self):
        self.assertTrue(self._closed('function Get-Date { 1 }\n$x = 2'))

    def test_a_redefinition_binding_a_visible_block_does_not_open_the_world(self):
        for source in (
            '${function:Get-Date} = { 1 }',
            '${function:Get-Date} = ({ 1 })',
            '${function:global:Get-Date} = { 1 }',
        ):
            with self.subTest(source):
                self.assertTrue(self._closed(source))
                self.assertTrue(
                    build_closed_world(Ps1Parser(source).parse()).command_shadowed('get-date'))

    def test_a_redefinition_binding_a_visible_block_in_a_multi_assignment_shadows_the_name(self):
        source = '${function:Get-Date}, $y = { 1 }, 2'
        self.assertTrue(build_closed_world(Ps1Parser(source).parse()).command_shadowed('get-date'))

    @opportunity
    def test_a_redefinition_by_multi_assignment_of_a_visible_block_does_not_open_the_world(self):
        self.assertTrue(self._closed('${function:Get-Date}, $y = { 1 }, 2'))

    def test_a_mutation_inside_a_visible_block_still_opens_the_world(self):
        for body in (
            'Update-TypeData -TypeName System.String -MemberName M -Value { 1 }',
            'param($p = (Update-TypeData -TypeName System.String -MemberName M -Value { 1 }))',
            'begin { Import-Module Evil }',
            'process { iex $x }',
            'end { Add-Member -InputObject $o -Name N -Value { 1 } }',
        ):
            with self.subTest(body):
                self.assertFalse(self._closed(F'${{function:Get-Date}} = {{ {body} }}'))

    def test_a_scope_qualified_redefinition_shadows_the_name_a_call_resolves_to(self):
        for source in (
            'function global:Get-Date { 1 }',
            'function local:Get-Date { 1 }',
            'function private:Get-Date { 1 }',
            'function script:Get-Date { 1 }',
            'function global:script:Get-Date { 1 }',
            'filter global:Get-Date { 1 }',
            '${function:global:Get-Date} = { 1 }',
        ):
            with self.subTest(source):
                world = build_closed_world(Ps1Parser(source).parse())
                self.assertTrue(world.command_shadowed('get-date'))

    def test_a_multi_assignment_shadows_every_identity_slot_it_writes(self):
        world = build_closed_world(Ps1Parser(
            '${function:Get-Date}, $y, $alias:gc = { 1 }, 2, 3').parse())
        self.assertTrue(world.command_shadowed('get-date'))
        self.assertTrue(world.command_shadowed('gc'))
        self.assertFalse(world.command_shadowed('y'))

    def test_a_module_qualified_name_does_not_shadow_the_bare_one(self):
        world = build_closed_world(Ps1Parser('function Module\\Get-Date { 1 }').parse())
        self.assertFalse(world.command_shadowed('get-date'))


class TestPs1OffTreeCodeOpensTheWorld(Ps1TypeWorldTest):

    def test_running_another_script_file_opens_the_world(self):
        for source in (
            ". '.\\stage2.ps1'",
            "& '.\\stage2.ps1'",
            'stage2.ps1',
            '& $PSScriptRoot\\stage2.ps1',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_running_a_block_supplied_as_data_opens_the_world(self):
        for source in (
            'Invoke-Command -ScriptBlock $sb',
            'New-Module -ScriptBlock $sb',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_defining_types_or_importing_identity_opens_the_world(self):
        for source in ('Add-Type -TypeDefinition $src', 'Import-Alias .\\a.csv'):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_module_qualifier_does_not_hide_an_opener(self):
        for source in (
            "& 'Microsoft.PowerShell.Utility\\Invoke-Expression' $x",
            "& 'Microsoft.PowerShell.Core\\Import-Module' Foo",
            "& 'Microsoft.PowerShell.Utility\\Update-TypeData' -TypeName System.String",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_the_execution_context_chain_is_matched_at_any_depth(self):
        for source in (
            '$ExecutionContext.InvokeCommand.InvokeScript($s)',
            '$ExecutionContext.SessionState.InvokeCommand.InvokeScript($s)',
            '$ExecutionContext.SessionState.InvokeCommand.NewScriptBlock($s)',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))


class TestPs1TypeDefinitionsOpenTheWorld(Ps1TypeWorldTest):

    def test_a_script_defined_type_opens_the_world(self):
        for source in (
            'class Loader { Loader([String]$s) { } }',
            'class Math { static [int] Abs([int]$x) { return 1 } }',
            'enum Version { A = 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))


class TestPs1QualifiedOpenerSpellings(Ps1TypeWorldTest):

    def test_a_scope_qualifier_does_not_hide_an_opener(self):
        for source in (
            "& 'global:iex' $x",
            "& 'script:Import-Module' Foo",
            "& 'global:Set-Alias' x Update-TypeData",
            'global:iex $x',
            'Microsoft.PowerShell.Utility\\iex $x',
            'Microsoft.PowerShell.Utility\\global:iex $x',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_qualified_provider_path_still_addresses_command_identity(self):
        for source in (
            'Set-Item function:Get-Date -Value { 1 }',
            "Set-Item 'Function::Get-Date' -Value { 1 }",
            "Set-Item 'Microsoft.PowerShell.Core\\Function::Get-Date' -Value { 1 }",
            "New-Item -Path 'Microsoft.PowerShell.Core\\Alias::gd' -Value Get-Date",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_the_drive_root_spelling_of_an_identity_path_names_the_same_item(self):
        for source in (
            'Set-Item Alias:\\zzq -Value Write-Output',
            'Set-Item alias:\\zzq -Value Write-Output',
            'New-Item -Path Alias:\\zzq -Value Write-Output',
            'Set-Item Function:\\foo -Value { 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_an_ordinary_path_argument_is_not_an_identity_write(self):
        for source in ('Set-Content C:\\tmp\\x.txt -Value 1', 'Get-Content .\\notes.txt'):
            with self.subTest(source):
                self.assertTrue(self._closed(source))


class TestPs1ClosedButForAliasBindings(Ps1TypeWorldTest):

    _SHAPES = (
        ('$x = 1', True, True),
        ('Get-ChildItem -Recurse', True, True),
        ('function f { 1 }', True, True),
        ('&{ 42 }', True, True),
        ('Set-Alias zzq Write-Output', False, True),
        ('sal zzq Write-Output', False, True),
        ('Set-Alias a X\nSet-Alias b Y', False, True),
        ('function f { Set-Alias zzq Write-Output }', False, True),
        ("& 'global:Set-Alias' zzq Write-Output", False, True),
        ('Set-Alias zzq Write-Output\niex $x', False, False),
        ('Set-Alias zzq Write-Output\n& $f', False, False),
        ('Set-Alias zzq Write-Output\nAdd-Type -TypeDefinition $s', False, False),
        ('Set-Alias zzq Write-Output\nclass C { }', False, False),
        ('Set-Alias zzq Write-Output\n${function:Get-Date} = $b', False, False),
        ("Set-Alias zzq Write-Output\n. '.\\stage2.ps1'", False, False),
        ('iex $x', False, False),
    )

    def test_both_verdicts_over_every_shape(self):
        for source, closed, but_for_bindings in self._SHAPES:
            with self.subTest(source):
                self.assertEqual(self._closed(source), closed)
                self.assertEqual(self._closed_but_for_aliases(source), but_for_bindings)

    def test_a_closed_world_is_closed_but_for_alias_bindings_as_well(self):
        for source in (
            '$x = 1',
            'Get-ChildItem -Recurse | Where-Object { $_.Name }',
            'New-Object System.Net.WebClient',
            'function Get-Date { 1 }',
        ):
            with self.subTest(source):
                self.assertTrue(self._closed(source))
                self.assertTrue(self._closed_but_for_aliases(source))

    def test_an_identity_change_that_is_not_a_binding_keeps_the_world_open(self):
        for source in (
            'New-Alias zzq Write-Output',
            'nal zzq Write-Output',
            'Remove-Alias zzq',
            'Import-Alias .\\a.csv',
            'Set-Item alias:zzq Write-Output',
            "$alias:zzq = 'Write-Output'",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed_but_for_aliases(source))

    @opportunity
    def test_a_dot_invoked_or_provider_spelled_binding_is_still_only_a_binding(self):
        for source in ('Set-Alias zzq alias:bar', '. Set-Alias zzq Write-Output'):
            with self.subTest(source):
                self.assertTrue(self._closed_but_for_aliases(source))

    def test_a_verdict_left_unstated_takes_the_value_of_the_closed_one(self):
        for closed in (True, False):
            with self.subTest(closed=closed):
                self.assertEqual(
                    Ps1TypeWorld(closed, frozenset()).closed_but_for_alias_bindings, closed)


class TestPs1IdentityProviderArguments(Ps1TypeWorldTest):

    @staticmethod
    def _touches(source: str) -> bool:
        script = Ps1Parser(source).parse()
        command, = (node for node in script.walk() if isinstance(node, Ps1CommandInvocation))
        return touches_identity_provider(command)

    def test_a_drive_qualified_argument_addresses_the_provider(self):
        for source in (
            'Set-Item alias:zzq Write-Output',
            'Remove-Item alias:zzq',
            'New-Item -Path alias:zzq -Value Write-Output',
            'Set-Item function:foo -Value { 1 }',
        ):
            with self.subTest(source):
                self.assertTrue(self._touches(source))
                self.assertFalse(self._closed(source))
        for source in (
            'Get-Content alias:gci',
            'Get-Content ALIAS:gci',
            'Get-Content Function:\\foo',
            'Get-Item Alias:\\zzq',
        ):
            with self.subTest(source):
                self.assertTrue(self._touches(source))

    def test_an_argument_that_only_spells_a_provider_name_is_an_ordinary_path(self):
        for source in (
            'Get-Content alias',
            'Set-Content function -Value 1',
            'Get-Content .\\alias.txt',
            'Remove-Item aliases.csv',
            'Set-Content aliasfunction -Value 1',
        ):
            with self.subTest(source):
                self.assertFalse(self._touches(source))
                self.assertTrue(self._closed(source))

    def test_a_drive_that_holds_no_command_identity_is_not_one_of_these(self):
        for source in (
            'Get-Content env:PATH',
            'Set-Item variable:x -Value 1',
            'Get-Content C:\\tmp\\x.txt',
        ):
            with self.subTest(source):
                self.assertFalse(self._touches(source))
                self.assertTrue(self._closed(source))


class TestPs1AliasNamespaceAssignments(TestBase):

    @staticmethod
    def _assigns(source: str) -> bool:
        script = Ps1Parser(source).parse()
        return any(assigns_an_alias_name(node) for node in script.walk())

    def test_a_write_through_the_alias_namespace_binds_a_command_name(self):
        for source in (
            "$alias:zzq = 'Get-Date'",
            "${alias:zzq} = 'Get-Date'",
            "$ALIAS:zzq = 'Get-Date'",
            "$alias:zzq += 'Get-Date'",
            "$alias:zzq, $y = 'Get-Date', 2",
            "$y, $alias:zzq = 1, 'Get-Date'",
        ):
            with self.subTest(source):
                self.assertTrue(self._assigns(source))

    def test_the_qualifier_belongs_inside_the_namespace_and_not_in_front_of_it(self):
        self.assertTrue(self._assigns("${alias:global:zzq} = 'Get-Date'"))
        self.assertFalse(self._assigns("$global:alias:zzq = 'Get-Date'"))

    def test_an_assignment_that_writes_no_alias_name_is_not_one(self):
        for source in (
            '$x = 1',
            "$alias = 'Get-Date'",
            "$aliaszzq = 'Get-Date'",
            "$env:alias = 'Get-Date'",
            '$y = $alias:zzq',
            '${function:foo} = { 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._assigns(source))


class TestPs1WorldAxes(Ps1TypeWorldTest):

    @staticmethod
    def _axes(source: str) -> tuple[bool, bool, bool]:
        world = build_closed_world(Ps1Parser(source).parse())
        return (
            world.type_system_closed,
            world.command_table_closed,
            world.closed_for_the_whole_run,
        )

    def test_each_opener_opens_exactly_the_axes_it_should(self):
        for source, type_closed, command_closed in (
            ("Write-Host 'A'", True, True),
            ('class C { }', False, True),
            ('enum E { A }', False, True),
            ("Add-Type -TypeDefinition 'public class Z {}'", False, True),
            ('Update-TypeData -Force -TypeName System.String -MemberName Q -Value 1', False, True),
            ("[System.Management.Automation.PSObject+TypeAccelerators]::Add('z', [int])", False, True),
            ('$o.PSObject.Members.Add($m)', False, True),
            ('Add-Member -InputObject $o -Name Q -Value 1 -MemberType NoteProperty', False, True),
            ('Import-Module .\\m.psm1', False, False),
            ('ipmo .\\m.psm1', False, False),
            ('New-Module -ScriptBlock $b', False, False),
            ('nmo -ScriptBlock $b', False, False),
            ('Set-Alias zzq Write-Output', True, False),
            ('New-Alias zzq Write-Output', True, False),
            ('${function:zzq} = $b', True, False),
            ('Invoke-Expression $code', False, False),
            (". '.\\stage2.ps1'", False, False),
            ('& $dispatch', False, False),
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._axes(source),
                    (type_closed, command_closed, type_closed and command_closed),
                )

    def test_the_whole_run_verdict_is_the_conjunction_not_a_stored_flag(self):
        self.assertTrue(Ps1TypeWorld(True, frozenset()).closed_for_the_whole_run)
        self.assertFalse(Ps1TypeWorld(False, frozenset()).closed_for_the_whole_run)
        self.assertTrue(
            Ps1TypeWorld(True, frozenset(), command_table_closed=True).closed_for_the_whole_run)
        self.assertFalse(
            Ps1TypeWorld(True, frozenset(), command_table_closed=False).closed_for_the_whole_run)

    def test_a_command_axis_left_unstated_takes_the_value_of_the_type_axis(self):
        for closed in (True, False):
            with self.subTest(closed=closed):
                world = Ps1TypeWorld(closed, frozenset())
                self.assertEqual(world.type_system_closed, closed)
                self.assertEqual(world.command_table_closed, closed)

    def test_every_opener_role_opens_at_least_one_axis(self):
        for role in WorldRole:
            if role is WorldRole.NONE:
                continue
            with self.subTest(role):
                self.assertTrue(_opens_type_system(role) or _opens_command_namespace(None, role))


class TestPs1CommandRole(TestBase):

    def test_a_command_that_runs_data_as_code_is_a_leak(self):
        for name in ('Invoke-Expression', 'Invoke-Command', 'Start-Job', 'Start-ThreadJob'):
            with self.subTest(name):
                self.assertEqual(command_role(name), WorldRole.LEAK)

    def test_a_command_that_mutates_the_type_system_is_a_mutation(self):
        for name in ('Add-Member', 'Add-Type', 'Import-Module', 'New-Module', 'Update-TypeData'):
            with self.subTest(name):
                self.assertEqual(command_role(name), WorldRole.MUTATION)

    def test_a_command_that_redefines_command_identity_is_an_identity_change(self):
        for name in ('Import-Alias', 'New-Alias', 'Remove-Alias', 'Set-Alias'):
            with self.subTest(name):
                self.assertEqual(command_role(name), WorldRole.IDENTITY)

    def test_a_name_no_deny_list_holds_leaves_the_world_as_it_found_it(self):
        for name in ('Get-ChildItem', 'Write-Output', 'Get-Date', 'Some-Unknown-Command'):
            with self.subTest(name):
                self.assertEqual(command_role(name), WorldRole.NONE)

    def test_no_name_denotes_an_unknown_role(self):
        names = (
            'Invoke-Expression',
            'Update-TypeData',
            'Set-Alias',
            'Get-ChildItem',
            "('Inv' + 'oke-Expression')",
            '',
        )
        self.assertEqual(
            {command_role(name) for name in names},
            {WorldRole.LEAK, WorldRole.MUTATION, WorldRole.IDENTITY, WorldRole.NONE},
        )

    def test_a_mutator_keeps_its_role_under_every_qualifier_it_can_arrive_with(self):
        spellings = (
            'update-typedata',
            'Update-TypeData',
            'UPDATE-TYPEDATA',
            'global:Update-TypeData',
            'script:Update-TypeData',
            'global:script:Update-TypeData',
            'Microsoft.PowerShell.Utility\\Update-TypeData',
            'Microsoft.PowerShell.Utility\\global:Update-TypeData',
        )
        self.assertEqual({command_role(name) for name in spellings}, {WorldRole.MUTATION})

    def test_a_leak_keeps_its_role_under_every_qualifier_it_can_arrive_with(self):
        spellings = (
            'invoke-expression',
            'Invoke-Expression',
            'global:Invoke-Expression',
            'Microsoft.PowerShell.Utility\\Invoke-Expression',
            'Microsoft.PowerShell.Utility\\script:Invoke-Expression',
        )
        self.assertEqual({command_role(name) for name in spellings}, {WorldRole.LEAK})

    def test_a_builtin_alias_spelling_reaches_the_entry_its_target_holds(self):
        for name, role in (
            ('icm', WorldRole.LEAK),
            ('iex', WorldRole.LEAK),
            ('sajb', WorldRole.LEAK),
            ('ipmo', WorldRole.MUTATION),
            ('nmo', WorldRole.MUTATION),
            ('ipal', WorldRole.IDENTITY),
            ('nal', WorldRole.IDENTITY),
            ('sal', WorldRole.IDENTITY),
        ):
            with self.subTest(name):
                self.assertEqual(command_role(name), role)

    def test_a_builtin_alias_of_a_command_no_deny_list_holds_is_still_none(self):
        for name in ('gci', 'gc', 'epal'):
            with self.subTest(name):
                self.assertEqual(command_role(name), WorldRole.NONE)

    def test_an_alias_spelling_collapses_under_a_qualifier_like_any_other(self):
        spellings = (
            'ipmo',
            'IPMO',
            'global:ipmo',
            'Microsoft.PowerShell.Core\\ipmo',
            'Microsoft.PowerShell.Core\\global:ipmo',
            'Import-Module',
        )
        self.assertEqual({command_role(name) for name in spellings}, {WorldRole.MUTATION})


class TestPs1TrustedEvalNarrowsTheOpenerListAndNothingElse(TestBase):

    _ONE_OF_EVERY_KIND = cleandoc("""
        Invoke-Expression $c
        & $f
        . C:/stage2.ps1
        Set-Alias Copy-Item $t
        Set-Item alias:Out-Null Write-Host
        Add-Type -TypeDefinition $src
        Update-TypeData -TypeName System.Int32 -MemberName X -Value 1
        class Zzq {
        }
        function Get-Date {
        }
    """)

    @classmethod
    def setUpClass(cls):
        script = Ps1Parser(cls._ONE_OF_EVERY_KIND).parse()
        cls.suspecting = measure_world(script, Ps1DeobfuscationOptions(trust_eval=False))
        cls.trusting = measure_world(script, Ps1DeobfuscationOptions(trust_eval=True))

    @staticmethod
    def _written_as(node) -> str:
        if isinstance(node, Ps1CommandInvocation):
            return get_command_name(node) or '&'
        return type(node).__name__

    def test_the_suspecting_model_records_every_construct(self):
        self.assertCountEqual(
            [self._written_as(node) for node in self.suspecting.openers],
            [
                'Ps1ClassDefinition',
                'Update-TypeData',
                'Add-Type',
                'Set-Item',
                'Set-Alias',
                'C:/stage2.ps1',
                '&',
                'Invoke-Expression',
            ],
        )

    def test_the_trusting_model_withholds_only_the_ones_running_unreadable_code(self):
        self.assertCountEqual(
            [self._written_as(node) for node in self.trusting.openers],
            [
                'Ps1ClassDefinition',
                'Update-TypeData',
                'Add-Type',
                'Set-Item',
            ],
        )

    def test_the_shadow_set_is_the_same_under_both_models(self):
        self.assertEqual(
            self.suspecting.world.shadowed_names,
            self.trusting.world.shadowed_names,
        )

    def test_the_invoked_names_are_the_same_under_both_models(self):
        self.assertEqual(
            self.suspecting.invoked_command_names,
            self.trusting.invoked_command_names,
        )
        self.assertLessEqual(
            {'invoke-expression', 'set-alias', 'set-item', 'add-type', 'update-typedata'},
            self.suspecting.invoked_command_names,
        )

    def test_the_verdict_and_the_opener_list_stay_one_fact(self):
        for name in ('suspecting', 'trusting'):
            with self.subTest(name):
                measured = getattr(self, name)
                self.assertEqual(measured.world.closed_for_the_whole_run, not measured.openers)


class TestPs1TheMeasurementRecordsEveryNameTheScriptInvokes(TestBase):

    @staticmethod
    def _invoked(source: str) -> frozenset[str]:
        return measure_world(Ps1Parser(cleandoc(source)).parse()).invoked_command_names

    def test_every_static_spelling_resolves_to_the_command_it_runs(self):
        self.assertEqual(
            self._invoked("""
                gci 'a'
                & 'global:iex' $x
                Microsoft.PowerShell.Utility\\Write-Output 'b'
                WRITE-HOST 'c'
                script:Get-Date
            """),
            {'get-childitem', 'invoke-expression', 'write-output', 'write-host', 'get-date'},
        )

    def test_a_computed_name_is_not_a_name(self):
        self.assertEqual(
            self._invoked("""
                & $f 'a'
                & ('i' + 'ex') 'b'
                & { Write-Host 'c' }
            """),
            {'write-host'},
        )

    def test_a_name_counts_wherever_in_the_tree_it_is_invoked(self):
        self.assertEqual(
            self._invoked("""
                function f { Zzq-Alpha }
                $b = { Zzq-Beta }
                if ($x) { Zzq-Gamma } else { Write-Output (Zzq-Delta) }
            """),
            {'zzq-alpha', 'zzq-beta', 'zzq-gamma', 'zzq-delta', 'write-output'},
        )

    def test_a_bare_noun_records_its_implicit_get_retry_name(self):
        self.assertEqual(
            self._invoked('item\nchilditem\nGet-Random'),
            {'item', 'get-item', 'childitem', 'get-childitem', 'get-random'},
        )

    def test_a_script_that_invokes_nothing_records_nothing(self):
        self.assertEqual(self._invoked("$x = 1\n$y = $x + 'a'"), frozenset())


class TestPs1ABindingOfOneNameIsTheOpenerTheFloodMayLeaveOut(TestBase):

    @staticmethod
    def _bound(source: str) -> str | None:
        opener, = measure_world(Ps1Parser(source).parse()).openers
        return opens_command_table_only_by_binding(opener)

    def test_a_written_out_binding_names_the_command_it_takes_over(self):
        for source in (
            'Set-Alias zzq Write-Output',
            'sal zzq Write-Output',
            'New-Alias zzq Write-Output',
            'nal zzq Write-Output',
            'Set-Alias -Name zzq -Value Write-Output',
            'Set-Alias -Value Write-Output -Name zzq',
            'Set-Alias -N zzq -V Write-Output',
            'Set-Alias zzq Write-*',
            'Set-Alias zzq i*x',
            'Set-Alias zzq zzq',
            '& Set-Alias zzq Write-Output',
        ):
            with self.subTest(source):
                self.assertEqual(self._bound(source), 'zzq')

    def test_the_name_is_read_the_way_a_call_to_it_resolves(self):
        for source, name in (
            ('Set-Alias gci Foo', 'get-childitem'),
            ('Set-Alias Get-ChildItem Foo', 'get-childitem'),
            ('Set-Alias ZZQ Foo', 'zzq'),
            ('Set-Alias global:zzq Foo', 'zzq'),
            ('Set-Alias script:zzq Foo', 'zzq'),
            ("Set-Alias 'Microsoft.PowerShell.Utility\\zzq' Foo", 'zzq'),
        ):
            with self.subTest(source):
                self.assertEqual(self._bound(source), name)

    def test_a_binding_the_reader_cannot_account_for_is_not_one(self):
        for source in (
            'Set-Alias zzq $target',
            "Set-Alias zzq 'dI6tW'.Remove(3, 3)",
            'Set-Alias zzq (Get-Command Write-Output)',
            'Set-Alias zzq Write-Output -Force',
            'Set-Alias zzq Write-Output -Option ReadOnly',
            'Set-Alias -Scope Global zzq Write-Output',
            'Set-Alias zzq Write-Output extra',
            'Set-Alias -Value -Name zzq Write-Output',
        ):
            with self.subTest(source):
                self.assertIsNone(self._bound(source))

    def test_an_opener_that_is_not_a_written_out_binding_is_not_one(self):
        for source in (
            'Set-Item alias:zzq Write-Output',
            'New-Item -Path Alias:\\zzq -Value Write-Output',
            "Import-Alias 'C:/a.csv'",
            'Remove-Alias zzq',
            '$alias:zzq = 1',
            '${function:zzq} = $blk',
            'Invoke-Expression $c',
            '& $f',
            '. C:/stage2.ps1',
            'Update-TypeData -TypeName System.Int32 -MemberName X -Value 1',
            'class Zzq {}',
        ):
            with self.subTest(source):
                self.assertIsNone(self._bound(source))


class TestPs1AMemberNameNobodyCanReadOnATypeLiteralIsOneOfItsStaticMembers(Ps1TypeWorldTest):

    def test_a_computed_static_call_on_a_collected_type_leaves_the_world_closed(self):
        for call in ("[Convert]::('FromBase64String')($p)", '[Convert]::($n)($p)'):
            with self.subTest(call=call):
                self.assertTrue(self._closed(call))

    def test_a_computed_call_on_anything_else_opens_the_world(self):
        for call in (
            '[Zq.Nope.Type]::($m)($b)',
            '$x.($m)($b)',
            '$ExecutionContext.InvokeCommand.($m)($b)',
            '([Convert])::($m)($b)',
        ):
            with self.subTest(call=call):
                self.assertFalse(self._closed(call))

    def test_a_computed_static_call_on_the_block_type_may_make_a_block(self):
        for call in ("[scriptblock]::($m)('f1')", "[scriptblock]::('Create')('f1')"):
            with self.subTest(call=call):
                self.assertFalse(self._closed(call))
