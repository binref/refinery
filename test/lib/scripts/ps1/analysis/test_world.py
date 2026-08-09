from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.analysis.world import (
    Ps1TypeWorld,
    WorldRole,
    assigns_an_alias_name,
    build_closed_world,
    command_role,
    touches_identity_provider,
)
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.parser import Ps1Parser


class Ps1TypeWorldTest(TestBase):
    """
    The closed-world predicate is the soundness floor under the member gate: a present-member purity
    grant is trusted only where no code the script runs could have mutated the type system or the
    command table, or executed opaque code that might. What matters is that every such opener is seen
    as one and an ordinary script is not, since a false "closed" deletes a read that runs code and a
    false "open" only keeps one.
    """

    @staticmethod
    def _closed(source: str) -> bool:
        script = Ps1Parser(source).parse()
        return build_closed_world(script).world_closed_at(None)

    @staticmethod
    def _closed_but_for_aliases(source: str) -> bool:
        script = Ps1Parser(source).parse()
        return build_closed_world(script).closed_but_for_alias_bindings


class TestPs1WorldOpeners(Ps1TypeWorldTest):

    def test_invoke_expression_opens_the_world(self):
        # Any Invoke-Expression, not only an opaque one: a constant argument can still carry a type
        # mutation, and it is inlined by a later pass than the one that consults this.
        for source in (
            'iex $x',
            "Invoke-Expression 'Get-Date'",
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
            '${function:Get-Date}, $y = { 1 }, 2',
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
        # The predicate walks the whole tree, so a mutator inside a defined function is seen even
        # before any call to it.
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
    """
    The shadow set records which command names the script redefines, so the analysis stops trusting
    the metadata for them. It is separate from the closed/open verdict — defining a function does not
    open the world (a benign helper would neuter every grant), it only distrusts that one name.
    """

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

    def test_a_defined_function_does_not_open_the_world(self):
        self.assertTrue(self._closed('function Get-Date { 1 }\n$x = 2'))

    def test_a_redefinition_binding_a_visible_block_does_not_open_the_world(self):
        # `${function:X} = { ... }` is `function X { ... }` in the other spelling, and the block
        # stands in the tree either way. Opening on it killed every member grant in the script over
        # a name the shadow set already distrusts.
        for source in (
            '${function:Get-Date} = { 1 }',
            '${function:Get-Date} = ({ 1 })',
            '${function:global:Get-Date} = { 1 }',
        ):
            with self.subTest(source):
                self.assertTrue(self._closed(source))
                self.assertTrue(
                    build_closed_world(Ps1Parser(source).parse()).command_shadowed('get-date'))

    def test_a_mutation_inside_a_visible_block_still_opens_the_world(self):
        # The relaxation above rests entirely on the walk reaching into the block, so a mutation
        # hidden in one has to be caught by presence like any other statement. Every place a block
        # can carry code is checked, because reaching only the plain body would make the relaxation
        # a way to smuggle a mutation past the gate.
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
        # A qualifier selects which scope table the definition is written to; it is not part of the
        # name. `function global:Get-Date` is what a later bare `Get-Date` runs, so a shadow set
        # holding the qualified spelling answers every consumer's question about the wrong name.
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
        # `Module\Get-Date` names one module's export and leaves the bare name alone, so stripping
        # the qualifier off this spelling would distrust a command nothing redefined.
        world = build_closed_world(Ps1Parser('function Module\\Get-Date { 1 }').parse())
        self.assertFalse(world.command_shadowed('get-date'))


class TestPs1OffTreeCodeOpensTheWorld(Ps1TypeWorldTest):
    """
    Every construct that runs code this tree does not contain has to open the world, whatever
    spelling it wears. The mutations that matter — an Extended Type System member, a type
    accelerator, an exported command — are runspace-global, so neither the operator used to reach
    the code nor the scope it runs in contains them.
    """

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
            'Start-Job -ScriptBlock $sb',
            'New-Module -ScriptBlock $sb',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_defining_types_or_importing_identity_opens_the_world(self):
        for source in ('Add-Type -TypeDefinition $src', 'Import-Alias .\\a.csv'):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_module_qualifier_does_not_hide_an_opener(self):
        # A qualifier selects which module's export is meant; it does not make the command something
        # the deny-list has never heard of. Only the quoted spelling is covered: the lexer splits an
        # unquoted `Module\\Command` at the backslash, so the name never reaches this predicate
        # whole.
        for source in (
            "& 'Microsoft.PowerShell.Utility\\Invoke-Expression' $x",
            "& 'Microsoft.PowerShell.Core\\Import-Module' Foo",
            "& 'Microsoft.PowerShell.Utility\\Update-TypeData' -TypeName System.String",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_the_execution_context_chain_is_matched_at_any_depth(self):
        # `$ExecutionContext.SessionState.InvokeCommand` reaches the same object the short spelling
        # does, so accepting only one depth leaves the other reading as an ordinary member call.
        for source in (
            '$ExecutionContext.InvokeCommand.InvokeScript($s)',
            '$ExecutionContext.SessionState.InvokeCommand.InvokeScript($s)',
            '$ExecutionContext.SessionState.InvokeCommand.NewScriptBlock($s)',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))


class TestPs1TypeDefinitionsOpenTheWorld(Ps1TypeWorldTest):
    """
    A `class` or `enum` puts a type into the session under a name the collected metadata never
    described — the same thing `Add-Type` does, and it is on the deny-list. The case that matters is
    a name the metadata *did* describe, because every purity grant keyed on a resolved type then
    vouches for a body standing in this very script.
    """

    def test_a_script_defined_type_opens_the_world(self):
        for source in (
            'class Loader { Loader([String]$s) { } }',
            'class Math { static [int] Abs([int]$x) { return 1 } }',
            'enum Version { A = 1 }',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))


class TestPs1QualifiedOpenerSpellings(Ps1TypeWorldTest):
    """
    A qualifier selects which module or scope an opener is taken from; it does not make the command
    something the deny-list has never heard of. Every qualifier the deny-list does not strip is a
    spelling that runs the opener while the world reports closed.
    """

    def test_a_scope_qualifier_does_not_hide_an_opener(self):
        for source in (
            "& 'global:iex' $x",
            "& 'script:Import-Module' Foo",
            "& 'global:Set-Alias' x Update-TypeData",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_a_qualified_provider_path_still_addresses_command_identity(self):
        # `Microsoft.PowerShell.Core\Function::Get-Date` is what `function:Get-Date` abbreviates, so
        # a test that only knows the short spelling reads the long one as an ordinary file path.
        for source in (
            'Set-Item function:Get-Date -Value { 1 }',
            "Set-Item 'Function::Get-Date' -Value { 1 }",
            "Set-Item 'Microsoft.PowerShell.Core\\Function::Get-Date' -Value { 1 }",
            "New-Item -Path 'Microsoft.PowerShell.Core\\Alias::gd' -Value Get-Date",
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_the_drive_root_spelling_of_an_identity_path_names_the_same_item(self):
        # `Alias:\gd` and `alias:gd` name one item of one provider; the root separator is only how
        # the path is written when it starts at the drive. Measured on 5.1, `Set-Item Alias:\gd
        # -Value Get-Date` binds `gd` and `Get-Item Alias:\gd` reads what it is bound to.
        for source in (
            'Set-Item Alias:\\zzq -Value Write-Output',
            'Set-Item alias:\\zzq -Value Write-Output',
            'New-Item -Path Alias:\\zzq -Value Write-Output',
            'Get-Item Alias:\\zzq',
            'Set-Item Function:\\foo -Value { 1 }',
            'Get-Content Function:\\foo',
        ):
            with self.subTest(source):
                self.assertFalse(self._closed(source))

    def test_an_ordinary_path_argument_is_not_an_identity_write(self):
        for source in ('Set-Content C:\\tmp\\x.txt -Value 1', 'Get-Content .\\notes.txt'):
            with self.subTest(source):
                self.assertTrue(self._closed(source))


class TestPs1ClosedButForAliasBindings(Ps1TypeWorldTest):
    """
    Whether the only thing holding a world open is that the script binds aliases, so that a pass
    which deleted every `Set-Alias` would leave it closed. A caller cannot reach this from
    `world_closed_at` and the list of what it is about to remove, because a verdict of open names no
    reason; it is read here so that the two answers cannot disagree about what an opener is.
    """

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
        """
        Only `Set-Alias` is set aside. `New-Alias` throws on a name that already has a binding,
        `Import-Alias` reads a file this analysis cannot see, and a provider path or a namespace
        assignment is not a binding this model reads at all, so none of them is something a caller
        is in a position to delete.
        """
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

    def test_a_binding_that_is_also_something_else_is_not_only_a_binding(self):
        for source in ('Set-Alias zzq alias:bar', '. Set-Alias zzq Write-Output'):
            with self.subTest(source):
                self.assertFalse(self._closed_but_for_aliases(source))

    def test_a_verdict_left_unstated_takes_the_value_of_the_closed_one(self):
        for closed in (True, False):
            with self.subTest(closed=closed):
                self.assertEqual(
                    Ps1TypeWorld(closed, frozenset()).closed_but_for_alias_bindings, closed)


class TestPs1IdentityProviderArguments(Ps1TypeWorldTest):
    """
    Whether an argument addresses the `alias:` or `function:` provider. The drive separator is the
    whole of the difference: measured on 5.1, `Get-Content alias:gci` reads `Get-ChildItem` out of
    the alias drive, while `Get-Content alias` looks for a file named `alias` in the current
    directory and fails when there is none.
    """

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
            'Get-Content alias:gci',
            'Get-Content ALIAS:gci',
            'Set-Item function:foo -Value { 1 }',
            'Get-Content Function:\\foo',
        ):
            with self.subTest(source):
                self.assertTrue(self._touches(source))
                self.assertFalse(self._closed(source))

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
    """
    Which assignments bind a command name through the `alias:` namespace. Measured on 5.1, every
    shape in the first test leaves the alias drive holding a definition for `zzq` that the statement
    put there, the `+=` form by appending to the definition the name already carried.
    """

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
        """
        Measured on 5.1: `${alias:global:zzq} = 'Get-Date'` puts an item into the alias drive, where
        `$global:alias:zzq = 'Get-Date'` makes a global *variable* named `alias:zzq` and leaves the
        alias drive with nothing in it.
        """
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


class TestPs1CommandRole(TestBase):
    """
    `command_role` is the one reading of the three deny-lists, keyed on a name rather than on a
    node. Both readers of a role reach the tables through it — the whole-script verdict above and
    the per-invocation refinement in the command model — so a spelling it misses is a spelling that
    dodges every table at once, and a role it names wrongly is named wrongly everywhere.
    """

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
        """
        Not knowing what runs is a fact about an invocation, never about a name: a name is by
        construction something the tables can be asked about, so even a spelling no command wears
        answers with the role it has, which is none.
        """
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
        """
        The one hop through the built-in alias table is part of the key. These eight are the whole
        of what it buys: every other spelling under which a denied command can arrive is a
        qualifier. A caller handing over one of them unresolved would otherwise be told by a
        deny-list that the command does nothing, which is the one direction a deny-list must not
        fail in.
        """
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
        """
        The hop resolves a spelling; it does not widen the tables. `epal` is the case that matters:
        exporting aliases to a file is not redefining one, so the aliasing family it belongs to has
        no claim on the identity list.
        """
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
