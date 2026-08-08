from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.commands import (
    AliasDefinition,
    CommandKind,
    Denotation,
    build_command_model,
    extract_alias_definition,
)
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.world import WorldRole
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1Script
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _script(source: str) -> Ps1Script:
    return Ps1Parser(source).parse()


def _use(tree: Ps1Script, name: str) -> Ps1CommandInvocation:
    return next(
        node for node in tree.walk()
        if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == name
    )


def _sole_invocation(tree: Ps1Script) -> Ps1CommandInvocation:
    invocation, = (node for node in tree.walk() if isinstance(node, Ps1CommandInvocation))
    return invocation


def _denotation(source: str, name: str) -> Denotation:
    tree = _script(source)
    return Ps1ModelCache(tree).commands.denotation(_use(tree, name))


def _world_role(source: str, name: str) -> WorldRole:
    tree = _script(source)
    return Ps1ModelCache(tree).commands.world_role(_use(tree, name))


def _sole_world_role(source: str) -> WorldRole:
    tree = _script(source)
    return Ps1ModelCache(tree).commands.world_role(_sole_invocation(tree))


def _binding(source: str) -> tuple[str, str | None, bool, bool, bool] | None:
    """
    What `extract_alias_definition` reads out of the one invocation in `source`, without the node it
    read it from.
    """
    definition = extract_alias_definition(_sole_invocation(_script(source)))
    if definition is None:
        return None
    return (
        definition.name,
        definition.target,
        definition.refuse,
        definition.wildcard,
        definition.throws_if_bound,
    )


def _implicated(source: str, name: str) -> frozenset[tuple[str, str | None]]:
    tree = _script(source)
    model = Ps1ModelCache(tree).commands
    return frozenset(
        (definition.name, definition.target)
        for definition in model.implicated_definitions(_use(tree, name))
    )


def _every_definition(source: str) -> tuple[tuple[str, str | None], ...]:
    model = Ps1ModelCache(_script(source)).commands
    return tuple(
        (definition.name, definition.target)
        for definition in model.every_alias_definition()
    )


def _definitions_for(source: str, name: str) -> tuple[tuple[str, str | None], ...]:
    model = Ps1ModelCache(_script(source)).commands
    return tuple(
        (definition.name, definition.target)
        for definition in model.alias_definitions(name)
    )


def _binding_only(source: str) -> bool:
    model = Ps1ModelCache(_script(source)).commands
    definition, = model.every_alias_definition()
    return model.binding_only_definition(definition)


def _introspected(source: str) -> frozenset[str] | None:
    return Ps1ModelCache(_script(source)).commands.introspected_names()


def _reads_success(source: str) -> bool:
    return Ps1ModelCache(_script(source)).commands.reads_command_success()


class TestPs1CommandDenotation(TestBase):

    def test_a_builtin_alias_resolves_to_its_cmdlet(self):
        self.assertEqual(
            _denotation('gci', 'gci'),
            Denotation(CommandKind.ALIAS, 'Get-ChildItem'))
        self.assertEqual(
            _denotation('echo', 'echo'),
            Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_builtin_alias_wins_over_a_function_of_the_same_name(self):
        self.assertEqual(
            _denotation("function echo { 'x' }\necho", 'echo'),
            Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_function_wins_over_a_cmdlet_of_the_same_name(self):
        self.assertEqual(
            _denotation("function Get-Content { 'x' }\nGet-Content", 'Get-Content'),
            Denotation(CommandKind.FUNCTION, 'Get-Content'))

    def test_a_function_namespace_assignment_takes_the_name_from_its_cmdlet(self):
        self.assertEqual(
            _denotation('Get-ChildItem', 'Get-ChildItem'),
            Denotation(CommandKind.CMDLET, 'Get-ChildItem'))
        self.assertNotEqual(
            _denotation("${function:Get-ChildItem} = { 'x' }\nGet-ChildItem", 'Get-ChildItem'),
            Denotation(CommandKind.CMDLET, 'Get-ChildItem'))

    def test_a_builtin_alias_wins_over_a_function_namespace_assignment(self):
        self.assertEqual(
            _denotation("${function:gci} = { 'x' }\ngci", 'gci'),
            Denotation(CommandKind.ALIAS, 'Get-ChildItem'))

    def test_a_cmdlet_named_directly_denotes_its_canonical_spelling(self):
        self.assertEqual(
            _denotation('get-childitem', 'get-childitem'),
            Denotation(CommandKind.CMDLET, 'Get-ChildItem'))

    def test_a_cmdlet_named_in_noncanonical_casing_denotes_its_canonical_spelling(self):
        self.assertEqual(
            _denotation('GeT-ChIlDiTeM', 'GeT-ChIlDiTeM'),
            Denotation(CommandKind.CMDLET, 'Get-ChildItem'))

    def test_a_script_alias_resolves_to_its_target_positional_named_and_mixed(self):
        expected = Denotation(CommandKind.ALIAS, 'Get-Process')
        for source in (
            'Set-Alias foo Get-Process\nfoo',
            'Set-Alias -Name foo -Value Get-Process\nfoo',
            'Set-Alias foo -Value Get-Process\nfoo',
        ):
            with self.subTest(source=source):
                self.assertEqual(_denotation(source, 'foo'), expected)

    def test_a_use_before_its_alias_definition_denotes_no_command(self):
        self.assertEqual(
            _denotation('foo\nSet-Alias foo Get-Process', 'foo'),
            Denotation(CommandKind.NOTHING, None))

    def test_an_alias_defined_in_a_function_body_does_not_reach_an_outer_use(self):
        self.assertEqual(
            _denotation('function f { Set-Alias foo Get-Process }\nfoo', 'foo'),
            Denotation(CommandKind.NOTHING, None))

    def test_a_cycle_of_aliases_denotes_no_command_and_terminates(self):
        self.assertEqual(
            _denotation('Set-Alias a b\nSet-Alias b a\na', 'a'),
            Denotation(CommandKind.NOTHING, None))

    def test_an_alias_whose_target_is_a_wildcard_denotes_no_command(self):
        self.assertEqual(
            _denotation('Set-Alias foo Get-*\nfoo', 'foo'),
            Denotation(CommandKind.NOTHING, None))

    def test_a_set_alias_onto_an_existing_builtin_alias_is_unknown(self):
        self.assertEqual(
            _denotation('Set-Alias gci Get-Process\ngci', 'gci'),
            Denotation(CommandKind.UNKNOWN, None))

    def test_a_forced_set_alias_is_unknown(self):
        self.assertEqual(
            _denotation('Set-Alias foo Get-Process -Force\nfoo', 'foo'),
            Denotation(CommandKind.UNKNOWN, None))

    def test_a_set_alias_carrying_an_option_is_unknown(self):
        """
        The module documents any `-Option` definition as unknown because a plain `Set-Alias` cannot
        say whether the rebind of a read-only or all-scope alias took, so a use downstream of it is
        not safe to rewrite whichever way it went.
        """
        self.assertEqual(
            _denotation('Set-Alias foo Get-Process -Option ReadOnly\nfoo', 'foo'),
            Denotation(CommandKind.UNKNOWN, None))

    def test_a_computed_command_name_is_unknown(self):
        tree = _script("& ('Write' + '-Output')")
        invocation = next(
            node for node in tree.walk() if isinstance(node, Ps1CommandInvocation))
        self.assertEqual(
            Ps1ModelCache(tree).commands.denotation(invocation),
            Denotation(CommandKind.UNKNOWN, None))


class TestPs1CommandWorldRole(TestBase):
    """
    What an invocation does to the type world and the command table, with the script's own aliases
    followed. The closed-world model reads a name one hop through the built-in alias table and no
    further, so every shape where a script alias stands between the invocation and the command it
    runs is a shape only this model can answer — `Set-Alias e iex` hides a leak from that one.
    """

    def test_a_leak_named_directly_is_a_leak(self):
        for source, name in (
            ('Invoke-Expression $payload', 'Invoke-Expression'),
            ('iex $payload', 'iex'),
            ('Invoke-Command -ScriptBlock $sb', 'Invoke-Command'),
        ):
            with self.subTest(source):
                self.assertEqual(_world_role(source, name), WorldRole.LEAK)

    def test_a_script_alias_to_a_leak_is_a_leak(self):
        for source, name in (
            ('Set-Alias e iex\ne $payload', 'e'),
            ('Set-Alias run Invoke-Expression\nrun $payload', 'run'),
            ('Set-Alias a b\nSet-Alias b iex\na $payload', 'a'),
        ):
            with self.subTest(source):
                self.assertEqual(_world_role(source, name), WorldRole.LEAK)

    def test_a_script_alias_to_a_type_system_mutator_is_a_mutation(self):
        source = 'Set-Alias utd Update-TypeData\nutd -TypeName System.String -MemberName M'
        self.assertEqual(_world_role(source, 'utd'), WorldRole.MUTATION)

    def test_a_script_alias_to_an_aliasing_cmdlet_is_an_identity_change(self):
        source = 'Set-Alias mkalias New-Alias\nmkalias gd Get-Date'
        self.assertEqual(_world_role(source, 'mkalias'), WorldRole.IDENTITY)

    def test_an_alias_defined_outside_a_block_reaches_a_use_inside_it(self):
        source = 'Set-Alias e iex\n@(1) | ForEach-Object { e $payload }'
        self.assertEqual(_world_role(source, 'e'), WorldRole.LEAK)

    def test_a_leak_inside_a_function_body_is_a_leak(self):
        self.assertEqual(_world_role('function f { iex $payload }', 'iex'), WorldRole.LEAK)

    def test_a_mutator_reached_through_a_pipeline_is_a_mutation(self):
        source = '$x | Add-Member -MemberType ScriptProperty -Name M -Value { 1 }'
        self.assertEqual(_world_role(source, 'Add-Member'), WorldRole.MUTATION)

    def test_the_name_as_written_is_classified_before_what_it_was_rebound_to(self):
        """
        The refinement may only name a role where the closed-world model named one, or name one
        where it named none. A script that aliases a mutator's own name to something harmless
        therefore still reads as a mutation, which is what the world reads from the name as written.
        """
        source = 'Set-Alias Update-TypeData Get-Date\nUpdate-TypeData -TypeName System.String'
        self.assertEqual(_world_role(source, 'Update-TypeData'), WorldRole.MUTATION)

    def test_opaque_dispatch_is_unknown(self):
        for source in ('& $f', '. $f', '& $env:x'):
            with self.subTest(source):
                self.assertEqual(_sole_world_role(source), WorldRole.UNKNOWN)

    def test_running_another_script_file_is_a_leak(self):
        for source in (". 'helper.ps1'", "& '.\\stage2.ps1'", 'stage2.ps1', '. helper'):
            with self.subTest(source):
                self.assertEqual(_sole_world_role(source), WorldRole.LEAK)

    def test_a_command_outside_the_collected_metadata_leaves_the_world_alone(self):
        """
        The deliberately permissive half of the line, and the declared soundness gap: mutation is a
        deny-list, so a command nothing in the script binds and the metadata never described is not
        treated as a mutator. Answering otherwise for every command outside the metadata would make
        the question vacuous.
        """
        for source, name in (
            ('Some-Unknown-Command $payload', 'Some-Unknown-Command'),
            ('curl.exe $url', 'curl.exe'),
        ):
            with self.subTest(source):
                self.assertEqual(_world_role(source, name), WorldRole.NONE)

    def test_an_inline_scriptblock_leaves_the_world_alone(self):
        """
        Naming no command is not on its own a reason to refuse: the block's body stands in the tree
        and the closed-world walk reads whatever it does, so there is no unread binding here.
        """
        self.assertEqual(_sole_world_role('&{ $x + 1 }'), WorldRole.NONE)

    def test_a_binding_the_model_could_not_read_through_is_unknown(self):
        """
        The other half: a refusal reached with evidence rather than from ignorance. The script binds
        each of these names to something this model cannot follow — a rebind whose outcome is not
        static, a `function:` takeover, a definition that does not statically reach the use — so
        nothing static bounds what the use runs, and answering that it leaves the world as it found
        it would contradict the model's own denotation.
        """
        for source, name in (
            ('Set-Alias e Invoke-Expression -Force\ne $payload', 'e'),
            ('Set-Alias e Get-Date -Option ReadOnly\ne $payload', 'e'),
            ('Set-Alias gci Invoke-Expression\ngci $payload', 'gci'),
            ('${function:Get-Date} = $blk\nGet-Date', 'Get-Date'),
            ('e $payload\nSet-Alias e iex', 'e'),
            ('function f { Set-Alias e iex }\ne $payload', 'e'),
        ):
            with self.subTest(source):
                self.assertEqual(_world_role(source, name), WorldRole.UNKNOWN)

    def test_a_binding_that_names_no_command_at_all_leaves_the_world_alone(self):
        """
        Read through rather than refused: the model followed each of these bindings and what it
        found is that the name runs nothing, since 5.1 raises rather than dispatching. A command
        that never runs has no role to doubt, which is why not naming one is not by itself unknown.
        """
        for source, name in (
            ('Set-Alias e Invoke-*\ne $payload', 'e'),
            ('Set-Alias a b\nSet-Alias b a\na $payload', 'a'),
        ):
            with self.subTest(source):
                self.assertEqual(_world_role(source, name), WorldRole.NONE)


class TestPs1WorldRoleAgreement(TestBase):
    """
    The role an invocation is given and the verdict the closed-world model reaches over it are one
    fact read twice, and the fact was moved out of that model: for every shape it has always
    classified, the world is open exactly where the role is not `WorldRole.NONE`. Each source is a
    single statement, so the whole-script verdict is the verdict on that one invocation.
    """

    _SHAPES = (
        ('Invoke-Expression $payload', WorldRole.LEAK),
        ('iex $payload', WorldRole.LEAK),
        ("& 'global:iex' $payload", WorldRole.LEAK),
        ("& 'Microsoft.PowerShell.Utility\\Invoke-Expression' $payload", WorldRole.LEAK),
        ('Invoke-Command -ScriptBlock $sb', WorldRole.LEAK),
        ('icm -ScriptBlock $sb', WorldRole.LEAK),
        ('Start-Job -ScriptBlock $sb', WorldRole.LEAK),
        ('Start-ThreadJob -ScriptBlock $sb', WorldRole.LEAK),
        ("& '.\\stage2.ps1'", WorldRole.LEAK),
        ('stage2.ps1', WorldRole.LEAK),
        (". 'helper.ps1'", WorldRole.LEAK),
        ('. helper', WorldRole.LEAK),
        ('Update-TypeData -TypeName System.String -MemberName M', WorldRole.MUTATION),
        ('Add-Type -TypeDefinition $source', WorldRole.MUTATION),
        ('Import-Module Foo', WorldRole.MUTATION),
        ('ipmo Foo', WorldRole.MUTATION),
        ('New-Module -ScriptBlock $sb', WorldRole.MUTATION),
        ('Add-Member -InputObject $o -Name N -Value { 1 }', WorldRole.MUTATION),
        ('Set-Alias gd Get-Date', WorldRole.IDENTITY),
        ('sal gd Get-Date', WorldRole.IDENTITY),
        ('New-Alias gd Get-Date', WorldRole.IDENTITY),
        ('Remove-Alias gd', WorldRole.IDENTITY),
        ('Import-Alias .\\aliases.csv', WorldRole.IDENTITY),
        ('Set-Item alias:utd Update-TypeData', WorldRole.IDENTITY),
        ("Set-Item 'Microsoft.PowerShell.Core\\Function::Get-Date' -Value 1", WorldRole.IDENTITY),
        ('& $f', WorldRole.UNKNOWN),
        ('. $f', WorldRole.UNKNOWN),
        ('& $env:x', WorldRole.UNKNOWN),
        ('Get-ChildItem -Recurse', WorldRole.NONE),
        ('Write-Output $x', WorldRole.NONE),
        ('Get-Content .\\notes.txt', WorldRole.NONE),
        ('Some-Unknown-Command $payload', WorldRole.NONE),
        ('&{ 42 }', WorldRole.NONE),
    )

    def test_both_readers_agree_on_every_shape_the_world_classifies(self):
        for source, role in self._SHAPES:
            with self.subTest(source):
                tree = _script(source)
                cache = Ps1ModelCache(tree)
                invocation = _sole_invocation(tree)
                self.assertEqual(cache.commands.world_role(invocation), role)
                self.assertEqual(
                    cache.closed_world.world_closed_at(invocation), role is WorldRole.NONE)


class TestExtractAliasDefinition(TestBase):

    def test_it_reads_a_set_alias_invocation_into_its_parts(self):
        tree = _script('Set-Alias foo Get-Process')
        invocation = _use(tree, 'Set-Alias')
        self.assertEqual(
            extract_alias_definition(invocation),
            AliasDefinition('foo', 'Get-Process', invocation, False, False, False))

    def test_it_reads_a_new_alias_invocation_as_one_that_throws_if_bound(self):
        tree = _script('New-Alias foo Get-Process')
        invocation = _use(tree, 'New-Alias')
        self.assertEqual(
            extract_alias_definition(invocation),
            AliasDefinition('foo', 'Get-Process', invocation, False, False, True))

    def test_it_returns_none_for_an_invocation_that_is_not_a_definition(self):
        tree = _script('Get-Process')
        self.assertIsNone(extract_alias_definition(_use(tree, 'Get-Process')))

    def test_a_positional_pair_binds_the_name_and_then_the_target(self):
        for source, throws_if_bound in (
            ('Set-Alias zzq Write-Output', False),
            ('sal zzq Write-Output', False),
            ('New-Alias zzq Write-Output', True),
            ('nal zzq Write-Output', True),
        ):
            with self.subTest(source):
                self.assertEqual(
                    _binding(source), ('zzq', 'Write-Output', False, False, throws_if_bound))

    def test_the_name_and_the_value_parameter_bind_in_either_order(self):
        """
        A parameter binds the argument that follows it, so which of the two is written first is not
        what decides which is the alias and which is the command it names. Reading them by position
        regardless made `Set-Alias -Value Write-Output -Name zzq` bind the alias `write-output` to
        `zzq`, which is the binding turned around.
        """
        for source in (
            'Set-Alias -Name zzq -Value Write-Output',
            'Set-Alias -Value Write-Output -Name zzq',
            'Set-Alias -Name:zzq -Value:Write-Output',
            'Set-Alias -Value:Write-Output -Name:zzq',
            'Set-Alias -NAME zzq -vAlUe Write-Output',
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', 'Write-Output', False, False, False))

    def test_a_parameter_abbreviation_binds_what_its_full_spelling_binds(self):
        for source in (
            'Set-Alias -Na zzq -Val Write-Output',
            'Set-Alias -Val Write-Output -Na zzq',
            'Set-Alias -N zzq -V Write-Output',
            'Set-Alias -V Write-Output -N zzq',
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', 'Write-Output', False, False, False))

    def test_a_mixed_form_reads_the_parameter_first_and_the_rest_by_position(self):
        for source in (
            'Set-Alias zzq -Value Write-Output',
            'Set-Alias -Name zzq Write-Output',
            'Set-Alias -Value Write-Output zzq',
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', 'Write-Output', False, False, False))

    def test_an_argument_beyond_the_name_and_the_value_is_a_reason_to_refuse(self):
        for source in (
            'Set-Alias zzq Write-Output -PassThru',
            'Set-Alias zzq Write-Output -Scope Global',
            'Set-Alias zzq Write-Output -Force',
            'Set-Alias zzq Write-Output -Option ReadOnly',
            'Set-Alias zzq Write-Output -WhatIf',
            'Set-Alias zzq Write-Output -Description d',
            'Set-Alias zzq Write-Output extra',
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', 'Write-Output', True, False, False))

    def test_a_switch_that_takes_no_argument_binds_the_same_wherever_it_stands(self):
        """
        `-Force`, `-PassThru` and `-WhatIf` take no argument of their own, so the name and the
        target are the two positionals around the switch wherever it is written. Read as a
        parameter that takes a value, one of them was eaten and the rebind went unread, which left
        a use of a default alias to be rewritten to what the built-in table binds.
        """
        for source, throws_if_bound in (
            ('Set-Alias -Force zzq Write-Output', False),
            ('Set-Alias zzq -Force Write-Output', False),
            ('Set-Alias zzq Write-Output -Force', False),
            ('Set-Alias -PassThru zzq Write-Output', False),
            ('Set-Alias -WhatIf zzq Write-Output', False),
            ('New-Alias -Force zzq Write-Output', True),
        ):
            with self.subTest(source):
                self.assertEqual(
                    _binding(source), ('zzq', 'Write-Output', True, False, throws_if_bound))
        self.assertEqual(
            _denotation('Set-Alias -Force gci Write-Output\ngci', 'gci'),
            Denotation(CommandKind.UNKNOWN, None))

    def test_an_unrecognized_switch_ends_the_reading_of_positional_arguments(self):
        """
        The parser hands a value-taking parameter over as a switch followed by a bare word, so a
        switch this does not know may have taken the argument that would otherwise read as the name.
        `Set-Alias -Description d zzq Write-Output` binds `zzq` on a 5.1 host; reading past the
        switch made it bind `d`.
        """
        for source in (
            'Set-Alias -Description d zzq Write-Output',
            'Set-Alias -Option ReadOnly zzq Write-Output',
            'Set-Alias -Scope Global zzq Write-Output',
        ):
            with self.subTest(source):
                self.assertIsNone(_binding(source))

    def test_a_name_bound_before_an_unrecognized_switch_is_left_without_a_target(self):
        self.assertEqual(
            _binding('Set-Alias -Name zzq -Description d Write-Output'),
            ('zzq', None, True, False, False))

    def test_a_wildcard_target_is_noted_wherever_the_target_is_written(self):
        for source, target in (
            ('Set-Alias zzq Get-*', 'Get-*'),
            ('Set-Alias -Name zzq -Value Get-*', 'Get-*'),
            ("Set-Alias -Value 'Get-?' -Name zzq", 'Get-?'),
            ("Set-Alias zzq 'Get-[abc]'", 'Get-[abc]'),
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', target, False, True, False))

    def test_a_target_this_cannot_read_is_a_refusal_that_still_names_the_alias(self):
        for source in (
            'Set-Alias zzq $x',
            'Set-Alias -Name zzq -Value $x',
            'Set-Alias zzq',
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), ('zzq', None, True, False, False))

    def test_a_name_this_cannot_read_is_not_a_definition_at_all(self):
        for source in (
            'Set-Alias $n Write-Output',
            'Set-Alias -Name $n -Value Write-Output',
            'Set-Alias -Value Write-Output',
            'Set-Alias -Name',
            'Set-Alias -Name -Value Write-Output',
            'Set-Alias',
        ):
            with self.subTest(source):
                self.assertIsNone(_binding(source))

    def test_a_scope_qualifier_is_part_of_the_alias_name(self):
        for source, name in (
            ('Set-Alias GLOBAL:Zzq Write-Output', 'global:zzq'),
            ('Set-Alias script:zzq Write-Output', 'script:zzq'),
        ):
            with self.subTest(source):
                self.assertEqual(_binding(source), (name, 'Write-Output', False, False, False))

    def test_a_command_that_binds_a_name_by_another_route_is_not_a_definition(self):
        for source in (
            'Set-Item alias:zzq Write-Output',
            'Set-Variable zzq Write-Output',
            'Export-Alias x.csv',
        ):
            with self.subTest(source):
                self.assertIsNone(_binding(source))


class TestPs1ImplicitGetPrefix(TestBase):
    """
    PowerShell retries a name it could not resolve with a `Get-` prefix. It is a last resort — the
    alias, function and cmdlet tiers are each asked first — and what it answers is the prefixed
    *name* rather than the command that name in turn denotes, because the retry resolves the
    prefixed spelling through the ordinary precedence as well.
    """

    def test_a_bare_noun_nothing_else_claims_resolves_to_its_prefixed_name(self):
        for source, name, target in (
            ('alias zzq', 'alias', 'Get-Alias'),
            ('date -Format o', 'date', 'Get-Date'),
            ('location', 'location', 'Get-Location'),
            ('content .\\notes.txt', 'content', 'Get-Content'),
            ('command zzq', 'command', 'Get-Command'),
        ):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, name), Denotation(CommandKind.ALIAS, target))

    def test_a_script_function_of_the_bare_name_wins_over_the_retry(self):
        """
        Measured on 5.1: `function alias { 'from-function' }; alias zzq` writes `from-function`.
        Holding such a name in the built-in alias table instead resolved it ahead of the function
        tier, and the call to the script's own function was then rewritten into a call to the
        cmdlet, deleting the body that ran.
        """
        for source, name in (
            ("function alias { 'from-function' }\nalias zzq", 'alias'),
            ("function date { 'from-function' }\ndate -Format o", 'date'),
        ):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, name), Denotation(CommandKind.FUNCTION, name))

    def test_a_function_of_a_bare_noun_takes_it_from_the_cmdlet_the_retry_would_reach(self):
        """
        Measured on 5.1: `function item { Write-Output 'from-function' }; item env:zzq` writes
        `from-function` rather than the environment variable, and the same holds for `member`,
        `variable` and `childitem`. Each of these nouns reaches its cmdlet only by the retry, so the
        script's own function of the name is asked first and answers.
        """
        for name, prefixed in (
            ('item', 'Get-Item'),
            ('member', 'Get-Member'),
            ('variable', 'Get-Variable'),
            ('childitem', 'Get-ChildItem'),
        ):
            with self.subTest(name):
                self.assertEqual(
                    _denotation(F'{name} env:zzq', name),
                    Denotation(CommandKind.ALIAS, prefixed))
                self.assertEqual(
                    _denotation(F"function {name} {{ 'from-function' }}\n{name} env:zzq", name),
                    Denotation(CommandKind.FUNCTION, name))

    def test_a_name_the_host_has_no_command_for_is_the_scripts_own_function(self):
        """
        `gerr` and `fhx` are aliases a later PowerShell ships; 5.1 binds neither name and has no
        `Get-Error` and no `Format-Hex` at all. Holding either in the built-in alias table would
        resolve it ahead of the function tier and rewrite the call into one to a command the host
        does not have.
        """
        for name in ('gerr', 'fhx'):
            with self.subTest(name):
                self.assertEqual(_denotation(name, name), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(
                    _denotation(F"function {name} {{ 'from-function' }}\n{name}", name),
                    Denotation(CommandKind.FUNCTION, name))

    def test_a_name_that_carries_a_dash_does_not_reach_a_prefixed_function(self):
        """
        Measured on 5.1: `function Get-Zq-Frob { }; Zq-Frob` raises CommandNotFoundException, as
        does `function Get-Get-Zqfrob { }; Get-Zqfrob`. The name is no more bounded with such a
        function written above it than without one, since the retry never reaches it.
        """
        for name, prefixed in (('Zq-Frob', 'Get-Zq-Frob'), ('Get-Zqfrob', 'Get-Get-Zqfrob')):
            with self.subTest(name):
                self.assertEqual(_denotation(name, name), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(
                    _denotation(F"function {prefixed} {{ 'from-function' }}\n{name}", name),
                    Denotation(CommandKind.UNKNOWN, None))

    def test_a_script_alias_of_the_bare_name_wins_over_the_retry(self):
        self.assertEqual(
            _denotation('Set-Alias alias Get-Date\nalias zzq', 'alias'),
            Denotation(CommandKind.ALIAS, 'Get-Date'))

    def test_a_cmdlet_of_the_bare_name_wins_over_the_retry(self):
        self.assertEqual(_denotation('help zzq', 'help'), Denotation(CommandKind.CMDLET, 'help'))

    def test_a_bare_name_the_script_took_over_is_refused_before_the_retry(self):
        self.assertEqual(
            _denotation('${function:alias} = $b\nalias zzq', 'alias'),
            Denotation(CommandKind.UNKNOWN, None))

    def test_a_definition_that_does_not_reach_the_use_still_keeps_the_retry_from_answering(self):
        self.assertEqual(
            _denotation('alias zzq\nSet-Alias alias Get-Date', 'alias'),
            Denotation(CommandKind.NOTHING, None))

    def test_the_prefixed_name_is_answered_even_where_a_function_claims_it(self):
        """
        What the retry reports is a name, not a command: `function Get-Alias { 'from-function' };
        alias zzq` writes `from-function` too, so rewriting `alias` to `Get-Alias` is
        meaning-preserving whichever tier ends up claiming the prefixed spelling.
        """
        self.assertEqual(
            _denotation("function Get-Alias { 'from-function' }\nalias zzq", 'alias'),
            Denotation(CommandKind.ALIAS, 'Get-Alias'))

    def test_a_definition_of_the_prefixed_name_is_implicated_by_the_bare_noun(self):
        """
        `Set-Alias Get-Alias Get-Date` makes `alias zzq` run `Get-Date`, so that definition is what
        the bare noun's answer rests on although the noun never named it. Refusing without saying so
        reported the definition as needed by nobody; once it was deleted the noun was rewritten to
        the very name it had rebound.
        """
        for source, name, target in (
            ('Set-Alias Get-Alias Get-Date\nalias zzq', 'alias', 'Get-Date'),
            ('alias zzq\nSet-Alias Get-Alias Get-Date', 'alias', 'Get-Date'),
            ('Set-Alias Get-Alias Get-*\nalias zzq', 'alias', 'Get-*'),
            ('Set-Alias Get-Process Get-Date\nprocess -Name x', 'process', 'Get-Date'),
            ('Set-Alias Get-Location Get-Date\nlocation', 'location', 'Get-Date'),
        ):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, name), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(
                    _implicated(source, name), frozenset({(F'get-{name}', target)}))
                self.assertEqual(_world_role(source, name), WorldRole.UNKNOWN)

    def test_a_prefixed_name_the_script_took_over_is_refused_with_nothing_to_implicate(self):
        source = '${function:Get-Alias} = $b\nalias zzq'
        self.assertEqual(_denotation(source, 'alias'), Denotation(CommandKind.UNKNOWN, None))
        self.assertEqual(_implicated(source, 'alias'), frozenset())
        self.assertEqual(_world_role(source, 'alias'), WorldRole.UNKNOWN)

    def test_a_prefixed_name_the_host_itself_aliases_is_refused_with_nothing_to_implicate(self):
        """
        The refusal on this path that no script definition explains: `Get-Language` and
        `Get-VMCheckpoint` are themselves built-in aliases, so the retry lands on a name that would
        need a second retry this does not make. The script bound nothing, so there is nothing to
        implicate, and the answer is still that nothing static bounds what the noun runs.
        """
        for source in ('language', 'vmcheckpoint'):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, source), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(_implicated(source, source), frozenset())
                self.assertEqual(_world_role(source, source), WorldRole.UNKNOWN)

    def test_a_bare_noun_no_prefixed_command_answers_is_unknown(self):
        self.assertEqual(_denotation('zzq', 'zzq'), Denotation(CommandKind.UNKNOWN, None))


class TestPs1NewAliasThrowsIfBound(TestBase):
    """
    `New-Alias` raises rather than rebinding, so where a name carries more than one definition the
    effective one is the *first* that ran — the opposite of the nearest-definition-wins rule the
    rest of the resolution runs on. The model refuses there and implicates every definition of the
    name, because any of them could be the one that took.
    """

    def test_a_single_new_alias_definition_still_resolves(self):
        for source in ('New-Alias zzq Write-Output\nzzq', 'nal zzq Write-Output\nzzq'):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, 'zzq'), Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_new_alias_among_several_definitions_of_the_name_is_refused(self):
        for source in (
            'New-Alias zzq Write-Output\nNew-Alias zzq Write-Host\nzzq',
            'New-Alias zzq Write-Output\nnal zzq Write-Host\nzzq',
            'Set-Alias zzq Write-Output\nNew-Alias zzq Write-Host\nzzq',
        ):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, 'zzq'), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(
                    _implicated(source, 'zzq'),
                    frozenset({('zzq', 'Write-Output'), ('zzq', 'Write-Host')}))

    def test_a_definition_out_of_the_uses_reach_still_counts_as_another_definition(self):
        source = 'function f { New-Alias zzq Write-Host }\nNew-Alias zzq Write-Output\nzzq'
        self.assertEqual(_denotation(source, 'zzq'), Denotation(CommandKind.UNKNOWN, None))

    def test_a_set_alias_reaching_the_use_rebinds_over_an_earlier_new_alias(self):
        source = 'New-Alias zzq Write-Output\nSet-Alias zzq Write-Host\nzzq'
        self.assertEqual(_denotation(source, 'zzq'), Denotation(CommandKind.ALIAS, 'Write-Host'))
        self.assertEqual(_implicated(source, 'zzq'), frozenset({('zzq', 'Write-Host')}))

    def test_a_new_alias_of_another_name_leaves_the_first_one_resolving(self):
        self.assertEqual(
            _denotation('New-Alias a Write-Output\nNew-Alias b Write-Host\na', 'a'),
            Denotation(CommandKind.ALIAS, 'Write-Output'))


class TestPs1ImplicatedDefinitions(TestBase):
    """
    Which alias definitions a use's answer depends on, asked from the use rather than from the
    definition. A definition counts wherever the resolution read it — where it was followed, where
    it is why the resolution refused, and where the name denotes nothing precisely because the
    definition exists somewhere the use cannot reach — because deleting it changes the answer in all
    three.
    """

    def test_a_name_that_resolves_without_a_script_definition_implicates_none(self):
        for source, name in (
            ('gci', 'gci'),
            ('echo', 'echo'),
            ('Get-Process', 'Get-Process'),
            ('Set-Alias zzq Write-Output\nzzq', 'Set-Alias'),
        ):
            with self.subTest(source):
                self.assertEqual(_implicated(source, name), frozenset())

    def test_the_definition_a_use_resolves_through_is_the_statement_that_defines_it(self):
        tree = _script('Set-Alias zzq Write-Output\nzzq')
        model = Ps1ModelCache(tree).commands
        implicated, = model.implicated_definitions(_use(tree, 'zzq'))
        self.assertIs(implicated.node, _use(tree, 'Set-Alias'))

    def test_every_hop_of_an_alias_chain_is_implicated(self):
        self.assertEqual(
            _implicated('Set-Alias a b\nSet-Alias b Write-Output\na', 'a'),
            frozenset({('a', 'b'), ('b', 'Write-Output')}))

    def test_a_definition_the_resolution_refused_because_of_is_implicated(self):
        for source, name, expected in (
            ('Set-Alias zzq Write-Output -Force\nzzq', 'zzq', ('zzq', 'Write-Output')),
            ('Set-Alias zzq Write-Output -Option ReadOnly\nzzq', 'zzq', ('zzq', 'Write-Output')),
            ('Set-Alias gci Write-Output\ngci', 'gci', ('gci', 'Write-Output')),
            ('Set-Alias zzq $x\nzzq', 'zzq', ('zzq', None)),
        ):
            with self.subTest(source):
                self.assertEqual(_denotation(source, name), Denotation(CommandKind.UNKNOWN, None))
                self.assertEqual(_implicated(source, name), frozenset({expected}))

    def test_a_definition_that_leaves_the_name_denoting_nothing_is_implicated(self):
        for source, name, expected in (
            ('Set-Alias zzq Get-*\nzzq', 'zzq', frozenset({('zzq', 'Get-*')})),
            ('Set-Alias a b\nSet-Alias b a\na', 'a', frozenset({('a', 'b'), ('b', 'a')})),
        ):
            with self.subTest(source):
                self.assertEqual(_denotation(source, name), Denotation(CommandKind.NOTHING, None))
                self.assertEqual(_implicated(source, name), expected)

    def test_a_definition_that_does_not_reach_the_use_is_implicated_by_it(self):
        for source in (
            'zzq\nSet-Alias zzq Write-Output',
            'function f { Set-Alias zzq Write-Output }\nzzq',
        ):
            with self.subTest(source):
                self.assertEqual(_denotation(source, 'zzq'), Denotation(CommandKind.NOTHING, None))
                self.assertEqual(_implicated(source, 'zzq'), frozenset({('zzq', 'Write-Output')}))

    def test_a_use_no_definition_reaches_implicates_every_definition_of_its_name(self):
        self.assertEqual(
            _implicated('zzq\nSet-Alias zzq Write-Output\nSet-Alias zzq Get-Date', 'zzq'),
            frozenset({('zzq', 'Write-Output'), ('zzq', 'Get-Date')}))

    def test_a_definition_overwritten_before_the_only_use_is_implicated_by_nobody(self):
        self.assertEqual(
            _implicated('Set-Alias zzq Get-Date\nSet-Alias zzq Write-Output\nzzq', 'zzq'),
            frozenset({('zzq', 'Write-Output')}))


class TestPs1EveryAliasDefinition(TestBase):

    _REBOUND = 'Set-Alias a X\nSet-Alias b Y\nSet-Alias a Z'

    def test_it_reports_every_definition_the_script_writes_wherever_it_sits(self):
        source = (
            'Set-Alias a X\n'
            'function f { Set-Alias b Y }\n'
            '@(1) | ForEach-Object { Set-Alias c Z }'
        )
        self.assertEqual(
            _every_definition(source),
            (('a', 'X'), ('b', 'Y'), ('c', 'Z')))

    def test_it_reports_a_definition_under_every_spelling_that_writes_one(self):
        self.assertEqual(
            _every_definition('Set-Alias a X\nsal b Y\nNew-Alias c Z\nnal d W'),
            (('a', 'X'), ('b', 'Y'), ('c', 'Z'), ('d', 'W')))

    def test_the_definitions_of_one_name_come_in_source_order(self):
        self.assertEqual(_definitions_for(self._REBOUND, 'a'), (('a', 'X'), ('a', 'Z')))
        self.assertEqual(_definitions_for(self._REBOUND, 'b'), (('b', 'Y'),))

    def test_every_definition_is_grouped_by_name_and_in_source_order_within_a_group(self):
        self.assertEqual(
            _every_definition(self._REBOUND),
            (('a', 'X'), ('a', 'Z'), ('b', 'Y')))

    def test_a_definition_the_model_will_not_act_on_is_still_one_it_reports(self):
        for source, expected in (
            ('Set-Alias zzq Write-Output -Force', ('zzq', 'Write-Output')),
            ('Set-Alias zzq Get-*', ('zzq', 'Get-*')),
            ('Set-Alias zzq $x', ('zzq', None)),
        ):
            with self.subTest(source):
                self.assertEqual(_every_definition(source), (expected,))

    def test_a_definition_this_could_not_read_is_absent(self):
        for source in ('Set-Alias $n Write-Output', 'Set-Alias -Description d zzq Write-Output'):
            with self.subTest(source):
                self.assertEqual(_every_definition(source), ())

    def test_a_defining_command_reached_under_the_scripts_own_alias_is_absent(self):
        """
        The documented limit: the defining command is matched by spelling, so a `Set-Alias` reached
        through an alias the script wrote itself binds a name this does not record. A caller that
        needs every definition accounted for asks `world_role` of every invocation instead.
        """
        self.assertEqual(
            _every_definition('Set-Alias sa Set-Alias\nsa zzq Write-Output'),
            (('sa', 'Set-Alias'),))

    def test_a_name_no_definition_writes_has_no_definitions(self):
        self.assertEqual(_definitions_for(self._REBOUND, 'zzq'), ())


class TestPs1BindingOnlyDefinition(TestBase):
    """
    Whether a definition does nothing but bind its name, so that a script without it differs only in
    that the name is unbound. Every refusal below is a way for the same statement to do something
    else besides.
    """

    def test_a_plain_set_alias_does_nothing_but_bind_its_name(self):
        for source in (
            'Set-Alias zzq Write-Output',
            'set-alias zzq Write-Output',
            'SET-ALIAS zzq Write-Output',
            'Set-Alias -Name zzq -Value Write-Output',
            'Set-Alias -Value Write-Output -Name zzq',
        ):
            with self.subTest(source):
                self.assertTrue(_binding_only(source))

    def test_the_defining_command_is_the_one_the_model_resolves_it_to(self):
        self.assertTrue(_binding_only('sal zzq Write-Output'))

    def test_a_definition_that_runs_a_script_function_of_the_name_is_not_a_binding(self):
        """
        The kind decides this, not the target: a script function named `Set-Alias` denotes
        `FUNCTION` under a target that is the function's own spelling, so a check that read the
        target alone called the statement a binding when what it does is run the body — and the
        removal that followed deleted a call that ran and printed.
        """
        for source in (
            'function Set-Alias { Write-Host 1 }\nSet-Alias zzq Write-Output',
            'function set-alias { 1 }\nSet-Alias zzq Write-Output',
            'function global:Set-Alias { 1 }\nSet-Alias zzq Write-Output',
            'filter Set-Alias { 1 }\nSet-Alias zzq Write-Output',
        ):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, 'Set-Alias'),
                    Denotation(CommandKind.FUNCTION, 'Set-Alias'))
                self.assertFalse(_binding_only(source))

    def test_a_function_a_default_alias_shadows_leaves_the_binding_alone(self):
        """
        The kind gate must not refuse what the measured precedence still resolves to `Set-Alias`: a
        default alias beats a script function of its name, so `function sal { }` does not take
        `sal` over and the statement below is still nothing but a binding.
        """
        source = 'function sal { 1 }\nsal zzq Write-Output'
        self.assertEqual(_denotation(source, 'sal'), Denotation(CommandKind.ALIAS, 'Set-Alias'))
        self.assertTrue(_binding_only(source))

    def test_new_alias_binds_but_writes_an_error_of_its_own(self):
        for source in ('New-Alias zzq Write-Output', 'nal zzq Write-Output'):
            with self.subTest(source):
                self.assertFalse(_binding_only(source))

    def test_a_name_the_host_already_binds_is_more_than_a_binding(self):
        for source in (
            'Set-Alias gci Write-Output',
            'Set-Alias echo Get-Date',
            'Set-Alias ls Get-Date',
            'Set-Alias iex Get-Date',
            'Set-Alias where Get-Date',
            'Set-Alias sal Get-Date',
        ):
            with self.subTest(source):
                self.assertFalse(_binding_only(source))

    def test_a_bare_noun_the_implicit_retry_reaches_is_not_a_name_the_host_binds(self):
        """
        `alias` is not in the host's alias table — measured on 5.1, a script function of that name
        wins, which no built-in alias would allow. It is reached by the implicit `Get-` retry
        instead, so binding it is an ordinary binding and not the rebind of a built-in that almost
        never takes.
        """
        for source in ('Set-Alias alias Get-Date', 'Set-Alias process Get-Date'):
            with self.subTest(source):
                self.assertTrue(_binding_only(source))

    def test_a_wildcard_target_is_more_than_a_binding(self):
        self.assertFalse(_binding_only('Set-Alias zzq Get-*'))

    def test_a_scope_qualified_name_is_more_than_a_binding(self):
        for source in ('Set-Alias global:zzq Write-Output', 'Set-Alias script:zzq Write-Output'):
            with self.subTest(source):
                self.assertFalse(_binding_only(source))

    def test_an_argument_beyond_the_name_and_the_value_is_more_than_a_binding(self):
        for source in (
            'Set-Alias zzq Write-Output -PassThru',
            'Set-Alias zzq Write-Output -Scope Global',
            'Set-Alias zzq Write-Output -Force',
            'Set-Alias zzq Write-Output -Option ReadOnly',
            'Set-Alias zzq Write-Output -WhatIf',
            'Set-Alias zzq Write-Output extra',
            'Set-Alias zzq $x',
        ):
            with self.subTest(source):
                self.assertFalse(_binding_only(source))

    def test_a_definition_whose_own_command_the_script_took_over_is_more_than_a_binding(self):
        self.assertFalse(_binding_only('${function:Set-Alias} = $b\nSet-Alias zzq Write-Output'))


class TestPs1IntrospectedNames(TestBase):
    """
    A rewrite reaches the uses of an alias, not the mentions of it, so a name the script reads back
    out of the alias table is still a name its definition is about. `None` is the top element and
    stands for every name, never for an error.
    """

    def test_a_reader_given_a_literal_name_reports_that_name(self):
        for source in (
            'Get-Alias zzq',
            'Get-Alias -Name zzq',
            'Get-Alias -Name:zzq',
            'gal zzq',
            'Get-Command zzq',
            'Get-Help zzq',
        ):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset({'zzq'}))

    def test_the_bare_noun_that_reaches_the_alias_reader_is_a_reader(self):
        """
        `alias` is not a built-in alias of `Get-Alias` — measured on 5.1, a script function of that
        name wins — but the implicit `Get-` retry still reaches `Get-Alias` where nothing else
        claims the name, so the name such a call reports on is a name the script reads.
        """
        for source in ('alias zzq', "function Get-Alias { 'x' }\nalias zzq"):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset({'zzq'}))

    def test_a_bare_noun_the_script_claimed_itself_is_not_a_reader(self):
        for source in (
            "function alias { 'x' }\nalias zzq",
            'Set-Alias alias Get-Date\nalias zzq',
        ):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset())

    def test_a_reader_reached_through_the_scripts_own_alias_is_recognized(self):
        self.assertEqual(_introspected('Set-Alias g Get-Alias\ng zzq'), frozenset({'zzq'}))

    def test_the_alias_variable_namespace_is_a_read_of_the_name(self):
        for source in ('${alias:zzq}', '$alias:zzq', '$alias:ZZQ'):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset({'zzq'}))

    def test_every_name_the_script_reads_is_reported(self):
        self.assertEqual(
            _introspected('Get-Alias a\nGet-Command b\n${alias:c}'),
            frozenset({'a', 'b', 'c'}))

    def test_a_reader_given_more_than_one_name_reports_every_one_of_them(self):
        """
        `-Name` is an array parameter on both readers, so a second bare word is a name the script
        may still be asking the table about. Reporting one the reader binds elsewhere costs a
        definition that stays; reporting one fewer than it reads deletes a definition it names.
        """
        self.assertEqual(_introspected('Get-Alias ls zzq'), frozenset({'ls', 'zzq'}))
        self.assertEqual(_introspected('Get-Command a b'), frozenset({'a', 'b'}))

    def test_a_reader_whose_names_this_cannot_list_stands_for_every_name(self):
        for source in (
            'Get-Alias $n',
            'Get-Alias -Name $n',
            'Get-Alias',
            'alias',
            'Get-Alias Get-*',
            'Get-Alias -Definition Write-Output',
            'Get-Alias -Scope Global',
            'Get-Command -CommandType Alias',
            'Export-Alias out.csv',
            'Trace-Command -Name x -Expression { 1 }',
        ):
            with self.subTest(source):
                self.assertIsNone(_introspected(source))

    def test_a_script_that_names_no_alias_reports_the_empty_set(self):
        for source in ('$x = 1', 'Get-Process', 'Set-Alias zzq Write-Output\nzzq 1'):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset())

    def test_a_command_this_cannot_identify_is_not_read_as_a_reader(self):
        """
        The declared residual, and the stance the closed-world model takes on mutation taken here
        for the same reason: the collected metadata omits hundreds of host commands, and reading
        every one of them as a possible reader would answer `None` for almost any script.
        """
        for source in ('Some-Unknown-Command zzq', '& $f'):
            with self.subTest(source):
                self.assertEqual(_introspected(source), frozenset())


class TestPs1ReadsCommandSuccess(TestBase):

    def test_a_read_of_the_success_variable_is_seen_wherever_it_stands(self):
        for source in (
            '$?',
            'if ($?) { 1 }',
            '$x = $?',
            '"$?"',
            'function f { $? }',
            '@(1) | ForEach-Object { $? }',
        ):
            with self.subTest(source):
                self.assertTrue(_reads_success(source))

    def test_a_script_that_never_reads_it_says_so(self):
        for source in ('$x = 1', 'Get-Process', 'Set-Alias zzq Write-Output\nzzq 1', "'$?'"):
            with self.subTest(source):
                self.assertFalse(_reads_success(source))


class TestPs1CommandModelCache(TestBase):

    def test_the_command_model_is_memoized_while_the_tree_is_unchanged(self):
        cache = Ps1ModelCache(_script('Set-Alias foo Get-Process\nfoo'))
        first = cache.commands
        self.assertIs(cache.commands, first)

    def test_mutating_the_cached_tree_rebuilds_the_command_model(self):
        tree = _script('Set-Alias foo Get-Process\nfoo')
        cache = Ps1ModelCache(tree)
        first = cache.commands
        _remove_from_parent(tree.body[0])
        self.assertIsNot(cache.commands, first)

    def test_a_denotation_is_memoized_while_the_tree_is_unchanged(self):
        tree = _script('gci')
        model = Ps1ModelCache(tree).commands
        invocation = _use(tree, 'gci')
        self.assertIs(model.denotation(invocation), model.denotation(invocation))

    def test_a_world_role_is_answered_from_the_tree_as_it_now_stands(self):
        tree = _script('Set-Alias e iex\ne $payload')
        cache = Ps1ModelCache(tree)
        use = _use(tree, 'e')
        self.assertEqual(cache.commands.world_role(use), WorldRole.LEAK)
        _remove_from_parent(tree.body[0])
        self.assertEqual(cache.commands.world_role(use), WorldRole.NONE)


class TestPs1CommandModelDirectBuild(TestBase):

    def test_the_direct_build_resolves_a_function_from_the_functions_set(self):
        tree = _script("function Get-Content { 'x' }\nGet-Content")
        control_flow = build_control_flow_model(tree)
        dominance = build_dominance(control_flow)
        blocks = build_block_model(tree)
        model = build_command_model(
            tree, control_flow, dominance, blocks, frozenset({'get-content'}), frozenset({'get-content'}))
        self.assertEqual(
            model.denotation(_use(tree, 'Get-Content')),
            Denotation(CommandKind.FUNCTION, 'Get-Content'))
