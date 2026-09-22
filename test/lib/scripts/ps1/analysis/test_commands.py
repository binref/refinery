from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts import Node, _remove_from_parent
from refinery.lib.scripts.ps1.analysis.aliasdef import AliasDefinition, extract_alias_definition
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.commands import (
    CommandKind,
    Denotation,
    Ps1CommandModel,
    build_command_model,
)
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.world import WorldRole
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1CommandInvocation,
    Ps1Script,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

from test.lib.scripts.ps1.test_oracle import CLAIM_TRANSCRIPTS


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


def _unread_bindings(source: str) -> tuple[Node, ...]:
    return tuple(Ps1ModelCache(_script(source)).commands.unread_alias_bindings())


def _unread_bindings_reaching(source: str, name: str) -> tuple[Node, ...]:
    tree = _script(source)
    model = Ps1ModelCache(tree).commands
    return tuple(model.unread_alias_bindings_reaching(_use(tree, name)))


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
    fact: for every shape it has always classified, the world is open exactly where the role is not
    `WorldRole.NONE`. Each source is a single statement, so the whole-script verdict is the verdict
    on that one invocation.
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
                    cache.closed_world.closed_for_the_whole_run, role is WorldRole.NONE)


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


class TestPs1UnreadAliasBindings(TestBase):
    """
    A statement that may bind an alias without this model having read which name it binds to what.
    Measured on 5.1, every rebinding below leaves `zzq` running `Get-Date` where the script bound it
    to `Write-Output` — the removal leaves it running nothing at all — so an answer of
    `Write-Output` for a use downstream of one is the command the script replaced.
    """

    _REBINDINGS = (
        'Set-Alias sx Set-Alias\nsx zzq Get-Date',
        'Set-Alias -Description d zzq Get-Date',
        'Set-Alias $n Get-Date',
        '& $c zzq Get-Date',
        'Set-Item alias:zzq Get-Date',
        'Remove-Item alias:zzq',
        "$alias:zzq = 'Get-Date'",
    )

    @staticmethod
    def _rebound_then_used(rebinding: str) -> str:
        return F'Set-Alias zzq Write-Output\n{rebinding}\nzzq'

    @staticmethod
    def _used_then_rebound(rebinding: str) -> str:
        return F'Set-Alias zzq Write-Output\nzzq\n{rebinding}'

    def test_a_use_below_a_binding_this_could_not_read_denotes_no_known_command(self):
        for rebinding in self._REBINDINGS:
            with self.subTest(rebinding):
                self.assertEqual(
                    _denotation(self._rebound_then_used(rebinding), 'zzq'),
                    Denotation(CommandKind.UNKNOWN, None))

    def test_a_use_above_such_a_binding_denotes_what_the_definition_above_it_wrote(self):
        for rebinding in self._REBINDINGS:
            with self.subTest(rebinding):
                self.assertEqual(
                    _denotation(self._used_then_rebound(rebinding), 'zzq'),
                    Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_definition_this_read_below_such_a_binding_answers_a_use_below_both(self):
        """
        Measured on 5.1: `$alias:zzq = 'Get-Date'` followed by `Set-Alias zzq Write-Output` leaves
        `zzq` running `Write-Output`, because the second statement rebinds what the first wrote.
        """
        self.assertEqual(
            _denotation("$alias:zzq = 'Get-Date'\nSet-Alias zzq Write-Output\nzzq", 'zzq'),
            Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_script_whose_every_binding_this_read_reports_none_unread(self):
        for source in (
            'Set-Alias zzq Write-Output\nzzq',
            'Set-Alias a X\nSet-Alias b Y\na\nb',
            'Set-Alias zzq Get-*\nzzq',
            'Set-Alias a b\nSet-Alias b a\na',
            'New-Alias zzq Write-Output\nzzq',
            'Get-Alias zzq',
            'Export-Alias out.csv',
            'Get-ChildItem -Recurse',
        ):
            with self.subTest(source):
                self.assertEqual(_unread_bindings(source), ())

    def test_each_rebinding_this_could_not_read_is_reported_as_exactly_one(self):
        for rebinding in self._REBINDINGS:
            with self.subTest(rebinding):
                self.assertEqual(len(_unread_bindings(self._rebound_then_used(rebinding))), 1)

    def test_a_command_this_could_not_read_is_reported_as_the_invocation_it_is(self):
        tree = _script('Set-Alias zzq Write-Output\nSet-Item alias:zzq Get-Date\nzzq')
        node, = Ps1ModelCache(tree).commands.unread_alias_bindings()
        self.assertIs(node, _use(tree, 'Set-Item'))

    def test_a_namespace_write_this_could_not_read_is_reported_as_the_assignment_it_is(self):
        tree = _script("Set-Alias zzq Write-Output\n$alias:zzq = 'Get-Date'\nzzq")
        node, = Ps1ModelCache(tree).commands.unread_alias_bindings()
        assignment, = (
            child for child in tree.walk() if isinstance(child, Ps1AssignmentExpression))
        self.assertIs(node, assignment)

    def test_an_alias_table_command_that_is_no_definition_this_reads_is_an_unread_binding(self):
        for source in ('Remove-Alias zzq', 'Import-Alias .\\a.csv'):
            with self.subTest(source):
                self.assertEqual(len(_unread_bindings(source)), 1)

    def test_such_a_binding_reaches_a_use_below_it_and_no_use_above_it(self):
        for rebinding in self._REBINDINGS:
            with self.subTest(rebinding):
                self.assertEqual(
                    len(_unread_bindings_reaching(self._rebound_then_used(rebinding), 'zzq')), 1)
                self.assertEqual(
                    _unread_bindings_reaching(self._used_then_rebound(rebinding), 'zzq'), ())

    def test_a_use_in_a_script_this_read_whole_is_reached_by_no_such_binding(self):
        for source, name in (
            ('Set-Alias zzq Write-Output\nzzq', 'zzq'),
            ('Set-Alias zzq Get-*\nzzq', 'zzq'),
            ('New-Alias zzq Write-Output\nzzq', 'zzq'),
            ('Get-ChildItem -Recurse', 'Get-ChildItem'),
        ):
            with self.subTest(source):
                self.assertEqual(_unread_bindings_reaching(source, name), ())

    def test_such_a_binding_is_reported_where_nothing_uses_the_name_it_spells(self):
        for rebinding in self._REBINDINGS:
            with self.subTest(rebinding):
                source = F'Set-Alias zzq Write-Output\n{rebinding}\nGet-ChildItem'
                self.assertEqual(len(_unread_bindings(source)), 1)

    def test_a_name_the_script_never_binds_is_computed_while_the_report_says_it_may_not_be(self):
        """
        The two answers are separate facts and a caller needs both. Measured on 5.1, with `$n`
        holding `Get-ChildItem`, `Set-Alias $n Get-Date` makes the `Get-ChildItem` below it run
        `Get-Date` — yet the denotation there is still the cmdlet, and it is
        `unread_alias_bindings_reaching` that reports the model incomplete at that use.
        """
        below = 'Set-Alias zzq Write-Output\nSet-Alias $n Get-Date\nGet-ChildItem'
        above = 'Set-Alias zzq Write-Output\nGet-ChildItem\nSet-Alias $n Get-Date'
        for source in (below, above):
            with self.subTest(source):
                self.assertEqual(
                    _denotation(source, 'Get-ChildItem'),
                    Denotation(CommandKind.CMDLET, 'Get-ChildItem'))
        self.assertEqual(len(_unread_bindings_reaching(below, 'Get-ChildItem')), 1)
        self.assertEqual(_unread_bindings_reaching(above, 'Get-ChildItem'), ())

    def test_a_binding_this_could_not_read_is_reported_wherever_the_use_it_reaches_stands(self):
        source = "Set-Alias zzq Write-Output\n$alias:zzq = 'Get-Date'\n@(1) | ForEach-Object { zzq }"
        self.assertEqual(len(_unread_bindings_reaching(source, 'zzq')), 1)
        self.assertEqual(_denotation(source, 'zzq'), Denotation(CommandKind.UNKNOWN, None))


class TestPs1ADefiningStatementThatRunsAScriptFunction(TestBase):
    """
    Measured on 5.1: a script `function Set-Alias` takes the name over, so the statement below it
    runs that body and binds no alias at all — `zzq` afterwards is reported as an unrecognized
    command. The statement still spells a binding of `zzq` to `Write-Output`, and the one answer the
    use may not be given is that target.
    """

    _SOURCE = "function Set-Alias { 'ran' }\nSet-Alias zzq Write-Output\nzzq"

    def test_the_statement_denotes_the_script_function_it_runs(self):
        self.assertEqual(
            _denotation(self._SOURCE, 'Set-Alias'), Denotation(CommandKind.FUNCTION, 'Set-Alias'))

    def test_the_statement_is_still_reported_as_a_definition_of_the_name_it_spells(self):
        self.assertEqual(_every_definition(self._SOURCE), (('zzq', 'Write-Output'),))

    def test_the_statement_is_a_binding_this_could_not_read(self):
        self.assertEqual(len(_unread_bindings(self._SOURCE)), 1)
        self.assertEqual(len(_unread_bindings_reaching(self._SOURCE, 'zzq')), 1)

    def test_the_use_below_it_denotes_no_known_command(self):
        self.assertEqual(_denotation(self._SOURCE, 'zzq'), Denotation(CommandKind.UNKNOWN, None))


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


class TestPs1AliasResolutionReadsAResumingTrapAsAnyOtherStatement(TestBase):
    """
    A `trap { continue }` resumes the block it guards at the statement after the one that threw, so
    a binder written above a call has run by the time the call does, whatever threw. Read through
    the over-approximate half of the graph — which claims a resumption reaches every statement of
    the block, earlier ones included — this invents a run in which the first call raises and control
    carries on *past* the `Set-Alias`. No such run exists: it would resume at the `Set-Alias`, that
    being the statement after the one that threw.
    """

    @staticmethod
    def _below_the_binder(prefix: str) -> Denotation:
        source = (
            F'{prefix}Copy-Item a b\n'
            'Set-Alias Copy-Item Write-Output\n'
            'Copy-Item c d'
        )
        tree = _script(source)
        use = [
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation)
            and get_command_name(node) == 'Copy-Item'
        ][-1]
        return Ps1ModelCache(tree).commands.denotation(use)

    def test_a_call_below_a_binder_resolves_where_no_handler_resumes(self):
        for prefix in ['', 'trap { break }\n', 'while ($c) { }\n']:
            with self.subTest(prefix or 'no prefix'):
                self.assertEqual(
                    self._below_the_binder(prefix),
                    Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_a_call_below_a_binder_resolves_under_a_resuming_trap_too(self):
        self.assertEqual(
            self._below_the_binder('trap { continue }\n'),
            Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_the_deobfuscator_resolves_the_call_where_the_resuming_trap_survives(self):
        """
        The model answering is only half of it: the trap above is removed as junk before the
        rewrite ever asks, so a shape whose handler *acts* is what shows the recall end to end.
        Both scripts are in `corpus.CLAIMS` and measured to print the same thing on 5.1.
        """
        source = (
            "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'")
        tree = _script(source)
        deobfuscate(tree)
        self.assertEqual(
            Ps1Synthesizer().convert(tree).splitlines(),
            [
                "trap {",
                "  Write-Host 'e'",
                "  continue",
                "}",
                "[int]'a'",
                "Set-Alias c Write-Output",
                "Write-Output 'hi'",
            ],
        )


class TestPs1AProcessBlockRerunsAndTheGraphDoesNotSaySo(TestBase):
    """
    A script's `process` block runs once per object the pipeline hands it, and the per-body graph
    draws it straight through with no edge back to its first statement. A definition written below a
    use therefore binds that use on the second object and on every one after, along a path no walk
    over this graph can take.

    An unread binder there is refused — `_project_binder` reports it unordered, the same refusal
    `worldflow` makes for the same block. A definition this model *did* read is refused the same
    way, whether the answer the graph would otherwise give is that nothing binds the name or that an
    older definition does.
    """

    _BELOW = (
        'trap { continue }; Copy-Item a b; '
        'Set-Alias mk Set-Alias -Force; mk Copy-Item Write-Output')

    @staticmethod
    def _first_use(source: str, name: str) -> tuple[Ps1CommandModel, Ps1CommandInvocation]:
        tree = _script(source)
        use = [
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == name
        ][0]
        return Ps1ModelCache(tree).commands, use

    def test_a_binder_written_below_a_use_at_the_root_does_not_reach_it(self):
        model, use = self._first_use(self._BELOW, 'Copy-Item')
        self.assertEqual(model.unread_alias_bindings_reaching(use), ())

    def test_a_binder_written_below_a_use_in_a_process_block_reaches_it(self):
        model, use = self._first_use(
            F'process {{ {self._BELOW} }}', 'Copy-Item')
        self.assertEqual(len(model.unread_alias_bindings_reaching(use)), 1)

    def test_a_definition_below_a_use_in_a_process_block_refuses_the_use(self):
        model, use = self._first_use("process { c 'hi'; Set-Alias c Write-Output }", 'c')
        self.assertEqual(model.denotation(use), Denotation(CommandKind.UNKNOWN, None))

    def test_a_binder_written_in_a_resuming_trap_body_reaches_the_block_it_resumes_into(self):
        """
        The handler runs before the statement it resumes at, so a binder written in its body
        precedes every use below the throw. The forward projection draws no edge saying so — it is
        what `refinery.lib.scripts.analysis.cfg.CfgNode.is_hub_bound` records — and the walk falls
        back to the hub for such a source rather than reporting that nothing reaches. Written here
        rather than beside the trap tests because the binder half is what this class is about: the
        two shapes below differ only in where the binder stands.
        """
        model, use = self._first_use(inspect.cleandoc("""
            Set-Alias mk Set-Alias -Force
            trap { mk Copy-Item Write-Output; continue }
            [int]'a'
            Copy-Item a b
        """), 'Copy-Item')
        self.assertEqual(len(model.unread_alias_bindings_reaching(use)), 1)

    def test_a_rebinding_below_a_use_in_a_process_block_refuses_the_definition_above_it(self):
        model, use = self._first_use(inspect.cleandoc("""
            begin { Set-Alias c Write-Host }
            process { c 'hi'; Set-Alias c Write-Output }
        """), 'c')
        self.assertEqual(model.denotation(use), Denotation(CommandKind.UNKNOWN, None))

    def test_a_definition_and_its_use_both_outside_the_process_block_still_resolve(self):
        model, use = self._first_use(inspect.cleandoc("""
            begin { Set-Alias c Write-Host; c 'hi' }
            process { 'x' }
        """), 'c')
        self.assertEqual(model.denotation(use), Denotation(CommandKind.ALIAS, 'Write-Host'))


class TestPs1AnAliasDefinitionResolvesOnlyWhereItCertainlyCompleted(TestBase):
    """
    Which definition shapes survive the completion gate and which do not, in one table, so that the
    line between the recall this recovers and the soundness it keeps is measured rather than argued.

    A definition is resolved through when no run leaves it on a throw and still reaches the use, or
    when it cannot raise a terminating error at all. Everything else is `UNKNOWN`: the name denotes
    a command this cannot spell, which is the answer a binding that may not have been made leaves.
    """

    @staticmethod
    def _denote_c(source: str) -> Denotation:
        tree = _script(source)
        use = [
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'c'
        ][-1]
        return Ps1ModelCache(tree).commands.denotation(use)

    _RESOLVED = Denotation(CommandKind.ALIAS, 'Write-Output')
    _REFUSED = Denotation(CommandKind.UNKNOWN, None)

    _SHAPES = {
        "Set-Alias c Write-Output; c 'hi'": _RESOLVED,
        "trap { continue }; Set-Alias c Write-Output; c 'hi'": _RESOLVED,
        "trap { break }; Set-Alias c Write-Output; c 'hi'": _RESOLVED,
        "try { Set-Alias c Write-Output } catch { }; c 'hi'": _RESOLVED,
        "sal c Write-Output; c 'hi'": _RESOLVED,
        "trap { continue }; sal c Write-Output; c 'hi'": _RESOLVED,
        "New-Alias c Write-Output; c 'hi'": _RESOLVED,
        "trap { continue }; New-Alias c Write-Output; c 'hi'": _REFUSED,
        "trap { continue }; Set-Alias c Write-Output -Force; c 'hi'": _REFUSED,
        "trap { continue }; Set-Alias c Write-Output -ErrorAction Stop; c 'hi'": _REFUSED,
        "$ErrorActionPreference = 'Stop'; trap { continue }; Set-Alias c Write-Output; "
        "c 'hi'": _REFUSED,
        "New-Variable ErrorActionPreference Stop -Force; trap { continue }; "
        "Set-Alias c Write-Output; c 'hi'": _REFUSED,
        "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; "
        "Set-Alias c Write-Output; c 'hi'": _REFUSED,
        "Set-Item Variable:ErrorActionPreference Stop; trap { continue }; "
        "Set-Alias c Write-Output; c 'hi'": _REFUSED,
        "Invoke-Expression '$ErrorActionPreference = \"Stop\"'; trap { continue }; "
        "Set-Alias c Write-Output; c 'hi'": _REFUSED,
        "trap { continue }; $x = \"$(1/0)$(Set-Alias c Write-Output)\"; c 'hi'": _REFUSED,
        "trap { continue }; $x = @((1/0), (Set-Alias c Write-Output)); c 'hi'": _REFUSED,
        "trap { continue }; Get-Item nope | Set-Alias c Write-Output; c 'hi'": _REFUSED,
        "$ErrorActionPreference = 'Continue'; trap { continue }; Set-Alias c Write-Output; "
        "c 'hi'": _REFUSED,
    }

    def test_each_shape_resolves_or_refuses_as_recorded(self):
        self.assertEqual(
            {source: self._denote_c(source) for source in self._SHAPES},
            dict(self._SHAPES),
        )


class TestPs1ResolvingAnAliasUnderAResumingTrapCanChangeBehaviour(TestBase):
    """
    The counter-case to the xfail above: the forward projection would resolve a call to the
    definition that dominates it, but a definition dominates a use only in the sense of running
    first, not of completing. A definition that throws under a `trap { continue }` is resumed past,
    so the name it was going to bind is never bound when the use runs — and resolving it there
    rewrites the call to a command the run does not execute.
    """

    _INPUT = (
        "$ErrorActionPreference = 'Stop'; trap { continue }; "
        "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'")
    _RESOLVED = (
        "$ErrorActionPreference = 'Stop'; trap { continue }; "
        "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'")
    _NO_TRAP = (
        "$ErrorActionPreference = 'Stop'; "
        "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'")

    @staticmethod
    def _denote_c(source: str) -> Denotation:
        tree = _script(source)
        use = [
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'c'
        ][-1]
        return Ps1ModelCache(tree).commands.denotation(use)

    @staticmethod
    def _deobfuscated(source: str) -> str:
        tree = _script(source)
        deobfuscate(tree)
        return Ps1Synthesizer().convert(tree)

    def test_the_model_refuses_the_alias_where_the_resuming_trap_makes_the_use_live(self):
        """
        `UNKNOWN` and not `NOTHING`: the name denotes a command this cannot put a spelling to, which
        is what a definition that may not have finished leaves behind. `NOTHING` would say 5.1
        raises here, and 5.1 runs `Write-Error`.
        """
        self.assertEqual(self._denote_c(self._INPUT), Denotation(CommandKind.UNKNOWN, None))

    def test_the_deobfuscator_leaves_the_call_below_the_resuming_trap_alone(self):
        self.assertEqual(
            self._deobfuscated(self._INPUT),
            Ps1Synthesizer().convert(_script(self._INPUT)))

    def test_without_the_trap_the_same_definitions_resolve_the_now_dead_call(self):
        self.assertEqual(
            self._denote_c(self._NO_TRAP),
            Denotation(CommandKind.ALIAS, 'Write-Output'))

    def test_resolving_the_alias_would_make_the_output_disagree_with_the_input(self):
        # Measured on a Windows PowerShell 5.1 host, recorded in test_oracle.CLAIM_TRANSCRIPTS: the
        # second Set-Alias throws (the alias is read-only) and $ErrorActionPreference makes it
        # terminating, so the trap resumes at the call, where c is still Write-Error, whose output
        # under Stop is itself terminating and swallowed by the trap. The input prints nothing; the
        # rewrite that resolves c to Write-Output prints 'hi'.
        self.assertEqual(CLAIM_TRANSCRIPTS[self._INPUT], ())
        self.assertEqual(CLAIM_TRANSCRIPTS[self._RESOLVED], ('OUT\tSystem.String\thi',))
        self.assertNotEqual(CLAIM_TRANSCRIPTS[self._INPUT], CLAIM_TRANSCRIPTS[self._RESOLVED])


class TestPs1AReadOnlyAliasConflictIsNotResolvedAsARebind(TestBase):
    """
    Unrelated to trap resumption and to the forward projection: a `Set-Alias` onto a read-only alias
    fails *without throwing*, so the name keeps its earlier binding while control passes on normally.
    A plain rebind of a name an earlier `-Option`/`-Force` definition may have locked has therefore
    not certainly taken, and the use below it is refused rather than resolved to the binding that may
    never have happened — so the deobfuscator keeps the call as written, with no trap in sight.
    """

    _INPUT = "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'"
    _RESOLVED = "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'"

    def test_the_input_and_its_resolved_form_run_different_commands_on_the_host(self):
        # Recorded in test_oracle.CLAIM_TRANSCRIPTS: c is left as Write-Error by the failed rebind,
        # so the input's last line writes an error record, while resolving c to Write-Output writes
        # to the output stream.
        self.assertEqual(
            CLAIM_TRANSCRIPTS[self._INPUT][-1],
            'ERROR\tMicrosoft.PowerShell.Commands.WriteErrorException'
            '\tMicrosoft.PowerShell.Commands.WriteErrorException')
        self.assertEqual(CLAIM_TRANSCRIPTS[self._RESOLVED][-1], 'OUT\tSystem.String\thi')

    def test_the_model_does_not_resolve_the_call_the_conflict_left_unbound(self):
        tree = _script(self._INPUT)
        use = [
            node for node in tree.walk_in_order()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'c'
        ][-1]
        self.assertEqual(
            Ps1ModelCache(tree).commands.denotation(use),
            Denotation(CommandKind.UNKNOWN, None))
