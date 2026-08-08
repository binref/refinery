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
            AliasDefinition('foo', 'Get-Process', invocation, False, False))

    def test_it_returns_none_for_an_invocation_that_is_not_a_definition(self):
        tree = _script('Get-Process')
        self.assertIsNone(extract_alias_definition(_use(tree, 'Get-Process')))


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
