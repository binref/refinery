from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.commands import (
    AliasDefinition,
    CommandKind,
    Denotation,
    build_command_model,
    extract_alias_definition,
)
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
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


def _denotation(source: str, name: str) -> Denotation:
    tree = _script(source)
    return Ps1ModelCache(tree).commands.denotation(_use(tree, name))


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


class TestPs1CommandModelDirectBuild(TestBase):

    def test_the_direct_build_resolves_a_function_from_the_functions_set(self):
        tree = _script("function Get-Content { 'x' }\nGet-Content")
        control_flow = build_control_flow_model(tree)
        dominance = build_dominance(control_flow)
        model = build_command_model(tree, control_flow, dominance, frozenset({'get-content'}))
        self.assertEqual(
            model.denotation(_use(tree, 'Get-Content')),
            Denotation(CommandKind.FUNCTION, 'Get-Content'))
