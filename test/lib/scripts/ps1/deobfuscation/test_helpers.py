from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.commands import CommandKind, Denotation
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.deobfuscation.helpers import set_command_name, switch_matches
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1Script
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def _command_named(tree: Ps1Script, name: str) -> Ps1CommandInvocation:
    return next(
        node for node in tree.walk()
        if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == name
    )


class TestPs1Helpers(TestPs1):

    def test_switch_matches_compares_the_operands_texts(self):
        for value, condition in (
            ('True', True),
            (True, 'True'),
            ('5', 5),
            (5, '5'),
            ('', None),
        ):
            with self.subTest(F'{value!r} {condition!r}'):
                self.assertTrue(switch_matches(value, condition))
        for value, condition in (
            (1, True),
            (0, False),
            (2, True),
            (True, 1),
            ('007', 7),
            (5, '005'),
            (5, '5.0'),
            (None, 0),
            (None, 'x'),
            ('abc', True),
            ('', False),
        ):
            with self.subTest(F'{value!r} {condition!r}'):
                self.assertFalse(switch_matches(value, condition))

    def test_switch_matches_compares_two_numbers_numerically(self):
        self.assertTrue(switch_matches(5, 5.0))
        self.assertTrue(switch_matches(5.0, 5))
        self.assertFalse(switch_matches(5, 5.5))

    def test_switch_matches_refuses_the_texts_the_host_culture_writes(self):
        for value, condition in (
            (5.5, '5.5'),
            ('5.5', 5.5),
            ('ss', 'ß'),
        ):
            with self.subTest(F'{value!r} {condition!r}'):
                self.assertIsNone(switch_matches(value, condition))


class TestPs1CommandNameRewrite(TestPs1):

    def test_a_rewritten_alias_denotes_the_cmdlet_now_written(self):
        tree = Ps1Parser('gci $x').parse()
        cache = Ps1ModelCache(tree)
        invocation = _command_named(tree, 'gci')
        self.assertEqual(
            cache.commands.denotation(invocation),
            Denotation(CommandKind.ALIAS, 'Get-ChildItem'),
        )
        self.assertTrue(set_command_name(invocation, 'Get-ChildItem'))
        self.assertEqual(Ps1Synthesizer().convert(tree), 'Get-ChildItem $x')
        self.assertEqual(
            cache.commands.denotation(invocation),
            Denotation(CommandKind.CMDLET, 'Get-ChildItem'),
        )

    def test_a_rewritten_script_file_path_opens_the_world_the_command_now_runs(self):
        tree = Ps1Parser('gci $x').parse()
        cache = Ps1ModelCache(tree)
        invocation = _command_named(tree, 'gci')
        self.assertTrue(cache.closed_world.closed_for_the_whole_run)
        self.assertTrue(set_command_name(invocation, 'C:\\Stage Two\\payload.ps1'))
        self.assertEqual(
            Ps1Synthesizer().convert(tree),
            "& 'C:\\Stage Two\\payload.ps1' $x",
        )
        self.assertFalse(cache.closed_world.closed_for_the_whole_run)
        self.assertEqual(
            cache.commands.denotation(invocation),
            Denotation(CommandKind.UNKNOWN, None),
        )

    def test_rewriting_a_command_name_to_the_one_already_written_changes_nothing(self):
        tree = Ps1Parser('Get-ChildItem $x').parse()
        cache = Ps1ModelCache(tree)
        invocation = _command_named(tree, 'Get-ChildItem')
        commands = cache.commands
        self.assertFalse(set_command_name(invocation, 'Get-ChildItem'))
        self.assertEqual(Ps1Synthesizer().convert(tree), 'Get-ChildItem $x')
        self.assertIs(cache.commands, commands)
