"""
What Windows PowerShell 5.1 does, measured, rather than what we believe it does.

Every other expectation about PowerShell in this suite was written by us, so wherever we
misunderstand the language the tests agree with us. These do not: they ask a real 5.1 host and
compare. They skip where no host is available, which is why
`TestPs1OracleIsAvailableOnWindows` is gated on the platform instead — a Windows run that quietly
stops measuring is the failure this whole file would not otherwise notice.

Two ledgers, because two different things are being recorded and they age differently.
`DIVERGENCES` are deliberate and permanent: our model answers a question 5.1 answers differently,
on purpose. `DEFECTS` are places we are measurably wrong, and each is temporary. Both are checked
in both directions, so neither a fix nor a regression can pass unremarked, and each entry states
what 5.1 does and what we do so that a failure can be read without leaving this file.
"""
from __future__ import annotations

import sys
import unittest

from test import TestBase
from test.lib.scripts.ps1 import corpus
from test.lib.scripts.ps1.oracle import (
    OracleError,
    behaviour,
    echo,
    host_info,
    parse_reports,
    windows_powershell,
)

from refinery.lib.scripts.ps1.model import Ps1ErrorNode
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

#: Questions our model answers differently from 5.1 on purpose. Permanent.
DIVERGENCES: dict[str, str] = {
    'a < b':
        '5.1 reserves `<` and reports RedirectionNotSupported. We parse an input redirection and '
        'keep its source, which is what Ps1InputRedirection exists for.',
    'echo a < b':
        'The same reservation, reached through a command argument.',
    'class C : B { [int] $P; [void] M() { 1 } }':
        '5.1 reports TypeNotFound because ParseInput resolves a class base type against the '
        'assemblies already loaded. That is name resolution, not grammar, and a parser that '
        'refused every unresolvable type could not read a script written against a module it '
        'cannot see.',
}

#: Places we are measurably wrong about 5.1. Each is a defect to fix, not a decision.
DEFECTS: dict[str, str] = {
    '()':
        '5.1 reports ExpectedExpression. We build Ps1ParenExpression(expression=None) and call it '
        'well formed, so the tool can emit a script 5.1 refuses.',
    '1 + ()':
        'The same empty parenthesis, as an operand.',
    '$a.Length ()':
        '5.1 reports UnexpectedToken and ExpectedExpression. We read a property access followed '
        'by an empty parenthesis.',
    'foo (a, b)':
        '5.1 reads `a` as a command name inside the bracket and then reports MissingArgument at '
        'the comma. We read an array of two bare words.',
    '$x = a, b':
        'The same shape as an assigned value: 5.1 reads `a` as a command name and reports '
        'MissingArgument.',
    '$x > out.txt':
        '5.1 accepts a redirection of an expression. We produce an error node; the narrower bug '
        'is already ledgered at test_parser_shape.py:578.',
}


#: Snippets whose deobfuscation does not behave like the snippet. Each is a semantics defect: the
#: tool's first promise is that its output does the same thing as its input.
BEHAVIOUR_DEFECTS: dict[str, str] = {
    "try { throw 'x' } catch { 'caught' }":
        "The catch body is emptied, so the snippet prints `caught` and its deobfuscation prints "
        "nothing. A bare expression at statement level writes to the output stream, and removal "
        "treats it as having no effect; the same body written `Write-Output 'caught'` survives.",
}


def has_parse_error(source: str) -> bool:
    """
    Whether our parser reported a problem with `source`. This is not `is_well_formed`, which also
    asks whether every node can be printed — a different question, defined for the fidelity law.
    """
    return any(isinstance(node, Ps1ErrorNode) for node in Ps1Parser(source).parse().walk())


class Ps1OracleTest(TestBase):
    """
    A test that may reach a PowerShell host. The sample store is taken away rather than merely
    left unused: `download_sample` is inherited from `TestBase` by every test in the suite, so a
    check that this module imports nothing from `samples` would guard the wrong boundary.
    """

    def download_sample(self, *args, **kwargs):
        raise AssertionError('a test that can reach a PowerShell host may not load a sample')


class TestPs1OracleIsAvailableOnWindows(TestBase):

    @unittest.skipUnless(sys.platform == 'win32', 'not a Windows host')
    def test_windows_powershell_is_present_on_a_windows_host(self):
        self.assertIsNotNone(windows_powershell())


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1OracleMeasuresWhatItClaims(Ps1OracleTest):
    """
    A harness that answered "no errors, no tokens" for everything would make every comparison in
    this file pass at once, so it is asked questions whose answers are known.
    """

    def test_the_host_is_windows_powershell_five_one(self):
        host = host_info()
        self.assertEqual(
            (host.edition, host.major >= 5, host.language),
            ('Desktop', True, 'FullLanguage'),
            F'the host on PATH is {host}',
        )

    def test_a_construct_powershell_cannot_parse_is_reported_as_an_error(self):
        report, = parse_reports(['if ('])
        self.assertEqual(report.errors, ('IfStatementMissingCondition',))

    def test_a_construct_powershell_accepts_is_reported_without_error(self):
        report, = parse_reports(['Write-Output 1'])
        self.assertEqual((report.errors, report.failed), ((), ''))

    def test_every_source_in_a_batch_gets_its_own_report(self):
        sources = ['1', '2', '3', 'if (']
        self.assertEqual([bool(r.errors) for r in parse_reports(sources)], [False, False, False, True])

    def test_the_corpus_reaches_the_host_unchanged(self):
        """
        The corpus carries smart quotes, carriage returns and here-strings, all of which a code
        page or a line-ending normalization would quietly alter on the way to the host.
        """
        sources = [*corpus.oracle_corpus(), 'say “hi”', 'line one\rline two', "'‘’‚‛'", '"“”„']
        self.assertEqual(echo(sources), sources)

    def test_a_snippet_that_is_not_in_the_corpus_is_not_executed(self):
        with self.assertRaises(OracleError):
            behaviour('Write-Output "not reviewed"')


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1ParserAgreesWithWindowsPowerShell(Ps1OracleTest):

    def test_acceptance_agrees_except_where_recorded(self):
        sources = corpus.oracle_corpus()
        disagreeing = sorted(
            source
            for source, report in zip(sources, parse_reports(sources))
            if report.accepted is has_parse_error(source)
        )
        self.assertEqual(disagreeing, sorted({**DIVERGENCES, **DEFECTS}))

    def test_every_ledger_entry_is_a_corpus_entry(self):
        listed = set(DIVERGENCES) | set(DEFECTS)
        self.assertEqual(sorted(listed - set(corpus.oracle_corpus())), [])

    def test_no_entry_is_both_deliberate_and_a_defect(self):
        self.assertEqual(sorted(set(DIVERGENCES) & set(DEFECTS)), [])

    def test_windows_powershell_accepts_everything_we_print(self):
        """
        The fidelity law checks our output through our own parser, so a spelling both sides are
        wrong about survives it. This asks the language instead.
        """
        sources = [
            source for source, report in zip(corpus.oracle_corpus(),
                                             parse_reports(corpus.oracle_corpus()))
            if report.accepted and not has_parse_error(source)
        ]
        rendered = [Ps1Synthesizer().convert(Ps1Parser(source).parse()) for source in sources]
        rejected = sorted(
            F'{source!r} -> {output!r} {report.errors}'
            for source, output, report in zip(sources, rendered, parse_reports(rendered))
            if not report.accepted
        )
        self.assertEqual(rejected, [])


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1WordSpellingAgreesWithWindowsPowerShell(Ps1OracleTest):
    """
    Whether a bare word keeps its spelling when it moves into a slot that reads a pipeline. 5.1
    answers this in the token stream, where a word it read as a command carries `CommandName`.
    """

    def _flags(self, source: str) -> dict[str, str]:
        report, = parse_reports([source])
        return {token.text: token.flags for token in report.tokens}

    def test_a_bare_word_argument_is_not_a_command_name(self):
        self.assertNotIn('CommandName', self._flags('foo a, b')['a'])

    def test_the_same_word_inside_a_bracket_is_a_command_name(self):
        self.assertIn('CommandName', self._flags('foo (a, b)')['a'])

    def test_a_comma_built_argument_of_bare_words_is_rejected_once_bracketed(self):
        self.assertEqual(parse_reports(['foo (a, b)'])[0].errors, ('MissingArgument',))

    def test_quoting_the_elements_is_what_makes_the_bracket_legal(self):
        self.assertEqual(parse_reports(["foo ('a', 'b')"])[0].errors, ())


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1DeobfuscationPreservesBehaviour(Ps1OracleTest):
    """
    The tool's first promise is that its output runs and does the same thing as its input. Every
    other test of that promise compares our output against our own expectation of it.
    """

    def test_the_output_behaves_like_the_input(self):
        unit = self.ldu('ps1')

        def deobfuscated(snippet: str) -> str:
            return bytes(snippet.encode('utf8') | unit).decode('utf8')

        changed = sorted(
            snippet for snippet in corpus.BEHAVIOURS
            if deobfuscated(snippet) != snippet
            and behaviour(snippet, deobfuscated) != behaviour(snippet)
        )
        self.assertEqual(changed, sorted(BEHAVIOUR_DEFECTS))

    def test_every_behaviour_defect_is_a_snippet_that_is_run(self):
        self.assertEqual(sorted(set(BEHAVIOUR_DEFECTS) - set(corpus.BEHAVIOURS)), [])
