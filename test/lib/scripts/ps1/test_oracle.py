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

import functools
import inspect
import sys
import unittest

from test import TestBase
from test.lib.scripts.ps1 import corpus
from test.lib.scripts.ps1.test_parser_shape import CORPUS as SHAPES
from test.lib.scripts.ps1.oracle import (
    OracleError,
    behaviour,
    behaviours,
    command_names,
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
    'Get-Content < in.txt':
        'The same reservation. The corruption ledger rests on this one: the operator moves '
        'nothing, so the file behind it is never written.',
    'Get-Content < in.txt > out.txt':
        'The same reservation, with the one redirection 5.1 does support standing behind it.',
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
    '1 | 2':
        '5.1 reports ExpressionsMustBeFirstInPipeline: an expression may stand only as the first '
        'element of a pipeline, and after a pipe it wants a command. We accept it, so the tool can '
        'emit a pipeline 5.1 refuses. `dir | & $sb` is how the same thing is written.',
    "1 | 'a'":
        'The same rule, with a string as the second element.',
    'dir | $sb':
        'The same rule. This is the shape it costs something to get wrong: a script block behind a '
        'pipe has to be invoked, and 5.1 will not read the bare variable there.',
    'dir | @{ a = 1 }':
        'The same rule, with a hash literal as the second element.',
    'Get-Process | $x > out.txt':
        'The same rule. `ParseInput` reports the error and still returns a tree, which is why a '
        'transcript of one can record a shape for a script 5.1 refuses.',
}


#: Snippets whose deobfuscation does not behave like the snippet. Each is a semantics defect: the
#: tool's first promise is that its output does the same thing as its input. Each entry states what
#: the snippet writes and what its output writes instead, so a failure can be read here.
#:
#: Every entry below the first is a claim of the corruption ledger, and every one of them is a
#: defect that ledger already carries as an `expectedFailure`. That the two agree entry for entry
#: matters: the ledger reaches its verdict by asking whether a store survived in the tree, and this
#: reaches it by running both scripts, so neither is evidence for the other.
BEHAVIOUR_DEFECTS: dict[str, str] = {
    "try { throw 'x' } catch { 'caught' }":
        "The catch body is emptied, so the snippet prints `caught` and its deobfuscation prints "
        "nothing. A bare expression at statement level writes to the output stream, and removal "
        "treats it as having no effect; the same body written `Write-Output 'caught'` survives.",
    "Set-Variable global:y 'b'; Write-Host $global:y":
        'The store is dropped, so `b` becomes nothing: a command that writes a variable is not '
        'read as the store the following read needs.',
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        'The read is folded to `b`, but 5.1 never evaluates the right operand of `-and` when the '
        'left one is false, so the store never happens and the snippet prints `a`.',
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]":
        'The read is folded to `b`, the order from before the sort. `[Array]::Sort` reorders the '
        'array the variable holds rather than returning a new one, so the snippet prints `a`.',
    "trap { continue }; throw 'e'; Write-Host 'after'":
        'The handler is removed, so the throw escapes and nothing is printed. Under 5.1 the trap '
        'handles it and `continue` resumes at the next statement, which prints `after`.',
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        'The store is removed and the read prints nothing. A child scope resolves `$script:x` to '
        'the caller, where the store put `a`.',
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        'The same, through a function body rather than a script block.',
    "$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb":
        'The second store is removed and the read folded to `a`. A script block is not a closure: '
        'it reads the value current when it is invoked, so the snippet prints `c`.',
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'":
        'The store is removed and the read prints nothing. The string names `$x` and resolves it '
        'in the scope that runs it, so the snippet prints `a`.',
    "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'":
        'The store is removed and the read prints nothing. The pattern reads a whole set of '
        'variables without naming any one of them.',
    "$x = 'a'; Get-Variable x; $x = 'c'":
        'The store is removed, so the read that follows it fails with VariableNotFound rather '
        'than emitting the variable.',
    "$x = 'a'; $c = '$script:x = \"b\"'; function f { iex $c }; f; Write-Host $x":
        'The read is folded to `a` across a call that rewrites it: the string carries a write to '
        '`$x`, so the snippet prints `b`.',
    "$x = 'a'; &('i' + 'ex') '$x = \"b\"'; Write-Host $x":
        'The same write, reached through a computed command name, and here the call itself is '
        'deleted as well.',
}


#: What 5.1 writes for each script the corruption ledger's beliefs rest on. Every entry was read off
#: a running host rather than reasoned about, and the whole table is compared at once, so a belief
#: that was never true and a belief that has stopped being true fail the same way.
#:
#: `INFO` is what `Write-Host` produces, which since 5.0 writes an information record rather than
#: going straight to the console. An empty one is a read of a variable that holds nothing.
CLAIM_TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    "$x = 'a'; . { Remove-Variable x }; Write-Host $x":
        ('INFO\t',),
    "$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x":
        ('INFO\tb',),
    "$x = 'a'; . { Write-Output 'b' -OutVariable x }; Write-Host $x":
        ('OUT\tSystem.String\tb', 'INFO\tb'),
    "Set-Variable global:y 'b'; Write-Host $global:y":
        ('INFO\tb',),
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        ('OUT\tSystem.Boolean\tFalse', 'INFO\ta'),
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]":
        ('INFO\ta',),
    "trap { continue }; throw 'e'; Write-Host 'after'":
        ('INFO\tafter',),
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'":
        ('INFO\ta',),
    "$v = 'a'; & { Write-Host $v }; $v = 'c'":
        ('INFO\ta',),
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        ('INFO\ta',),
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        ('INFO\ta',),
    "$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb":
        ('INFO\tc',),
    "$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'":
        ('INFO\ta', 'INFO\ta'),
    "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'":
        ('INFO\ta',),
    "$x = 'a'; Get-Variable x; $x = 'c'":
        ('OUT\tSystem.Management.Automation.PSVariable'
         '\tSystem.Management.Automation.PSVariable',),
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v':
        ('INFO\t42', 'INFO\t41'),
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i":
        ('INFO\t42',),
    "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z":
        ('INFO\t7',),
    '% { Write-Host 1 }':
        ('INFO\t1',),
    "$x = 'a'; $c = '$script:x = \"b\"'; function f { iex $c }; f; Write-Host $x":
        ('INFO\tb',),
    "$x = 'a'; &('i' + 'ex') '$x = \"b\"'; Write-Host $x":
        ('INFO\tb',),
    "& { $env:z = 'set' }; Write-Host $env:z":
        ('INFO\tset',),
    "$n = 'script:q'; function g($p = (Set-Variable $n 'v')) { }; g; Write-Host $q":
        ('INFO\tv',),
}

#: Which words 5.1 read as a command name, for each script whose corruption entry turns on where a
#: command name ends. A name runs to whitespace: that is one claim, and every entry is a case of it.
COMMAND_NAMES: dict[str, tuple[str, ...]] = {
    R'.\a.ps1': (R'.\a.ps1',),
    R'. .\a.ps1': (R'.\a.ps1',),
    'Copy-Item . dest': ('Copy-Item',),
    'Test-Path .': ('Test-Path',),
    'Get-ChildItem . -Recurse': ('Get-ChildItem',),
    'Copy-Item .. dest': ('Copy-Item',),
    R'C:\x\y.exe': (R'C:\x\y.exe',),
    'Exit-PSSession': ('Exit-PSSession',),
    'Break-Glass': ('Break-Glass',),
    'Return-Value': ('Return-Value',),
    'exit 1': (),
    'openssl enc -d -a -in x': ('openssl',),
    'foo.exe -noprofile -file x': ('foo.exe',),
    'try{foo}catch[System.Exception]{bar}': ('foo', 'catch[System.Exception]', 'bar'),
    'try{foo}catch [System.Exception]{bar}': ('foo', 'bar'),
    'try{foo}catch{bar}': ('foo', 'bar'),
    'Get-Content < in.txt > out.txt': ('Get-Content',),
    'Get-Content < in.txt': ('Get-Content',),
    '% { Write-Host 1 }': ('%', 'Write-Host'),
    'ForEach-Object { Write-Host 1 }': ('ForEach-Object', 'Write-Host'),
}


def has_parse_error(source: str) -> bool:
    """
    Whether our parser reported a problem with `source`. This is not `is_well_formed`, which also
    asks whether every node can be printed — a different question, defined for the fidelity law.
    """
    return any(isinstance(node, Ps1ErrorNode) for node in Ps1Parser(source).parse().walk())


@functools.cache
def asked_of_the_host() -> tuple[str, ...]:
    """
    Every source 5.1 is asked to parse, deduplicated and in a stable order: the reviewed corpus, and
    the fragments of `test_parser_shape.py`, whose expected tree was transcribed by hand from a 5.1
    session. Those fragments stay where they are rather than moving here, because a source is only
    worth reading beside the tree it is paired with; what they add is the other two questions a host
    can answer about them, which is whether 5.1 accepts them and whether it accepts what we print.

    Their trees are deliberately not re-derived. 5.1 wraps most nodes in a `NamedBlockAst`,
    `StatementBlockAst` or `CommandExpressionAst` we have no counterpart for, and names its classes
    where we name our fields, so a comparison would run through a normalizer of ours — and a
    hand-transcribed witness is worth more than a re-derivation through our own assumptions.

    Nothing here is executed. `corpus.executable()` remains exactly the text that may be run, which
    is where the judgement that a script is synthetic, small and safe is recorded.
    """
    seen: dict[str, None] = {}
    for source in corpus.oracle_corpus():
        seen.setdefault(source, None)
    for shape in SHAPES:
        seen.setdefault(inspect.cleandoc(shape.source), None)
    return tuple(seen)


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
        self.assertEqual(
            [bool(report.errors) for report in parse_reports(sources)],
            [False, False, False, True],
        )

    def test_the_corpus_reaches_the_host_unchanged(self):
        """
        The corpus carries smart quotes, carriage returns and here-strings, all of which a code
        page or a line-ending normalization would quietly alter on the way to the host.
        """
        sources = [*asked_of_the_host(), 'say “hi”', 'line one\rline two', "'‘’‚‛'", '"“”„']
        self.assertEqual(echo(sources), sources)

    def test_a_snippet_that_is_not_in_the_corpus_is_not_executed(self):
        with self.assertRaises(OracleError):
            behaviour('Write-Output "not reviewed"')


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1ParserAgreesWithWindowsPowerShell(Ps1OracleTest):

    def test_acceptance_agrees_except_where_recorded(self):
        sources = asked_of_the_host()
        disagreeing = sorted(
            source
            for source, report in zip(sources, parse_reports(sources))
            if report.accepted is has_parse_error(source)
        )
        self.assertEqual(disagreeing, sorted({**DIVERGENCES, **DEFECTS}))

    def test_every_ledger_entry_is_a_corpus_entry(self):
        listed = set(DIVERGENCES) | set(DEFECTS)
        self.assertEqual(sorted(listed - set(asked_of_the_host())), [])

    def test_no_entry_is_both_deliberate_and_a_defect(self):
        self.assertEqual(sorted(set(DIVERGENCES) & set(DEFECTS)), [])

    def test_windows_powershell_accepts_everything_we_print(self):
        """
        The fidelity law checks our output through our own parser, so a spelling both sides are
        wrong about survives it. This asks the language instead.
        """
        accepted = zip(asked_of_the_host(), parse_reports(asked_of_the_host()))
        sources = [
            source for source, report in accepted
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

        rewritten = [
            snippet for snippet in (*corpus.BEHAVIOURS, *corpus.CLAIMS)
            if deobfuscated(snippet) != snippet
        ]
        changed = sorted(
            snippet
            for snippet, before, after in zip(
                rewritten, behaviours(rewritten), behaviours(rewritten, deobfuscated))
            if before != after
        )
        self.assertEqual(changed, sorted(BEHAVIOUR_DEFECTS))

    def test_every_behaviour_defect_is_a_snippet_that_is_run(self):
        self.assertEqual(sorted(set(BEHAVIOUR_DEFECTS) - corpus.executable()), [])


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1CorruptionLedgerRestsOnMeasuredBeliefs(Ps1OracleTest):
    """
    `test_corruptions.py` states in prose what 5.1 does with each of its scripts, measured once by
    hand. These re-derive those statements from a running host, so that a belief the ledger rests on
    cannot quietly stop being true — or turn out never to have been.

    Where a belief states a possibility rather than an outcome — "the string `Invoke-Expression`
    runs *may* carry a write" — its own script leaves the mechanism open and a host has nothing to
    answer. Such a belief is measured through a witness that makes the mechanism happen instead,
    which is what the last four entries of `corpus.CLAIMS` are for.

    Two beliefs are reachable no other way and are left as the ledger states them. That
    `Invoke-Command -ComputerName` runs its block on another machine cannot be shown without one.
    That a native program receives `-in` as text rather than as an abbreviated parameter name cannot
    be shown without running the program: what is measured here is the tokenizer half of it, that
    the spelling reaches the command unaltered.
    """

    def test_every_belief_about_what_a_script_does_is_what_powershell_does(self):
        measured = dict(zip(corpus.CLAIMS, behaviours(corpus.CLAIMS)))
        self.assertEqual(measured, CLAIM_TRANSCRIPTS)

    def test_every_belief_about_where_a_command_name_ends_is_where_powershell_ends_it(self):
        measured = dict(zip(corpus.NAMES, command_names(corpus.NAMES)))
        self.assertEqual(measured, COMMAND_NAMES)

    def test_a_keyword_joined_to_more_text_is_not_the_keyword(self):
        """
        The comparison the ledger's claim rests on, which a table of command names alone does not
        make: `exit` is a keyword and produces no command name at all, and `Exit-PSSession` is a
        command name, so the two are not read the same way.
        """
        measured = dict(zip(corpus.NAMES, command_names(corpus.NAMES)))
        self.assertEqual(
            (measured['exit 1'], measured['Exit-PSSession']),
            ((), ('Exit-PSSession',)),
        )
