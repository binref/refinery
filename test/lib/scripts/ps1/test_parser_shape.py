from __future__ import annotations

import inspect
import unittest

from collections import Counter
from typing import NamedTuple

from test import TestBase

# The deobfuscation package has to be imported before the synthesizer, which cannot be the first
# module of the PowerShell package to be imported in a fresh interpreter.
import refinery.lib.scripts.ps1.deobfuscation  # noqa: F401

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.ast import get_named_blocks, get_param_block, string_value
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.lib.scripts.ps1.model import (
    Ps1Attribute,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1ErrorNode,
    Ps1FileRedirection,
    Ps1FunctionDefinition,
    Ps1InputRedirection,
    Ps1IntegerLiteral,
    Ps1MergingRedirection,
    Ps1RealLiteral,
    Ps1StringLiteral,
    Ps1TrapStatement,
    Ps1TypeExpression,
    Ps1Variable,
)


def _detail(node: Node) -> str:
    if isinstance(node, Ps1StringLiteral):
        return repr(node.value)
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return node.raw
    if isinstance(node, Ps1Variable):
        return F'${node.name}'
    if isinstance(node, Ps1CommandArgument):
        return F'{node.kind.value} {node.name}'.strip()
    if isinstance(node, Ps1FileRedirection):
        return F'{node.stream.name} append' if node.append else node.stream.name
    if isinstance(node, Ps1MergingRedirection):
        return F'{node.from_stream.name}>{node.to_stream.name}'
    if isinstance(node, (Ps1TypeExpression, Ps1Attribute, Ps1FunctionDefinition)):
        return node.name
    if isinstance(node, Ps1TrapStatement):
        return node.type_name
    if isinstance(node, Ps1CatchClause):
        return ', '.join(node.types)
    if isinstance(node, Ps1ErrorNode):
        return repr(node.text)
    return ''


def outline(node: Node, indent: int = 0) -> str:
    """
    The parse tree of `node` as one indented line per node, in the format the measurement
    transcripts use: the node type, followed by the little that distinguishes one node of that type
    from another. Every child is rendered, so a node that appears or vanishes changes the outline.
    """
    lines = [F'{"  " * indent}{type(node).__name__} {_detail(node)}'.rstrip()]
    lines.extend(outline(child, indent + 1) for child in node.children())
    return '\n'.join(lines)


def redirections(node: Node) -> Counter[tuple]:
    """
    What each redirection in the subtree of `node` *is*, counted. A `<` and a `>` over the same file
    are different entries, and so are an appending and a truncating write.
    """
    counted: Counter[tuple] = Counter()
    for current in node.walk():
        if isinstance(current, Ps1FileRedirection):
            target = string_value(current.target)
            counted[('file', current.stream.name, current.append, target)] += 1
        elif isinstance(current, Ps1MergingRedirection):
            counted[('merge', current.from_stream.name, current.to_stream.name)] += 1
        elif isinstance(current, Ps1InputRedirection):
            counted[('input', string_value(current.source))] += 1
    return counted


class Shape(NamedTuple):
    source: str
    tree: str


CORPUS = [
    Shape(
        'echo a < b',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'echo'
              Ps1CommandArgument positional
                Ps1StringLiteral 'a'
              Ps1InputRedirection
                Ps1StringLiteral 'b'
        """,
    ),
    Shape(
        'Get-Content < in.txt > out.txt',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Get-Content'
              Ps1InputRedirection
                Ps1StringLiteral 'in.txt'
              Ps1FileRedirection OUTPUT
                Ps1StringLiteral 'out.txt'
        """,
    ),
    Shape(
        'echo a<b',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'echo'
              Ps1CommandArgument positional
                Ps1StringLiteral 'a<b'
        """,
    ),
    Shape(
        'echo a[b',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'echo'
              Ps1CommandArgument positional
                Ps1StringLiteral 'a[b'
        """,
    ),
    Shape(
        '::Foo',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral '::Foo'
        """,
    ),
    Shape(
        '::Foo(1)',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral '::Foo'
              Ps1CommandArgument positional
                Ps1ParenExpression
                  Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        '=x',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral '=x'
        """,
    ),
    Shape(
        '= 1',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral '='
              Ps1CommandArgument positional
                Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        ']',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral ']'
        """,
    ),
    Shape(
        '1 | 2',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1Pipeline
              Ps1PipelineElement
                Ps1IntegerLiteral 1
              Ps1PipelineElement
                Ps1IntegerLiteral 2
        """,
    ),
    Shape(
        "1 | 'a'",
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1Pipeline
              Ps1PipelineElement
                Ps1IntegerLiteral 1
              Ps1PipelineElement
                Ps1StringLiteral 'a'
        """,
    ),
    Shape(
        'dir | @{ a = 1 }',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1Pipeline
              Ps1PipelineElement
                Ps1CommandInvocation
                  Ps1StringLiteral 'dir'
              Ps1PipelineElement
                Ps1HashLiteral
                  Ps1StringLiteral 'a'
                  Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        'dir | $sb',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1Pipeline
              Ps1PipelineElement
                Ps1CommandInvocation
                  Ps1StringLiteral 'dir'
              Ps1PipelineElement
                Ps1Variable $sb
        """,
    ),
    Shape(
        'Get-Process | $x > out.txt',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1Pipeline
              Ps1PipelineElement
                Ps1CommandInvocation
                  Ps1StringLiteral 'Get-Process'
              Ps1PipelineElement
                Ps1Variable $x
                Ps1FileRedirection OUTPUT
                  Ps1StringLiteral 'out.txt'
        """,
    ),
    Shape(
        '$x = Get-Process | ForEach-Object { $_ }',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1AssignmentExpression
              Ps1Variable $x
              Ps1Pipeline
                Ps1PipelineElement
                  Ps1CommandInvocation
                    Ps1StringLiteral 'Get-Process'
                Ps1PipelineElement
                  Ps1CommandInvocation
                    Ps1StringLiteral 'ForEach-Object'
                    Ps1CommandArgument positional
                      Ps1ScriptBlock
                        Ps1ExpressionStatement
                          Ps1Variable $_
        """,
    ),
    Shape(
        'Should -BeOfType [string[]]',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Should'
              Ps1CommandArgument switch -BeOfType
              Ps1CommandArgument positional
                Ps1StringLiteral '[string[]]'
        """,
    ),
    Shape(
        'Setup -Dir [test-dir]',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Setup'
              Ps1CommandArgument switch -Dir
              Ps1CommandArgument positional
                Ps1StringLiteral '[test-dir]'
        """,
    ),
    Shape(
        'Write-Host $a [0]',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Write-Host'
              Ps1CommandArgument positional
                Ps1Variable $a
              Ps1CommandArgument positional
                Ps1StringLiteral '[0]'
        """,
    ),
    Shape(
        'Write-Host $a[0]',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Write-Host'
              Ps1CommandArgument positional
                Ps1IndexExpression
                  Ps1Variable $a
                  Ps1IntegerLiteral 0
        """,
    ),
    Shape(
        'Write-Host [ 0 ]',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Write-Host'
              Ps1CommandArgument positional
                Ps1StringLiteral '['
              Ps1CommandArgument positional
                Ps1IntegerLiteral 0
              Ps1CommandArgument positional
                Ps1StringLiteral ']'
        """,
    ),
    Shape(
        'Write-Host [',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Write-Host'
              Ps1CommandArgument positional
                Ps1StringLiteral '['
        """,
    ),
    Shape(
        'foo [int]$x',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'foo'
              Ps1CommandArgument positional
                Ps1ExpandableString
                  Ps1StringLiteral '[int]'
                  Ps1Variable $x
        """,
    ),
    Shape(
        'Should -Be [System.Management.Automation.LanguagePrimitives]::ConvertTo($rval, [string])',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Should'
              Ps1CommandArgument switch -Be
              Ps1CommandArgument positional
                Ps1StringLiteral '[System.Management.Automation.LanguagePrimitives]::ConvertTo'
              Ps1CommandArgument positional
                Ps1ParenExpression
                  Ps1ArrayLiteral
                    Ps1Variable $rval
                    Ps1TypeExpression string
        """,
    ),
    Shape(
        'echo a,-not',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'echo'
              Ps1CommandArgument positional
                Ps1ArrayLiteral
                  Ps1StringLiteral 'a'
                  Ps1StringLiteral '-not'
        """,
    ),
    Shape(
        'echo a,-join,b',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'echo'
              Ps1CommandArgument positional
                Ps1ArrayLiteral
                  Ps1StringLiteral 'a'
                  Ps1StringLiteral '-join'
                  Ps1StringLiteral 'b'
        """,
    ),
    Shape(
        r'Get-ChildItem -Path C:\ -Recurse',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Get-ChildItem'
              Ps1CommandArgument switch -Path
              Ps1CommandArgument positional
                Ps1StringLiteral 'C:\\'
              Ps1CommandArgument switch -Recurse
        """,
    ),
    Shape(
        'param($x=1)',
        r"""
        Ps1Script
          Ps1ParamBlock
            Ps1ParameterDeclaration
              Ps1Variable $x
              Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        r"""
        [CmdletBinding()]
        param($x)
        $x
        """,
        r"""
        Ps1Script
          Ps1ParamBlock
            Ps1Attribute CmdletBinding
            Ps1ParameterDeclaration
              Ps1Variable $x
          Ps1ExpressionStatement
            Ps1Variable $x
        """,
    ),
    Shape(
        'function f { [Parameter(Mandatory)]param($x) }',
        r"""
        Ps1Script
          Ps1FunctionDefinition f
            Ps1ScriptBlock
              Ps1ParamBlock
                Ps1Attribute Parameter
                  Ps1StringLiteral 'Mandatory'
                Ps1ParameterDeclaration
                  Ps1Variable $x
        """,
    ),
    Shape(
        'try { 1 } catch [System.Exception] { 2 }',
        r"""
        Ps1Script
          Ps1TryCatchFinally
            Block
              Ps1ExpressionStatement
                Ps1IntegerLiteral 1
            Ps1CatchClause System.Exception
              Block
                Ps1ExpressionStatement
                  Ps1IntegerLiteral 2
        """,
    ),
    Shape(
        'trap [Exception] { 1 }',
        r"""
        Ps1Script
          Ps1TrapStatement Exception
            Block
              Ps1ExpressionStatement
                Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        'param.exe 1',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'param.exe'
              Ps1CommandArgument positional
                Ps1IntegerLiteral 1
        """,
    ),
    Shape(
        'Set-Variable 007 v',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Set-Variable'
              Ps1CommandArgument positional
                Ps1IntegerLiteral 007
              Ps1CommandArgument positional
                Ps1StringLiteral 'v'
        """,
    ),
    Shape(
        'Set-Variable 0x10 v',
        r"""
        Ps1Script
          Ps1ExpressionStatement
            Ps1CommandInvocation
              Ps1StringLiteral 'Set-Variable'
              Ps1CommandArgument positional
                Ps1IntegerLiteral 0x10
              Ps1CommandArgument positional
                Ps1StringLiteral 'v'
        """,
    ),
]


class TestPs1ParseShape(TestBase):
    """
    The expectation for each fragment below is the tree Windows PowerShell 5.1 builds for it, taken
    from a transcript of `[System.Management.Automation.Language.Parser]::ParseInput` on a 5.1 host.
    The one exception is `param($x=1)`, whose transcript covers the same block with an invalid
    default. The oracle is the *shape*: which top-level construct a fragment is, how many arguments
    a command has, and what kind each argument is. A defect in any of these is well formed and
    reports no parse error, so counting error nodes would see nothing.

    Three places where our node model spells 5.1's tree differently, and where the outline therefore
    reads differently from a transcript of that tree:

    - A command argument is a `Ps1CommandArgument` wrapper around its value, where 5.1 lists the
      value directly under its `CommandAst`; a `-Name` parameter, which 5.1 spells as a
      `CommandParameterAst`, is such a wrapper of switch kind and carries no value.
    - A statement holding an expression is a `Ps1ExpressionStatement`, where 5.1 wraps in a
      `PipelineAst` with one `CommandExpressionAst`; a pipe makes the wrapper explicit as a
      `Ps1Pipeline` of `Ps1PipelineElement` nodes, one per element.
    - 5.1 discards a `<` operator together with the word after it. We keep that word under a
      `Ps1InputRedirection`, which performs no transfer, so the fragment an analyst reads back still
      spells what was written.
    """

    def test_parse_shape_matches_windows_powershell(self):
        for row in CORPUS:
            source = inspect.cleandoc(row.source)
            with self.subTest(source):
                self.assertEqual(
                    outline(Ps1Parser(source).parse()),
                    inspect.cleandoc(row.tree),
                )


class TestPs1AnExpressionStatementKeepsItsRedirection(TestBase):
    """
    A redirection behind the *first* pipeline element is dropped when that element is an expression.
    5.1 reports no error and gives one pipeline whose expression carries the write; we give three
    statements, of which one is an error node and one invents a call to a program named after the
    file. Behind a pipe the same source is read correctly, so what is missing is only the carrier for
    an element that has no pipe — a statement that would have to become a pipeline of one to hold it.

    Ledgered rather than fixed: the carrier is its own change, and a `Ps1Pipeline` wrapping every
    redirected statement is a shape every pass that reads pipelines would have to be told about.
    """

    @unittest.expectedFailure
    def test_a_redirection_behind_an_expression_statement_is_kept(self):
        self.assertEqual(
            outline(Ps1Parser('$x > out.txt').parse()),
            inspect.cleandoc(
                r"""
                Ps1Script
                  Ps1ExpressionStatement
                    Ps1Pipeline
                      Ps1PipelineElement
                        Ps1Variable $x
                        Ps1FileRedirection OUTPUT
                          Ps1StringLiteral 'out.txt'
                """
            ),
        )

    def test_the_same_redirection_behind_a_pipe_is_kept(self):
        self.assertEqual(
            outline(Ps1Parser('Get-Process | $x > out.txt').parse()),
            inspect.cleandoc(
                r"""
                Ps1Script
                  Ps1ExpressionStatement
                    Ps1Pipeline
                      Ps1PipelineElement
                        Ps1CommandInvocation
                          Ps1StringLiteral 'Get-Process'
                      Ps1PipelineElement
                        Ps1Variable $x
                        Ps1FileRedirection OUTPUT
                          Ps1StringLiteral 'out.txt'
                """
            ),
        )


class TestPs1ParseShapeConservation(TestBase):
    """
    Properties that hold for every fragment of the corpus regardless of its shape. They cost one
    parse each and cover what a table of hand-written trees cannot: a fragment whose tree is right
    and whose redirections the synthesizer then loses, and a fragment that parses to nothing at all.
    """

    def test_synthesis_conserves_redirections(self):
        synthesizer = Ps1Synthesizer()
        for row in CORPUS:
            source = inspect.cleandoc(row.source)
            with self.subTest(source):
                parsed = Ps1Parser(source).parse()
                emitted = synthesizer.convert(parsed)
                self.assertEqual(
                    redirections(parsed),
                    redirections(Ps1Parser(emitted).parse()),
                    emitted,
                )

    def test_no_fragment_parses_to_nothing(self):
        for row in CORPUS:
            source = inspect.cleandoc(row.source)
            with self.subTest(source):
                script = Ps1Parser(source).parse()
                self.assertTrue(
                    script.body or get_named_blocks(script) or get_param_block(script))
