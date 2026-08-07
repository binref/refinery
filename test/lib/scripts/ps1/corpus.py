"""
The PowerShell the ps1 tests are quantified over, and the only PowerShell that may be handed to a
real 5.1 host.

Every entry here is hand-authored. Nothing is read from disk, downloaded, or derived from a sample,
and this module imports nothing from `test`, so it cannot reach the sample store even indirectly.
That is what makes it safe to feed to `refinery`'s 5.1 oracle.

`BEHAVIOURS` is held to a stricter rule than the rest, because it is the only thing that is
executed. Each entry must be synthetic, small and safe: written by hand for the purpose, short
enough to take in at a glance, and doing nothing beyond printing — no network, no file writes, no
process creation, no environment or registry change, no dependence on the state of the machine.
`refinery.test.lib.scripts.ps1.oracle.behaviour` refuses anything that is not listed here, so
adding an entry is the review step.
"""
from __future__ import annotations

#: One script per node class, written by hand rather than generated, and kept minimal so that a
#: failure names the construct it is about. Where a node has a child list, the snippet fills it
#: with two entries: the fidelity generator truncates from there, and a rendering that is only
#: correct at the cardinality its author had in mind is what that is looking for.
SNIPPETS: dict[str, str] = {
    'Block'                   : 'if ($a) { 1 }',
    'Ps1ArrayExpression'      : '@(1, 2)',
    'Ps1ArrayLiteral'         : '$x = 1, 2',
    'Ps1AssignmentExpression' : '$x = 1',
    'Ps1Attribute'            : 'function f { [CmdletBinding()] param($a) }',
    'Ps1BinaryExpression'     : '1 + 2',
    'Ps1BreakStatement'       : 'while ($a) { break }',
    'Ps1CastExpression'       : '[int]$x',
    'Ps1CatchClause'          : 'try { 1 } catch [A], [B] { 2 } catch { 3 }',
    'Ps1ClassDefinition'      : 'class C : B { [int] $P; [void] M() { 1 } }',
    'Ps1CommandArgument'      : 'Get-Item -Path a b',
    'Ps1CommandInvocation'    : 'Get-Item a b',
    'Ps1ContinueStatement'    : 'while ($a) { continue }',
    'Ps1DataSection'          : 'data d { 1 }',
    'Ps1DoLoop'               : 'do { 1 } while ($a)',
    'Ps1EnumDefinition'       : 'enum E { A = 1; B = 2 }',
    'Ps1EnumMember'           : 'enum E { A = 1; B = 2 }',
    'Ps1ExitStatement'        : 'exit 1',
    'Ps1ExpandableHereString' : '@"\na$b\n"@',
    'Ps1ExpandableString'     : '"a$b c"',
    'Ps1ExpressionStatement'  : '1',
    'Ps1FileRedirection'      : 'a > b',
    'Ps1ForEachLoop'          : 'foreach ($i in $a) { 1 }',
    'Ps1ForLoop'              : 'for ($i = 0; $i -lt 2; $i++) { 1 }',
    'Ps1FunctionDefinition'   : 'function f { 1 }',
    'Ps1HashLiteral'          : '@{ a = 1; b = 2 }',
    'Ps1HereString'           : "@'\nabc\n'@",
    'Ps1IfStatement'          : 'if ($a) { 1 } elseif ($b) { 2 } else { 3 }',
    'Ps1IndexExpression'      : '$x[0]',
    'Ps1InputRedirection'     : 'a < b',
    'Ps1IntegerLiteral'       : '1',
    'Ps1InvokeMember'         : '$x.Substring(1, 2)',
    'Ps1MemberAccess'         : '$x.Length',
    'Ps1MergingRedirection'   : 'a 2>&1',
    'Ps1MethodMember'         : 'class C { [void] M() { 1 } }',
    'Ps1ParamBlock'           : 'function f { param($a, $b) }',
    'Ps1ParameterDeclaration' : 'function f { param([int] $a, $b) }',
    'Ps1ParenExpression'      : '(1)',
    'Ps1Pipeline'             : 'a | b',
    'Ps1PipelineElement'      : 'a | b',
    'Ps1PropertyMember'       : 'class C { [int] $P }',
    'Ps1RangeExpression'      : '1..2',
    'Ps1RealLiteral'          : '1.5',
    'Ps1ReturnStatement'      : 'return 1',
    'Ps1Script'               : '1',
    'Ps1ScriptBlock'          : '{ 1; 2 }',
    'Ps1StringLiteral'        : "'a'",
    'Ps1SubExpression'        : '$(1; 2)',
    'Ps1SwitchStatement'      : 'switch ($a) { 1 { "x" } default { "y" } }',
    'Ps1ThrowStatement'       : 'throw 1',
    'Ps1TrapStatement'        : 'trap [E] { 1 }',
    'Ps1TryCatchFinally'      : 'try { 1 } catch { 2 } finally { 3 }',
    'Ps1TypeExpression'       : 'function f { param([int] $a) }',
    'Ps1UnaryExpression'      : '-not $x',
    'Ps1Variable'             : '$x',
    'Ps1WhileLoop'            : 'while ($a) { 1 }',
}

#: Constructs we hold an open question about, asked of the oracle directly. A question that has been
#: settled stays here: it is what keeps the answer from drifting when the parser changes.
PROBES: tuple[str, ...] = (
    '()',
    '1 + ()',
    '$a.Length ()',
    'a < b',
    'echo a < b',
    '$x > out.txt',
    'do { 1 }',
    'try { 1 }',
    '$x = ,',
    '@()',
    ',1',
    '$x = ,1',
)

#: How a word may be written where a command name is read, and where a value is. This is the
#: question M1 stalled on — whether a bare word keeps its spelling when it moves into a slot that
#: reads a pipeline — and 5.1 answers it in the token stream rather than the tree.
SPELLINGS: tuple[str, ...] = (
    'Get-Item a',
    "Get-Item 'a'",
    'Get-Item "a"',
    'foo a, b',
    "foo 'a', 'b'",
    'foo (a, b)',
    "foo ('a', 'b')",
    '$x = a, b',
    "$x = 'a', 'b'",
    '(a)',
    "('a')",
    '$x = (a)',
    'New-Object IO.MemoryStream(,$b)',
)

#: Snippets that are executed. Read the rule in this module's own documentation before adding one:
#: synthetic, small, safe. Each is written so that its whole behaviour is what it prints, because a
#: differential that compares output cannot see an effect that produces none — `$x = 5` and a
#: rewrite that dropped it look alike, `$x = 5; $x` does not.
BEHAVIOURS: tuple[str, ...] = (
    "'a' + 'b'",
    "'{0}-{1}' -f 'a', 'b'",
    "$x = 'hello'; $x",
    "('a', 'b', 'c') -join ''",
    "[string]::Join('', ('a', 'b'))",
    "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGk='))",
    "if ($true) { 'yes' } else { 'no' }",
    '1..3 | ForEach-Object { $_ * 2 }',
    '$a = 1; $b = 2; $a + $b',
    "'ABC'.ToLower()",
    "$x = @('a', 'b'); $x[1]",
    "switch ('b') { 'a' { 'first' } 'b' { 'second' } }",
    "$h = @{ k = 'v' }; $h['k']",
    "[int]'42' + 1",
    "'a' * 3",
    "$null -eq $undefined",
    "try { throw 'x' } catch { 'caught' }",
    "&('Write' + '-Output') 'indirect'",
    "$s = 'abc'; $s.Substring(1, 2)",
    "'a{0}c' -f 'b'",
)


def oracle_corpus() -> tuple[str, ...]:
    """
    Everything that may be handed to a 5.1 host, deduplicated and in a stable order.
    """
    seen: dict[str, None] = {}
    for source in (*SNIPPETS.values(), *PROBES, *SPELLINGS, *BEHAVIOURS):
        seen.setdefault(source, None)
    return tuple(seen)
