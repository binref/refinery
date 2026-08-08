"""
The PowerShell the ps1 tests are quantified over, and the only PowerShell that may be *run* by a
real 5.1 host. Parsing is a weaker thing to ask of a host and other modules add sources to it;
running is not, and `executable()` below is the whole of what may be run.

Every entry here is hand-authored. Nothing is read from disk, downloaded, or derived from a sample,
and this module imports nothing from `test`, so it cannot reach the sample store even indirectly.
That is what makes it safe to feed to `refinery`'s 5.1 oracle.

`BEHAVIOURS` and `CLAIMS` are held to a stricter rule than the rest, because they are the only
things that are executed. Each entry must be synthetic, small and safe: written by hand for the
purpose, short enough to take in at a glance, and doing nothing beyond printing — no network, no
file writes, no process creation, no persistent environment or registry change, no dependence on
the state of the machine. `refinery.test.lib.scripts.ps1.oracle.behaviour` refuses anything that is
not listed in one of them, so adding an entry is the review step.

A `$env:` assignment is admitted under that rule and a registry or `[Environment]::SetEnvironment`
write is not, because the two do different things: `$env:z = '7'` writes a variable of the host
process, which is discarded when it exits, and is therefore exactly as short-lived as `$x = '7'`.
Nothing here may write an environment that outlives the process.
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

#: The constructs a deobfuscation is asked to preserve the behaviour of. Read the rule in this
#: module's own documentation before adding one: synthetic, small, safe. Each is written so that its
#: whole behaviour is what it prints, because a differential that compares output cannot see an
#: effect that produces none — `$x = 5` and a rewrite that dropped it look alike, `$x = 5; $x` does
#: not.
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
    "Write-Host 'a'; return; Write-Host 'b'",
    "try { return } finally { Write-Host 'f' }",
    "try { throw 'x' } catch { 'caught' }",
    "&('Write' + '-Output') 'indirect'",
    "$s = 'abc'; $s.Substring(1, 2)",
    "'a{0}c' -f 'b'",
    "function echo { 'from-function' }; echo 'from-alias'",
    "zzq 'early'; Set-Alias zzq Write-Output",
    "function f { Set-Alias zzq Write-Output }; f; zzq 'leaked'",
    "Set-Alias zzq Write-Output; zzq 'resolved'",
    "Set-Alias zzq iex; zzq 'Write-Output loaded'",
    "Set-Alias -Na zzq -Val Write-Output; zzq 'abbreviated'",
    "Set-Alias zzq Write-Output; $n = 'zzq'; & $n 'dispatched'",
    "Set-Alias zzq *; (Get-Alias zzq).Definition; zzq 'nothing'",
    "Set-Alias zzq Write-Output; (Get-Alias zzq).Definition",
    "Set-Alias zzq Write-Output; $n = 'zzq'; (Get-Alias $n).Definition",
    "Set-Alias zzq Write-Output; (Get-Alias | Where-Object { $_.Name -eq 'zzq' }).Definition",
    "Set-Alias zzq Write-Output; (alias zzq).Definition",
    "Set-Alias zzq Write-Output; ${alias:zzq}",
    "Set-Alias zzq Write-Output; zzq 'exported'; Export-ModuleMember -Alias zzq",
    "Get-Command zzqnope -ErrorAction SilentlyContinue; Set-Alias zzq Write-Output; $?",
    "New-Alias zzq Write-Output; New-Alias zzq Write-Host; zzq 'first-wins'",
    "Set-Alias global:zzq Write-Output; (Get-Alias 'global:zzq').Definition; zzq 'unqualified'",
    "Set-Alias -Value Write-Output -Name zzq; zzq 'named-out-of-order'",
    "Set-Alias -N zzq -V Write-Output; zzq 'one-letter'",
    "Set-Alias -Description d zzq Write-Output; zzq 'described'",
    "function alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq",
    "function Get-Alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq",
    "Set-Alias -Force zzq Write-Output; zzq 'forced'",
    "Set-Alias zzq Write-Output -PassThru; zzq 'passthru'",
)


#: The scripts the corruption ledger's beliefs about 5.1 rest on, each of which is run so that the
#: belief is measured rather than remembered. Same rule as `BEHAVIOURS`: synthetic, small, safe, and
#: the deobfuscation differential is quantified over these too, since a script written to catch a
#: change of meaning is the last one that should go unchecked for it.
#:
#: Most are the corruption entry's own script, so that what is measured is what is deobfuscated.
#: The rest are witnesses written for a belief whose own script cannot be run — one that states a
#: possibility rather than an outcome, such as "the string `Invoke-Expression` runs may carry a
#: write". A witness makes the mechanism happen instead of leaving it open, which is the part a
#: host can answer.
CLAIMS: tuple[str, ...] = (
    "$x = 'a'; . { Remove-Variable x }; Write-Host $x",
    "$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x",
    "$x = 'a'; . { Write-Output 'b' -OutVariable x }; Write-Host $x",
    "Set-Variable global:y 'b'; Write-Host $global:y",
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x",
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]",
    "trap { continue }; throw 'e'; Write-Host 'after'",
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'",
    "$v = 'a'; & { Write-Host $v }; $v = 'c'",
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'",
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'",
    "$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'",
    "$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb",
    "$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'",
    "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'",
    "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'",
    "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'",
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'",
    "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'",
    "$x = 'a'; Get-Variable x; $x = 'c'",
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v',
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i",
    "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z",
    '% { Write-Host 1 }',
    "$x = 'a'; $c = '$script:x = \"b\"'; function f { iex $c }; f; Write-Host $x",
    "$x = 'a'; &('i' + 'ex') '$x = \"b\"'; Write-Host $x",
    "& { $env:z = 'set' }; Write-Host $env:z",
    "$n = 'script:q'; function g($p = (Set-Variable $n 'v')) { }; g; Write-Host $q",
)


#: The corruption ledger's beliefs about what 5.1 reads as a command name. A name runs to
#: whitespace, which is why a keyword joined to more text is not a keyword, a path is not split at
#: its punctuation, and a `catch` joined to its type filter is neither. Every belief here is settled
#: by which tokens 5.1 flags as a command name, so none of these is run.
NAMES: tuple[str, ...] = (
    R'.\a.ps1',
    R'. .\a.ps1',
    'Copy-Item . dest',
    'Test-Path .',
    'Get-ChildItem . -Recurse',
    'Copy-Item .. dest',
    R'C:\x\y.exe',
    'Exit-PSSession',
    'Break-Glass',
    'Return-Value',
    'exit 1',
    'openssl enc -d -a -in x',
    'foo.exe -noprofile -file x',
    'try{foo}catch[System.Exception]{bar}',
    'try{foo}catch [System.Exception]{bar}',
    'try{foo}catch{bar}',
    'Get-Content < in.txt > out.txt',
    'Get-Content < in.txt',
    '% { Write-Host 1 }',
    'ForEach-Object { Write-Host 1 }',
)


def executable() -> frozenset[str]:
    """
    Every script a real PowerShell host may be asked to run.
    """
    return frozenset(BEHAVIOURS) | frozenset(CLAIMS)


def oracle_corpus() -> tuple[str, ...]:
    """
    Everything that may be handed to a 5.1 host, deduplicated and in a stable order.
    """
    seen: dict[str, None] = {}
    for source in (*SNIPPETS.values(), *PROBES, *SPELLINGS, *BEHAVIOURS, *CLAIMS, *NAMES):
        seen.setdefault(source, None)
    return tuple(seen)
