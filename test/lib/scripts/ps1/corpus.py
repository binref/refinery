"""
The PowerShell the ps1 tests are quantified over, and the only PowerShell that may be *run* by a
real 5.1 host. Parsing is a weaker thing to ask of a host and other modules add sources to it;
running is not, and `executable()` below is the whole of what may be run.

Every entry here is hand-authored. Nothing is read from disk, downloaded, or derived from a sample,
and this module imports nothing from `test`, so it cannot reach the sample store even indirectly.
That is what makes it safe to feed to `refinery`'s 5.1 oracle.

`BEHAVIOURS`, `CLAIMS`, `TABLES` and `TYPES` are held to a stricter rule than the rest, because they
are the only things that are executed. Each entry must be synthetic, small and safe: written by hand
for the purpose, short enough to take in at a glance, and doing nothing beyond printing — no
network, no file writes, no process creation, no persistent environment or registry change, no
dependence on the state of the machine. `refinery.test.lib.scripts.ps1.oracle.behaviour` refuses
anything that is not listed in one of them, so adding an entry is the review step.

`TABLES` is the one exception to the last of those, and it is an exception on purpose rather than a
relaxation: those entries read the command tables of a Windows PowerShell 5.1 installation, which is
the oracle's whole subject. The rule they are still held to is the rest of it, and the reasoning for
the exception is recorded where they are defined.

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

#: Where one token ends and the next begins. 5.1 decides this from the character after a token
#: rather than from the grammar, so a construct that is plainly an expression in one slot is one
#: word in another, and no amount of reasoning about what a script *means* finds the boundary.
#:
#: Two subjects, and the second is the reason the first cannot be repaired alone. A dash in an
#: argument slot never signs a numeral, so `f -1` passes the string; and a numeral swallows a
#: trailing dot, so `3.ToString` is one word while `3..5` counts from three and `0xFF.GetType()`
#: reads the member.
#:
#: Each spelling that ends a numeral for a reason other than the dot is asked separately —
#: hexadecimal, real, exponent, type suffix, multiplier — and the same words are asked again in an
#: argument slot, where none of them reads a member and the numeral is one word with what follows.
#:
#: A sign is asked of the same boundary, because a numeral that carries one is a receiver like any
#: other value and the whole of what follows binds to it: `-1kb.GetType()` reads the member of
#: minus one kilobyte, `- 1kb.GetType()` negates what one kilobyte answers, and `--1kb.GetType()`
#: is the decrement operator. The three differ only in where a space stands, and no two of them are
#: the same program.
BOUNDARIES: tuple[str, ...] = (
    'f -1',
    'f -1.5',
    'f -.5',
    'f -1kb',
    'f -0xFF',
    'f -1x',
    'f -1L',
    'f -1e3',
    'f -',
    'f - x',
    'f -$x',
    'f --1',
    'f -Recurse',
    'f -_1',
    'f -?',
    'f 1,-2',
    'f -Name -2',
    'f @(-2)',
    'f (1,-2)',
    'f 3.',
    'f 3..5',
    'f 0xFF.GetType',
    '$x = -1',
    '$x = 3.ToString()',
    '$x = 3.GetType',
    '$x = 3..5',
    '$x = 3...5',
    '$x = 3[0]',
    '$x = 3.5.ToString()',
    '$x = 0xFF.GetType()',
    '$x = 1kb.GetType()',
    '$x = 1e3.GetType()',
    '$x = 1L.GetType()',
    '$x = -1kb.GetType()',
    '$x = -0xFF.GetType()',
    '$x = -1.5.GetType()',
    '$x = - 1kb.GetType()',
    '$x = - -1kb.GetType()',
    '$x = 0b1010',
    '$x = 1_000',
    '$x = 0xFF_FF',
    '$x = 1dkb',
    '$x = 1.5L',
    '$x = 1k',
    '$x = 1e3.5',
    '$x = $y.5',
    '$x = (1).5',
    '$x = $y.5.6',
    '$x = $y[0].5',
    'f $y.5',
    'f $y[0]',
    'f $y[-1]',
    'f $y.',
    'f 1e3.5',
)

#: How a word may be written where a command name is read, and where a value is: whether a bare
#: word keeps its spelling when it moves into a slot that reads a pipeline — and 5.1 answers it in
#: the token stream rather than the tree.
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
#:
#: The transcript drops an error's message and target, so two `CommandNotFoundException`s read
#: alike: a witness has to differ in the kind or the count of the lines it writes, which is what the
#: `Write-Output` against `Write-Host` pairs below are for — one writes to the success stream and
#: the other to the information stream. A witness may not name `Get-Date` or the working directory
#: for the same reason a snippet may not depend on the state of the machine.
#:
#: Not every question about the alias table can be asked here. `Import-Alias` reads a CSV, and a
#: corpus entry may not create one, so what it does to the table is a question for a model-level
#: test rather than for a host.
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
    'try { zzqfoo =5 } catch {}; $v = Get-Variable Error; Write-Host $v.Value.Count',
    "try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }",
    "Set-StrictMode -Version 1; try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }",
    "Set-PSDebug -Strict; try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }",
    "function f { Set-PSDebug -Strict }; f; try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }",
    "function f { Set-StrictMode -Version 1 }; f; try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }",
    'function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f',
    'function f { [void]$input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f',
    "$s = { try { zzqfoo =5 } catch { 'caught' }; Set-Alias -Scope Script zzqfoo Write-Output }; & $s; & $s",
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
    "$env:zzq = '7'; (item env:zzq).Value",
    "$env:zzq = '7'; function item { Write-Output 'from-function' }; item env:zzq",
    "function member { Write-Output 'from-function' }; member",
    "function variable { Write-Output 'from-function' }; variable zzqnope",
    "function childitem { Write-Output 'from-function' }; childitem zzqnope",
    "function gerr { Write-Output 'from-function' }; gerr",
    "function fhx { Write-Output 'from-function' }; fhx",
    "function Set-Alias { Write-Output 'nope' }; Set-Alias zzq Write-Output; zzq 'x'",
    "Set-Alias zzq Write-Host; Set-Alias mk Set-Alias -Force; mk zzq Write-Output; zzq 'x'",
    "$n = 'zq2'; Set-Alias zq2 Write-Host; Set-Alias $n Write-Output; zq2 'y'",
    "Set-Alias zzq Write-Host; $c = 'Set-Alias'; & $c zzq Write-Output; zzq 'x'",
    "Set-Alias zzq Write-Output; Set-Item alias:zzq Write-Host; zzq 'hi'",
    "Set-Alias zzq Write-Output; Remove-Item alias:zzq; zzq 'hi'",
    "Set-Alias zq3 Write-Output; ${alias:zq3} = 'Write-Host'; zq3 'z'",
    "Set-Alias zzq Write-Output; Invoke-Expression 'Set-Alias zzq Write-Host'; zzq 'x'",
    "$h = @{ k = 'Set-Alias zzq Write-Host' }; Set-Alias zzq Write-Output; iex $h.k; zzq 'x'",
    "$s = 'abc'; [Array]::Reverse($s); Write-Output $s",
    "$x = 1, 2, 3; Write-Output $x[0]; [Array]::Reverse($x); Write-Output $x[0]",
    "$x = 1, 2, 3; $x[0] = 9; [Array]::Reverse($x); Write-Output $x",
    "$x = 1, 2, 3; Write-Output $x[0]; $x[0] = 9; Write-Output $x[0]",
    "$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]",
    "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x",
    "function f { [Array]::Reverse($x) }; $x = 1, 2, 3; f; Write-Output $x",
    "$x = $(Write-Host 'a'; 1), $(Write-Host 'b'; 2); [Array]::Reverse($x); Write-Output $x",
    "$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x",
    "$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x",
    "$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y",
    "$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x",
    "$x = 1, 2, 3; $x.SetValue(9, 0); Write-Output $x",
    "$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y",
    "$x = 1, 2, 3; $y = $x; $y[0] = 9; Write-Output $x[0]",
    "$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }",
    "$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x",
    "$p = @(@(1, 2), @(3, 4)); [Array]::Reverse($p[0]); Write-Output $p[0]",
    "$b = 1, 2, 3; [Array]::Reverse($b, 0, 99); Write-Output $b",
    "$x = 1, 2, 3; $script:x[0] = 9; Write-Output $x[0]",
    "$x = 1, 2, 3; [Array]::Reverse($script:x); Write-Output $x",
    "$x = 1, 2, 3; $y = $x; $x = 9, 9, 9; Write-Output $y",
    "[string]$q = 'abc'; Write-Output $q.Substring(1, 1)",
    '[int]$q = 5; Write-Output $q.ToString()',
    "$q, $r = 'abc', 'd'; Write-Output $q.SUBSTRING(1, 1); Write-Output $r",
    '[string]$q = 5; $q = 1, 2, 3; Write-Output $q.Length',
    '[string]$q = 5; $q = 1, 2, 3; Write-Output (,$q)',
    "[string]$q = 5; $q += 'a'; Write-Output (,$q)",
    "$q = [string]5; $q = 1, 2, 3; Write-Output (,$q)",
    "[string]$q = 5; $q = 1, 2, 3; Write-Output $q.GetType().FullName",
    "$q = 'abc'; [int]$q = 5; Write-Output $q.GetType().FullName",
    "[int]$q = 5; $q = 'abc'; Write-Output $q",
    "function Get-Zqfrob { Write-Output 'hit' }; Zqfrob",
    "Set-Alias Get-Zqal Write-Output; Zqal 'x'",
    "function Get-Zqfrob { Write-Output 'p' }; function Zqfrob { Write-Output 'b' }; Zqfrob",
    "function Get-Get-Zqfrob { Write-Output 'hit' }; Get-Zqfrob",
    "function Get-Zq-Frob { Write-Output 'hit' }; Zq-Frob",
    "$env:zzq = '7'; function Get-Item { Write-Output 'from-function' }; item env:zzq",
    "$x = 'a'; function f { Write-Host (variable x -ValueOnly) }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (item variable:x).Value }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (Get-Item variable:x).Value }; f; $x = 'c'",
    "$env:z = 'v'; Write-Output $env:z",
    '$x = 1, 2, 3; $y = $x; $y = 9, 9, 9; [Array]::Reverse($x); Write-Output $y',
    '$x = 1, 2, 3; $y = $x; $z = $y; [Array]::Reverse($z); Write-Output $x',
    "$s = 'abcd'; $t = $s; $t = 1, 2, 3; [Array]::Reverse($t); Write-Output $s.Length",
    '$x = 1, 2, 3; $y = [array]$x; $y[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; $y = $x -as [array]; $y[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; [int[]]$y = $x; $y[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse([int[]]$x); Write-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; $x[0] = 9; Write-Output $h['k'][0]",
    '$x = 1, 2, 3; $a = @($Null); $a[0] = $x; $x[0] = 9; Write-Output $a[0][0]',
    "$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); Write-Output $x[0]",
    '$s = [byte[]](1, 2, 3); $d = [byte[]](0, 0, 0); '
    '[Buffer]::BlockCopy($s, 0, $d, 0, 3); Write-Output $d',
    "[Convert]::ToBase64CharArray(1, 2, 3, 4); Write-Output 'after'",
    "[string]$q = 5; [System.String]$q = 'ab'; Write-Output $q",
    '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y',
    '$x = 1, 2, 3; $o.P = $x; $x[0] = 9; Write-Output $o.P[0]',
    '$x = 1, 2, 3; $l.Add($x); $x[0] = 9; Write-Output $l[0][0]',
    '$x = 1, 2, 3; $o = New-Object PSObject; $o.P = $x; $x[0] = 9; Write-Output $o.P[0]',
    '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); '
    '$x[0] = 9; Write-Output $l[0][0]',
    '$x = 1, 2, 3; $h = @{ k = $x }; $x[0] = 9; Write-Output $h[\'k\'][0]',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $x[0] = 9; Write-Output $a[0][0]',
    '$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]',
    '$x = 1, 2, 3; $y = $x; . { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y',
    '$x = 1, 2, 3; $y = $x; & { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y',
    '[string]$y = 0; $x = 1, 2, 3; $y = $x; [Array]::Reverse($x); Write-Output $y',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x",
    '$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; Write-Output $p[0]',
    '$x = 1, 2, 3; $y = if ($True) { $x }; $x[0] = 9; Write-Output $y[0]',
    'function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]',
    '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z',
    '$x = 1, 2, 3; Write-Output -NoEnumerate $x | Set-Variable z; $y = $x; $y[0] = 9; '
    'Write-Output $z',
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $x[0] = 9; Write-Output $o.P',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; Write-Output $h['k']",
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; Write-Output $o.P',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; Write-Output $a[0]',
    '$x = 1, 2, 3; $h = @{ k = $x }; Write-Output $h.k',
    '$x = 1, 2, 3; $a, $b = $x, 9; Write-Output $a',
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $x',
    '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); $l[0][0] = 9; '
    'Write-Output $x',
    '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $x',
    "$x = 1, 2, 3; $h = @{ k = $x }; $y = $h['k']; $y[0] = 9; Write-Output $x",
    '$p = @(@(1, 2), @(3, 4)); $q = $p[0]; $q[0] = 9; Write-Output $p[0][0]',
    '$p = @(@(1, 2), @(3, 4)); $p | ForEach-Object { [Array]::Reverse($_) }; Write-Output $p[0]',
    '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; '
    'Write-Output $p[0]',
    'function f($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; f $x; Write-Output $x',
    '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $x; Write-Output $x',
    '$x = 1, 2, 3; function f { , $script:x }; $y = f; $y[0] = 9; Write-Output $x[0]',
    '$x = 1, 2, 3; $a, $b = $x, 9; [Array]::Reverse($a); Write-Output $x',

    #: What observes the removal of a statement or of a function definition. A junk remover argues
    #: that nothing sees what it drops, and each of these names one thing that does: the statements
    #: a fault would have skipped, the parameter binder, the automatic success variable, a read of
    #: the function table, a reader of the command table, the text a stored block renders as, and a
    #: second binding the name already had. Written in pairs wherever the same shape has a benign
    #: twin, so that a refusal covering both says nothing.
    "function K { $Null = [Int]'abc' }; K; Write-Host 'A'",
    "$Null = [Int]'abc'; Write-Host 'A'",
    "$Null = 1 / 0; Write-Host 'A'",
    "$Null = [Int]'42'; Write-Host 'A'",
    "function K { param([int] $x = 'abc') }; K; Write-Host 'A'",
    "function K { param([int] $x = '42') }; K; Write-Host 'A'",
    "function K { $Null = 1 }; Write-Error 'e'; K; Write-Host $?",
    'function K { $Null = 1 }; K; Write-Host ($function:K -ne $Null)',
    "function K { $Null = 1 }; K; $Null = (Get-Command K).Name; Write-Host 'A'",
    "$Null = (Get-Command K).Name; function K { $Null = 1 }; K; Write-Host 'A'",
    "function vnMTH { $Null = 1 }; vnMTH; $Null = (Get-Command *vnMT*).Name; Write-Host 'A'",
    'K; function K { $Null = 1 }; Write-Host $?',
    'function K { $Null = 1 }; K; $b = { K }; Write-Host $b',
    'function Measure-Object { $Null = 1 }; Measure-Object; 1, 2, 3 | measure',
    "function Get-Language { $Null = 668 }; language; Write-Host 'A'",
    "function q { $Null = 1 }; ${function:q} = { Write-Host 'P' }; q",
    "$n = 'q'; function K { $Null = 1 }; Set-Alias $n K; q; Write-Host 'A'",
    "function K { [Alias('q')] param() $Null = 1 }; q; Write-Host 'A'",
    "$env:B = 'function K { Write-Host P }'; Invoke-Expression $env:B; function K { 42 }; "
    "$x = K; Write-Output $x; $env:C = 'K'; Invoke-Expression $env:C",

    #: A member the Extended Type System re-points is not the member the collected metadata
    #: describes, which is the whole reason the closed-world model exists. Each of these mutates one
    #: and then reads it; the pair beneath them reads the same member with nothing mutated, so a
    #: refusal covering both says nothing.
    "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty "
    "-Value { Write-Host 'S' }; $Null = 'abc'.Zq; Write-Host 'A'",
    "Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty "
    "-Value { 99 }; Write-Host 'abc'.Length",
    "$Null = 'abc'.Length; Write-Host 'A'",
    "Write-Host 'abc'.Length",

    #: What a raise abandons. A bareword carrying an assignment marker is the shape an obfuscator
    #: pads with, and 5.1 answers it with `CommandNotFoundException` — terminating at script scope,
    #: caught by an empty `catch` inside a `try`. Either way the statements it skips do not run, and
    #: a rewrite that drops the raise has to drop them with it.
    "try { zzq0000=5; 'tail' } catch {}; 'next'",
    "function f { try { zzq0000=5; 'tail' } catch {} }; Write-Host (f)",
    "function f { try { 'tail' } catch {} }; Write-Host (f)",
    "try { zzq0000=5 } catch {}; 'next'",
    "zzqfoo1; function zzqfoo1 { 'boom' }; zzqfoo1",
    "function zzqfoo1 { 'boom' }; zzqfoo1",

    #: What the empty `catch` around a noise bareword is claimed to swallow. A clause with a type
    #: filter that misses swallows nothing and 5.1 ends the run; a clause that matches leaves the
    #: error in `$Error` and `$?` all the same. Each is paired with the form the removal is entitled
    #: to, so a refusal covering both says nothing.
    "try { zzqq0 =5 } catch [System.IO.IOException] {}; Write-Host 'after'",
    "try { zzqq0 =5 } catch {}; Write-Host 'after'",
    "$Error.Clear(); try { zzqq0 =5 } catch {}; Write-Host $Error.Count",
    "$Error.Clear(); Write-Host $Error.Count",
    "try { zzqq0 =5 } catch {}; Write-Host $?",
    "try { item =5 } catch {}; Write-Host 'after'",
    "trap { continue }; zzq0000=5; Write-Host 'after'",
    "trap { Write-Host 'trapped'; continue }; zzq0000=5; Write-Host 'after'",
    "try { zzq0000=5 } finally { Write-Host 'fin' }; Write-Host 'after'",

    #: What a sub-expression that stores and loops is asked to preserve the behaviour of. The first
    #: two are bodies the sub-expression evaluator folds, so the differential holds the transcript
    #: the fold has to keep; each of the rest is a body it must refuse, and each names the one thing
    #: that makes the fold unsound — a name the enclosing scope wrote, a name the body writes that
    #: a later statement observes, the state a second evaluation of one site would carry, the
    #: `$null` 5.1 keeps where the interpreter's stream drops it, and a write no occurrence in the
    #: tree names.
    "Write-Output $($r = ''; foreach ($e in 'a', 'b') { $r = $r + $e }; $r)",
    'Write-Output $(foreach ($e in \'a\', \'b\') { $e })',
    "$q = 'a'; Write-Output $($q + 'b')",
    'Write-Output $($w = \'x\'; $w); Write-Output $w',
    "Set-Variable s 'A'; Write-Output $($s + 'B')",
    "foreach ($i in 1..2) { Write-Output $($c = $c + 'x'; $c) }",
    'foreach ($i in 1..2) { Write-Output $(if (0) { $m = \'A\' }; $o = "${m}"; '
    "$m = 'B'; $o) }",
    "Write-Output @($('a'; $z; 'b')).Count",
    'iex \'$u = "U"\'; Write-Output $($u + \'x\')',
    "Set-Variable q 5; function fq { $q + 1 }; Write-Output (fq)",

    #: What a fold's value spelling is asked to preserve the behaviour of. A `Char` and a `Byte`
    #: are the two widths the language spells no literal of, so each row reads the type back after
    #: the fold has spelled the value the body computed; a fold that wrote the wider value the
    #: payload alone names would answer the read the other way.
    '$x = $($r = [char]66; $r); Write-Output ($x -is [char])',
    '$x = $($r = [byte]77; $r); Write-Output ($x -is [byte])',

    #: What retention is asked to preserve the behaviour of. The read is spelled, so the retained
    #: store is owed in both models; the read inside the payload is not, so the row is the one the
    #: trusting model's contract costs — the defect it opens is recorded beside the differential.
    "$x = $($w = 'a'; 'v'); Write-Output $w",
    "$c = 'Write-Output $w'; $x = $($w = 'a'; 'v'); iex $c",

    #: What an abbreviated parameter is asked to preserve the behaviour of. Each binding was
    #: measured on 5.1: the alias and any unambiguous prefix name the parameter the written-out
    #: spelling does, a cmdlet's own parameters winning over the common ones where a prefix matches
    #: both, and a prefix that names two parameters or a common parameter the cmdlet does not carry
    #: binding nothing at all. Spelling one out therefore changes nothing the script does, and the
    #: two that bind nothing are left as written.
    "Set-Alias q1 -V Write-Output; q1 'x'",
    "Set-Alias q2 -v Write-Output; q2 'y'",
    "$o = [pscustomobject]@{}; Add-Member -Type NoteProperty k v -InputObject $o; $o.k",
    "$o = [pscustomobject]@{}; Add-Member -ty NoteProperty k v -InputObject $o; $o.k",
    "Get-Date -c; Write-Output 'ran'",
    "Write-Output (Get-Date -Y 2020 -Month 1 -Day 1).Year",
)


#: The scripts a host-free ledger's beliefs about 5.1 rest on, each of which is run so that the
#: belief is measured rather than remembered. Same rule as `BEHAVIOURS`: synthetic, small, safe, and
#: the deobfuscation differential is quantified over these too, since a script written to catch a
#: change of meaning is the last one that should go unchecked for it.
#:
#: Most are the corruption entry's own script, so that what is measured is what is deobfuscated.
#: The rest are witnesses written for a belief whose own script cannot be run — one that states a
#: possibility rather than an outcome, such as "the string `Invoke-Expression` runs may carry a
#: write". A witness makes the mechanism happen instead of leaving it open, which is the part a
#: host can answer.
#:
#: A fold the tool does not take belongs here as much as a corruption does. Such an entry states
#: what the folded script would have to write, and the value it names is only worth asserting in a
#: host-free test once a host has said it — so the backlog entries of
#: `test/lib/scripts/ps1/deobfuscation/test_folding.py` are carried here beside the ledger's.
CLAIMS: tuple[str, ...] = (
    "$x = 'a'; . { Remove-Variable x }; Write-Host $x",
    "$x = 'a'; . { New-Variable x 'b' -Force }; Write-Host $x",
    "$x = 'a'; . { Write-Output 'b' -OutVariable x }; Write-Host $x",
    "Set-Variable global:y 'b'; Write-Host $global:y",
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x",
    "$x = 'a'; $true -or ($x = 'b'); Write-Host $x",
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]",
    "trap { continue }; throw 'e'; Write-Host 'after'",
    "[int]'a'; Write-Host 'after'",
    "trap { continue }; [int]'a'; Write-Host 'after'",
    "trap { continue }; Write-Host 'one'; throw 'e'; Write-Host 'three'",
    "trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'",
    "trap { continue }; foreach ($i in 1..2) { throw 'e'; Write-Host 'tail' }; "
    "Write-Host 'next'",
    "trap { continue }; switch (1) { 1 { throw 'e'; Write-Host 'tail' } }; Write-Host 'next'",
    "trap { continue }; try { throw 'e' } catch { throw 'f'; Write-Host 'tail' }; "
    "Write-Host 'next'",
    "if ($true) { trap { continue }; Write-Host 'in'; throw 'e' }; Write-Host 'after'",
    "$x = 'a'; trap { $x = 'b'; continue }; throw 'e'; Write-Host $x",
    "trap { Write-Host 'outer'; continue }; if ($true) { trap { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'",
    "trap { Write-Host 'outer'; continue }; if ($true) { "
    "trap [System.IO.IOException] { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'",
    "function A { Write-Host 'a' }; function B { Write-Host 'b' }; Set-Alias x A; "
    "trap { Set-Alias x B; continue }; throw 'e'; x",
    "function A { Write-Host 'a' }; function B { Write-Host 'b' }; Set-Alias x A; "
    "trap { Set-Alias x B -Scope 1; continue }; throw 'e'; x",
    "$ErrorActionPreference = 'Stop'; trap { continue }; "
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'",
    "$ErrorActionPreference = 'Stop'; trap { continue }; "
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'",
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'",
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'",
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'",
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; Write-Output 'hi'",
    "trap { continue }; 1/0; Write-Host 'after'",
    "trap { continue }; $x = \"$(1/0)$(Set-Alias zzq Write-Output)\"; zzq 'hi'",
    "trap { break }; [int]'a'; Write-Host 'after'",
    "trap { }; [int]'a'; Write-Host 'after'",
    "Get-Item nope -ErrorAction Stop; Write-Host 'after'",
    "trap { continue }; Get-Item nope -ErrorAction Stop; Write-Host 'after'",
    "Get-Item nope -ErrorAc Stop; Write-Host 'after'",
    "Get-Item nope -ErrorAction:Stop; Write-Host 'after'",
    "Get-Item nope -ErrorAction 1; Write-Host 'after'",
    "Get-Item nope -ErrorAction Continue; Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'; [int]'a'; Write-Host 'after'",
    "Get-Item nope -e Stop; Write-Host 'after'",
    "Get-Item nope -errora Stop; Write-Host 'after'",
    "Get-Item nope -ErrorAction S; Write-Host 'after'",
    "& { trap { break }; [int]'a' }; Write-Host 'after'",
    "trap { continue }; & { trap { break }; [int]'a' }; Write-Host 'after'",
    "trap { continue }; iex 'throw 1'; Write-Host 'after'",
    "trap { continue }; $s = { throw 'x' }; [int]'a'; Write-Host 'after'",
    "New-Variable ErrorActionPreference Stop -Force; trap { continue }; [int]'a'; "
    "Write-Host 'after'",
    "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; Get-Item nope; "
    "Write-Host 'after'",
    "function Raise { throw 'e' }; function Wrap { trap { continue }; Raise; Write-Host 'in' }; "
    "Wrap; Write-Host 'after'",
    "throw 'e'; Write-Host 'after'",
    "$x = $(trap { continue }; [int]'a'; 'in'); Write-Host $x",
    "$(trap { continue }); [int]'a'; Write-Host 'after'",
    "trap { continue }; $x = $([int]'a'; 'in'); Write-Host $x",
    "$x = @(trap { continue }; [int]'a'; 'in'); Write-Host $x",
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
    "$script:y = 'b'; Write-Output $script:y",
    "$global:y = 'b'; Write-Output $global:y",
    "$s = 'x'; Write-Output $script:s",
    "$script:s = 'x'; Write-Output $s",
    '$n = 1; $n += 2; Write-Output $n',
    "$s = 'a'; $s += 'b'; $s += 'c'; Write-Output $s",
    '$n = 1; $n++; Write-Output $n',
    '$n = 5; $n -= 2; Write-Output $n',
    "$c = 'Write-Out'; $c += 'put 5'; Invoke-Expression $c",
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

    #: What a scriptblock created from a string is asked to preserve the behaviour of. A created
    #: block reads the scope that runs it and cannot assign its locals — where the same text run
    #: through `Invoke-Expression`, or through a dot, can — so each row makes one of those three
    #: facts happen and prints what survives of the caller's variable. The tail each row carries is
    #: what the tool rewrites, which is what puts the row in the differential at all.
    "$v = 'a'; & ([ScriptBlock]::Create('$v + \"b\"')); Write-Output (1 + 1)",
    "$v = 'a'; & ([ScriptBlock]::Create('$v = \"b\"')); Write-Output $v; Write-Output (1 + 1)",
    "$v = 'a'; . ([ScriptBlock]::Create('$v = \"b\"')); Write-Output $v; Write-Output (1 + 1)",
)


#: What the host's own command tables hold, which is the premise the tables in
#: `refinery.lib.scripts.ps1.data` encode. Those were captured once and have been edited by hand
#: since; a name added to the alias table that 5.1 does not bind as an alias inverts the resolution
#: precedence for it, because nothing in ordinary name lookup beats an alias.
#:
#: This is the one place a script is asked about the machine on purpose. The rest of the corpus is
#: written to be independent of it; these read the state of a Windows PowerShell 5.1 installation,
#: which is the oracle's whole subject, and the ledger they feed is a claim about 5.1 rather than
#: about the box that ran it. Nothing here writes anything: `Get-Alias` and `Get-Command` read, and
#: the one entry that loads a module loads one that ships with the host, which is the same thing
#: every `Get-Alias` capture does implicitly and the reason the CIM block in `data` exists.
#:
#: Each name is asked beside a control, because "the host does not bind this" and "the measurement
#: found nothing" are the same transcript otherwise: `iex` against the disputed aliases, and
#: `Get-Item` against the commands the disputed entries name.
TABLES: tuple[str, ...] = (
    'Get-Alias iex',
    'Get-Alias item',
    'Get-Alias member',
    'Get-Alias variable',
    'Get-Alias childitem',
    'Get-Alias gerr',
    'Get-Alias fhx',
    'Get-Command Get-Item',
    'Get-Command Get-Member',
    'Get-Command Get-Variable',
    'Get-Command Get-ChildItem',
    'Get-Command Get-Error',
    'Get-Command Format-Hex',
    '(Get-Command help).CommandType',
    '(Get-Command gcim -ErrorAction SilentlyContinue).CommandType',
)


#: What a value's type is and what an operation produces, measured rather than assumed. The unit
#: had no place to keep a type — a Char and a one-character String were the same object to it — so
#: every belief about one was written by us, which is the condition these exist to end.
#:
#: Two witnesses per entry, because one is not enough to see the question. `Write-Output (,$t)`
#: names the container and `Write-Output $t` unrolls it, so that the transcript's own type column
#: names first the whole and then each element: an `Object[]` of Char and an `Object[]` of String
#: render alike and differ only in the second witness, and an arithmetic answer is wrong in its
#: value rather than in its type. `Write-Host` cannot be used for either — it writes an information
#: record carrying `MessageData`, which is the rendered text with the type gone.
#:
#: The container witness is `(,$t)` rather than `$t.GetType().FullName` because a witness has to
#: survive the rewriting it is there to measure. `Write-Output` unrolls one level, the comma adds
#: one back, and what reaches the transcript is `$t` itself with its type stamped on it — the same
#: name `GetType().FullName` would have printed, obtained without asking `$t` for a member. That
#: matters twice over: 5.1 refuses to parse a numeric literal standing as a receiver, so a folded
#: row asking `GetType` reports a parse error and says nothing about its own subject; and `$null`
#: has no `GetType` at all, so a row whose value is null used to have to settle for `$null -eq`.
#:
#: Where a question is whether one spelling behaves like another, the entry prints both and the
#: comparison is between its own two lines rather than against a remembered answer: that is what
#: settles where a Char may be written as a String, which the folder does everywhere today and which
#: 5.1 permits only in some places.
#:
#: Assignment is what the value passes through rather than an extra step: `$t = <expression>` is the
#: shape the defects are about, it evaluates the expression once, and PowerShell does not unwrap a
#: one-element collection on the way.
#:
#: A comparison is asked in both orders, because the operand on the left settles what kind of
#: comparison happens: `'10' -lt 9` orders two texts and `10 -lt '9'` two numbers, so a row that
#: measured only one of the two would say nothing about the rule. An absent operand is asked against
#: the value it would convert to on the other side — a zero, an empty text, a `$false` — since those
#: are the three the presence rule and a conversion disagree about, and against nothing else the two
#: answer alike.
#:
#: A `System.Decimal` is asked at the extremes of its range, which is where Python's own arithmetic
#: stops agreeing with .NET's: the type is a 96 bit coefficient with a scale of at most 28 and
#: Python rounds every result to `decimal.getcontext().prec`, 28 by default. So each row is a
#: magnitude or a scale that context cannot hold, and one either side of the largest value the type
#: reaches, which is where an arithmetic overflow starts.
TYPES: tuple[str, ...] = (
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output (,$t); Write-Output $t",
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')",
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }",
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output (,$t)',
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t',
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output (,$t)",
    '$t = [char]65; Write-Output (,$t); Write-Output $t',
    '$t = [char[]](72, 73); Write-Output (,$t); Write-Output $t',
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])",
    "$t = 'ABC'[0]; Write-Output (,$t); Write-Output $t",
    "$t = [char[]]'ABC'; Write-Output (,$t); Write-Output $t.Count",
    "$t = 'ABC'.ToCharArray(); Write-Output (,$t); Write-Output $t.Count",
    "Write-Output ('x' -replace 'x', [char]65); Write-Output ('x' -replace 'x', 'A')",
    "Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')",
    "Write-Output ([char]65 + 1); Write-Output ('A' + 1)",
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')",
    'Write-Output (([char]65) * 3)',
    "Write-Output ('A' * 3)",
    "Write-Output (([char]65).ToString()); Write-Output (('A').ToString())",
    "Write-Output ('a,b' -split [char]44); Write-Output ('a,b' -split ',')",
    "Write-Output ('xyx'.Replace([char]120, [char]122)); Write-Output ('xyx'.Replace('x', 'z'))",
    "Write-Output ('{0}' -f [char]65); Write-Output ('{0}' -f 'A')",
    "Write-Output (([char]65, [char]66) -join ''); Write-Output (('A', 'B') -join '')",
    "Write-Output ([string][char]65); Write-Output ([string]'A')",
    '$c = [char]65; $s = \'A\'; Write-Output "$c"; Write-Output "$s"',
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])",
    "Write-Output (([char]65).Length); Write-Output (('A').Length)",
    "Write-Output (([char]65).Count); Write-Output (('A').Count)",
    "Write-Output ([char]65 -eq 'A'); Write-Output ('A' -eq 'A')",
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }',
    "$t = 'AB'.Count; Write-Output (,$t); Write-Output $t",
    '$t = (5).Count; Write-Output (,$t); Write-Output $t',
    '$t = (5).Length; Write-Output (,$t); Write-Output $t',
    "$t = 1 + 'AB'.Count; Write-Output (,$t); Write-Output $t",
    '$t = @(1, 2, 3).Rank; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2, 3).Count; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2, 3).Length; Write-Output (,$t); Write-Output $t',
    "$t = 'AB'.Length; Write-Output (,$t); Write-Output $t",
    'Write-Output ((5).PSTypeNames)',
    "Write-Output (('AB').PSTypeNames)",
    'Write-Output ((5).PSObject.GetType().FullName)',
    '$t = (5).Rank; Write-Output (,$t)',
    "$t = 'AB'.Zqnope; Write-Output (,$t)",
    '$t = (5).Zqnope; Write-Output (,$t)',
    '$t = $null.Count; Write-Output (,$t); Write-Output $t',
    '$f = New-Object IO.MemoryStream; Write-Output $f.Length.GetType().FullName',
    '$f = New-Object IO.MemoryStream; $f.Dispose(); Write-Output $f.Length',
    '$t = @(); Write-Output (,$t); Write-Output $t.Count',
    '$t = , 1; Write-Output (,$t); Write-Output $t.Count',
    '$t = 0xFF; Write-Output (,$t); Write-Output $t',
    '$s = 0xFF; $t = "$s"; Write-Output (,$t); Write-Output $t',
    '$t = 0x7FFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = 1kb; Write-Output (,$t); Write-Output $t',
    '$t = 1L; Write-Output (,$t); Write-Output $t',
    '$t = 10d; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFF + 0; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output (,$t); Write-Output $t',
    '$t = 1kb + 0; Write-Output (,$t); Write-Output $t',
    '$t = 1L + 0; Write-Output (,$t); Write-Output $t',
    '$t = 10d + 0; Write-Output (,$t); Write-Output $t',
    '$t = 2147483648; Write-Output (,$t); Write-Output $t',
    '$t = 1.5; Write-Output (,$t); Write-Output $t',
    '$t = -0.0; Write-Output (,$t); Write-Output $t',
    '$t = 1e3; Write-Output (,$t); Write-Output $t',
    '$t = 4gb; Write-Output (,$t); Write-Output $t',
    '$t = 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = 10D; Write-Output (,$t); Write-Output $t',
    '$t = 1l; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFL; Write-Output (,$t); Write-Output $t',
    '$t = 0x100000000; Write-Output (,$t); Write-Output $t',
    '$t = 0x7FFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = 9223372036854775807; Write-Output (,$t); Write-Output $t',
    '$t = 9223372036854775808; Write-Output (,$t); Write-Output $t',
    '$t = 100000000000000000000000000000000; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = 007; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFFFFFFFL; Write-Output (,$t); Write-Output $t',
    '$t = 1lkb; Write-Output (,$t); Write-Output $t',
    '$t = 1dkb; Write-Output (,$t); Write-Output $t',
    '$t = 0x0000000000000001; Write-Output (,$t); Write-Output $t',
    '$t = -2147483649; Write-Output (,$t); Write-Output $t',
    '$t = 1.5L; Write-Output (,$t); Write-Output $t',
    '$t = 2.5L; Write-Output (,$t); Write-Output $t',
    '$t = -(2147483648); Write-Output (,$t); Write-Output $t',
    '$t = -(2147483647); Write-Output (,$t); Write-Output $t',
    '$t = - 2147483648; Write-Output (,$t); Write-Output $t',
    '$t = - 2147483647; Write-Output (,$t); Write-Output $t',
    '$t = 1.5kb; Write-Output (,$t); Write-Output $t',
    '$t = 0xFFkb; Write-Output (,$t); Write-Output $t',
    '$t = 10 - $null; Write-Output (,$t); Write-Output $t',
    '$t = $null + 5; Write-Output (,$t); Write-Output $t',
    '$t = $null - 5; Write-Output (,$t); Write-Output $t',
    '$t = 10 - $null + 3; Write-Output (,$t); Write-Output $t',
    '$t = $null -band 1; Write-Output (,$t); Write-Output $t',
    '$a = $null; $b = 5; $t = $a * $b; Write-Output (,$t)',
    '$a = $null; $t = $a * 5; Write-Output (,$t)',
    '$t = $null * 1; Write-Output (,$t)',
    '$t = 1_0; Write-Output (,$t); Write-Output $t',
    '$t = 2147483647 + 1; Write-Output (,$t); Write-Output $t',
    '$t = 512MB * 512MB; Write-Output (,$t); Write-Output $t',
    '$t = 9223372036854775807 + 2; Write-Output (,$t); Write-Output $t',
    '$t = [decimal]::MaxValue + 1; Write-Output (,$t); Write-Output $t',
    '$t = 100000000000000d * 100000000000000d; Write-Output (,$t); Write-Output $t',
    '$t = 10000000000000000000000000000d; Write-Output (,$t); Write-Output $t',
    '$t = 1E+28d; Write-Output (,$t); Write-Output $t',
    "$t = 12 + '0xabc'; Write-Output (,$t); Write-Output $t",
    "$t = 16 + 'file'; Write-Output (,$t); Write-Output $t",
    "$t = 5 + '5'; Write-Output (,$t); Write-Output $t",
    "$t = '5' + 5; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0x10'; Write-Output (,$t); Write-Output $t",
    '$t = -2147483647 - 1; Write-Output (,$t); Write-Output $t',
    '$t = -2147483648; Write-Output (,$t); Write-Output $t',
    '$t = [int64]::MaxValue * 2; Write-Output (,$t); Write-Output $t',
    '$t = [double]::PositiveInfinity; Write-Output (,$t); Write-Output $t',
    '$t = [double]::NaN; Write-Output (,$t); Write-Output $t',
    '$t = 10, 20, 30, 20, 10 -ne 20; Write-Output (,$t); Write-Output $t',
    '$t = 10, 20, 30 -eq 20; Write-Output (,$t); Write-Output $t',
    '$t = 10 -ne 20; Write-Output (,$t); Write-Output $t',
    "$t = [string]('a', 'b'); Write-Output (,$t); Write-Output $t",
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t",
    '$OFS = \'-\'; Write-Output "$(1, 2)"',
    '$t = ([char]65).ToUpper(); Write-Output (,$t); Write-Output $t',
    "$t = ('A').ToUpper(); Write-Output (,$t); Write-Output $t",
    '$t = ([char]65).Substring(0); Write-Output (,$t); Write-Output $t',
    "$t = ('A').Substring(0); Write-Output (,$t); Write-Output $t",
    '$t = ([char]65).ToString(); Write-Output (,$t); Write-Output $t',
    '$t = [int][char]48; Write-Output (,$t); Write-Output $t',
    "$t = [int]'0'; Write-Output (,$t); Write-Output $t",
    "$h = @{}; $h[[char]65] = 1; $t = $h['A']; Write-Output (,$t)",
    "$h = @{}; $h['A'] = 1; $t = $h[[char]65]; Write-Output (,$t)",
    "$t = 1 + '2147483648'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '5'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '1e3'; Write-Output (,$t); Write-Output $t",
    "$t = [double]'1,5'; Write-Output (,$t); Write-Output $t",
    '$t = -bnot 0xFFFFFFFF; Write-Output (,$t); Write-Output $t',
    '$t = -bnot 0xFF; Write-Output (,$t); Write-Output $t',
    '$t = -bnot [byte]5; Write-Output (,$t); Write-Output $t',
    '$t = -bnot [uint32]7; Write-Output (,$t); Write-Output $t',
    '$t = -bnot 1L; Write-Output (,$t); Write-Output $t',
    '$t = -bnot 1.5; Write-Output (,$t); Write-Output $t',
    '$t = -bnot $null; Write-Output (,$t); Write-Output $t',
    "$t = -bnot '5'; Write-Output (,$t); Write-Output $t",
    "$t = -bnot 'abc'; Write-Output (,$t); Write-Output $t",
    '$t = -bnot [char]65; Write-Output (,$t); Write-Output $t',
    '$t = -bnot $true; Write-Output (,$t); Write-Output $t',
    '$t = -bnot 10d; Write-Output (,$t); Write-Output $t',
    '$t = -bnot 3000000000.0; Write-Output (,$t); Write-Output $t',
    "$t = 'ab' * 0xFFFFFFFF; Write-Output (,$t); Write-Output $t",
    'Write-Output "abc".Length',
    "Write-Output 'abc'.Length",
    'Write-Output 1',
    'Write-Output -1',
    'Write-Output (-1)',
    'Write-Output -1.5',
    'Write-Output -1L',
    '$t = @(@(1, 2)); Write-Output (,$t); Write-Output $t.Count',
    '$t = @((1, 2)); Write-Output (,$t); Write-Output $t.Count',
    '$t = @(@(1, 2), 3); Write-Output (,$t); Write-Output $t.Count',
    '$t = ,(1, 2); Write-Output (,$t); Write-Output $t.Count',
    '$t = (1, 2), 3; Write-Output (,$t); Write-Output $t.Count',
    "$t = 'a', 1; Write-Output (,$t); Write-Output $t",
    '$t = [int]5; Write-Output (,$t); Write-Output $t',
    '$t = [long]5; Write-Output (,$t); Write-Output $t',
    '$t = [byte]5; Write-Output (,$t); Write-Output $t',
    '$t = [byte]300; Write-Output (,$t); Write-Output $t',
    '$t = [byte]-1; Write-Output (,$t); Write-Output $t',
    '$t = [sbyte]-5; Write-Output (,$t); Write-Output $t',
    '$t = [int16]7; Write-Output (,$t); Write-Output $t',
    '$t = [uint16]7; Write-Output (,$t); Write-Output $t',
    '$t = [uint32]7; Write-Output (,$t); Write-Output $t',
    '$t = [uint64]7; Write-Output (,$t); Write-Output $t',
    '$t = [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    '$t = [int]2147483648; Write-Output (,$t); Write-Output $t',
    '$t = [int]1.5; Write-Output (,$t); Write-Output $t',
    '$t = [int]2.5; Write-Output (,$t); Write-Output $t',
    '$t = [int]1.4; Write-Output (,$t); Write-Output $t',
    '$t = [int]-1.5; Write-Output (,$t); Write-Output $t',
    '$t = [long]1.5; Write-Output (,$t); Write-Output $t',
    '$t = [double]5; Write-Output (,$t); Write-Output $t',
    '$t = [decimal]5; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5; Write-Output (,$t); Write-Output $t',
    '$t = [double]1.5d; Write-Output (,$t); Write-Output $t',
    '$t = [int]10d; Write-Output (,$t); Write-Output $t',
    '$t = [char]0; Write-Output (,$t); Write-Output $t',
    '$t = [char]65535; Write-Output (,$t); Write-Output $t',
    '$t = [char]65536; Write-Output (,$t); Write-Output $t',
    '$t = [char]-1; Write-Output (,$t); Write-Output $t',
    '$t = [int][char]65; Write-Output (,$t); Write-Output $t',
    '$t = [bool]0; Write-Output (,$t); Write-Output $t',
    '$t = [bool]1; Write-Output (,$t); Write-Output $t',
    "$t = [bool]''; Write-Output (,$t); Write-Output $t",
    "$t = [bool]'a'; Write-Output (,$t); Write-Output $t",
    '$t = [int]$true; Write-Output (,$t); Write-Output $t',
    '$t = [string]5; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.5; Write-Output (,$t); Write-Output $t',
    '$t = [string]$true; Write-Output (,$t); Write-Output $t',
    '$t = [string]10d; Write-Output (,$t); Write-Output $t',
    "$t = [int]'5'; Write-Output (,$t); Write-Output $t",
    "$t = [int]' 5 '; Write-Output (,$t); Write-Output $t",
    "$t = [int]'abc'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1e3'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'1e3'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1_0'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0b1010'; Write-Output (,$t); Write-Output $t",
    "$t = [int]''; Write-Output (,$t); Write-Output $t",
    "$t = [int]'   '; Write-Output (,$t); Write-Output $t",
    "$t = [int]'+7'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'007'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'.5'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'5.'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1,000'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1kb'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0o17'; Write-Output (,$t); Write-Output $t",
    '$t = [int]"`t`r5`n"; Write-Output (,$t); Write-Output $t',
    "$t = [int]'7.5'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'2.5'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'-1'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'0x80'; Write-Output (,$t); Write-Output $t",
    "$t = [sbyte]'0x80'; Write-Output (,$t); Write-Output $t",
    "$t = [uint16]'0xFFFF'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0xFFFFFFFF'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'0x100'; Write-Output (,$t); Write-Output $t",
    "$t = [char]'A'; Write-Output (,$t); Write-Output $t",
    "$t = [char]'AB'; Write-Output (,$t); Write-Output $t",
    "$t = [char]''; Write-Output (,$t); Write-Output $t",
    "$t = [bool]'0'; Write-Output (,$t); Write-Output $t",
    "$t = [string]'foo'; Write-Output (,$t); Write-Output $t",
    '$t = [int]$null; Write-Output (,$t); Write-Output $t',
    '$t = [string]$null; Write-Output (,$t); Write-Output $t',
    '$t = [bool]$null; Write-Output (,$t); Write-Output $t',
    '$t = [char]$null; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + $null; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + $true; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + 1.50d; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + 1.5; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + @(1, 2); Write-Output (,$t); Write-Output $t",
    "$t = [double]'1.5'; Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('FFFFFFFF', 16); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('80000000', 16); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('0x10'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('1_0'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('7.5'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32(' 5 '); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('-10', 16); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('017', 8); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToByte('FF', 16); Write-Output (,$t); Write-Output $t",
    '$t = [Convert]::ToInt64(5); Write-Output (,$t); Write-Output $t',
    '$t = [Convert]::ToInt32(1.5); Write-Output (,$t); Write-Output $t',
    '$t = [Convert]::ToInt32(1.5d); Write-Output (,$t); Write-Output $t',
    '$t = [Convert]::ToInt32($null); Write-Output (,$t); Write-Output $t',
    '$t = [Convert]::ToChar(65); Write-Output (,$t); Write-Output $t',
    "$t = 'abc' -as [int]; Write-Output (,$t); Write-Output $t",
    '$t = 5 -as [long]; Write-Output (,$t); Write-Output $t',
    '$t = 300 -as [byte]; Write-Output (,$t); Write-Output $t',
    '$a = New-Object byte[] 1; $t = $a[0]; Write-Output (,$t); Write-Output $t',
    "$a = New-Object byte[] '0b10'; $t = $a.Count; Write-Output (,$t); Write-Output $t",
    "$a = New-Object byte[] '0o10'; $t = $a.Count; Write-Output (,$t); Write-Output $t",
    'function f { ,$args }; $t = f 1 2; Write-Output (,$t); Write-Output $t.Count',
    "$a = 10, 20, 30; $t = $a['1']; Write-Output (,$t); Write-Output $t",
    "$t = switch ('1') { 1 { 'number' } }; Write-Output (,$t); Write-Output $t",
    "$t = switch (1) { '1' { 'text' } }; Write-Output (,$t); Write-Output $t",
    "$t = switch ('0x10') { 16 { 'hex' } }; Write-Output (,$t); Write-Output $t",
    "$t = 'abc' -replace '(?<x>b)', '[${x}]'; Write-Output (,$t); Write-Output $t",
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t",
    '$t = [string]1E20; Write-Output (,$t); Write-Output $t',
    '$t = [string]0.0000001; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.5E-7; Write-Output (,$t); Write-Output $t',
    '$t = 1 -ceq 1; Write-Output (,$t); Write-Output $t',
    "$t = 'A' -ceq 'a'; Write-Output (,$t); Write-Output $t",
    "$t = 'A' -ieq 'a'; Write-Output (,$t); Write-Output $t",
    '$t = [array]5; Write-Output (,$t); Write-Output $t.Count',
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t',
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t',
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    'function f { $i = 0; $i++; $i++; $i }; $t = f; Write-Output (,$t); Write-Output $t',
    "function f { $s = 'abc'; $s++; $s }; $t = f; Write-Output (,$t); Write-Output $t",
    'function g { ,(1, 2) }; $t = @(g); Write-Output $t.Count; Write-Output (,$t[0])',
    "$t = @('1') -contains 1; Write-Output (,$t); Write-Output $t",
    "$t = @(1) -contains '1'; Write-Output (,$t); Write-Output $t",
    "$t = 'a*' -like 'a`*'; Write-Output (,$t); Write-Output $t",
    "$t = 'ab' -like 'a`*'; Write-Output (,$t); Write-Output $t",
    "$t = 'b' -like '[!a]'; Write-Output (,$t); Write-Output $t",
    "$t = '1_0' -band 15; Write-Output (,$t); Write-Output $t",
    '$t = [byte]400; Write-Output (,$t); Write-Output $t',
    '$t = [byte](200 * 2); Write-Output (,$t); Write-Output $t',
    'function f { $null; 1; $null }; $t = f; Write-Output $t.Count; Write-Output (,$t)',
    "$t = 'ſ' -match 's'; Write-Output (,$t); Write-Output $t",
    "$t = 'ſ' -cmatch 's'; Write-Output (,$t); Write-Output $t",
    '$t = 2147483647 * 2147483647; Write-Output (,$t); Write-Output $t',
    '$t = 9223372036854775807L + 1; Write-Output (,$t); Write-Output $t',
    '$t = 9223372036854775807L - -1L; Write-Output (,$t); Write-Output $t',
    '$t = -2147483648 - 9223372036854775807L; Write-Output (,$t); Write-Output $t',
    '$t = -2147483648 % -1; Write-Output (,$t); Write-Output $t',
    '$t = -2147483648 / -1; Write-Output (,$t); Write-Output $t',
    '$t = 0 - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    '$t = 1 + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    '$t = [uint64]18446744073709551615 + 1; Write-Output (,$t); Write-Output $t',
    '$t = -1 * [uint64]1; Write-Output (,$t); Write-Output $t',
    '$t = 2147483647 * [uint32]4294967295; Write-Output (,$t); Write-Output $t',
    '$t = -1 -band [uint32]1; Write-Output (,$t); Write-Output $t',
    '$t = 1 / [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    '$t = 0 + [char]65; Write-Output (,$t); Write-Output $t',
    '$t = [char]48 -band [byte]255; Write-Output (,$t); Write-Output $t',
    '$t = [char]48 -bxor [char]48; Write-Output (,$t); Write-Output $t',
    '$t = 1.5 * [char]48; Write-Output (,$t); Write-Output $t',
    '$t = [char]48 - 0.0; Write-Output (,$t); Write-Output $t',
    '$t = [char]65 -bxor 32; Write-Output (,$t); Write-Output $t',
    "$t = 0 + '5'; Write-Output (,$t); Write-Output $t",
    "$t = $true + ''; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '0xFFFFFFFF'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '1kb'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '1.5L'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '1e400'; Write-Output (,$t); Write-Output $t",
    '$t = [decimal]::MaxValue % 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = [decimal]::MaxValue % 1; Write-Output (,$t); Write-Output $t',
    '$t = 1d + 0.1; Write-Output (,$t); Write-Output $t',
    '$t = 1d - 0.1; Write-Output (,$t); Write-Output $t',
    '$t = [byte]1 -shl 4; Write-Output (,$t); Write-Output $t',
    '$t = [byte]1 -shl -1; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5 -shl 1; Write-Output (,$t); Write-Output $t',
    '$t = 1L -shl 64; Write-Output (,$t); Write-Output $t',
    '$t = $true + 9223372036854775807L; Write-Output (,$t); Write-Output $t',
    '$t = $null + $true; Write-Output (,$t); Write-Output $t',
    '$t = $null -band [uint32]1; Write-Output (,$t); Write-Output $t',
    '$t = $true * 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = 1.5 / -0.0; Write-Output (,$t); Write-Output $t',
    "$t = 'ab' * 1.5; Write-Output (,$t); Write-Output $t",
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t',
    '$v = [single]1.5; $t = $v + 1; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5 + 1; Write-Output (,$t); Write-Output $t',
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t',
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t',
    "$t = 1 + ' 7 '; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '+5'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '  '; Write-Output (,$t); Write-Output $t",
    "$t = '5' - 1; Write-Output (,$t); Write-Output $t",
    "$t = 1 - '5'; Write-Output (,$t); Write-Output $t",
    "$t = '5' * 2; Write-Output (,$t); Write-Output $t",
    "$t = '10' -band 6; Write-Output (,$t); Write-Output $t",
    "$t = '5' / 2; Write-Output (,$t); Write-Output $t",
    "$t = '1e400' + 1; Write-Output (,$t); Write-Output $t",
    '$t = $true + 1; Write-Output (,$t); Write-Output $t',
    '$t = 1 + $true; Write-Output (,$t); Write-Output $t',
    '$t = $true - 1; Write-Output (,$t); Write-Output $t',
    '$t = 1 - $true; Write-Output (,$t); Write-Output $t',
    '$t = $true * 2; Write-Output (,$t); Write-Output $t',
    '$t = 2 * $true; Write-Output (,$t); Write-Output $t',
    '$t = $true -band 1; Write-Output (,$t); Write-Output $t',
    '$t = $true + $true; Write-Output (,$t); Write-Output $t',
    '$t = $false + 1; Write-Output (,$t); Write-Output $t',
    '$t = $true / 1; Write-Output (,$t); Write-Output $t',
    '$t = $true + 1.5; Write-Output (,$t); Write-Output $t',
    '$t = $true -bxor $false; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2) + @(3, 4); Write-Output (,$t); Write-Output $t.Count',
    '$t = @(1, 2) + 5; Write-Output (,$t); Write-Output $t.Count',
    '$t = 5 + @(1, 2); Write-Output (,$t); Write-Output $t.Count',
    '$t = @(1, 2) * 2; Write-Output (,$t); Write-Output $t.Count',
    '$t = 2 * @(1, 2); Write-Output (,$t); Write-Output $t.Count',
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count',
    '$t = @() + 1; Write-Output (,$t); Write-Output $t.Count',
    '$t = @(1, 2) + $null; Write-Output (,$t); Write-Output $t.Count',
    '$t = $null + @(1, 2); Write-Output (,$t); Write-Output $t.Count',
    "$t = @(1, 2) + 'a'; Write-Output (,$t); Write-Output $t.Count",
    '$t = @(1, 2) - 1; Write-Output (,$t); Write-Output $t.Count',
    '$t = @(1, 2) * 0; Write-Output (,$t); Write-Output $t.Count',
    "$t = $null + 'abc'; Write-Output (,$t); Write-Output $t",
    '$t = $null + [char]65; Write-Output (,$t); Write-Output $t',
    '$t = $null + 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = $true -and $true; Write-Output (,$t); Write-Output $t',
    '$t = 1 -and 2; Write-Output (,$t); Write-Output $t',
    '$t = 1 -and 0; Write-Output (,$t); Write-Output $t',
    '$t = 0 -or 0; Write-Output (,$t); Write-Output $t',
    '$t = $true -xor $true; Write-Output (,$t); Write-Output $t',
    '$t = 5 -xor 0; Write-Output (,$t); Write-Output $t',
    "$t = 'abc' -and $true; Write-Output (,$t); Write-Output $t",
    "$t = '' -or $false; Write-Output (,$t); Write-Output $t",
    "$t = '0' -and $true; Write-Output (,$t); Write-Output $t",
    "$t = 'false' -and $true; Write-Output (,$t); Write-Output $t",
    "$t = ' ' -and $true; Write-Output (,$t); Write-Output $t",
    '$t = [char]0 -or $false; Write-Output (,$t); Write-Output $t',
    "$t = [char]'0' -and $true; Write-Output (,$t); Write-Output $t",
    '$t = 0.0 -or $false; Write-Output (,$t); Write-Output $t',
    '$t = -0.0 -or $false; Write-Output (,$t); Write-Output $t',
    '$t = 0.0d -or $false; Write-Output (,$t); Write-Output $t',
    '$t = [uint64]0 -or $false; Write-Output (,$t); Write-Output $t',
    '$t = $null -or $false; Write-Output (,$t); Write-Output $t',
    '$t = @() -or $false; Write-Output (,$t); Write-Output $t',
    '$t = @(0) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @(0, 0) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @($false) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @($null) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @(@()) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = [bool][char]0; Write-Output (,$t); Write-Output $t',
    "$t = [bool][char]'0'; Write-Output (,$t); Write-Output $t",
    '$t = [bool]0.0; Write-Output (,$t); Write-Output $t',
    '$t = [bool]-0.0; Write-Output (,$t); Write-Output $t',
    '$t = [bool]0.0d; Write-Output (,$t); Write-Output $t',
    '$t = [bool](0.0 / 0.0); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@(); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@(0); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@(0, 0); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@($false); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@($null); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@(@()); Write-Output (,$t); Write-Output $t',
    "$t = [bool]' '; Write-Output (,$t); Write-Output $t",
    "$t = [bool]'false'; Write-Output (,$t); Write-Output $t",
    '$t = -not @(); Write-Output (,$t); Write-Output $t',
    '$t = -not @(0); Write-Output (,$t); Write-Output $t',
    "$t = -not '0'; Write-Output (,$t); Write-Output $t",
    '$t = -not [char]0; Write-Output (,$t); Write-Output $t',
    "$t = if ([char]0) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = if ('0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = if (@(@())) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    '$t = (,(,0)) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,(,@())) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,[char]0) -and $true; Write-Output (,$t); Write-Output $t',
    "$t = (,'') -and $true; Write-Output (,$t); Write-Output $t",
    "$t = (,' ') -and $true; Write-Output (,$t); Write-Output $t",
    '$t = (,0.0) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,0.0d) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = [bool](,(,0)); Write-Output (,$t); Write-Output $t',
    '$t = [bool](,[char]0); Write-Output (,$t); Write-Output $t',
    '$t = -not (,[char]0); Write-Output (,$t); Write-Output $t',
    "$t = if ((,[char]0)) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = - '0'; Write-Output (,$t); Write-Output $t",
    "$t = - 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = - '5'; Write-Output (,$t); Write-Output $t",
    "$t = if (- '0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    '$t = (,@(1, 2)) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,$true) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = [byte]0 -or $false; Write-Output (,$t); Write-Output $t',
    '$t = 0L -or $false; Write-Output (,$t); Write-Output $t',
    '$t = 1.5d -and $true; Write-Output (,$t); Write-Output $t',
    '$t = $true -and [char]0; Write-Output (,$t); Write-Output $t',
    "$t = $true -and ''; Write-Output (,$t); Write-Output $t",
    '$t = $true -and @(); Write-Output (,$t); Write-Output $t',
    '$t = [char]65 -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @() * [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t.Count',
    '$t = @() * 5000; Write-Output (,$t); Write-Output $t.Count',
    '$t = (,@()) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,(,(,0))) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = (,1) -and $true; Write-Output (,$t); Write-Output $t',
    "$t = (,'a') -and $true; Write-Output (,$t); Write-Output $t",
    '$t = (,[char]65) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2, 3) -and $true; Write-Output (,$t); Write-Output $t',
    '$t = [bool](,@()); Write-Output (,$t); Write-Output $t',
    '$t = [bool](,1); Write-Output (,$t); Write-Output $t',
    '$t = - 0; Write-Output (,$t); Write-Output $t',
    '$t = - 5; Write-Output (,$t); Write-Output $t',
    '$t = - 0.0; Write-Output (,$t); Write-Output $t',
    '$t = - 1.5; Write-Output (,$t); Write-Output $t',
    '$t = - $null; Write-Output (,$t); Write-Output $t',
    '$t = - $true; Write-Output (,$t); Write-Output $t',
    '$t = - $false; Write-Output (,$t); Write-Output $t',
    '$t = - [char]65; Write-Output (,$t); Write-Output $t',
    '$t = - [char]0; Write-Output (,$t); Write-Output $t',
    '$t = - 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = - [byte]5; Write-Output (,$t); Write-Output $t',
    '$t = - [uint32]1; Write-Output (,$t); Write-Output $t',
    '$t = - (-2147483648); Write-Output (,$t); Write-Output $t',
    '$t = - 9223372036854775807L; Write-Output (,$t); Write-Output $t',
    '$t = - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    '$t = - @(); Write-Output (,$t); Write-Output $t',
    "$t = - '1e3'; Write-Output (,$t); Write-Output $t",
    "$t = - ' 5 '; Write-Output (,$t); Write-Output $t",
    "$t = - ''; Write-Output (,$t); Write-Output $t",
    '$t = [bool][sbyte]0; Write-Output (,$t); Write-Output $t',
    '$t = [bool][int16]0; Write-Output (,$t); Write-Output $t',
    '$t = [bool][uint16]0; Write-Output (,$t); Write-Output $t',
    '$t = [bool][uint32]0; Write-Output (,$t); Write-Output $t',
    '$t = [bool]1.5d; Write-Output (,$t); Write-Output $t',
    '$t = [bool](,$null); Write-Output (,$t); Write-Output $t',
    '$t = [bool](,@(1, 2)); Write-Output (,$t); Write-Output $t',
    '$t = [bool]@(0, 0, 0); Write-Output (,$t); Write-Output $t',
    "$t = -not (- '0'); Write-Output (,$t); Write-Output $t",
    "$t = (- '0') -and $true; Write-Output (,$t); Write-Output $t",
    "$t = if (- '5') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    '$t = $null -eq 0; Write-Output (,$t); Write-Output $t',
    '$t = 0 -eq $null; Write-Output (,$t); Write-Output $t',
    '$t = $null -eq $null; Write-Output (,$t); Write-Output $t',
    "$t = '' -eq 0; Write-Output (,$t); Write-Output $t",
    "$t = '' -eq '0'; Write-Output (,$t); Write-Output $t",
    "$t = $null -eq ''; Write-Output (,$t); Write-Output $t",
    "$t = '' -eq $null; Write-Output (,$t); Write-Output $t",
    "$t = '0' -eq 0; Write-Output (,$t); Write-Output $t",
    "$t = 0 -eq '0'; Write-Output (,$t); Write-Output $t",
    "$t = '1.0' -eq 1; Write-Output (,$t); Write-Output $t",
    "$t = 1 -eq '1.0'; Write-Output (,$t); Write-Output $t",
    '$t = $null -lt 1; Write-Output (,$t); Write-Output $t',
    "$t = '10' -lt '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -lt 9; Write-Output (,$t); Write-Output $t",
    "$t = 10 -lt '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -ge 9; Write-Output (,$t); Write-Output $t",
    "$t = 10 -ge '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -ne 10; Write-Output (,$t); Write-Output $t",
    "$t = 10 -ne '10'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -gt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -cgt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -igt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -cle '9'; Write-Output (,$t); Write-Output $t",
    '$t = $true -eq 1; Write-Output (,$t); Write-Output $t',
    '$t = $true -eq 2; Write-Output (,$t); Write-Output $t',
    '$t = 2 -eq $true; Write-Output (,$t); Write-Output $t',
    "$t = $true -eq 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 'abc' -eq $true; Write-Output (,$t); Write-Output $t",
    "$t = $true -eq ''; Write-Output (,$t); Write-Output $t",
    '$t = $false -eq 0; Write-Output (,$t); Write-Output $t',
    '$t = $true -ne 2; Write-Output (,$t); Write-Output $t',
    '$t = $true -gt $false; Write-Output (,$t); Write-Output $t',
    '$t = $false -lt 5; Write-Output (,$t); Write-Output $t',
    "$t = $true -ge 'abc'; Write-Output (,$t); Write-Output $t",
    '$t = $null -ne 0; Write-Output (,$t); Write-Output $t',
    '$t = $null -ne $null; Write-Output (,$t); Write-Output $t',
    "$t = $null -lt 'abc'; Write-Output (,$t); Write-Output $t",
    '$t = $null -gt 1; Write-Output (,$t); Write-Output $t',
    '$t = $null -ge 1; Write-Output (,$t); Write-Output $t',
    '$t = $null -le 1; Write-Output (,$t); Write-Output $t',
    '$t = 1 -lt $null; Write-Output (,$t); Write-Output $t',
    '$t = 1 -gt $null; Write-Output (,$t); Write-Output $t',
    '$t = 1 -le $null; Write-Output (,$t); Write-Output $t',
    '$t = 1 -ge $null; Write-Output (,$t); Write-Output $t',
    '$t = 1 -ne $null; Write-Output (,$t); Write-Output $t',
    "$t = 'abc' -lt $null; Write-Output (,$t); Write-Output $t",
    '$t = $false -eq $null; Write-Output (,$t); Write-Output $t',
    '$t = $null -eq $false; Write-Output (,$t); Write-Output $t',
    '$t = $true -eq $null; Write-Output (,$t); Write-Output $t',
    '$t = 0 -gt $null; Write-Output (,$t); Write-Output $t',
    '$t = $null -lt 0; Write-Output (,$t); Write-Output $t',
    "$t = '' -gt $null; Write-Output (,$t); Write-Output $t",
    "$t = $null -lt ''; Write-Output (,$t); Write-Output $t",
    '$t = $false -gt $null; Write-Output (,$t); Write-Output $t',
    "$t = 1 -lt 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -gt 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -eq 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -ne 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -lt '5'; Write-Output (,$t); Write-Output $t",
    '$t = 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t',
    '$t = -79228162514264337593543950335d; Write-Output (,$t); Write-Output $t',
    '$t = - 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t',
    '$t = 7922816251426433759354395033.5d; Write-Output (,$t); Write-Output $t',
    '$t = 1.2345678901234567890123456789d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d - 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950334d + 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d + 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d * 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d / 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d - -1d; Write-Output (,$t); Write-Output $t',
    '$t = 1.2345678901234567890123456789d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.50d + 1.50d; Write-Output (,$t); Write-Output $t',
    '$t = 1d / 3d; Write-Output (,$t); Write-Output $t',
    '$t = 1d / 0d; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.50d; Write-Output (,$t); Write-Output $t',
    '$t = [string]0.5d; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + 0.5d; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + $false; Write-Output (,$t); Write-Output $t",
    '$t = [string]$false; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + 1L; Write-Output (,$t); Write-Output $t",
    '$t = [string]1L; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t",
    '$t = [string]79228162514264337593543950335d; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t",
    '$t = [string][uint64]18446744073709551615; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + -1.50d; Write-Output (,$t); Write-Output $t",
    '$t = [string]-1.50d; Write-Output (,$t); Write-Output $t',
    "$t = 'a' + [char]65; Write-Output (,$t); Write-Output $t",
    '$t = - 0d; Write-Output (,$t); Write-Output $t',
    '$t = - 0.0d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d + 0d; Write-Output (,$t); Write-Output $t',
    "$t = '1000' -eq 1e3d; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + 1e3d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 1.0d; Write-Output (,$t); Write-Output $t",
    "$t = [char]48 * '1'; Write-Output (,$t); Write-Output $t",
    "$t = $true * '1'; Write-Output (,$t); Write-Output $t",
    '$t = [char]48 * 2; Write-Output (,$t); Write-Output $t',
    '$t = 2 * [char]48; Write-Output (,$t); Write-Output $t',
    '$t = $true - 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = $true + 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d - $true; Write-Output (,$t); Write-Output $t',
    "$t = [char]48 - '1'; Write-Output (,$t); Write-Output $t",
    '$t = $true - 1.5; Write-Output (,$t); Write-Output $t',
    '$t = $true / 1.0d; Write-Output (,$t); Write-Output $t',
    "$t = [char]48 -eq '0'; Write-Output (,$t); Write-Output $t",
    '$t = [char]48 -eq 48; Write-Output (,$t); Write-Output $t',
    '$t = [char]65 -eq [char]97; Write-Output (,$t); Write-Output $t',
    '$t = [char]65 -ceq [char]97; Write-Output (,$t); Write-Output $t',
    '$t = [char]97 -lt [char]66; Write-Output (,$t); Write-Output $t',
    '$t = [char]65 -lt [char]97; Write-Output (,$t); Write-Output $t',
    "$t = 'ss' -eq [char]0x00DF; Write-Output (,$t); Write-Output $t",
    "$t = [char]0x00DF -eq 'ss'; Write-Output (,$t); Write-Output $t",
    '$t = $true -lt 2; Write-Output (,$t); Write-Output $t',
    '$t = $true -gt 2; Write-Output (,$t); Write-Output $t',
    "$t = $true -eq '0'; Write-Output (,$t); Write-Output $t",
    '$t = $null -lt -5; Write-Output (,$t); Write-Output $t',
    '$t = $null -gt -5; Write-Output (,$t); Write-Output $t',
    '$t = $null -le -5; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2) -eq $null; Write-Output (,$t); Write-Output $t',
    "$t = '2' -lt '10'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -le '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -gt 9; Write-Output (,$t); Write-Output $t",
    '$t = 9.9999999999999999999999999999d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d + 0d; Write-Output (,$t); Write-Output $t',
    "$t = 'x' + 1.10d; Write-Output (,$t); Write-Output $t",
    '$t = [string]1.10d; Write-Output (,$t); Write-Output $t',
    '$t = 1.10d; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.000d; Write-Output (,$t); Write-Output $t',
    "$t = 'x' + 2.0d; Write-Output (,$t); Write-Output $t",
    '$t = [string]2.0d; Write-Output (,$t); Write-Output $t',
    '$t = [string]0.0d; Write-Output (,$t); Write-Output $t',
    "$z = 1.0d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t",
    "$z = 1.10d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t",
    '$z = 1.0d; $t = $z + 0d; Write-Output (,$t); Write-Output $t',
    "$t = 'x' + 1.00d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 1.000d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 1.100d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 10.0d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 0.0d; Write-Output (,$t); Write-Output $t",
    "$t = 'x' + 1.2300d; Write-Output (,$t); Write-Output $t",
    "$z = 1.00d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t",
    "$z = 1.000d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t",
    "$z = 1.100d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t",
    '$t = 1.00d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.000d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.10d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.100d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d - 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d * 1d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d / 1d; Write-Output (,$t); Write-Output $t',
    '$t = 2.50d + 0d; Write-Output (,$t); Write-Output $t',
    '$t = 1.500d + 1.500d; Write-Output (,$t); Write-Output $t',
    '$t = 1.0d + 2.0d; Write-Output (,$t); Write-Output $t',
    '$z = 1.00d; $t = $z + 0d; Write-Output (,$t); Write-Output $t',
    '$z = 1.100d; $t = $z + 0d; Write-Output (,$t); Write-Output $t',
    '$z = 1.50d; $t = $z + 1.50d; Write-Output (,$t); Write-Output $t',
    '$t = - 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = - 1.00d; Write-Output (,$t); Write-Output $t',
    '$t = - 1.10d; Write-Output (,$t); Write-Output $t',
    '$z = 1.0d; $t = - $z; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.00d; Write-Output (,$t); Write-Output $t',
    '$t = [string]1.100d; Write-Output (,$t); Write-Output $t',
    "$t = 'x' + (1.0d); Write-Output (,$t); Write-Output $t",
    "$t = 'x' + [decimal]'1.0'; Write-Output (,$t); Write-Output $t",
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


#: The operand values the shipped operator grid was captured from, as they stood when the domain's
#: `_SPANNED` was measured. Written here rather than read out of the resource on purpose: it is what
#: makes a regeneration of the grid fail loudly instead of leaving that measurement quietly stale.
#:
#: The measurement is a differential and no test can re-run it. The whole grid was captured a second
#: time with the extremes these values are missing, and the cells that moved are `GRID_WITNESS_GAPS`
#: below; the types no moved cell blames are the ones a cell may be read as a fact over.
#:
#: Re-measured when the grid was recaptured. The differential was run twice: once with every type
#: widened, which moves 153 of the 9024 cells and blames only `Single`, `Decimal`, `Int64` and
#: `Char`, and once with **only** the spanned types widened — `[byte]128`, `[uint16]32768`,
#: `[uint32]2147483648`, `[uint64]9223372036854775808`, and five more Doubles including the
#: magnitudes either side of the width changes — which moves **nothing at all**. The second is the
#: one that justifies the span: a cell over a spanned operand is what it was however hard the
#: witnesses for that operand are pushed.
GRID_WITNESSES: dict[str, tuple[str, ...]] = {
    'System.Byte'     : ('[byte]0', '[byte]1', '[byte]255'),
    'System.SByte'    : ('[sbyte]0', '[sbyte]1', '[sbyte]-128', '[sbyte]127'),
    'System.Int16'    : ('[int16]0', '[int16]1', '[int16]-32768', '[int16]32767'),
    'System.UInt16'   : ('[uint16]0', '[uint16]1', '[uint16]65535'),
    'System.Int32'    : ('0', '1', '-1', '2147483647', '-2147483648'),
    'System.UInt32'   : ('[uint32]0', '[uint32]1', '[uint32]4294967295'),
    'System.Int64'    : ('0L', '1L', '-1L', '9223372036854775807L'),
    'System.UInt64'   : ('[uint64]0', '[uint64]1', '[uint64]18446744073709551615'),
    'System.Single'   : ('[single]0', '[single]1.5', '[single]-1.5'),
    'System.Double'   : ('0.0', '1.5', '-1.5', '3000000000.0', '5000000000.0',
                         '[double]::MaxValue'),
    'System.Decimal'  : ('0d', '1.5d', '-1.5d', '[decimal]::MaxValue'),
    'System.String'   : ("''", "'abc'", "'5'", "'0xabc'", "'-2'"),
    'System.Char'     : ('[char]65', '[char]0', '[char]48'),
    'System.Boolean'  : ('$true', '$false'),
    'System.Object[]' : ('@()', '@(5)', ',@(1, 2)', '@(@(1, 2), @(3, 4))', '@(1, 2)',
                         "@('a', 'b')", '@(10, 20, 30)'),
    'System.Void'     : ('$null',),
}


#: The operand types the witnesses above do not reach every outcome of, each with one cell that
#: proves it: the operator, the two operand types, what the shipped grid records, and what the type
#: really produces there. The second half is measured — the same capture again, with
#: `[int64]::MinValue`, `[single]::MaxValue` and `::MinValue`, `[decimal]::MinValue`, `[char]65535`,
#: six more strings and three more collections added — and 390 of the 4096 binary cells moved in
#: all, 93 of them by gaining a throw the resource says cannot happen. Every one of the 390 carries
#: an operand named here, and no other type is named by one.
#:
#: `System.String` is the one the type ledger already had from the other side: `Byte + String`
#: records `Int32`, and `1 + '2147483648'` is measured an `Int64` in `TYPES`.
#:
#: The recorded half of each row is a ratchet on the shipped resource; the produced half is what a
#: regeneration would have to reproduce, and until one happens it is what the resource is wrong by.
GRID_WITNESS_GAPS: dict[str, tuple[str, str, str, tuple[str, ...], tuple[str, ...]]] = {
    'System.String': (
        '+', 'System.Byte', 'System.String',
        ('System.Int32', 'throw'),
        ('System.Decimal', 'System.Double', 'System.Int32', 'System.Int64', 'throw'),
    ),
    'System.Int64': (
        '-', 'System.Byte', 'System.Int64',
        ('System.Int64',),
        ('System.Double', 'System.Int64'),
    ),
    'System.Char': (
        '*', 'System.UInt16', 'System.Char',
        ('System.Int32',),
        ('System.Double', 'System.Int32'),
    ),
    'System.Decimal': (
        '-', 'System.Byte', 'System.Decimal',
        ('System.Decimal',),
        ('System.Decimal', 'throw'),
    ),
    'System.Single': (
        '-band', 'System.Byte', 'System.Single',
        ('System.Int64', 'System.UInt64'),
        ('System.Int64', 'System.UInt64', 'throw'),
    ),
}


#: The operand types the re-measurement found complete and the value domain still does not read a
#: cell over. `Object[]` is the whole set, and it is here rather than among the gaps because it is
#: not one: widening the collection row on its own — `@($null)`, `@(1)`, `@(0)`, `@(1, 'a')` and a
#: collection holding an empty one — moves not a single cell of the shipped grid. What convicted it
#: before was `[int] @(...)` reporting an Int32 beside its throw, and that Int32 was `$null`'s: an
#: empty collection reached the capture as `$null` until the witness was built to survive.
#:
#: Reading it would be a change to what the deobfuscator folds rather than to what is recorded here,
#: so it is deferred with the evidence rather than taken along with the recapture. Two ratchets say
#: what it would cost to look at: the measured-operation count and the throw-carrying count in
#: `test_value_facts` both move when `Object[]` joins `values._SPANNED`.
GRID_COMPLETE_BUT_UNREAD: frozenset[str] = frozenset({'System.Object[]'})


#: Every table whose entries a real host may be asked to *run*, in one place, so that the set the
#: execution rule is written about and the set handed to a host cannot come apart: a table added to
#: one and not the other is either runnable but never measured, or listed and refused at run time.
_EXECUTABLE: tuple[str, ...] = (*BEHAVIOURS, *CLAIMS, *TABLES, *TYPES)


def executable() -> frozenset[str]:
    """
    Every script a real PowerShell host may be asked to run.
    """
    return frozenset(_EXECUTABLE)


def oracle_corpus() -> tuple[str, ...]:
    """
    Everything that may be handed to a 5.1 host, deduplicated and in a stable order.
    """
    seen: dict[str, None] = {}
    for source in (
        *SNIPPETS.values(),
        *PROBES,
        *BOUNDARIES,
        *SPELLINGS,
        *_EXECUTABLE,
        *NAMES,
    ):
        seen.setdefault(source, None)
    return tuple(seen)
