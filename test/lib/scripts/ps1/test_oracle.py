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

import base64
import functools
import inspect
import json
import sys
import unittest

from collections import Counter
from collections.abc import Callable, Sequence
from unittest.mock import patch

from test import TestBase
from test.lib.scripts.ps1 import corpus, oracle
from test.lib.scripts.ps1.test_parser_shape import CORPUS as SHAPES
from test.lib.scripts.ps1.oracle import (
    Behaviour,
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
    '$x = 3.ToString()':
        'The same empty parenthesis, reached by the boundary rule rather than by a property '
        'access: a numeral swallows the dot that touches it, so 5.1 and we both read the command '
        '`3.ToString` and hand it `()` — and only 5.1 refuses the empty bracket. `3.ToString(1)` '
        'is accepted by both, which is what says the divergence is the bracket and not the word.',
    'foo (a, b)':
        '5.1 reads `a` as a command name inside the bracket and then reports MissingArgument at '
        'the comma. We read an array of two bare words.',
    '$x = a, b':
        'The same shape as an assigned value: 5.1 reads `a` as a command name and reports '
        'MissingArgument. We read a call to `a` and drop the comma with it, so the assignment '
        'prints back as `$x = a b`, which is a second defect in the same source.',
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
    '$t = 0xFFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        '5.1 reports NumericConstantTooLarge: a hexadecimal literal is read as the bit pattern of '
        'the smallest signed type that holds it, and seventeen digits fit neither Int32 nor Int64, '
        'so there is no value for it to denote. We read it as an arbitrary-width Python integer '
        'and accept it, which is the same open-endedness that reads `0xFFFFFFFF` as 4294967295 '
        'where 5.1 reads -1.',
}


#: Snippets whose deobfuscation writes something different from the snippet on purpose. The unit's
#: default strips a statement whose only effect is a value on the success output stream, treating the
#: input as a standalone script whose console output is not the artifact; `ps1 -k` keeps it. The
#: error stream is read the same way: a statement-terminating error 5.1 reports and steps over leaves
#: a record nothing here reads, so a raise whose only effect is that record, or an inert handler that
#: merely suppressed one, is removed without changing the artifact. So a divergence here is the
#: documented behaviour of that default and not a bug, which is why it is held apart from
#: `BEHAVIOUR_DEFECTS`. Both tables are checked against the measured set in both directions, so a
#: divergence that stops happening and a new one that starts both fail.
BEHAVIOUR_DIVERGENCES: dict[str, str] = {
    "try { zzq0000=5; 'tail' } catch {}; 'next'":
        'Nothing is carried out of the `try` any more: the drop claims the bareword raised, and a '
        'raise abandons the rest of its block. What runs first at script scope is the strip, which '
        'takes both bare values, and a body left holding the bareword alone then dissolves — so '
        'the snippet writes `next` and the default writes nothing. `ps1 -k` emits the input '
        'unchanged. The carry itself is measured where the value has a consumer that the strip '
        'leaves alone, which is its function-scope spelling in the corpus.',
    "$Null = [Int]'abc'; Write-Host 'A'":
        'The cast is removed. 5.1 reports the failed conversion, steps over it and runs `A`, so the '
        'only difference is the error record the removal drops; the error stream, like the success '
        'stream, is not the artifact. `ps1 -k` keeps the cast.',
    "$Null = 1 / 0; Write-Host 'A'":
        'The same in its division spelling, so that neither entry rests on the cast.',
    "function K { $Null = [Int]'abc' }; K; Write-Host 'A'":
        'The same fault in a called body: the definition and its only call are removed together and '
        '`A` runs, where the snippet also left the error record the cast raised.',
    "trap { continue }; [int]'a'; Write-Host 'after'":
        'The handler is removed. The cast raises a statement-terminating error 5.1 steps over with '
        'or without a `trap`, so `after` runs either way and the handler only suppressed the record '
        'the removal now lets through.',
    "trap { continue }; 1/0; Write-Host 'after'":
        'The same handler over a division rather than a cast.',
    "trap { continue }; zzq0000=5; Write-Host 'after'":
        'The same over a bareword 5.1 cannot resolve: the CommandNotFound is statement-terminating '
        'and steps over with or without the `trap`, so `after` runs and the removal only lets its '
        'record through.',
}

#: Snippets whose deobfuscation does not behave like the snippet. Each is a semantics defect: the
#: output must do the same thing as the input. Each entry states what the snippet writes and what
#: its output writes instead, so a failure can be read here.
#:
#: The variable entries are each a claim of the corruption ledger as well, and a defect that ledger
#: already carries as an `expectedFailure`. That the two agree entry for entry matters there: the
#: ledger reaches its verdict by asking whether a store survived in the tree, and this reaches it by
#: running both scripts, so neither is evidence for the other.
#:
#: An entry this table holds alone would not have that second witness, and every test in this file
#: is skipped where no PowerShell host is available — so on a machine without one such an entry
#: ratchets in neither direction, and a fix and a regression are alike invisible. Every entry needs
#: a witness of its own shape somewhere host-free. They are carried by `test_corruptions.py`, which
#: asks whether a store survived in the tree and what the reads below it can still print. That is
#: not evidence for what is written here, because this reaches its verdict by running both scripts.
BEHAVIOUR_DEFECTS: dict[str, str] = {
    "Set-Variable global:y 'b'; Write-Host $global:y":
        'The store is dropped, so `b` becomes nothing: a command that writes a variable is not '
        'read as the store the following read needs.',
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        'The read is folded to `b`, but 5.1 never evaluates the right operand of `-and` when the '
        'left one is false, so the store never happens and the snippet prints `a`.',
    "$x = 'a'; $true -or ($x = 'b'); Write-Host $x":
        'The same rule spelled with the other operator: 5.1 never evaluates the right operand of '
        '`-or` when the left one is true. Held apart from the `-and` entry because the two are '
        'separate spellings and a fix that reaches one need not reach the other.',
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        'The store is removed and the read prints nothing. A child scope resolves `$script:x` to '
        'the caller, where the store put `a`.',
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        'The same, through a function body rather than a script block.',
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
    '$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]':
        'The read is folded to `1`. A multi-assignment slot is handed the very object standing '
        'against it, so `$a` and `$x` name one array and the store through `$a` is a store into it; '
        'the snippet prints `7`. The alias relation is minted from an assignment whose value is a '
        'bare variable, and the climb breaks on the array literal a multi-assignment stands on.',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x":
        'The read is folded to the array as written. A container holds the object rather than a '
        'copy of it, so reversing what the key names reverses what `$x` names and the snippet '
        'prints `3 2 1`. The alias relation joins two *variables*, so nothing relates a name to an '
        'object a container is holding for it.',
    '$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; Write-Output $p[0]':
        'The read is folded to the element as written. A `foreach` variable is bound to the element '
        'object itself, which is the same hand-off an assignment of a bare variable is, so '
        'reversing `$e` reverses the element and the snippet prints `2 1`.',
    'function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]':
        'The argument is substituted, so the callee stores a second array and the read prints `1`. '
        'The body keeps what it was handed, so `$k` and `$x` name one array and the snippet prints '
        '`9`. Nothing asks what a called body does with an argument it is given.',
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; Write-Output $x':
        'The read is folded to the array as written. The property holds the array itself, so the '
        'store through it reaches what `$x` holds and the snippet writes `9 2 3`.',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $x':
        'The same through an element of another array.',
    '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); $l[0][0] = 9; '
    'Write-Output $x':
        'The same through a list a call was handed the array to keep.',
    '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $x':
        'The same through a key written into a hash literal rather than stored into one.',
    "$x = 1, 2, 3; $h = @{ k = $x }; $y = $h['k']; $y[0] = 9; Write-Output $x":
        'The same reached from the third side: the array is taken back *out* of the container into '
        'a name, and a store through that name is one `$x` observes.',
    '$p = @(@(1, 2), @(3, 4)); $q = $p[0]; $q[0] = 9; Write-Output $p[0][0]':
        'The same where the container is an array of arrays and the name is taken from an element.',
    '$p = @(@(1, 2), @(3, 4)); $p | ForEach-Object { [Array]::Reverse($_) }; Write-Output $p[0]':
        'The pipeline variable is bound to the element object itself, so reversing `$_` reverses '
        'what the collection holds and the snippet writes `2 1`.',
    'function f($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; f $x; Write-Output $x':
        'The parameter is bound to the array the argument named rather than to a copy, so the call '
        'reverses what `$x` holds and the snippet writes `3 2 1`.',
    '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $x; Write-Output $x':
        'The same through a script block parameter rather than a function parameter.',
    '$x = 1, 2, 3; $a, $b = $x, 9; [Array]::Reverse($a); Write-Output $x':
        'The same through a multi-assignment slot, which is handed the object standing against it.',
    '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y':
        'The read is folded to the reversal. A subexpression collects a fresh array rather than '
        'handing the object over, so the two names hold two arrays and the snippet writes `1 2 3`. '
        '`Ps1Simplifications` rewrites `$($x)` to `$x` before the alias relation is built, minting '
        'a share the script does not have, so the defect is in that pass rather than in the '
        'aliasing.',
    "trap { continue }; iex 'throw 1'; Write-Host 'after'":
        'The handler is removed, and the removal is self-inflicting: a command that runs a string '
        'is read as raising nothing, so the `trap` goes in one round, and a later round then '
        'inlines the string and materialises the very `throw` the first round answered False for. '
        'What is left is `throw 1` and nothing else.',
    "New-Variable ErrorActionPreference Stop -Force; trap { continue }; [int]'a'; Write-Host "
    "'after'":
        'The handler is removed. The preference is recognised where it is written as an '
        'assignment and not where a cmdlet sets it, so the script reads as arming nothing and the '
        'cast error reads as one 5.1 would step over.',
    "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; Get-Item nope; "
    "Write-Host 'after'":
        'The handler is removed. The table binds `-ErrorAction Stop` into every command that '
        'takes one, so no action is written at the call site and no preference is assigned; '
        'neither gate is looking at an index expression.',
    "function Raise { throw 'e' }; function Wrap { trap { continue }; Raise; Write-Host 'in' "
    "}; Wrap; Write-Host 'after'":
        'The handler is removed. What reaches it is the *call*, whose subtree carries no `throw`, '
        'and the callee is a body of its own; answering this needs the call graph, which the '
        'fault model deliberately has none of.',
    "function K { $Null = 1 }; K; $Null = (Get-Command K).Name; Write-Host 'A'":
        'The definition is removed although `Get-Command` names it literally. A literal name that '
        'matches nothing writes a `CommandNotFoundException` to the error stream whatever is done '
        'with the result, so the output writes an error record the snippet does not. A pattern '
        'that matches nothing writes none, which is the neighbouring `*vnMT*` row.',
    'function K { $Null = 1 }; K; $b = { K }; Write-Host $b':
        'The call inside the stored block is removed along with the definition, but a `ScriptBlock` '
        'renders as its own source text, so the block the snippet writes out is no longer the block '
        'it wrote.',
    "$env:B = 'function K { Write-Host P }'; Invoke-Expression $env:B; function K { 42 }; "
    "$x = K; Write-Output $x; $env:C = 'K'; Invoke-Expression $env:C":
        'The `function` definition shadows one an `Invoke-Expression` above it bound under the same '
        'name, and removing it uncovers the shadowed body rather than leaving the name unbound. Both '
        'strings are resolved, so the output holds the payload definition and calls it, where the '
        'snippet calls the definition standing in its own text. This is the risk a name-keyed '
        'removal takes when it stops requiring that the tree be the whole story: not a call to a '
        'name nothing defines, but a call to a body the input never ran.',
    "function K { [Alias('q')] param() $Null = 1 }; q; Write-Host 'A'":
        'The definition is removed and the call under its attribute alias is left standing. An '
        '`[Alias]` attribute on a `param` block binds a second command name for the function when '
        'the definition runs, and nothing here reads it as a binding, so the output calls a name it '
        'no longer defines.',
    "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty "
    "-Value { Write-Host 'S' }; $Null = 'abc'.Zq; Write-Host 'A'":
        'The read is discarded and removed, but the member it names is a script property the '
        'statement above it installed, so reading it runs that body. A member read reaches the '
        'closed-world gate through its receiver, and a literal receiver never asks it: the '
        'value domain answers from the literal alone.',
    "Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty "
    "-Value { 99 }; Write-Host 'abc'.Length":
        'The same gap reached through folding rather than removal, and aimed at a member the '
        'metadata proves inert: `Length` is re-pointed to a script property and the read is '
        'folded to the number the metadata carries, so the output prints a value 5.1 never '
        'produces.',
}


#: What 5.1 writes for each script the corruption ledger's beliefs rest on. Every entry was read off
#: a running host rather than reasoned about, and the whole table is compared at once, so a belief
#: that was never true and a belief that has stopped being true fail the same way.
#:
#: `INFO` is what `Write-Host` produces, which since 5.0 writes an information record rather than
#: going straight to the console. An empty one is a read of a variable that holds nothing.
CLAIM_TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    "trap { continue }; 1/0; Write-Host 'after'":
        ('INFO\tafter',),
    "trap { continue }; $x = \"$(1/0)$(Set-Alias zzq Write-Output)\"; zzq 'hi'":
        (),
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'":
        ('INFO	e', 'OUT	System.String	hi'),
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; Write-Output 'hi'":
        ('INFO	e', 'OUT	System.String	hi'),
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
    "$x = 'a'; $true -or ($x = 'b'); Write-Host $x":
        ('OUT\tSystem.Boolean\tTrue', 'INFO\ta'),
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]":
        ('INFO\ta',),
    "trap { continue }; throw 'e'; Write-Host 'after'":
        ('INFO\tafter',),
    "[int]'a'; Write-Host 'after'": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'INFO\tafter',
    ),
    "trap { continue }; [int]'a'; Write-Host 'after'":
        ('INFO\tafter',),
    "trap { continue }; Write-Host 'one'; throw 'e'; Write-Host 'three'":
        ('INFO\tone', 'INFO\tthree'),
    "trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        ('INFO\tnext',),
    "trap { continue }; foreach ($i in 1..2) { throw 'e'; Write-Host 'tail' }; "
    "Write-Host 'next'":
        ('INFO\tnext',),
    "trap { continue }; switch (1) { 1 { throw 'e'; Write-Host 'tail' } }; Write-Host 'next'":
        ('INFO\tnext',),
    "trap { continue }; try { throw 'e' } catch { throw 'f'; Write-Host 'tail' }; "
    "Write-Host 'next'":
        ('INFO\tnext',),
    "if ($true) { trap { continue }; Write-Host 'in'; throw 'e' }; Write-Host 'after'":
        ('INFO\tin', 'INFO\tafter'),
    "$x = 'a'; trap { $x = 'b'; continue }; throw 'e'; Write-Host $x":
        ('INFO\ta',),
    "trap { Write-Host 'outer'; continue }; if ($true) { trap { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        ('INFO\tinner', 'INFO\ttail', 'INFO\tnext'),
    "trap { Write-Host 'outer'; continue }; if ($true) { "
    "trap [System.IO.IOException] { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        ('INFO\touter', 'INFO\tnext'),
    "function A { Write-Host 'a' }; function B { Write-Host 'b' }; Set-Alias x A; "
    "trap { Set-Alias x B; continue }; throw 'e'; x":
        ('INFO\ta',),
    "function A { Write-Host 'a' }; function B { Write-Host 'b' }; Set-Alias x A; "
    "trap { Set-Alias x B -Scope 1; continue }; throw 'e'; x":
        ('INFO\tb',),
    "$ErrorActionPreference = 'Stop'; trap { continue }; "
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'":
        (),
    "$ErrorActionPreference = 'Stop'; trap { continue }; "
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'":
        ('OUT\tSystem.String\thi',),
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; c 'hi'": (
        'ERROR\tAliasNotWritable,Microsoft.PowerShell.Commands.SetAliasCommand'
        '\tSystem.Management.Automation.SessionStateUnauthorizedAccessException',
        'ERROR\tMicrosoft.PowerShell.Commands.WriteErrorException'
        '\tMicrosoft.PowerShell.Commands.WriteErrorException',
    ),
    "Set-Alias c Write-Error -Option ReadOnly; Set-Alias c Write-Output; Write-Output 'hi'": (
        'ERROR\tAliasNotWritable,Microsoft.PowerShell.Commands.SetAliasCommand'
        '\tSystem.Management.Automation.SessionStateUnauthorizedAccessException',
        'OUT\tSystem.String\thi',
    ),
    "trap { break }; [int]'a'; Write-Host 'after'":
        ('THROW\tInvalidCastFromStringToInteger',),
    "trap { }; [int]'a'; Write-Host 'after'": (
        'ERROR\tInvalidCastFromStringToInteger'
        '\tSystem.Management.Automation.RuntimeException',
        'INFO\tafter',
    ),
    "Get-Item nope -ErrorAction Stop; Write-Host 'after'":
        ('THROW\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',),
    "trap { continue }; Get-Item nope -ErrorAction Stop; Write-Host 'after'":
        ('INFO\tafter',),
    "Get-Item nope -ErrorAc Stop; Write-Host 'after'":
        ('THROW\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',),
    "Get-Item nope -ErrorAction:Stop; Write-Host 'after'":
        ('THROW\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',),
    "Get-Item nope -ErrorAction 1; Write-Host 'after'":
        ('THROW\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',),
    "Get-Item nope -ErrorAction Continue; Write-Host 'after'": (
        'ERROR\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand'
        '\tSystem.Management.Automation.ItemNotFoundException',
        'INFO\tafter',
    ),
    "$ErrorActionPreference = 'Stop'; [int]'a'; Write-Host 'after'":
        ('THROW\tInvalidCastFromStringToInteger',),
    "throw 'e'; Write-Host 'after'":
        ('THROW\te',),
    "$x = $(trap { continue }; [int]'a'; 'in'); Write-Host $x":
        ('INFO\tin',),
    "$(trap { continue }); [int]'a'; Write-Host 'after'": (
        'OUT\t\t<null>',
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'INFO\tafter',
    ),
    "trap { continue }; $x = $([int]'a'; 'in'); Write-Host $x":
        ('INFO\t',),
    "$x = @(trap { continue }; [int]'a'; 'in'); Write-Host $x":
        ('INFO\tin',),
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
    "$script:y = 'b'; Write-Output $script:y":
        ('OUT\tSystem.String\tb',),
    "$global:y = 'b'; Write-Output $global:y":
        ('OUT\tSystem.String\tb',),
    "$s = 'x'; Write-Output $script:s":
        ('OUT\tSystem.String\tx',),
    "$script:s = 'x'; Write-Output $s":
        ('OUT\tSystem.String\tx',),
    '$n = 1; $n += 2; Write-Output $n':
        ('OUT\tSystem.Int32\t3',),
    "$s = 'a'; $s += 'b'; $s += 'c'; Write-Output $s":
        ('OUT\tSystem.String\tabc',),
    '$n = 1; $n++; Write-Output $n':
        ('OUT\tSystem.Int32\t2',),
    '$n = 5; $n -= 2; Write-Output $n':
        ('OUT\tSystem.Int32\t3',),
    "$c = 'Write-Out'; $c += 'put 5'; Invoke-Expression $c":
        ('OUT\tSystem.Int32\t5',),
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
    "Get-Item nope -e Stop; Write-Host 'after'":
        ('INFO\tafter',),
    "Get-Item nope -errora Stop; Write-Host 'after'":
        ('THROW\tPathNotFound,Microsoft.PowerShell.Commands.GetItemCommand',),
    "Get-Item nope -ErrorAction S; Write-Host 'after'": (
        'ERROR\tCannotConvertArgumentNoMessage,Microsoft.PowerShell.Commands.GetItemCommand'
        '\tSystem.Management.Automation.ParameterBindingException',
        'INFO\tafter',
    ),
    "& { trap { break }; [int]'a' }; Write-Host 'after'":
        ('THROW\tInvalidCastFromStringToInteger',),
    "trap { continue }; & { trap { break }; [int]'a' }; Write-Host 'after'":
        ('INFO\tafter',),
    "trap { continue }; iex 'throw 1'; Write-Host 'after'":
        ('INFO\tafter',),
    "trap { continue }; $s = { throw 'x' }; [int]'a'; Write-Host 'after'":
        ('INFO\tafter',),
    "New-Variable ErrorActionPreference Stop -Force; trap { continue }; [int]'a'; Write-Host "
    "'after'":
        ('INFO\tafter',),
    "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; Get-Item nope; "
    "Write-Host 'after'":
        ('INFO\tafter',),
    "function Raise { throw 'e' }; function Wrap { trap { continue }; Raise; Write-Host 'in' "
    "}; Wrap; Write-Host 'after'":
        ('INFO\tin', 'INFO\tafter'),
}

#: What the host's own command tables hold, measured. The tables in `refinery.lib.scripts.ps1.data`
#: are a capture of these that has been edited by hand since, and an alias the host does not bind is
#: not a harmless surplus: nothing in ordinary name lookup beats an alias, so such an entry takes a
#: name away from the function or the retry that 5.1 would have given it.
#:
#: `ItemNotFoundException` from `Get-Alias` is the host reporting that it binds no such alias, and
#: `iex` beside it is what tells that apart from a measurement that found nothing at all.
#:
#: These are deliberately left out of the deobfuscation differential, which the rest of the
#: executable corpus is quantified over. A probe of the command tables is not a script whose meaning
#: is worth preserving — it is the measurement itself, and rewriting `gcim` to `Get-CimInstance`,
#: which is correct, would make it measure a different thing and report the rewrite as a defect.
#: What `Get-Alias` writes for a name the host binds no alias for, and what `Get-Command` writes for
#: a name it has no command of. Written once rather than at each name, so that a name whose measured
#: answer differs from its neighbours' differs visibly.
_NO_SUCH_ALIAS = (
    'ERROR\tItemNotFoundException,Microsoft.PowerShell.Commands.GetAliasCommand'
    '\tSystem.Management.Automation.ItemNotFoundException',
)
_NO_SUCH_COMMAND = (
    'ERROR\tCommandNotFoundException,Microsoft.PowerShell.Commands.GetCommandCommand'
    '\tSystem.Management.Automation.CommandNotFoundException',
)

TABLE_TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    'Get-Alias iex':
        ('OUT\tSystem.Management.Automation.AliasInfo\tiex',),
    'Get-Alias item': _NO_SUCH_ALIAS,
    'Get-Alias member': _NO_SUCH_ALIAS,
    'Get-Alias variable': _NO_SUCH_ALIAS,
    'Get-Alias childitem': _NO_SUCH_ALIAS,
    'Get-Alias gerr': _NO_SUCH_ALIAS,
    'Get-Alias fhx': _NO_SUCH_ALIAS,
    'Get-Command Get-Item':
        ('OUT\tSystem.Management.Automation.CmdletInfo\tGet-Item',),
    'Get-Command Get-Member':
        ('OUT\tSystem.Management.Automation.CmdletInfo\tGet-Member',),
    'Get-Command Get-Variable':
        ('OUT\tSystem.Management.Automation.CmdletInfo\tGet-Variable',),
    'Get-Command Get-ChildItem':
        ('OUT\tSystem.Management.Automation.CmdletInfo\tGet-ChildItem',),
    'Get-Command Get-Error': _NO_SUCH_COMMAND,
    'Get-Command Format-Hex': _NO_SUCH_COMMAND,
    '(Get-Command help).CommandType':
        ('OUT\tSystem.Management.Automation.CommandTypes\tFunction',),
    '(Get-Command gcim -ErrorAction SilentlyContinue).CommandType':
        ('OUT\tSystem.Management.Automation.CommandTypes\tAlias',),
}


def claimed_bindings(table: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    """
    The entries of a command table that record the host *binding* a name, which is the half a
    subset check over a live host enforces. A binding is a transcript that only wrote output; a
    transcript carrying an error is the table recording the host *not* binding the name, and a host
    is free to contradict that by binding more than the clean set defines.
    """
    return {
        name: transcript
        for name, transcript in table.items()
        if transcript and all(line.startswith('OUT') for line in transcript)
    }


#: What 5.1 makes of a value's type and of an operation's result, measured. The unit had no place
#: to keep a type — a Char and a one-character String were the same object to it — so every belief
#: about one was written by us, and this is the table that ends that. Read the rule in
#: `corpus.TYPES` before adding an entry: two witnesses, and `Write-Host` may not be either of
#: them.
#:
#: Nothing here is a claim about the tool. It is what PowerShell does, and it is pinned so that the
#: commits which give the unit a type cannot quietly move the target they are measured against.
TYPE_TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Object[]\ta b',
            'OUT\tSystem.String\ta',
            'OUT\tSystem.String\tb',
        ),
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')":
        ('OUT\tSystem.String\ta-b',),
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }":
        (
            'OUT\tSystem.String\ta',
            'OUT\tSystem.String\tb',
        ),
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output (,$t)':
        ('OUT\tSystem.Object[]\tA B',),
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tB',
        ),
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output (,$t)":
        ('OUT\tSystem.Object[]\ta b c',),
    '$t = [char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tA',
        ),
    '$t = [char[]](72, 73); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char[]\tH I',
            'OUT\tSystem.Char\tH',
            'OUT\tSystem.Char\tI',
        ),
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'ABC'[0]; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tA',
        ),
    "$t = [char[]]'ABC'; Write-Output (,$t); Write-Output $t.Count":
        (
            'OUT\tSystem.Char[]\tA B C',
            'OUT\tSystem.Int32\t3',
        ),
    "$t = 'ABC'.ToCharArray(); Write-Output (,$t); Write-Output $t.Count":
        (
            'OUT\tSystem.Char[]\tA B C',
            'OUT\tSystem.Int32\t3',
        ),
    "Write-Output ('x' -replace 'x', [char]65); Write-Output ('x' -replace 'x', 'A')":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    "Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')":
        (
            'OUT\tSystem.String\tr5',
            'OUT\tSystem.String\tr5',
        ),
    "Write-Output ([char]65 + 1); Write-Output ('A' + 1)":
        (
            'OUT\tSystem.String\tA1',
            'OUT\tSystem.String\tA1',
        ),
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')": (
        'OUT\tSystem.Int32\t66',
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
    ),
    'Write-Output (([char]65) * 3)':
        ('ERROR\tNotADefinedOperationForType\tSystem.Management.Automation.RuntimeException',),
    "Write-Output ('A' * 3)":
        ('OUT\tSystem.String\tAAA',),
    "Write-Output (([char]65).ToString()); Write-Output (('A').ToString())":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    "Write-Output ('a,b' -split [char]44); Write-Output ('a,b' -split ',')":
        (
            'OUT\tSystem.String\ta',
            'OUT\tSystem.String\tb',
            'OUT\tSystem.String\ta',
            'OUT\tSystem.String\tb',
        ),
    "Write-Output ('xyx'.Replace([char]120, [char]122)); Write-Output ('xyx'.Replace('x', 'z'))":
        (
            'OUT\tSystem.String\tzyz',
            'OUT\tSystem.String\tzyz',
        ),
    "Write-Output ('{0}' -f [char]65); Write-Output ('{0}' -f 'A')":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    "Write-Output (([char]65, [char]66) -join ''); Write-Output (('A', 'B') -join '')":
        (
            'OUT\tSystem.String\tAB',
            'OUT\tSystem.String\tAB',
        ),
    "Write-Output ([string][char]65); Write-Output ([string]'A')":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    '$c = [char]65; $s = \'A\'; Write-Output "$c"; Write-Output "$s"':
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "Write-Output (([char]65).Length); Write-Output (('A').Length)":
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    "Write-Output (([char]65).Count); Write-Output (('A').Count)":
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    "Write-Output ([char]65 -eq 'A'); Write-Output ('A' -eq 'A')":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }':
        ('OUT\tSystem.Char\tA',),
    "$t = 'AB'.Count; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = (5).Count; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = (5).Length; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    "$t = 1 + 'AB'.Count; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = @(1, 2, 3).Rank; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = @(1, 2, 3).Count; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t3',
            'OUT\tSystem.Int32\t3',
        ),
    '$t = @(1, 2, 3).Length; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t3',
            'OUT\tSystem.Int32\t3',
        ),
    "$t = 'AB'.Length; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    'Write-Output ((5).PSTypeNames)':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.String\tSystem.ValueType',
            'OUT\tSystem.String\tSystem.Object',
        ),
    "Write-Output (('AB').PSTypeNames)":
        (
            'OUT\tSystem.String\tSystem.String',
            'OUT\tSystem.String\tSystem.Object',
        ),
    'Write-Output ((5).PSObject.GetType().FullName)':
        ('OUT\tSystem.String\tSystem.Management.Automation.PSObject',),
    '$t = (5).Rank; Write-Output (,$t)':
        ('OUT\t\t<null>',),
    "$t = 'AB'.Zqnope; Write-Output (,$t)":
        ('OUT\t\t<null>',),
    '$t = (5).Zqnope; Write-Output (,$t)':
        ('OUT\t\t<null>',),
    '$t = $null.Count; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$f = New-Object IO.MemoryStream; Write-Output $f.Length.GetType().FullName':
        ('OUT\tSystem.String\tSystem.Int64',),
    '$f = New-Object IO.MemoryStream; $f.Dispose(); Write-Output $f.Length':
        ('OUT\t\t<null>',),
    '$t = @(); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = , 1; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = 0xFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t255',
            'OUT\tSystem.Int32\t255',
        ),
    '$s = 0xFF; $t = "$s"; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t255',
            'OUT\tSystem.String\t255',
        ),
    '$t = 0x7FFFFFFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2147483647',
            'OUT\tSystem.Int32\t2147483647',
        ),
    '$t = 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-91',
            'OUT\tSystem.Int32\t-91',
        ),
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-1',
            'OUT\tSystem.Int64\t-1',
        ),
    '$t = 1kb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1024',
            'OUT\tSystem.Int32\t1024',
        ),
    '$t = 1L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t1',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = 10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 0xFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-1',
            'OUT\tSystem.Int64\t-1',
        ),
    '$t = 1kb + 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1024',
            'OUT\tSystem.Int32\t1024',
        ),
    '$t = 1L + 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t1',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = 10d + 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 2147483648; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t2147483648',
            'OUT\tSystem.Int64\t2147483648',
        ),
    '$t = 1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1.5',
            'OUT\tSystem.Double\t1.5',
        ),
    '$t = -0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t0',
            'OUT\tSystem.Double\t0',
        ),
    '$t = 1e3; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1000',
            'OUT\tSystem.Double\t1000',
        ),
    '$t = 4gb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t4294967296',
            'OUT\tSystem.Int64\t4294967296',
        ),
    '$t = 1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.5',
            'OUT\tSystem.Decimal\t1.5',
        ),
    '$t = 10D; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 1l; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t1',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = 0xFFL; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t255',
            'OUT\tSystem.Int64\t255',
        ),
    '$t = 0x100000000; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t4294967296',
            'OUT\tSystem.Int64\t4294967296',
        ),
    '$t = 0x7FFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t9223372036854775807',
            'OUT\tSystem.Int64\t9223372036854775807',
        ),
    '$t = 9223372036854775807; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t9223372036854775807',
            'OUT\tSystem.Int64\t9223372036854775807',
        ),
    '$t = 9223372036854775808; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t9223372036854775808',
            'OUT\tSystem.Decimal\t9223372036854775808',
        ),
    '$t = 100000000000000000000000000000000; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1E+32',
            'OUT\tSystem.Double\t1E+32',
        ),
    '$t = 0xFFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        ('THROW\tParseException',),
    '$t = 007; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t7',
            'OUT\tSystem.Int32\t7',
        ),
    '$t = 0xFFFFFFFFL; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t4294967295',
            'OUT\tSystem.Int64\t4294967295',
        ),
    '$t = 1lkb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t1024',
            'OUT\tSystem.Int64\t1024',
        ),
    '$t = 1dkb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1024',
            'OUT\tSystem.Decimal\t1024',
        ),
    '$t = 0x0000000000000001; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = -2147483649; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-2147483649',
            'OUT\tSystem.Int64\t-2147483649',
        ),
    '$t = 1.5L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t2',
            'OUT\tSystem.Int64\t2',
        ),
    '$t = 2.5L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t2',
            'OUT\tSystem.Int64\t2',
        ),
    '$t = -(2147483648); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-2147483648',
            'OUT\tSystem.Int64\t-2147483648',
        ),
    '$t = -(2147483647); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2147483647',
            'OUT\tSystem.Int32\t-2147483647',
        ),
    '$t = - 2147483648; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-2147483648',
            'OUT\tSystem.Int64\t-2147483648',
        ),
    '$t = - 2147483647; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2147483647',
            'OUT\tSystem.Int32\t-2147483647',
        ),
    '$t = 1.5kb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1536',
            'OUT\tSystem.Double\t1536',
        ),
    '$t = 0xFFkb; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t261120',
            'OUT\tSystem.Int32\t261120',
        ),
    '$t = 10 - $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t10',
            'OUT\tSystem.Int32\t10',
        ),
    '$t = $null + 5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    '$t = $null - 5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-5',
            'OUT\tSystem.Int32\t-5',
        ),
    '$t = 10 - $null + 3; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t13',
            'OUT\tSystem.Int32\t13',
        ),
    '$t = $null -band 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$a = $null; $b = 5; $t = $a * $b; Write-Output (,$t)':
        ('OUT\t\t<null>',),
    '$a = $null; $t = $a * 5; Write-Output (,$t)':
        ('OUT\t\t<null>',),
    '$t = $null * 1; Write-Output (,$t)':
        ('OUT\t\t<null>',),
    '$t = 1_0; Write-Output (,$t); Write-Output $t': (
        'ERROR\tCommandNotFoundException\tSystem.Management.Automation.CommandNotFoundException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 2147483647 + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2147483648',
            'OUT\tSystem.Double\t2147483648',
        ),
    '$t = 512MB * 512MB; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2.88230376151712E+17',
            'OUT\tSystem.Double\t2.88230376151712E+17',
        ),
    '$t = 9223372036854775807 + 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t9.22337203685478E+18',
            'OUT\tSystem.Double\t9.22337203685478E+18',
        ),
    '$t = [decimal]::MaxValue + 1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tRuntimeException\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 100000000000000d * 100000000000000d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
        ),
    '$t = 10000000000000000000000000000d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
        ),
    '$t = 1E+28d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
            'OUT\tSystem.Decimal\t10000000000000000000000000000',
        ),
    "$t = 12 + '0xabc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2760',
            'OUT\tSystem.Int32\t2760',
        ),
    "$t = 16 + 'file'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = 5 + '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t10',
            'OUT\tSystem.Int32\t10',
        ),
    "$t = '5' + 5; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\t55',
            'OUT\tSystem.String\t55',
        ),
    "$t = [int]'0x10'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t16',
            'OUT\tSystem.Int32\t16',
        ),
    '$t = -2147483647 - 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2147483648',
            'OUT\tSystem.Int32\t-2147483648',
        ),
    '$t = -2147483648; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2147483648',
            'OUT\tSystem.Int32\t-2147483648',
        ),
    '$t = [int64]::MaxValue * 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1.84467440737095E+19',
            'OUT\tSystem.Double\t1.84467440737095E+19',
        ),
    '$t = [double]::PositiveInfinity; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\tInfinity',
            'OUT\tSystem.Double\tInfinity',
        ),
    '$t = [double]::NaN; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\tNaN',
            'OUT\tSystem.Double\tNaN',
        ),
    '$t = 10, 20, 30, 20, 10 -ne 20; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Object[]\t10 30 10',
            'OUT\tSystem.Int32\t10',
            'OUT\tSystem.Int32\t30',
            'OUT\tSystem.Int32\t10',
        ),
    '$t = 10, 20, 30 -eq 20; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Object[]\t20',
            'OUT\tSystem.Int32\t20',
        ),
    '$t = 10 -ne 20; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [string]('a', 'b'); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta b',
            'OUT\tSystem.String\ta b',
        ),
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        ('OUT\tSystem.String\ta-b',),
    '$OFS = \'-\'; Write-Output "$(1, 2)"':
        ('OUT\tSystem.String\t1-2',),
    '$t = ([char]65).ToUpper(); Write-Output (,$t); Write-Output $t': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = ('A').ToUpper(); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    '$t = ([char]65).Substring(0); Write-Output (,$t); Write-Output $t': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = ('A').Substring(0); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    '$t = ([char]65).ToString(); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\tA',
            'OUT\tSystem.String\tA',
        ),
    '$t = [int][char]48; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t48',
            'OUT\tSystem.Int32\t48',
        ),
    "$t = [int]'0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$h = @{}; $h[[char]65] = 1; $t = $h['A']; Write-Output (,$t)":
        ('OUT\t\t<null>',),
    "$h = @{}; $h['A'] = 1; $t = $h[[char]65]; Write-Output (,$t)":
        ('OUT\t\t<null>',),
    "$t = 1 + '2147483648'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int64\t2147483649',
            'OUT\tSystem.Int64\t2147483649',
        ),
    "$t = 1 + '1e3'; Write-Output (,$t); Write-Output $t":
        (
            'OUT	System.Double	1001',
            'OUT	System.Double	1001',
        ),
    "$t = 1 + '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t6',
            'OUT\tSystem.Int32\t6',
        ),
    "$t = [double]'1,5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Double\t15',
            'OUT\tSystem.Double\t15',
        ),
    '$t = -bnot 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = -bnot 0xFF; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-256',
            'OUT\tSystem.Int32\t-256',
        ),
    '$t = -bnot [byte]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-6',
            'OUT\tSystem.Int32\t-6',
        ),
    '$t = -bnot [uint32]7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt32\t4294967288',
            'OUT\tSystem.UInt32\t4294967288',
        ),
    '$t = -bnot 1L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-2',
            'OUT\tSystem.Int64\t-2',
        ),
    '$t = -bnot 1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-3',
            'OUT\tSystem.Int32\t-3',
        ),
    '$t = -bnot $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    "$t = -bnot '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-6',
            'OUT\tSystem.Int32\t-6',
        ),
    "$t = -bnot 'abc'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = -bnot [char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-66',
            'OUT\tSystem.Int32\t-66',
        ),
    '$t = -bnot $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2',
            'OUT\tSystem.Int32\t-2',
        ),
    '$t = -bnot 10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-11',
            'OUT\tSystem.Int32\t-11',
        ),
    '$t = -bnot 3000000000.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt32\t1294967295',
            'OUT\tSystem.UInt32\t1294967295',
        ),
    "$t = 'ab' * 0xFFFFFFFF; Write-Output (,$t); Write-Output $t": (
        'ERROR\tSystem.ArgumentOutOfRangeException\tSystem.ArgumentOutOfRangeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    'Write-Output "abc".Length':
        ('OUT\tSystem.Int32\t3',),
    "Write-Output 'abc'.Length":
        ('OUT\tSystem.Int32\t3',),
    'Write-Output 1':
        ('OUT\tSystem.Int32\t1',),
    'Write-Output -1':
        ('OUT\tSystem.String\t-1',),
    'Write-Output (-1)':
        ('OUT\tSystem.Int32\t-1',),
    'Write-Output -1.5':
        ('OUT\tSystem.String\t-1.5',),
    'Write-Output -1L':
        ('OUT\tSystem.String\t-1L',),
    '$t = @(@(1, 2)); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = @((1, 2)); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = @(@(1, 2), 3); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\tSystem.Object[] 3',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = ,(1, 2); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\tSystem.Object[]',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = (1, 2), 3; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\tSystem.Object[] 3',
            'OUT\tSystem.Int32\t2',
        ),
    "$t = 'a', 1; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Object[]\ta 1',
            'OUT\tSystem.String\ta',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = [int]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    '$t = [long]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t5',
            'OUT\tSystem.Int64\t5',
        ),
    '$t = [byte]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Byte\t5',
            'OUT\tSystem.Byte\t5',
        ),
    '$t = [byte]300; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [byte]-1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [sbyte]-5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.SByte\t-5',
            'OUT\tSystem.SByte\t-5',
        ),
    '$t = [int16]7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int16\t7',
            'OUT\tSystem.Int16\t7',
        ),
    '$t = [uint16]7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt16\t7',
            'OUT\tSystem.UInt16\t7',
        ),
    '$t = [uint32]7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt32\t7',
            'OUT\tSystem.UInt32\t7',
        ),
    '$t = [uint64]7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt64\t7',
            'OUT\tSystem.UInt64\t7',
        ),
    '$t = [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt64\t18446744073709551615',
            'OUT\tSystem.UInt64\t18446744073709551615',
        ),
    '$t = [int]2147483648; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [int]1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = [int]2.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = [int]1.4; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = [int]-1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-2',
            'OUT\tSystem.Int32\t-2',
        ),
    '$t = [long]1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t2',
            'OUT\tSystem.Int64\t2',
        ),
    '$t = [double]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t5',
            'OUT\tSystem.Double\t5',
        ),
    '$t = [decimal]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t5',
            'OUT\tSystem.Decimal\t5',
        ),
    '$t = [single]1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Single\t1.5',
            'OUT\tSystem.Single\t1.5',
        ),
    '$t = [double]1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1.5',
            'OUT\tSystem.Double\t1.5',
        ),
    '$t = [int]10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t10',
            'OUT\tSystem.Int32\t10',
        ),
    '$t = [char]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\t\x00',
            'OUT\tSystem.Char\t\x00',
        ),
    '$t = [char]65535; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\t\uffff',
            'OUT\tSystem.Char\t\uffff',
        ),
    '$t = [char]65536; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [char]-1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [int][char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t65',
            'OUT\tSystem.Int32\t65',
        ),
    '$t = [bool]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [bool]''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = [bool]'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [int]$true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = [string]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t5',
            'OUT\tSystem.String\t5',
        ),
    '$t = [string]1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.5',
            'OUT\tSystem.String\t1.5',
        ),
    '$t = [string]$true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\tTrue',
            'OUT\tSystem.String\tTrue',
        ),
    '$t = [string]10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t10',
            'OUT\tSystem.String\t10',
        ),
    "$t = [int]'5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = [int]' 5 '; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = [int]'abc'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]'1e3'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1000',
            'OUT\tSystem.Int32\t1000',
        ),
    "$t = [byte]'1e3'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]'1_0'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]'0b1010'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$t = [int]'   '; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]'007'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t7',
            'OUT\tSystem.Int32\t7',
        ),
    "$t = [int]'.5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$t = [int]'5.'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = [int]'1,000'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1000',
            'OUT\tSystem.Int32\t1000',
        ),
    "$t = [int]'1kb'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [int]'0o17'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [int]"`t`r5`n"; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = [int]'+7'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t7',
            'OUT\tSystem.Int32\t7',
        ),
    "$t = [int]'7.5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t8',
            'OUT\tSystem.Int32\t8',
        ),
    "$t = [int]'2.5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    "$t = [byte]'-1'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [byte]'0x80'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Byte\t128',
            'OUT\tSystem.Byte\t128',
        ),
    "$t = [sbyte]'0x80'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.SByte\t-128',
            'OUT\tSystem.SByte\t-128',
        ),
    "$t = [uint16]'0xFFFF'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.UInt16\t65535',
            'OUT\tSystem.UInt16\t65535',
        ),
    "$t = [int]'0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    "$t = [byte]'0x100'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [char]'A'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tA',
        ),
    "$t = [char]'AB'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastParseTargetInvocation\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [char]''; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastParseTargetInvocation\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [bool]'0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [string]'foo'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tfoo',
            'OUT\tSystem.String\tfoo',
        ),
    '$t = [int]$null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = [string]$null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t',
            'OUT\tSystem.String\t',
        ),
    '$t = [bool]$null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [char]$null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\t\x00',
            'OUT\tSystem.Char\t\x00',
        ),
    "$t = 'a' + $null; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta',
            'OUT\tSystem.String\ta',
        ),
    "$t = 'a' + $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\taTrue',
            'OUT\tSystem.String\taTrue',
        ),
    "$t = 'a' + 1.50d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta1.50',
            'OUT\tSystem.String\ta1.50',
        ),
    "$t = 'a' + 1.5; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta1.5',
            'OUT\tSystem.String\ta1.5',
        ),
    "$t = 'a' + @(1, 2); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta1 2',
            'OUT\tSystem.String\ta1 2',
        ),
    "$t = [double]'1.5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Double\t1.5',
            'OUT\tSystem.Double\t1.5',
        ),
    "$t = [Convert]::ToInt32('FFFFFFFF', 16); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    "$t = [Convert]::ToInt32('80000000', 16); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-2147483648',
            'OUT\tSystem.Int32\t-2147483648',
        ),
    "$t = [Convert]::ToInt32('0x10'); Write-Output (,$t); Write-Output $t": (
        'ERROR\tFormatException\tSystem.Management.Automation.MethodInvocationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [Convert]::ToInt32('1_0'); Write-Output (,$t); Write-Output $t": (
        'ERROR\tFormatException\tSystem.Management.Automation.MethodInvocationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [Convert]::ToInt32('7.5'); Write-Output (,$t); Write-Output $t": (
        'ERROR\tFormatException\tSystem.Management.Automation.MethodInvocationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [Convert]::ToInt32(' 5 '); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = [Convert]::ToInt32('-10', 16); Write-Output (,$t); Write-Output $t": (
        'ERROR\tArgumentException\tSystem.Management.Automation.MethodInvocationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [Convert]::ToInt32('017', 8); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t15',
            'OUT\tSystem.Int32\t15',
        ),
    "$t = [Convert]::ToByte('FF', 16); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Byte\t255',
            'OUT\tSystem.Byte\t255',
        ),
    '$t = [Convert]::ToInt64(5); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t5',
            'OUT\tSystem.Int64\t5',
        ),
    '$t = [Convert]::ToInt32(1.5); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = [Convert]::ToInt32(1.5d); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = [Convert]::ToInt32($null); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = [Convert]::ToChar(65); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tA',
        ),
    "$t = 'abc' -as [int]; Write-Output (,$t); Write-Output $t":
        (
            'OUT\t\t<null>',
            'OUT\t\t<null>',
        ),
    '$t = 5 -as [long]; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t5',
            'OUT\tSystem.Int64\t5',
        ),
    '$t = 300 -as [byte]; Write-Output (,$t); Write-Output $t':
        (
            'OUT\t\t<null>',
            'OUT\t\t<null>',
        ),
    '$a = New-Object byte[] 1; $t = $a[0]; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Byte\t0',
            'OUT\tSystem.Byte\t0',
        ),
    "$a = New-Object byte[] '0b10'; $t = $a.Count; Write-Output (,$t); Write-Output $t": (
        'ERROR\tConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand'
        '\tSystem.Management.Automation.MethodException',
        'OUT\tSystem.Int32\t0',
        'OUT\tSystem.Int32\t0',
    ),
    "$a = New-Object byte[] '0o10'; $t = $a.Count; Write-Output (,$t); Write-Output $t": (
        'ERROR\tConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand'
        '\tSystem.Management.Automation.MethodException',
        'OUT\tSystem.Int32\t0',
        'OUT\tSystem.Int32\t0',
    ),
    'function f { ,$args }; $t = f 1 2; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2',
            'OUT\tSystem.Int32\t2',
        ),
    "$a = 10, 20, 30; $t = $a['1']; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t20',
            'OUT\tSystem.Int32\t20',
        ),
    "$t = switch ('1') { 1 { 'number' } }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tnumber',
            'OUT\tSystem.String\tnumber',
        ),
    "$t = switch (1) { '1' { 'text' } }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ttext',
            'OUT\tSystem.String\ttext',
        ),
    "$t = switch ('0x10') { 16 { 'hex' } }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\t\t<null>',
            'OUT\t\t<null>',
        ),
    "$t = 'abc' -replace '(?<x>b)', '[${x}]'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta[b]c',
            'OUT\tSystem.String\ta[b]c',
        ),
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tb',
            'OUT\tSystem.String\tb',
        ),
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tb,c',
            'OUT\tSystem.String\tb,c',
        ),
    '$t = [string]1E20; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1E+20',
            'OUT\tSystem.String\t1E+20',
        ),
    '$t = [string]0.0000001; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1E-07',
            'OUT\tSystem.String\t1E-07',
        ),
    '$t = [string]1.5E-7; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.5E-07',
            'OUT\tSystem.String\t1.5E-07',
        ),
    '$t = 1 -ceq 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'A' -ceq 'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 'A' -ieq 'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [array]5; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t5',
            'OUT\tSystem.Int32\t1',
        ),
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tno',
            'OUT\tSystem.String\tno',
        ),
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tyes',
            'OUT\tSystem.String\tyes',
        ),
    'function f { $i = 0; $i++; $i++; $i }; $t = f; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    "function f { $s = 'abc'; $s++; $s }; $t = f; Write-Output (,$t); Write-Output $t": (
        'ERROR\tOperatorRequiresNumber\tSystem.Management.Automation.RuntimeException',
        'OUT\tSystem.String\tabc',
        'OUT\tSystem.String\tabc',
    ),
    'function g { ,(1, 2) }; $t = @(g); Write-Output $t.Count; Write-Output (,$t[0])':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Object[]\t1 2',
        ),
    "$t = @('1') -contains 1; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = @(1) -contains '1'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'a*' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'ab' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 'b' -like '[!a]'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '1_0' -band 15; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [byte]400; Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [byte](200 * 2); Write-Output (,$t); Write-Output $t': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    'function f { $null; 1; $null }; $t = f; Write-Output $t.Count; Write-Output (,$t)':
        (
            'OUT\tSystem.Int32\t3',
            'OUT\tSystem.Object[]\t 1 ',
        ),
    "$t = 'ſ' -match 's'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 'ſ' -cmatch 's'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 2147483647 * 2147483647; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t4.61168601413242E+18',
            'OUT\tSystem.Double\t4.61168601413242E+18',
        ),
    '$t = 9223372036854775807L + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t9.22337203685478E+18',
            'OUT\tSystem.Double\t9.22337203685478E+18',
        ),
    '$t = 9223372036854775807L - -1L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t9.22337203685478E+18',
            'OUT\tSystem.Double\t9.22337203685478E+18',
        ),
    '$t = -2147483648 - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-9.22337203900226E+18',
            'OUT\tSystem.Double\t-9.22337203900226E+18',
        ),
    '$t = -2147483648 % -1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = -2147483648 / -1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2147483648',
            'OUT\tSystem.Double\t2147483648',
        ),
    '$t = 0 - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-1.84467440737096E+19',
            'OUT\tSystem.Double\t-1.84467440737096E+19',
        ),
    '$t = 1 + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1.84467440737096E+19',
            'OUT\tSystem.Double\t1.84467440737096E+19',
        ),
    '$t = [uint64]18446744073709551615 + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t1.84467440737096E+19',
            'OUT\tSystem.Double\t1.84467440737096E+19',
        ),
    '$t = -1 * [uint64]1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1',
            'OUT\tSystem.Decimal\t-1',
        ),
    '$t = 2147483647 * [uint32]4294967295; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t9.22337203041232E+18',
            'OUT\tSystem.Double\t9.22337203041232E+18',
        ),
    '$t = -1 -band [uint32]1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.UInt32\t1',
            'OUT\tSystem.UInt32\t1',
        ),
    '$t = 1 / [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t5.42101086242752E-20',
            'OUT\tSystem.Double\t5.42101086242752E-20',
        ),
    '$t = 0 + [char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t65',
            'OUT\tSystem.Int32\t65',
        ),
    '$t = [char]48 -band [byte]255; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t48',
            'OUT\tSystem.Int32\t48',
        ),
    '$t = [char]48 -bxor [char]48; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = 1.5 * [char]48; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t72',
            'OUT\tSystem.Double\t72',
        ),
    '$t = [char]48 - 0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t48',
            'OUT\tSystem.Double\t48',
        ),
    '$t = [char]65 -bxor 32; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t97',
            'OUT\tSystem.Int32\t97',
        ),
    "$t = 0 + '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t5',
            'OUT\tSystem.Int32\t5',
        ),
    "$t = $true + ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    "$t = 1 + '0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$t = 1 + '1kb'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1025',
            'OUT\tSystem.Int32\t1025',
        ),
    "$t = 1 + '1.5L'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int64\t3',
            'OUT\tSystem.Int64\t3',
        ),
    "$t = 1 + '1e400'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [decimal]::MaxValue % 1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0',
            'OUT\tSystem.Decimal\t0',
        ),
    '$t = [decimal]::MaxValue % 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0',
            'OUT\tSystem.Decimal\t0',
        ),
    '$t = 1d + 0.1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.1',
            'OUT\tSystem.Decimal\t1.1',
        ),
    '$t = 1d - 0.1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0.9',
            'OUT\tSystem.Decimal\t0.9',
        ),
    '$t = [byte]1 -shl 4; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Byte\t16',
            'OUT\tSystem.Byte\t16',
        ),
    '$t = [byte]1 -shl -1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Byte\t0',
            'OUT\tSystem.Byte\t0',
        ),
    '$t = [single]1.5 -shl 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t4',
            'OUT\tSystem.Int32\t4',
        ),
    '$t = 1L -shl 64; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t1',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = $true + 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t9.22337203685478E+18',
            'OUT\tSystem.Double\t9.22337203685478E+18',
        ),
    '$t = $null + $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -band [uint32]1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidCastException\tSystem.InvalidCastException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = $true * 1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.5',
            'OUT\tSystem.Decimal\t1.5',
        ),
    '$t = 1.5 / -0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-Infinity',
            'OUT\tSystem.Double\t-Infinity',
        ),
    "$t = 'ab' * 1.5; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tabab',
            'OUT\tSystem.String\tabab',
        ),
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidCastException\tSystem.InvalidCastException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$v = [single]1.5; $t = $v + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2.5',
            'OUT\tSystem.Double\t2.5',
        ),
    '$t = [single]1.5 + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2.5',
            'OUT\tSystem.Double\t2.5',
        ),
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidCastException\tSystem.InvalidCastException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Byte\t16',
            'OUT\tSystem.Byte\t16',
        ),
    "$t = 1 + ' 7 '; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t8',
            'OUT\tSystem.Int32\t8',
        ),
    "$t = 1 + '+5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t6',
            'OUT\tSystem.Int32\t6',
        ),
    "$t = 1 + '  '; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    "$t = '5' - 1; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t4',
            'OUT\tSystem.Int32\t4',
        ),
    "$t = 1 - '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-4',
            'OUT\tSystem.Int32\t-4',
        ),
    "$t = '5' * 2; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\t55',
            'OUT\tSystem.String\t55',
        ),
    "$t = '10' -band 6; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    "$t = '5' / 2; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Double\t2.5',
            'OUT\tSystem.Double\t2.5',
        ),
    "$t = '1e400' + 1; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\t1e4001',
            'OUT\tSystem.String\t1e4001',
        ),
    '$t = $true + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = 1 + $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = $true - 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = 1 - $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = $true * 2; Write-Output (,$t); Write-Output $t': (
        'ERROR\tNotADefinedOperationForType\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 2 * $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = $true -band 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = $true + $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = $false + 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = $true / 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = $true + 1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2.5',
            'OUT\tSystem.Double\t2.5',
        ),
    '$t = $true -bxor $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = @(1, 2) + @(3, 4); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2 3 4',
            'OUT\tSystem.Int32\t4',
        ),
    '$t = @(1, 2) + 5; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2 5',
            'OUT\tSystem.Int32\t3',
        ),
    '$t = 5 + @(1, 2); Write-Output (,$t); Write-Output $t.Count': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\tSystem.Int32\t0',
    ),
    '$t = @(1, 2) * 2; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2 1 2',
            'OUT\tSystem.Int32\t4',
        ),
    '$t = 2 * @(1, 2); Write-Output (,$t); Write-Output $t.Count': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\tSystem.Int32\t0',
    ),
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\tSystem.Int32\t0',
    ),
    '$t = @() + 1; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = @(1, 2) + $null; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2 ',
            'OUT\tSystem.Int32\t3',
        ),
    '$t = $null + @(1, 2); Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t1 2',
            'OUT\tSystem.Int32\t2',
        ),
    "$t = @(1, 2) + 'a'; Write-Output (,$t); Write-Output $t.Count":
        (
            'OUT\tSystem.Object[]\t1 2 a',
            'OUT\tSystem.Int32\t3',
        ),
    '$t = @(1, 2) - 1; Write-Output (,$t); Write-Output $t.Count': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\tSystem.Int32\t0',
    ),
    '$t = @(1, 2) * 0; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t',
            'OUT\tSystem.Int32\t0',
        ),
    "$t = $null + 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tabc',
            'OUT\tSystem.String\tabc',
        ),
    '$t = $null + [char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tA',
        ),
    '$t = $null + 1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.5',
            'OUT\tSystem.Decimal\t1.5',
        ),
    '$t = $true -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 1 -and 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 1 -and 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 0 -or 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -xor $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 5 -xor 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'abc' -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '' -or $false; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '0' -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'false' -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = ' ' -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [char]0 -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = [char]'0' -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 0.0 -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = -0.0 -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 0.0d -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [uint64]0 -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @() -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @(0) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @(0, 0) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = @($false) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @($null) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @(@()) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @(1, 2) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool][char]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = [bool][char]'0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool]0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]-0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]0.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool](0.0 / 0.0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool]@(); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]@(0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]@(0, 0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool]@($false); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]@($null); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]@(@()); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = [bool]' '; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [bool]'false'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = -not @(); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = -not @(0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = -not '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = -not [char]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = if ([char]0) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tno',
            'OUT\tSystem.String\tno',
        ),
    "$t = if ('0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tyes',
            'OUT\tSystem.String\tyes',
        ),
    "$t = if (@(@())) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tno',
            'OUT\tSystem.String\tno',
        ),
    '$t = (,(,0)) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,(,@())) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,[char]0) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = (,'') -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = (,' ') -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,0.0) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = (,0.0d) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool](,(,0)); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool](,[char]0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = -not (,[char]0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = if ((,[char]0)) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tyes',
            'OUT\tSystem.String\tyes',
        ),
    "$t = - '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    "$t = - 'abc'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = - '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-5',
            'OUT\tSystem.Int32\t-5',
        ),
    "$t = if (- '0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tno',
            'OUT\tSystem.String\tno',
        ),
    '$t = (,@(1, 2)) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,$true) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [byte]0 -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 0L -or $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 1.5d -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $true -and [char]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $true -and ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -and @(); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [char]65 -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = @() * [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t.Count': (
        'ERROR\tInvalidCastIConvertible\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\tSystem.Int32\t0',
    ),
    '$t = @() * 5000; Write-Output (,$t); Write-Output $t.Count':
        (
            'OUT\tSystem.Object[]\t',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = (,@()) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = (,(,(,0))) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,1) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = (,'a') -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = (,[char]65) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = @(1, 2, 3) -and $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool](,@()); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool](,1); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = - 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = - 5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-5',
            'OUT\tSystem.Int32\t-5',
        ),
    '$t = - 0.0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t0',
            'OUT\tSystem.Double\t0',
        ),
    '$t = - 1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-1.5',
            'OUT\tSystem.Double\t-1.5',
        ),
    '$t = - $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = - $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-1',
            'OUT\tSystem.Int32\t-1',
        ),
    '$t = - $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = - [char]65; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-65',
            'OUT\tSystem.Int32\t-65',
        ),
    '$t = - [char]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = - 1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1.5',
            'OUT\tSystem.Decimal\t-1.5',
        ),
    '$t = - [byte]5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t-5',
            'OUT\tSystem.Int32\t-5',
        ),
    '$t = - [uint32]1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-1',
            'OUT\tSystem.Double\t-1',
        ),
    '$t = - (-2147483648); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t2147483648',
            'OUT\tSystem.Double\t2147483648',
        ),
    '$t = - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int64\t-9223372036854775807',
            'OUT\tSystem.Int64\t-9223372036854775807',
        ),
    '$t = - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-1.84467440737096E+19',
            'OUT\tSystem.Double\t-1.84467440737096E+19',
        ),
    '$t = - @(); Write-Output (,$t); Write-Output $t': (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = - '1e3'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Double\t-1000',
            'OUT\tSystem.Double\t-1000',
        ),
    "$t = - ' 5 '; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t-5',
            'OUT\tSystem.Int32\t-5',
        ),
    "$t = - ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t0',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = [bool][sbyte]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool][int16]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool][uint16]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool][uint32]0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool]1.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool](,$null); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [bool](,@(1, 2)); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [bool]@(0, 0, 0); Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = -not (- '0'); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = (- '0') -and $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = if (- '5') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tyes',
            'OUT\tSystem.String\tyes',
        ),
    '$t = $null -eq 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 0 -eq $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -eq $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '' -eq 0; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '' -eq '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $null -eq ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '' -eq $null; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '0' -eq 0; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 0 -eq '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '1.0' -eq 1; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 1 -eq '1.0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -lt 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '10' -lt '9'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '10' -lt 9; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 10 -lt '9'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '10' -ge 9; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 10 -ge '9'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '10' -ne 10; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 10 -ne '10'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 'B' -gt 'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'B' -cgt 'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'B' -igt 'a'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '10' -cle '9'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $true -eq 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $true -eq 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 2 -eq $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $true -eq 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'abc' -eq $true; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $true -eq ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $false -eq 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $true -ne 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -gt $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $false -lt 5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = $true -ge 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -ne 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -ne $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $null -lt 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -gt 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -ge 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -le 1; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 1 -lt $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 1 -gt $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 1 -le $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 1 -ge $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 1 -ne $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'abc' -lt $null; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $false -eq $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -eq $false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -eq $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 0 -gt $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -lt 0; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '' -gt $null; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = $null -lt ''; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $false -gt $null; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 1 -lt 'abc'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = 1 -gt 'abc'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = 1 -eq 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = 1 -ne 'abc'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 1 -lt '5'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
        ),
    '$t = -79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-79228162514264337593543950335',
            'OUT\tSystem.Decimal\t-79228162514264337593543950335',
        ),
    '$t = - 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-79228162514264337593543950335',
            'OUT\tSystem.Decimal\t-79228162514264337593543950335',
        ),
    '$t = 7922816251426433759354395033.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t7922816251426433759354395033.5',
            'OUT\tSystem.Decimal\t7922816251426433759354395033.5',
        ),
    '$t = 1.2345678901234567890123456789d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.2345678901234567890123456789',
            'OUT\tSystem.Decimal\t1.2345678901234567890123456789',
        ),
    '$t = 79228162514264337593543950335d - 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950334',
            'OUT\tSystem.Decimal\t79228162514264337593543950334',
        ),
    '$t = 79228162514264337593543950334d + 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
        ),
    '$t = 79228162514264337593543950335d + 1d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tRuntimeException\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 79228162514264337593543950335d * 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
        ),
    '$t = 79228162514264337593543950335d / 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
        ),
    '$t = 79228162514264337593543950335d - -1d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tRuntimeException\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 1.2345678901234567890123456789d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.2345678901234567890123456789',
            'OUT\tSystem.Decimal\t1.2345678901234567890123456789',
        ),
    '$t = 1.50d + 1.50d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t3.00',
            'OUT\tSystem.Decimal\t3.00',
        ),
    '$t = 1d / 3d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0.3333333333333333333333333333',
            'OUT\tSystem.Decimal\t0.3333333333333333333333333333',
        ),
    '$t = 1d / 0d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tRuntimeException\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [string]1.50d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.50',
            'OUT\tSystem.String\t1.50',
        ),
    '$t = [string]0.5d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t0.5',
            'OUT\tSystem.String\t0.5',
        ),
    "$t = 'a' + 0.5d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta0.5',
            'OUT\tSystem.String\ta0.5',
        ),
    "$t = 'a' + $false; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\taFalse',
            'OUT\tSystem.String\taFalse',
        ),
    '$t = [string]$false; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\tFalse',
            'OUT\tSystem.String\tFalse',
        ),
    "$t = 'a' + 1L; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta1',
            'OUT\tSystem.String\ta1',
        ),
    '$t = [string]1L; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1',
            'OUT\tSystem.String\t1',
        ),
    "$t = 'a' + 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta79228162514264337593543950335',
            'OUT\tSystem.String\ta79228162514264337593543950335',
        ),
    '$t = [string]79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t79228162514264337593543950335',
            'OUT\tSystem.String\t79228162514264337593543950335',
        ),
    "$t = 'a' + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta18446744073709551615',
            'OUT\tSystem.String\ta18446744073709551615',
        ),
    '$t = [string][uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t18446744073709551615',
            'OUT\tSystem.String\t18446744073709551615',
        ),
    "$t = 'a' + -1.50d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta-1.50',
            'OUT\tSystem.String\ta-1.50',
        ),
    '$t = [string]-1.50d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t-1.50',
            'OUT\tSystem.String\t-1.50',
        ),
    "$t = 'a' + [char]65; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\taA',
            'OUT\tSystem.String\taA',
        ),
    '$t = - 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0',
            'OUT\tSystem.Decimal\t0',
        ),
    '$t = - 0.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0',
            'OUT\tSystem.Decimal\t0',
        ),
    '$t = 79228162514264337593543950335d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
            'OUT\tSystem.Decimal\t79228162514264337593543950335',
        ),
    "$t = '1000' -eq 1e3d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'a' + 1e3d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\ta1000',
            'OUT\tSystem.String\ta1000',
        ),
    "$t = 'x' + 1.0d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1',
            'OUT\tSystem.String\tx1',
        ),
    "$t = [char]48 * '1'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = $true * '1'; Write-Output (,$t); Write-Output $t": (
        'ERROR\tMethodNotFound\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = [char]48 * 2; Write-Output (,$t); Write-Output $t': (
        'ERROR\tNotADefinedOperationForType\tSystem.Management.Automation.RuntimeException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 2 * [char]48; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Int32\t96',
            'OUT\tSystem.Int32\t96',
        ),
    '$t = $true - 1.0d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidOperationException\tSystem.InvalidOperationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = $true + 1.0d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidOperationException\tSystem.InvalidOperationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    '$t = 1.0d - $true; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t0',
            'OUT\tSystem.Decimal\t0',
        ),
    "$t = [char]48 - '1'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Int32\t47',
            'OUT\tSystem.Int32\t47',
        ),
    '$t = $true - 1.5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Double\t-0.5',
            'OUT\tSystem.Double\t-0.5',
        ),
    '$t = $true / 1.0d; Write-Output (,$t); Write-Output $t': (
        'ERROR\tSystem.InvalidOperationException\tSystem.InvalidOperationException',
        'OUT\t\t<null>',
        'OUT\t\t<null>',
    ),
    "$t = [char]48 -eq '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [char]48 -eq 48; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [char]65 -eq [char]97; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = [char]65 -ceq [char]97; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [char]97 -lt [char]66; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = [char]65 -lt [char]97; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'ss' -eq [char]0x00DF; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [char]0x00DF -eq 'ss'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -lt 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $true -gt 2; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = $true -eq '0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -lt -5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = $null -gt -5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    '$t = $null -le -5; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = @(1, 2) -eq $null; Write-Output (,$t); Write-Output $t':
        ('OUT\tSystem.Object[]\t',),
    "$t = '2' -lt '10'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    "$t = '10' -le '9'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tTrue',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = '10' -gt 9; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tFalse',
        ),
    '$t = 9.9999999999999999999999999999d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t10',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 1.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.0',
            'OUT\tSystem.Decimal\t1.0',
        ),
    '$t = [string]1.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.0',
            'OUT\tSystem.String\t1.0',
        ),
    '$t = 1.0d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    "$t = 'x' + 1.10d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.10',
            'OUT\tSystem.String\tx1.10',
        ),
    '$t = [string]1.10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.10',
            'OUT\tSystem.String\t1.10',
        ),
    '$t = 1.10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.10',
            'OUT\tSystem.Decimal\t1.10',
        ),
    '$t = [string]1.000d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.000',
            'OUT\tSystem.String\t1.000',
        ),
    "$t = 'x' + 2.0d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx2',
            'OUT\tSystem.String\tx2',
        ),
    '$t = [string]2.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t2.0',
            'OUT\tSystem.String\t2.0',
        ),
    '$t = [string]0.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t0.0',
            'OUT\tSystem.String\t0.0',
        ),
    "$z = 1.0d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.0',
            'OUT\tSystem.String\tx1.0',
        ),
    "$z = 1.10d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.10',
            'OUT\tSystem.String\tx1.10',
        ),
    '$z = 1.0d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.0',
            'OUT\tSystem.Decimal\t1.0',
        ),
    "$t = 'x' + 1.00d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1',
            'OUT\tSystem.String\tx1',
        ),
    "$t = 'x' + 1.000d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1',
            'OUT\tSystem.String\tx1',
        ),
    "$t = 'x' + 1.100d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.100',
            'OUT\tSystem.String\tx1.100',
        ),
    "$t = 'x' + 10.0d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx10',
            'OUT\tSystem.String\tx10',
        ),
    "$t = 'x' + 0.0d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx0',
            'OUT\tSystem.String\tx0',
        ),
    "$t = 'x' + 1.2300d; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.2300',
            'OUT\tSystem.String\tx1.2300',
        ),
    "$z = 1.00d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.00',
            'OUT\tSystem.String\tx1.00',
        ),
    "$z = 1.000d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.000',
            'OUT\tSystem.String\tx1.000',
        ),
    "$z = 1.100d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.100',
            'OUT\tSystem.String\tx1.100',
        ),
    '$t = 1.00d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    '$t = 1.000d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    '$t = 1.10d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.10',
            'OUT\tSystem.Decimal\t1.10',
        ),
    '$t = 1.100d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.100',
            'OUT\tSystem.Decimal\t1.100',
        ),
    '$t = 1.0d - 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    '$t = 1.0d * 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    '$t = 1.0d / 1d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1',
            'OUT\tSystem.Decimal\t1',
        ),
    '$t = 2.50d + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t2.50',
            'OUT\tSystem.Decimal\t2.50',
        ),
    '$t = 1.500d + 1.500d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t3.000',
            'OUT\tSystem.Decimal\t3.000',
        ),
    '$t = 1.0d + 2.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t3',
            'OUT\tSystem.Decimal\t3',
        ),
    '$z = 1.00d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.00',
            'OUT\tSystem.Decimal\t1.00',
        ),
    '$z = 1.100d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t1.100',
            'OUT\tSystem.Decimal\t1.100',
        ),
    '$z = 1.50d; $t = $z + 1.50d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t3.00',
            'OUT\tSystem.Decimal\t3.00',
        ),
    '$t = - 1.0d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1',
            'OUT\tSystem.Decimal\t-1',
        ),
    '$t = - 1.00d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1',
            'OUT\tSystem.Decimal\t-1',
        ),
    '$t = - 1.10d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1.10',
            'OUT\tSystem.Decimal\t-1.10',
        ),
    '$z = 1.0d; $t = - $z; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.Decimal\t-1.0',
            'OUT\tSystem.Decimal\t-1.0',
        ),
    '$t = [string]1.00d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.00',
            'OUT\tSystem.String\t1.00',
        ),
    '$t = [string]1.100d; Write-Output (,$t); Write-Output $t':
        (
            'OUT\tSystem.String\t1.100',
            'OUT\tSystem.String\t1.100',
        ),
    "$t = 'x' + (1.0d); Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1',
            'OUT\tSystem.String\tx1',
        ),
    "$t = 'x' + [decimal]'1.0'; Write-Output (,$t); Write-Output $t":
        (
            'OUT\tSystem.String\tx1.0',
            'OUT\tSystem.String\tx1.0',
        ),
}


#: Rows of `corpus.TYPES` whose deobfuscation does not behave like the row. Held apart from
#: `BEHAVIOUR_DEFECTS` rather than merged into it, because that table carries one entry per defect
#: with a host-free twin for each, and these share a handful of root causes: the Char erasure and
#: the cast whose target the fold drops.
#:
#: What is left of the Char erasure here is a wrong type in the interpreter, which computes with no
#: Char: a `[char]` cast inside a body it folds reaches the tree as the one-character String the
#: character spells. The value domain no longer shares that gap — a `[char[]]` cast is answered as
#: the `Char[]` it is, so `-is [string]` over one is `False` and its `.Count` is the element count —
#: and `[int][char]48` folds to the code point `48` the way 5.1 reads it. The row below is that
#: wrong type and nothing else.
TYPE_DEFECTS: dict[str, str] = {
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        'The count is right and the elements are not: the interpreter has no Char in the values '
        'it computes with, so a [char] cast reaches the tree as a one-character String.',
    'function f { $i = 0; $i++; $i++; $i }; $t = f; Write-Output (,$t); Write-Output $t':
        'An increment written as a statement hands nothing to the success stream on 5.1, so the '
        'body produces the one number it ends with. The interpreter contributes the value of every '
        'expression statement, so each increment joins the stream and the call answers a '
        'collection of three.',
    "function f { $s = 'abc'; $s++; $s }; $t = f; Write-Output (,$t); Write-Output $t":
        'Incrementing a String throws on 5.1 — the operator wants a number and says so. The '
        'interpreter substitutes zero for an operand it cannot read as one, so a script that '
        'stopped answers a collection instead.',
    'function f { $null; 1; $null }; $t = f; Write-Output $t.Count; Write-Output (,$t)':
        'A statement whose value is `$null` hands `$null` to the success stream, so the body '
        'produces three objects. The interpreter spells *emitted nothing* with the same `None` it '
        'spells `$null` with and drops it on append, so two of the three never reach the stream '
        'and the call answers the one number left.',
    'function g { ,(1, 2) }; $t = @(g); Write-Output $t.Count; Write-Output (,$t[0])':
        'The unary comma hands out one array, and a pipeline unrolls a collection exactly once, so '
        '@( ) collects the single Object[] the body wrote. The interpreter unrolls it a second '
        'time, once where the statement contributes its value and again where the stream is '
        'appended to, and the array arrives as its two elements.',
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


def rewritten_by(unit, snippets: Sequence[str]) -> Callable[[str], str]:
    """
    What `unit` makes of each of `snippets`, computed before any host starts and handed back as a
    lookup. `behaviours` runs its hosts on a thread pool and calls the rewrite from each of them,
    and a unit is a generator rather than a function: entered from two threads at once it raises
    `ValueError: generator already executing`, which reads as a broken host rather than as what it
    is. Rewriting up front is also the more honest boundary, because what the hosts are asked to
    run is then settled before any measurement begins.
    """
    emitted = {snippet: bytes(snippet.encode('utf8') | unit).decode('utf8') for snippet in snippets}
    return emitted.__getitem__


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


#: What a payload holds beyond the sources the budget is charged for: the brackets around them.
_PAYLOAD_WRAPPER = len('[]')


class _RecordingEchoHost:
    """
    What the echo script does to a payload, in process, and a record of every payload it was asked
    about. The JSON is read back out of the script the host was handed rather than serialised again
    here: what a batch costs is a question about the module's own two halves, and a stand-in that
    spelled the payload itself would answer it with what the test believes instead.
    """

    def __init__(self):
        self.batches: list[str] = []

    def __call__(self, script: str, timeout: float = 120.0) -> Behaviour:
        head, tail = oracle._ECHO_SCRIPT.split('@PAYLOAD@')
        batch = base64.b64decode(script[len(head):len(script) - len(tail)]).decode('utf-8')
        self.batches.append(batch)
        echoed = [
            base64.b64encode(source.encode('utf-8')).decode('ascii')
            for source in json.loads(batch)
        ]
        return Behaviour(json.dumps({'echoed': echoed}), '', 0)


class TestPs1OracleBatchesFitTheBudget(Ps1OracleTest):
    """
    `_BATCH_BUDGET` is a bound on the JSON one batch of sources comes to rather than an estimate of
    it, so what `_batches` charges for a source has to be what `_ask` then serialises for it. A
    discrepancy between the two is paid once for every source in a batch, which is why many short
    sources is the case that tells a bound from an estimate. No host is started, so this measures
    the same thing wherever the tests run.
    """

    def _batches_sent(self, sources: Sequence[str]) -> list[str]:
        host = _RecordingEchoHost()
        with patch.object(oracle, 'run', host):
            echo(sources)
        return host.batches

    def _beyond_the_budget(self, sources: Sequence[str]) -> list[int]:
        return [
            len(batch) for batch in self._batches_sent(sources)
            if len(batch) > oracle._BATCH_BUDGET + _PAYLOAD_WRAPPER
        ]

    def test_no_batch_of_the_corpus_carries_more_json_than_the_budget(self):
        self.assertEqual(self._beyond_the_budget(asked_of_the_host()), [])

    def test_no_batch_of_many_short_sources_carries_more_json_than_the_budget(self):
        self.assertEqual(self._beyond_the_budget(['$x'] * 4000), [])

    def test_every_source_travels_to_a_host_exactly_once_and_in_order(self):
        sources = list(asked_of_the_host())
        host = _RecordingEchoHost()
        with patch.object(oracle, 'run', host):
            self.assertEqual(echo(sources), sources)


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
class TestPs1OracleReportsASourceItCannotSend(Ps1OracleTest):
    """
    A source too large for one command line is refused by Windows before the host is reached, and
    the refusal names no script: it arrives as a `FileNotFoundError` that reads as if
    `powershell.exe` were missing. `OracleError` is what this module declares for a host that could
    not be run and what every caller is written against, so this reaches one too.
    """

    def test_a_source_too_large_for_one_command_line_is_an_oracle_error(self):
        oversized = 'A' * 40000
        with self.assertRaises(OracleError):
            parse_reports([oversized])


class _RecordingUnit:
    """
    A stand-in for the `ps1` unit that hands each input straight back and counts how often it was
    entered. It cannot be entered twice at once any more than the real unit can, but what is asked
    here is *when* it is entered rather than from where, which needs no threads to answer.
    """

    def __init__(self):
        self.entries = 0

    def __ror__(self, data: bytes) -> bytes:
        self.entries += 1
        return data


class TestPs1RewritingHappensBeforeAnyHostRuns(TestBase):
    """
    `rewritten_by` settles every rewrite before any host starts (see its docstring for why that
    matters), so the property to hold is that using the lookup enters the unit no further. No host
    is started, so this ratchets wherever the tests run.
    """

    def test_every_rewrite_is_computed_before_the_lookup_is_returned(self):
        unit = _RecordingUnit()
        rewritten_by(unit, ['$x = 1', '$y = 2', '$z = 3'])
        self.assertEqual(unit.entries, 3)

    def test_using_the_lookup_does_not_enter_the_unit(self):
        unit = _RecordingUnit()
        rewrite = rewritten_by(unit, ['$x = 1', '$y = 2'])
        rewrite('$x = 1')
        rewrite('$y = 2')
        rewrite('$x = 1')
        self.assertEqual(unit.entries, 2)

    def test_the_lookup_answers_what_the_unit_made_of_each_snippet(self):
        unit = _RecordingUnit()
        rewrite = rewritten_by(unit, ['$x = 1', '$y = 2'])
        self.assertEqual([rewrite('$x = 1'), rewrite('$y = 2')], ['$x = 1', '$y = 2'])


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
    The output must run and do the same thing as the input. Every other test of that compares our
    output against our own expectation of it; this one measures both on a host.
    """

    def test_the_output_behaves_like_the_input(self):
        snippets = (*corpus.BEHAVIOURS, *corpus.CLAIMS)
        deobfuscated = rewritten_by(self.ldu('ps1'), snippets)
        rewritten = [snippet for snippet in snippets if deobfuscated(snippet) != snippet]
        changed = sorted(
            snippet
            for snippet, before, after in zip(
                rewritten, behaviours(rewritten), behaviours(rewritten, deobfuscated))
            if before != after
        )
        self.assertEqual(changed, sorted({**BEHAVIOUR_DEFECTS, **BEHAVIOUR_DIVERGENCES}))

    def test_every_behaviour_defect_is_a_snippet_that_is_run(self):
        self.assertEqual(sorted(set(BEHAVIOUR_DEFECTS) - corpus.executable()), [])

    def test_every_behaviour_divergence_is_a_snippet_that_is_run(self):
        self.assertEqual(sorted(set(BEHAVIOUR_DIVERGENCES) - corpus.executable()), [])

    def test_no_behaviour_entry_is_both_deliberate_and_a_defect(self):
        self.assertEqual(sorted(set(BEHAVIOUR_DIVERGENCES) & set(BEHAVIOUR_DEFECTS)), [])


#: The corpus snippets the tool emits unchanged. See `TestPs1EverySnippetIsStillRewritten`.
UNREWRITTEN_SNIPPETS: frozenset[str] = frozenset()


class TestPs1EverySnippetIsStillRewritten(TestBase):
    """
    The differential above runs only the snippets the tool rewrites, so a snippet it stops rewriting
    leaves that comparison rather than failing it — and leaving it reads exactly like the defect
    being fixed. This closes that direction, and needs no host to do it, so it ratchets on a machine
    where every other test in this file is skipped.

    What it does not close is a snippet the tool rewrites *less*. Nearly every snippet here is
    changed by the console strip alone, so the emitted text differs from the source whether or not
    the name a refusal was about was resolved. A refusal that narrowed rather than stopped the
    rewrite is caught by the differential where the snippet's behaviour changes and by
    `test_aliases.py` where it does not.
    """

    def test_every_corpus_snippet_is_rewritten(self):
        unit = self.ldu('ps1')
        untouched = frozenset(
            snippet for snippet in (*corpus.BEHAVIOURS, *corpus.CLAIMS)
            if bytes(snippet.encode('utf8') | unit).decode('utf8') == snippet
        )
        self.assertEqual(sorted(untouched), sorted(UNREWRITTEN_SNIPPETS))


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1ValueTypesRestOnMeasuredBeliefs(Ps1OracleTest):
    """
    What a value's type is, and what an operation produces, asked of the host rather than assumed.
    The unit answers both from tables and rules we wrote, so every other test of them agrees with us
    wherever we are wrong; these do not.

    The two questions are kept apart. This class asks only what PowerShell does, so that the table it
    pins is a measurement and not a comparison, and `TestPs1DeobfuscationPreservesValueTypes` asks
    whether the unit's output still does it.
    """

    def test_every_belief_about_a_value_type_is_what_powershell_does(self):
        measured = dict(zip(corpus.TYPES, behaviours(corpus.TYPES)))
        self.assertEqual(measured, TYPE_TRANSCRIPTS)

    def test_a_char_and_a_one_character_string_are_told_apart(self):
        """
        The comparison the table alone does not make. Every witness in it is a transcript line, and
        a harness that had stopped reporting the type would make a Char and a String read alike —
        which is the defect the whole table is about, so it would pass unremarked.
        """
        measured = behaviours([
            '$t = [char]65; Write-Output (,$t); Write-Output $t',
            "$t = ('A').ToUpper(); Write-Output (,$t); Write-Output $t",
            "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])",
        ])
        self.assertEqual(
            [measured[0][0], measured[1][0], measured[2][0], measured[2][1]],
            [
                'OUT\tSystem.Char\tA',
                'OUT\tSystem.String\tA',
                'OUT\tSystem.Boolean\tTrue',
                'OUT\tSystem.Boolean\tFalse',
            ],
        )


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1DeobfuscationPreservesValueTypes(Ps1OracleTest):
    """
    The same promise `TestPs1DeobfuscationPreservesBehaviour` checks, over the rows written to make
    a type observable. They are quantified separately and ledgered separately because they share a
    few root causes rather than being independent defects, and because three of those causes are
    not about types at all — see `TYPE_DEFECTS`.
    """

    def test_the_output_behaves_like_the_row(self):
        rewrite = rewritten_by(self.ldu('ps1'), corpus.TYPES)
        rows = corpus.TYPES
        changed = sorted(
            row for row, before, after in zip(rows, behaviours(rows), behaviours(rows, rewrite))
            if before != after
        )
        self.assertEqual(changed, sorted(TYPE_DEFECTS))

    def test_every_type_defect_is_a_row_that_is_run(self):
        self.assertEqual(sorted(set(TYPE_DEFECTS) - set(corpus.TYPES)), [])

    def test_no_row_is_ledgered_as_both_a_type_defect_and_a_behaviour_defect(self):
        self.assertEqual(sorted(set(TYPE_DEFECTS) & set(BEHAVIOUR_DEFECTS)), [])


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


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1CommandTablesRestOnMeasuredBeliefs(Ps1OracleTest):
    """
    `refinery.lib.scripts.ps1.data` holds the host's alias and cmdlet tables, captured once and
    edited by hand since. Which names those tables contain is the premise every command resolution
    rests on, and an entry the host does not have is not a harmless surplus: nothing in ordinary
    name lookup beats an alias, so an invented alias takes a name away from the function or the
    implicit `Get-` retry 5.1 would have given it.

    These ask the host what it actually binds. They are the only scripts in the corpus written to
    depend on the machine, and the machine they depend on is a Windows PowerShell 5.1 installation,
    which is the oracle's subject.

    That subject is the *default* set a clean 5.1 defines, which is what a resolver can model. A
    particular installation may carry more — a module a runner preinstalls exports an alias into the
    session — and a name bound there but nowhere a clean host reaches is that installation's surplus,
    not the table's omission. So the belief the class enforces is one-directional: every binding the
    table claims, the host must have; what the host binds beyond them, it is free to.
    """

    def test_every_binding_the_table_claims_the_host_also_binds(self):
        """
        Every binding the table claims — an alias it resolves, a cmdlet it has, a command whose type
        it names — the host must still have; a binding the table claims and the host lacks is the
        invented one this class exists to catch.
        """
        measured = dict(zip(corpus.TABLES, behaviours(corpus.TABLES)))
        claimed = claimed_bindings(TABLE_TRANSCRIPTS)
        self.assertEqual({name: measured[name] for name in claimed}, claimed)

    def test_a_name_the_host_binds_is_not_measured_like_one_it_does_not(self):
        """
        The comparison the table alone does not make. Every disputed name answers the same way, so
        without a name the host does bind standing beside them, a probe that had stopped working
        would read as the host binding nothing.
        """
        measured = behaviours(['Get-Alias iex', 'Get-Alias item'])
        self.assertEqual(
            [line.split('\t')[0] for transcript in measured for line in transcript],
            ['OUT', 'ERROR'],
        )


class TestPs1CommandTableCheckIsASubsetNotAnEquality(TestBase):
    """
    What `claimed_bindings` selects, and so which way the command-table oracle can fail, decided on
    the table's own shape without a host. The oracle enforces one direction — every binding the
    table claims, the host has — so an installation that binds a name the table calls unbound does
    not fail it, while the table claiming a binding the host lacks still does. This is the property
    that keeps a runner's preinstalled alias from reading as a fault in a table that maps the
    default set, without letting an invented alias through.
    """

    def test_a_host_binding_a_name_the_table_calls_unbound_is_tolerated(self):
        unbound = next(
            name for name, transcript in TABLE_TRANSCRIPTS.items()
            if not transcript[0].startswith('OUT')
        )
        measured = dict(TABLE_TRANSCRIPTS)
        measured[unbound] = ('OUT\tSystem.Management.Automation.AliasInfo\tsurplus',)
        claimed = claimed_bindings(TABLE_TRANSCRIPTS)
        self.assertEqual([name for name in claimed if measured[name] != claimed[name]], [])

    def test_a_binding_the_table_claims_the_host_lacks_is_caught(self):
        invented = next(
            name for name, transcript in TABLE_TRANSCRIPTS.items()
            if transcript[0].startswith('OUT')
        )
        measured = dict(TABLE_TRANSCRIPTS)
        measured[invented] = _NO_SUCH_ALIAS
        claimed = claimed_bindings(TABLE_TRANSCRIPTS)
        self.assertEqual([name for name in claimed if measured[name] != claimed[name]], [invented])


class TestPs1NoCorpusTableListsTheSameScriptTwice(TestBase):
    """
    A duplicated row costs a host process and fails nothing: every transcript above is compared as
    `dict(zip(table, behaviours(table)))`, and a dict keyed by the source keeps one of the two rows
    and throws the second measurement away. `SNIPPETS` is not one of these tables and is left out by
    being a dict rather than a sequence: it is keyed by node class, and a script that witnesses two
    of them is written under both on purpose.

    The tables are found rather than listed, so that one added to the corpus is guarded from the day
    it is written, and the names found are pinned below, so that finding none cannot pass for
    finding no duplicate.
    """

    def _tables(self) -> dict[str, tuple[str, ...]]:
        return {
            name: value
            for name, value in vars(corpus).items()
            if not name.startswith('_')
            and isinstance(value, tuple)
            and all(isinstance(row, str) for row in value)
        }

    def test_the_tables_found_are_the_ones_the_corpus_publishes(self):
        self.assertEqual(sorted(self._tables()), [
            'BEHAVIOURS',
            'BOUNDARIES',
            'CLAIMS',
            'NAMES',
            'PROBES',
            'SPELLINGS',
            'TABLES',
            'TYPES',
        ])

    def test_no_table_lists_the_same_script_twice(self):
        repeated = {}
        for name, table in self._tables().items():
            rows = sorted(row for row, count in Counter(table).items() if count > 1)
            if rows:
                repeated[name] = rows
        self.assertEqual(repeated, {})
