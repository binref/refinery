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
}


#: Snippets whose deobfuscation writes something different from the snippet on purpose. The unit's
#: default strips a statement whose only effect is a value on the success output stream, treating the
#: input as a standalone script whose console output is not the artifact; `ps1 -k` keeps it. So a
#: divergence here is the documented behaviour of that default and not a bug, which is why it is held
#: apart from `BEHAVIOUR_DEFECTS` the way the parser's `DIVERGENCES` are held apart from its
#: `DEFECTS`. Both tables are checked against the measured set in both directions, so a divergence
#: that stops happening and a new one that starts both fail.
BEHAVIOUR_DIVERGENCES: dict[str, str] = {
    "try { throw 'x' } catch { 'caught' }":
        "The catch body is a bare expression whose only effect is the success stream, so the "
        "default strips it and the snippet's `caught` is not printed; `ps1 -k` keeps it. A real but "
        "separate defect stands beside this one: `Write-Output 'caught'` in the same place survives, "
        "so the strip recognises implicit output and not explicit, where it should ask the output "
        "model about both alike. That asymmetry is a question for the output model, not this table.",
}

#: Snippets whose deobfuscation does not behave like the snippet. Each is a semantics defect: the
#: tool's first promise is that its output does the same thing as its input. Each entry states what
#: the snippet writes and what its output writes instead, so a failure can be read here.
#:
#: The variable entries are each a claim of the corruption ledger as well, and a defect that ledger
#: already carries as an `expectedFailure`. That the two agree entry for entry matters there: the
#: ledger reaches its verdict by asking whether a store survived in the tree, and this reaches it by
#: running both scripts, so neither is evidence for the other.
#:
#: An entry this table holds alone would not have that second witness, and every test in this file
#: is skipped where no PowerShell host is available — so on a machine without one such an entry
#: ratchets in neither direction, and a fix and a regression are alike invisible. Every entry needs
#: a witness of its own shape somewhere host-free. The variable entries are carried by
#: `test_corruptions.py`, which asks whether a store survived in the tree; the `[Array]::Reverse`
#: entries are carried by
#: `test.lib.scripts.ps1.deobfuscation.test_folding.TestPs1ArrayReverseIsAppliedWhereItIsWritten`,
#: which asks what the tool emits. Neither of those is evidence for what is written here, because
#: this reaches its verdict by running both scripts.
BEHAVIOUR_DEFECTS: dict[str, str] = {
    "Set-Variable global:y 'b'; Write-Host $global:y":
        'The store is dropped, so `b` becomes nothing: a command that writes a variable is not '
        'read as the store the following read needs.',
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        'The read is folded to `b`, but 5.1 never evaluates the right operand of `-and` when the '
        'left one is false, so the store never happens and the snippet prints `a`.',
    "$x = @('b', 'a'); [Array]::Sort($x); Write-Host $x[0]":
        'The read is folded to `b`, the order from before the sort. `[Array]::Sort` reorders the '
        'array the variable holds rather than returning a new one, so the snippet prints `a`.',
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
    "$s = 'abc'; [Array]::Reverse($s); Write-Output $s":
        'The string is emitted reversed. 5.1 binds a String to the `System.Array` parameter by '
        'converting it to a fresh `Char[]`, reverses that copy and discards it, so the variable is '
        'left holding `abc`.',
    "$x = 1, 2, 3; Write-Output $x[0]; [Array]::Reverse($x); Write-Output $x[0]":
        'The reversal is folded back into the statement that built the array, so the read above it '
        'reports the order that only holds below it: both reads emit 3 where 5.1 prints 1 and then '
        '3.',
    "$x = 1, 2, 3; $x[0] = 9; [Array]::Reverse($x); Write-Output $x":
        'The same relocation, across a write rather than a read: the element written before the '
        'reversal ends up at the near end instead of the far one, so `9 2 1` is emitted where 5.1 '
        'leaves `3 2 9`.',
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

#: What the whole `_UNPARSEABLE_RECEIVER` group of `TYPE_DEFECTS` has in common. 5.1 reads a digit
#: that starts a token as the start of a number, so a numeric literal cannot stand as a
#: member-access receiver: `3.ToString()` is a parse error, and in a command argument every numeric
#: literal is, `0xFF` and `1kb` and `1.5` alike. The unit inlines a folded value into that slot
#: without parentheses, so `$n = 5; $n.ToString()` becomes a script PowerShell will not read.
_UNPARSEABLE_RECEIVER = (
    'The value is folded to a numeric literal left standing as a member-access receiver without '
    'parentheses, which 5.1 refuses to parse. That is a defect of how a value is spelled rather '
    'than of what the unit believes it to be, so this phase does not retire it.'
)

#: What 5.1 makes of a value's type and of an operation's result, measured. The unit has no place to
#: keep a type — a Char and a one-character String are the same object to it — so every belief about
#: one was written by us, and this is the table that ends that. Read the rule in `corpus.TYPES`
#: before adding an entry: two witnesses, and `Write-Host` may not be either of them.
#:
#: Nothing here is a claim about the tool. It is what PowerShell does, and it is pinned so that the
#: commits which give the unit a type cannot quietly move the target they are measured against.
TYPE_TRANSCRIPTS: dict[str, tuple[str, ...]] = {
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Object[]',
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
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.GetType().FullName':
        ('OUT\tSystem.String\tSystem.Object[]',),
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        (
            'OUT\tSystem.Int32\t2',
            'OUT\tSystem.Char\tA',
            'OUT\tSystem.Char\tB',
        ),
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output $t.GetType().FullName":
        ('OUT\tSystem.String\tSystem.Object[]',),
    '$t = [char]65; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Char',
            'OUT\tSystem.Char\tA',
        ),
    '$t = [char[]](72, 73); Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Char[]',
            'OUT\tSystem.Char\tH',
            'OUT\tSystem.Char\tI',
        ),
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = 'ABC'[0]; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Char',
            'OUT\tSystem.Char\tA',
        ),
    "$t = [char[]]'ABC'; Write-Output $t.GetType().FullName; Write-Output $t.Count":
        (
            'OUT\tSystem.String\tSystem.Char[]',
            'OUT\tSystem.Int32\t3',
        ),
    "$t = 'ABC'.ToCharArray(); Write-Output $t.GetType().FullName; Write-Output $t.Count":
        (
            'OUT\tSystem.String\tSystem.Char[]',
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
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')":
        (
            'OUT\tSystem.Int32\t66',
            'THROW\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',
        ),
    'Write-Output (([char]65) * 3)':
        ('THROW\tNotADefinedOperationForType\tSystem.Management.Automation.RuntimeException',),
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
    "$t = 'AB'.Count; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = (5).Count; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = (5).Length; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1',
        ),
    "$t = 1 + 'AB'.Count; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t2',
        ),
    '$t = @(1, 2, 3).Rank; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = @(1, 2, 3).Count; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t3',
        ),
    '$t = @(1, 2, 3).Length; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t3',
        ),
    "$t = 'AB'.Length; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
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
    '$t = (5).Rank; Write-Output ($null -eq $t)':
        ('OUT\tSystem.Boolean\tTrue',),
    "$t = 'AB'.Zqnope; Write-Output ($null -eq $t)":
        ('OUT\tSystem.Boolean\tTrue',),
    '$t = (5).Zqnope; Write-Output ($null -eq $t)':
        ('OUT\tSystem.Boolean\tTrue',),
    '$t = $null.Count; Write-Output ($null -eq $t); Write-Output $t':
        (
            'OUT\tSystem.Boolean\tFalse',
            'OUT\tSystem.Int32\t0',
        ),
    '$f = New-Object IO.MemoryStream; Write-Output $f.Length.GetType().FullName':
        ('OUT\tSystem.String\tSystem.Int64',),
    '$f = New-Object IO.MemoryStream; $f.Dispose(); Write-Output $f.Length':
        ('OUT\t\t<null>',),
    '$t = @(); Write-Output $t.GetType().FullName; Write-Output $t.Count':
        (
            'OUT\tSystem.String\tSystem.Object[]',
            'OUT\tSystem.Int32\t0',
        ),
    '$t = , 1; Write-Output $t.GetType().FullName; Write-Output $t.Count':
        (
            'OUT\tSystem.String\tSystem.Object[]',
            'OUT\tSystem.Int32\t1',
        ),
    '$t = 0xFF; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t255',
        ),
    '$t = 0x7FFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t2147483647',
        ),
    '$t = 0xFFFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t-1',
        ),
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t-91',
        ),
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int64',
            'OUT\tSystem.Int64\t-1',
        ),
    '$t = 1kb; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1024',
        ),
    '$t = 1L; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int64',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = 10d; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Decimal',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 0xFFFFFFFF + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t-1',
        ),
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int64',
            'OUT\tSystem.Int64\t-1',
        ),
    '$t = 1kb + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t1024',
        ),
    '$t = 1L + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int64',
            'OUT\tSystem.Int64\t1',
        ),
    '$t = 10d + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Decimal',
            'OUT\tSystem.Decimal\t10',
        ),
    '$t = 2147483648; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int64',
            'OUT\tSystem.Int64\t2147483648',
        ),
    '$t = 1.5; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t1.5',
        ),
    '$t = 1e3; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t1000',
        ),
    '$t = 2147483647 + 1; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t2147483648',
        ),
    '$t = 512MB * 512MB; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t2.88230376151712E+17',
        ),
    '$t = 9223372036854775807 + 2; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t9.22337203685478E+18',
        ),
    '$t = [decimal]::MaxValue + 1; Write-Output $t.GetType().FullName; Write-Output $t':
        ('THROW\tRuntimeException\tSystem.Management.Automation.RuntimeException',),
    "$t = 12 + '0xabc'; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t2760',
        ),
    "$t = 16 + 'file'; Write-Output $t.GetType().FullName; Write-Output $t":
        ('THROW\tInvalidCastFromStringToInteger\tSystem.Management.Automation.RuntimeException',),
    "$t = 5 + '5'; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t10',
        ),
    "$t = '5' + 5; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.String',
            'OUT\tSystem.String\t55',
        ),
    "$t = [int]'0x10'; Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t16',
        ),
    '$t = -2147483647 - 1; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t-2147483648',
        ),
    '$t = -2147483648; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Int32',
            'OUT\tSystem.Int32\t-2147483648',
        ),
    '$t = [int64]::MaxValue * 2; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\t1.84467440737095E+19',
        ),
    '$t = [double]::PositiveInfinity; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\tInfinity',
        ),
    '$t = [double]::NaN; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Double',
            'OUT\tSystem.Double\tNaN',
        ),
    '$t = 10, 20, 30, 20, 10 -ne 20; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Object[]',
            'OUT\tSystem.Int32\t10',
            'OUT\tSystem.Int32\t30',
            'OUT\tSystem.Int32\t10',
        ),
    '$t = 10, 20, 30 -eq 20; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Object[]',
            'OUT\tSystem.Int32\t20',
        ),
    '$t = 10 -ne 20; Write-Output $t.GetType().FullName; Write-Output $t':
        (
            'OUT\tSystem.String\tSystem.Boolean',
            'OUT\tSystem.Boolean\tTrue',
        ),
    "$t = [string]('a', 'b'); Write-Output $t.GetType().FullName; Write-Output $t":
        (
            'OUT\tSystem.String\tSystem.String',
            'OUT\tSystem.String\ta b',
        ),
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        ('OUT\tSystem.String\ta-b',),
    '$OFS = \'-\'; Write-Output "$(1, 2)"':
        ('OUT\tSystem.String\t1-2',),
}


#: Rows of `corpus.TYPES` whose deobfuscation does not behave like the row. Held apart from
#: `BEHAVIOUR_DEFECTS` rather than merged into it, because that table carries one entry per defect
#: with a host-free twin for each, and these share a handful of root causes: the pipeline collapse,
#: the `$Null` mint, the Char erasure, and one that is not about types at all.
#:
#: That last one is `_UNPARSEABLE_RECEIVER`, and it is the largest group here. It is a defect of how
#: a value is *spelled* rather than of what the unit believes it to be, so the commits of this phase
#: do not retire it; it is pinned host-free in
#: `test.lib.scripts.ps1.deobfuscation.test_value_domain` so that it ratchets where a host is not
#: available, and it is the reason a type witness cannot be read through the deobfuscated script.
#:
#: Two entries record something worse than a wrong answer. `'AB'.Count` and `(5).PSObject` are
#: folded to `$Null`, and the `$Null` then receives a method call, so a script that printed a number
#: throws instead. A mint that answers wrongly and a mint that stops the script are the same bug and
#: are not held apart here, but the difference is why the member surface is the first thing the
#: phase corrects.
TYPE_DEFECTS: dict[str, str] = {
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output $t.GetType().FullName; Write-Output $t":
        'A pipeline builds an Object[]. The emulator collapses a list of one-character strings'
        'into one string, so both the container type and the element count are lost.',
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')":
        'The same collapse, seen through a join: one element means the separator never appears.',
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }":
        'The same collapse, as changed control flow: the loop runs once over one string rather'
        'than twice over two.',
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.GetType().FullName':
        'The same collapse over Char results, which is the shape a char-building loader writes.',
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        'The collapse loses the count, and .Count on the result mints $Null where 5.1 answers 2.',
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output $t.GetType().FullName":
        'The collapse is not about Char at all: any list of one-character strings falls to it.',
    '$t = [char]65; Write-Output $t.GetType().FullName; Write-Output $t':
        'A Char folds to a one-character String, so GetType and -is both answer differently.',
    '$t = [char[]](72, 73); Write-Output $t.GetType().FullName; Write-Output $t':
        'The same erasure for an array of Char, which folds to one String.',
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        'A Char[] is not a String; the fold makes it answer as though it were.',
    "$t = 'ABC'[0]; Write-Output $t.GetType().FullName; Write-Output $t":
        'Indexing a string yields a Char. folding.py:302 produces a String.',
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')":
        'The left operand decides: Int + Char is Int32 66, and Int + String parses the string as a'
        'number. Spelling the Char as a String turns a working line into a throw.',
    'Write-Output (([char]65) * 3)':
        'LangSpec 7.6.2 replicates only where the left operand is a String, so 5.1 throws. The'
        'fold spells the Char as a String and answers AAA.',
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])":
        'The fold makes a Char answer False to -is [char].',
    "Write-Output (([char]65).Count); Write-Output (('A').Count)":
        'Count is an engine intrinsic the per-type capture cannot hold, so $Null is minted where'
        '5.1 answers 1.',
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }':
        'The loop variable is a Char in 5.1 and a String after the fold.',
    "$t = 'AB'.Count; Write-Output $t.GetType().FullName; Write-Output $t":
        'The minted $Null then receives .GetType(), so the script throws where 5.1 printed'
        'System.Int32. The mint does not merely answer wrongly, it stops the script.',
    '$t = (5).Count; Write-Output $t.GetType().FullName; Write-Output $t':
        'The same, on a scalar receiver.',
    '$t = (5).Length; Write-Output $t.GetType().FullName; Write-Output $t':
        'The same, for Length on a scalar.',
    "$t = 1 + 'AB'.Count; Write-Output $t.GetType().FullName; Write-Output $t":
        _UNPARSEABLE_RECEIVER,
    '$t = @(1, 2, 3).Rank; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = @(1, 2, 3).Count; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = @(1, 2, 3).Length; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    "$t = 'AB'.Length; Write-Output $t.GetType().FullName; Write-Output $t":
        _UNPARSEABLE_RECEIVER,
    'Write-Output ((5).PSTypeNames)':
        'PSTypeNames is added by the PSObject adapter to every object, so Get-Member -Force cannot'
        'capture it per type and the mint answers $Null for it.',
    "Write-Output (('AB').PSTypeNames)":
        'The same, on a String receiver.',
    'Write-Output ((5).PSObject.GetType().FullName)':
        'PSObject is the same kind of intrinsic, and the minted $Null then receives .GetType(), so'
        'the script throws.',
    '$t = 0xFF; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0x7FFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0xFFFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 1kb; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 1L; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 10d; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0xFFFFFFFF + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 1L + 0; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 2147483648; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 1.5; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 1e3; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 2147483647 + 1; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    '$t = 9223372036854775807 + 2; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    "$t = [int]'0x10'; Write-Output $t.GetType().FullName; Write-Output $t":
        _UNPARSEABLE_RECEIVER,
    '$t = -2147483647 - 1; Write-Output $t.GetType().FullName; Write-Output $t':
        _UNPARSEABLE_RECEIVER,
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        'A collection renders to a String separated by $OFS (LangSpec 6.8), which this script'
        'sets. The fold bakes in the default separator.',
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
            '$t = [char]65; Write-Output $t.GetType().FullName; Write-Output $t',
            "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])",
        ])
        self.assertEqual(
            [measured[0][0], measured[1][0], measured[1][1]],
            [
                'OUT\tSystem.String\tSystem.Char',
                'OUT\tSystem.Boolean\tTrue',
                'OUT\tSystem.Boolean\tFalse',
            ],
        )


@unittest.skipIf(windows_powershell() is None, 'Windows PowerShell is not available')
class TestPs1DeobfuscationPreservesValueTypes(Ps1OracleTest):
    """
    The same promise `TestPs1DeobfuscationPreservesBehaviour` checks, over the rows written to make
    a type observable. They are quantified separately and ledgered separately because they share a
    few root causes rather than being independent defects, and because one of those causes is not
    about types at all — see `TYPE_DEFECTS`.
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
    """

    def test_every_belief_about_what_the_host_binds_is_what_the_host_binds(self):
        measured = dict(zip(corpus.TABLES, behaviours(corpus.TABLES)))
        self.assertEqual(measured, TABLE_TRANSCRIPTS)

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
