from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from refinery.lib.scripts import canonical
from refinery.lib.scripts.ps1.model import (
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandInvocation,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser

from test.lib.scripts.ps1 import dispatch


def _occurs(output: str, texts: tuple[str, ...]) -> bool:
    return all(output.count(text) >= texts.count(text) for text in texts)


def _program(source: str) -> object:
    tree = Ps1Parser(source).parse()
    for node in tree.walk():
        if isinstance(node, Ps1Variable):
            node.name = node.name.casefold()
            node.drive = node.drive.casefold()
        elif isinstance(node, Ps1TypeExpression):
            node.name = node.name.casefold()
        elif isinstance(node, Ps1CastExpression):
            node.type_name = node.type_name.casefold()
        elif isinstance(node, Ps1CommandArgument):
            node.name = node.name.casefold()
        elif isinstance(node, (Ps1MemberAccess, Ps1InvokeMember)) and isinstance(node.member, str):
            node.member = node.member.casefold()
        elif isinstance(node, Ps1CommandInvocation) and isinstance(node.name, Ps1StringLiteral):
            node.name.value = node.name.value.casefold()
    return canonical(tree)


class Simplified(NamedTuple):
    keeps: tuple[str, ...] = ()
    gains: tuple[str, ...] = ()
    lacks: tuple[str, ...] = ()

    def kept_by(self, output: str, script: str) -> bool:
        return _occurs(output, self.keeps)

    def met_by(self, output: str, script: str) -> bool:
        if not self.kept_by(output, script) or not _occurs(output, self.gains):
            return False
        folded = output.lower()
        return not any(text.lower() in folded for text in self.lacks)


@dataclass(frozen=True)
class Emptied:

    def kept_by(self, output: str, script: str) -> bool:
        return True

    def met_by(self, output: str, script: str) -> bool:
        return not output.strip()


@dataclass(frozen=True)
class KeptAsWritten:

    def kept_by(self, output: str, script: str) -> bool:
        return _program(output) == _program(script)

    def met_by(self, output: str, script: str) -> bool:
        return self.kept_by(output, script)


Expectation = Simplified | Emptied | KeptAsWritten


def _dispatched(name: str) -> str:
    program, preference, on = dispatch.ANCHORS[name]
    return dispatch.render(program, preference, on)


SIMPLIFIED: dict[str, Expectation] = {
    'if ($a) { 1 }':
        Emptied(),
    '1 + 2':
        Simplified(gains=('3',), lacks=('+',)),
    'while ($a) { break }':
        Emptied(),
    'while ($a) { continue }':
        Emptied(),
    'do { 1 } while ($a)':
        Simplified(keeps=('1',), lacks=('do', 'while')),
    'if ($a) { 1 } elseif ($b) { 2 } else { 3 }':
        Simplified(keeps=('3',), lacks=('if',)),
    '(1)':
        Simplified(keeps=('1',), lacks=('(',)),
    'trap [E] { 1 }':
        Emptied(),
    '-not $x':
        Simplified(gains=('$True',), lacks=('-not',)),
    'while ($a) { 1 }':
        Emptied(),
    "('a')":
        Simplified(keeps=("'a'",), lacks=('(',)),
    "'a' + 'b'":
        Simplified(gains=("'ab'",), lacks=('+',)),
    "'{0}-{1}' -f 'a', 'b'":
        Simplified(gains=("'a-b'",), lacks=('-f',)),
    "$x = 'hello'; $x":
        Simplified(keeps=("'hello'",), lacks=('$x',)),
    "('a', 'b', 'c') -join ''":
        Simplified(gains=("'abc'",), lacks=('-join',)),
    "[string]::Join('', ('a', 'b'))":
        Simplified(gains=("'ab'",), lacks=('Join',)),
    "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGk='))":
        Simplified(gains=("'hi'",), lacks=('FromBase64String', 'GetString')),
    "if ($true) { 'yes' } else { 'no' }":
        Simplified(keeps=("'yes'",), lacks=("'no'", 'if')),
    '1..3 | ForEach-Object { $_ * 2 }':
        Simplified(gains=('2, 4, 6',), lacks=('ForEach-Object', '$_')),
    '$a = 1; $b = 2; $a + $b':
        Simplified(gains=('3',), lacks=('$a', '$b')),
    "'ABC'.ToLower()":
        Simplified(gains=("'abc'",), lacks=('ToLower',)),
    "$x = @('a', 'b'); $x[1]":
        Simplified(keeps=("'b'",), lacks=('$x', "'a'")),
    "switch ('b') { 'a' { 'first' } 'b' { 'second' } }":
        Simplified(keeps=("'second'",), lacks=('switch', "'first'")),
    "[int]'42' + 1":
        Simplified(gains=('43',), lacks=('[int]',)),
    "'a' * 3":
        Simplified(gains=("'aaa'",), lacks=('*',)),
    '$null -eq $undefined':
        Simplified(gains=('$True',), lacks=('-eq',)),
    "Write-Host 'a'; return; Write-Host 'b'":
        Simplified(keeps=("Write-Host 'a'",), lacks=("Write-Host 'b'",)),
    "try { throw 'x' } catch { 'caught' }":
        Simplified(keeps=("'caught'",), lacks=('try', 'throw')),
    "&('Write' + '-Output') 'indirect'":
        Simplified(keeps=("'indirect'",), gains=("Write-Output 'indirect'",), lacks=('&',)),
    "$s = 'abc'; $s.Substring(1, 2)":
        Simplified(gains=("'bc'",), lacks=('Substring', '$s')),
    "'a{0}c' -f 'b'":
        Simplified(gains=("'abc'",), lacks=('-f',)),
    "function echo { 'from-function' }; echo 'from-alias'":
        Simplified(
            keeps=("'from-alias'",),
            gains=("Write-Output 'from-alias'",),
            lacks=("'from-function'",),
        ),
    "try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }":
        Simplified(keeps=("Write-Host 'quiet'",), lacks=('$undefzz',)),
    "Set-Alias zzq Write-Output; zzq 'resolved'":
        Simplified(
            keeps=("'resolved'",),
            gains=("Write-Output 'resolved'",),
            lacks=('Set-Alias', 'zzq'),
        ),
    "Set-Alias zzq iex; zzq 'Write-Output loaded'":
        Simplified(
            keeps=('Write-Output loaded',),
            lacks=('Set-Alias', 'zzq', 'iex', 'Invoke-Expression'),
        ),
    "Set-Alias -Na zzq -Val Write-Output; zzq 'abbreviated'":
        Simplified(
            keeps=("'abbreviated'",),
            gains=("Write-Output 'abbreviated'",),
            lacks=('Set-Alias', 'zzq'),
        ),
    "Set-Alias zzq Write-Output; $n = 'zzq'; & $n 'dispatched'":
        Simplified(
            keeps=("'dispatched'",),
            gains=("Write-Output 'dispatched'",),
            lacks=('Set-Alias', '$n'),
        ),
    "Set-Alias zzq Write-Output; zzq 'exported'; Export-ModuleMember -Alias zzq":
        Simplified(
            keeps=('Set-Alias', 'Export-ModuleMember', "'exported'"),
            gains=("Write-Output 'exported'",),
        ),
    "Set-Alias -Value Write-Output -Name zzq; zzq 'named-out-of-order'":
        Simplified(
            keeps=("'named-out-of-order'",),
            gains=("Write-Output 'named-out-of-order'",),
            lacks=('Set-Alias', 'zzq'),
        ),
    "$n = 'zq2'; Set-Alias zq2 Write-Host; Set-Alias $n Write-Output; zq2 'y'":
        Simplified(keeps=("'y'",), gains=("Write-Output 'y'",), lacks=('Set-Alias', 'zq2')),
    '$x = 1, 2, 3; Write-Output $x[0]; [Array]::Reverse($x); Write-Output $x[0]':
        Simplified(gains=('Write-Output 1', 'Write-Output 3'), lacks=('$x[0]',)),
    '$x = 1, 2, 3; Write-Output $x[0]; $x[0] = 9; Write-Output $x[0]':
        Simplified(gains=('Write-Output 1', 'Write-Output 9'), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]':
        Simplified(gains=('Write-Output 1', 'Write-Output 3'), lacks=('$y[0]',)),
    "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x":
        Simplified(gains=('Write-Output (9, 8, 7)',), lacks=('iex', '$c', 'Invoke-Expression')),
    '$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x':
        Simplified(gains=('Write-Output (3, 2, 1)',), lacks=('$r',)),
    '$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x':
        Simplified(gains=('Write-Output (2, 1, 3)',), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x':
        Simplified(gains=('Write-Output (3, 2, 1)',), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; [Array]::Reverse($script:x); Write-Output $x':
        Simplified(gains=('Write-Output (3, 2, 1)',), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; $y = $x; $x = 9, 9, 9; Write-Output $y':
        Simplified(keeps=('1, 2, 3',), gains=('Write-Output (1, 2, 3)',), lacks=('9, 9, 9', '$y')),
    "[string]$q = 'abc'; Write-Output $q.Substring(1, 1)":
        Simplified(gains=("Write-Output 'b'",), lacks=('Substring', '$q')),
    '[int]$q = 5; Write-Output $q.ToString()':
        Simplified(gains=("Write-Output '5'",), lacks=('ToString', '$q')),
    "$q, $r = 'abc', 'd'; Write-Output $q.SUBSTRING(1, 1); Write-Output $r":
        Simplified(gains=("Write-Output 'b'", "Write-Output 'd'"), lacks=('Substring',)),
    "[string]$q = 5; $q += 'a'; Write-Output (,$q)":
        Simplified(keeps=('Write-Output',), gains=("'5a'",), lacks=('$q',)),
    '$q = [string]5; $q = 1, 2, 3; Write-Output (,$q)':
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('[string]5', '$q')),
    "$q = 'abc'; [int]$q = 5; Write-Output $q.GetType().FullName":
        Simplified(gains=('System.Int32',), lacks=('GetType',)),
    "$env:z = 'v'; Write-Output $env:z":
        Simplified(gains=("Write-Output 'v'",)),
    '$x = 1, 2, 3; $y = $x; $y = 9, 9, 9; [Array]::Reverse($x); Write-Output $y':
        Simplified(gains=('Write-Output (9, 9, 9)',), lacks=('$y',)),
    "$s = 'abcd'; $t = $s; $t = 1, 2, 3; [Array]::Reverse($t); Write-Output $s.Length":
        Simplified(gains=('Write-Output 4',), lacks=('$s',)),
    '$x = 1, 2, 3; $y = $x -as [array]; $y[0] = 9; Write-Output $x':
        Simplified(gains=('Write-Output (9, 2, 3)',), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x':
        Simplified(gains=('Write-Output (3, 2, 1)',), lacks=('Write-Output $x',)),
    "$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); Write-Output $x[0]":
        Simplified(gains=('Write-Output 3',), lacks=('$m', '$x[0]')),
    "[string]$q = 5; [System.String]$q = 'ab'; Write-Output $q":
        Simplified(keeps=("'ab'",), gains=("Write-Output 'ab'",), lacks=('$q',)),
    '$x = 1, 2, 3; $y = $x; & { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y':
        Simplified(gains=('Write-Output (3, 2, 1)',), lacks=('Write-Output $y',)),
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; Write-Output $h['k']":
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('$x',)),
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; Write-Output $o.P':
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('$x',)),
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; Write-Output $a[0]':
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('$x',)),
    '$x = 1, 2, 3; $h = @{ k = $x }; Write-Output $h.k':
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('$x',)),
    '$x = 1, 2, 3; $a, $b = $x, 9; Write-Output $a':
        Simplified(keeps=('1, 2, 3', 'Write-Output'), lacks=('$x',)),
    "$private:x = 'a'; Write-Output $x":
        Simplified(gains=("Write-Output 'a'",), lacks=('$private:x',)),
    "function K { $Null = [Int]'abc' }; K; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('function K', "[Int]'abc'")),
    "$Null = [Int]'abc'; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=("[Int]'abc'",)),
    "$Null = 1 / 0; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('1 / 0',)),
    "$Null = [Int]'42'; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=("[Int]'42'",)),
    "function K { param([int] $x = '42') }; K; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('function K',)),
    "function Get-Language { $Null = 668 }; language; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('language',)),
    "function q { $Null = 1 }; ${function:q} = { Write-Host 'P' }; q":
        Simplified(keeps=("Write-Host 'P'",), lacks=('$Null = 1',)),
    "$Null = 'abc'.Length; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('Length',)),
    "function f { try { 'tail' } catch {} }; Write-Host (f)":
        Simplified(keeps=("'tail'",), gains=("Write-Host 'tail'",), lacks=('function f',)),
    "try { zzq0000=5 } catch {}; 'next'":
        Simplified(keeps=("'next'",), lacks=('zzq0000',)),
    "function zzqfoo1 { 'boom' }; zzqfoo1":
        Simplified(keeps=("'boom'",), lacks=('function', 'zzqfoo1')),
    "try { zzqq0 =5 } catch {}; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('zzqq0',)),
    "try { item =5 } catch {}; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('=5', 'try')),
    "trap { continue }; zzq0000=5; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('zzq0000', 'trap')),
    "Write-Output $($r = ''; foreach ($e in 'a', 'b') { $r = $r + $e }; $r)":
        Simplified(gains=("Write-Output 'ab'",), lacks=('foreach',)),
    "Write-Output $(foreach ($e in 'a', 'b') { $e })":
        Simplified(keeps=("'a', 'b'", 'Write-Output'), lacks=('foreach',)),
    "$q = 'a'; Write-Output $($q + 'b')":
        Simplified(gains=("Write-Output 'ab'",), lacks=('$q',)),
    "Write-Output $($w = 'x'; $w); Write-Output $w":
        Simplified(gains=("Write-Output 'x'", "Write-Output 'x'"), lacks=('$w',)),
    "Set-Variable s 'A'; Write-Output $($s + 'B')":
        Simplified(gains=("Write-Output 'AB'",), lacks=('Set-Variable', '$s')),
    'iex \'$u = "U"\'; Write-Output $($u + \'x\')':
        Simplified(gains=("Write-Output 'Ux'",), lacks=('iex', '$u')),
    'Set-Variable q 5; function fq { $q + 1 }; Write-Output (fq)':
        Simplified(gains=('Write-Output 6',), lacks=('function fq',)),
    '$x = $($r = [char]66; $r); Write-Output ($x -is [char])':
        Simplified(keeps=('Write-Output',), gains=('$True',), lacks=('-is',)),
    '$x = $($r = [byte]77; $r); Write-Output ($x -is [byte])':
        Simplified(keeps=('Write-Output',), gains=('$True',), lacks=('-is',)),
    "$x = $($w = 'a'; 'v'); Write-Output $w":
        Simplified(gains=("Write-Output 'a'",), lacks=('$w',)),
    "$c = 'Write-Output $w'; $x = $($w = 'a'; 'v'); iex $c":
        Simplified(gains=("Write-Output 'a'",), lacks=('iex', '$c')),
    'Write-Output (Get-Date -Y 2020 -Month 1 -Day 1).Year':
        Simplified(
            keeps=('Write-Output', '-Month 1 -Day 1'),
            gains=('-Year 2020',),
            lacks=('-Y 2020',),
        ),
    '$x = 1, 2, 3; $b, $c = $x; [Array]::Reverse($x); Write-Output $b':
        Simplified(gains=('Write-Output 1',), lacks=('Write-Output $b',)),
    "$b = 'a'; $v = Get-Variable b -ValueOnly; $v = 'x'; Write-Output $b":
        Simplified(gains=("Write-Output 'a'",), lacks=('Get-Variable', '$v')),
    "$b = 'a'; Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('b'); $b = 'c'; "
    'Write-Output $b':
        Simplified(keeps=("GetValue('b')",), gains=("Write-Output 'c'",)),
    '$b = 0; foreach ($i in 1) { $b = 1 }; while ($b -ne 2) { switch ($b) { 0 { Write-Host '
    "'zero'; $b = 2 } 1 { Write-Host 'one'; $b = 2 } } }":
        Simplified(keeps=("Write-Host 'one'",), lacks=('switch', "'zero'")),
    "$s = 0; while ($s -ne -1) { switch ($s) { 0 { Write-Host 'a'; $s = -1 } default { break } } "
    '}; Write-Host $s':
        Simplified(keeps=("Write-Host 'a'",), gains=('Write-Host (-1)',), lacks=('switch',)),
    '$t = [array]::Reverse((1, 2, 3, 4)); Write-Output ($null -eq $t)':
        Simplified(keeps=('Write-Output',), gains=('$True',), lacks=('Reverse',)),
    'function dec($d, $k) { $o = @(0) * $d.Length; for ($i = 0; $i -lt $d.Length; $i++) { $o[$i] '
    '= $d[$i] -bxor $k[$i % $k.Length] }; $o }; $key = 1, 2, 3; Write-Output (dec (4, 5, 6) $key)':
        Simplified(keeps=('Write-Output',), gains=('5, 7, 5',), lacks=('-bxor',)),
    '$bytes = 72, 105; $s = [Text.Encoding]::ASCII.GetString($bytes); Write-Output $s; $buf = 0, '
    '0; $buf[0] = 7':
        Simplified(gains=("Write-Output 'Hi'",), lacks=('GetString',)),
    '$y = 1, 2; $z = $y * 2; $z[0] = 9; Write-Output $y':
        Simplified(gains=('Write-Output (1, 2)',), lacks=('Write-Output $y',)),
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'":
        Simplified(
            keeps=("Write-Host 'e'", "[int]'a'", "'hi'"),
            gains=("Write-Output 'hi'",),
            lacks=("c 'hi'",),
        ),
    "Get-Item nope -ErrorAc Stop; Write-Host 'after'":
        Simplified(keeps=('Get-Item nope',), gains=('-ErrorAction Stop',), lacks=('-ErrorAc ',)),
    "Get-Item nope -errora Stop; Write-Host 'after'":
        Simplified(keeps=('Get-Item nope',), gains=('-ErrorAction Stop',), lacks=('-errora ',)),
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=("$x = 'c'",)),
    "$v = 'a'; & { Write-Host $v }; $v = 'c'":
        Simplified(gains=("Write-Host 'a'",), lacks=('$v',)),
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        Simplified(gains=("Write-Host 'a'",), lacks=('$x', '$script:x')),
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=("$x = 'b'",)),
    "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'":
        Simplified(gains=("Write-Host 'a'",), lacks=('Invoke-Command', '$x')),
    "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'":
        Simplified(gains=("Write-Host 'a'",), lacks=('$x',)),
    "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'":
        Simplified(gains=("Write-Host 'a'",), lacks=('InvokeScript', '$x')),
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=('iex', 'Invoke-Expression')),
    "$script:y = 'b'; Write-Output $script:y":
        Simplified(gains=("Write-Output 'b'",), lacks=('$script:y',)),
    "$global:y = 'b'; Write-Output $global:y":
        Simplified(gains=("Write-Output 'b'",)),
    "$s = 'x'; Write-Output $script:s":
        Simplified(gains=("Write-Output 'x'",), lacks=('$script:s',)),
    "$script:s = 'x'; Write-Output $s":
        Simplified(gains=("Write-Output 'x'",), lacks=('$s',)),
    '$n = 1; $n += 2; Write-Output $n':
        Simplified(gains=('Write-Output 3',), lacks=('+=', '$n')),
    "$s = 'a'; $s += 'b'; $s += 'c'; Write-Output $s":
        Simplified(gains=("Write-Output 'abc'",), lacks=('+=', '$s')),
    '$n = 1; $n++; Write-Output $n':
        Simplified(gains=('Write-Output 2',), lacks=('++', '$n')),
    '$n = 5; $n -= 2; Write-Output $n':
        Simplified(gains=('Write-Output 3',), lacks=('-=', '$n')),
    "$c = 'Write-Out'; $c += 'put 5'; Invoke-Expression $c":
        Simplified(gains=('Write-Output 5',), lacks=('Invoke-Expression', '$c')),
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=('Get-Variable',)),
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v':
        Simplified(gains=('Write-Host 42', 'Write-Host 41'), lacks=('$v',)),
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i":
        Simplified(gains=('Write-Host 42',), lacks=('TryParse',)),
    '% { Write-Host 1 }':
        Simplified(keeps=('Write-Host 1',), lacks=('%',)),
    '$x = \'a\'; &(\'i\' + \'ex\') \'$x = "b"\'; Write-Host $x':
        Simplified(keeps=('Write-Host',), gains=('Write-Host "b"',), lacks=('$x', 'iex')),
    '$v = \'a\'; & ([ScriptBlock]::Create(\'$v + "b"\')); Write-Output (1 + 1)':
        Simplified(gains=('Write-Output 2',), lacks=('Create', '$v')),
    '$v = \'a\'; & ([ScriptBlock]::Create(\'$v = "b"\')); Write-Output $v; Write-Output (1 + 1)':
        Simplified(gains=("Write-Output 'a'", 'Write-Output 2'), lacks=('Create',)),
    '$v = \'a\'; . ([ScriptBlock]::Create(\'$v = "b"\')); Write-Output $v; Write-Output (1 + 1)':
        Simplified(gains=('Write-Output "b"', 'Write-Output 2'), lacks=('Create',)),
    "trap { continue }; Write-Host (Get-Item nope -ErrorAction Stop); Write-Host 'after'; "
    'Write-Output (1 + 1)':
        Simplified(keeps=("Write-Host 'after'",), gains=('Write-Output 2',), lacks=('1 + 1',)),
    "trap { continue }; Write-Host (Get-Item nope -ErrorAction Continue); Write-Host 'after'; "
    'Write-Output (1 + 1)':
        Simplified(
            keeps=("Write-Host 'after'",),
            gains=('Write-Output 2',),
            lacks=('1 + 1', 'trap'),
        ),
    "Write-Host (Get-Item nope -ErrorAction Continue); Write-Host 'after'; Write-Output (1 + 1)":
        Simplified(keeps=("Write-Host 'after'",), gains=('Write-Output 2',), lacks=('1 + 1',)),
    'Get-Item nope -ErrorAction SilentlyContinue | Write-Host; Write-Host $?; Write-Output (1 + 1)':
        Simplified(keeps=('Write-Host $?',), gains=('Write-Output 2',), lacks=('1 + 1',)),
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')":
        Simplified(gains=("Write-Output 'a-b'",), lacks=('-join', '$t')),
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('$False', '$True'),
            lacks=('-is',),
        ),
    "Write-Output ('x' -replace 'x', [char]65); Write-Output ('x' -replace 'x', 'A')":
        Simplified(gains=("Write-Output 'A'", "Write-Output 'A'"), lacks=('-replace',)),
    "Write-Output ([char]65 + 1); Write-Output ('A' + 1)":
        Simplified(gains=("Write-Output 'A1'", "Write-Output 'A1'"), lacks=('+',)),
    "Write-Output ('A' * 3)":
        Simplified(gains=("Write-Output 'AAA'",), lacks=('*',)),
    "Write-Output (([char]65).ToString()); Write-Output (('A').ToString())":
        Simplified(gains=("Write-Output 'A'", "Write-Output 'A'"), lacks=('ToString',)),
    "Write-Output ('xyx'.Replace([char]120, [char]122)); Write-Output ('xyx'.Replace('x', 'z'))":
        Simplified(gains=("Write-Output 'zyz'", "Write-Output 'zyz'"), lacks=('Replace',)),
    "Write-Output ('{0}' -f [char]65); Write-Output ('{0}' -f 'A')":
        Simplified(gains=("Write-Output 'A'", "Write-Output 'A'"), lacks=('-f',)),
    "Write-Output (([char]65, [char]66) -join ''); Write-Output (('A', 'B') -join '')":
        Simplified(gains=("Write-Output 'AB'", "Write-Output 'AB'"), lacks=('-join',)),
    "Write-Output ([string][char]65); Write-Output ([string]'A')":
        Simplified(gains=("Write-Output 'A'", "Write-Output 'A'"), lacks=('[string]',)),
    '$c = [char]65; $s = \'A\'; Write-Output "$c"; Write-Output "$s"':
        Simplified(gains=("Write-Output 'A'", "Write-Output 'A'"), lacks=('$c', '$s')),
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('$True', '$False'),
            lacks=('-is',),
        ),
    "Write-Output (([char]65).Length); Write-Output (('A').Length)":
        Simplified(gains=('Write-Output 1', 'Write-Output 1'), lacks=('Length',)),
    "Write-Output (([char]65).Count); Write-Output (('A').Count)":
        Simplified(gains=('Write-Output 1', 'Write-Output 1'), lacks=('Count',)),
    "Write-Output ([char]65 -eq 'A'); Write-Output ('A' -eq 'A')":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('$True', '$True'),
            lacks=('-eq',),
        ),
    '$t = @(); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 0',),
            lacks=('$t',),
        ),
    '$t = , 1; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 1',),
            lacks=('$t',),
        ),
    '$s = 0xFF; $t = "$s"; Write-Output (,$t); Write-Output $t':
        Simplified(keeps=('Write-Output (,',), gains=("Write-Output '255'",), lacks=('$s', '$t')),
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        Simplified(gains=("Write-Output 'a-b'",), lacks=('[string]', '$t')),
    '$OFS = \'-\'; Write-Output "$(1, 2)"':
        Simplified(gains=("Write-Output '1-2'",), lacks=('$(',)),
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=("Write-Output 'b'",),
            lacks=('$t',),
        ),
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('-split',),
        ),
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=('Write-Output', 'Write-Output'), gains=("'b,c'",), lacks=('-split',)),
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 0',),
            lacks=('$i',),
        ),
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 0',),
            lacks=('$i',),
        ),
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=("'no'", 'Write-Output', 'Write-Output'), lacks=("'yes'",)),
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=("'yes'", 'Write-Output', 'Write-Output'), lacks=("'no'",)),
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 16',),
            lacks=('-shl',),
        ),
    '$t = @(1, 2) + @(3, 4); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 4',),
            lacks=('$t',),
        ),
    '$t = @(1, 2) + 5; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 3',),
            lacks=('$t',),
        ),
    '$t = @(1, 2) * 2; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 4',),
            lacks=('$t',),
        ),
    '$t = @() + 1; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 1',),
            lacks=('$t',),
        ),
    '$t = @(1, 2) + $null; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 3',),
            lacks=('$t',),
        ),
    '$t = $null + @(1, 2); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('$t',),
        ),
    "$t = @(1, 2) + 'a'; Write-Output (,$t); Write-Output $t.Count":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 3',),
            lacks=('$t',),
        ),
    '$t = @(1, 2) * 0; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 0',),
            lacks=('$t',),
        ),
    '$t = @() * 5000; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 0',),
            lacks=('$t',),
        ),
    "$z = 1.0d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=('Write-Output (,',), gains=("Write-Output 'x1.0'",), lacks=('$z', '$t')),
    "$z = 1.10d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=('Write-Output (,',), gains=("Write-Output 'x1.10'",), lacks=('$z', '$t')),
    "$z = 1.00d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        Simplified(keeps=('Write-Output (,',), gains=("Write-Output 'x1.00'",), lacks=('$z', '$t')),
    "$z = 1.000d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        Simplified(
            keeps=('Write-Output (,',),
            gains=("Write-Output 'x1.000'",),
            lacks=('$z', '$t'),
        ),
    "$z = 1.100d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        Simplified(
            keeps=('Write-Output (,',),
            gains=("Write-Output 'x1.100'",),
            lacks=('$z', '$t'),
        ),
    "Write-Output ([Text.Encoding].GetProperty('UTF8').GetValue($Null))":
        Simplified(
            keeps=('Write-Output',),
            gains=('[Text.Encoding]::UTF8',),
            lacks=('GetProperty',),
        ),
    "Write-Output ([Text.Encoding].GetProperty('UTF8').GetValue($Null, $Null))":
        Simplified(
            keeps=('Write-Output',),
            gains=('[Text.Encoding]::UTF8',),
            lacks=('GetProperty',),
        ),
    "Write-Output ([object]::ReferenceEquals([Text.Encoding].GetProperty('UTF8').GetValue($Null), "
    '[Text.Encoding]::UTF8))':
        Simplified(keeps=('Write-Output',), lacks=('GetProperty',)),
    "$sb = New-Object Text.StringBuilder -ArgumentList 'aGk='; $x = $sb.ToString(); $t = "
    "[Convert].GetMethod('FromBase64String', [type[]]@([string])).Invoke($Null, @($x)); "
    'Write-Output (,$t); Write-Output $t':
        Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('GetMethod',)),
    'for ($i = 0; $i -lt 2; $i++) { 1 }':
        Simplified(keeps=('1',), lacks=('for',)),
    '1..2':
        Simplified(gains=('1, 2',), lacks=('..',)),
    'echo a < b':
        Simplified(keeps=('a < b',), gains=('Write-Output',), lacks=('echo',)),
    '$x = 3..5':
        Simplified(keeps=('$x = ',), gains=('3, 4, 5',), lacks=('..',)),
    '$x = 1e3.5':
        Simplified(keeps=('$x = ',), gains=('$Null',), lacks=('1e3',)),
    '$x = (1).5':
        Simplified(keeps=('$x = ',), gains=('$Null',), lacks=('(1)',)),
    "Set-Alias zzq Write-Output; $n = 'zzq'; (Get-Alias $n).Definition":
        Simplified(keeps=('Write-Output',), lacks=('$n',)),
    'Set-Alias zzq Write-Output; (alias zzq).Definition':
        Simplified(keeps=('Write-Output',), lacks=('(alias ',)),
    "Set-Alias -N zzq -V Write-Output; zzq 'one-letter'":
        Simplified(
            keeps=("'one-letter'",),
            gains=("Write-Output 'one-letter'",),
            lacks=('Set-Alias', 'zzq'),
        ),
    "function alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        Simplified(keeps=("'from-function'",), lacks=('function alias', 'Set-Alias', 'alias zzq')),
    "function Get-Alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        Simplified(
            keeps=("'from-function'",),
            lacks=('function Get-Alias', 'Set-Alias', 'alias zzq'),
        ),
    "$env:zzq = '7'; (item env:zzq).Value":
        Simplified(keeps=("'7'",), lacks=('(item ',)),
    "Set-Alias zzq Write-Host; $c = 'Set-Alias'; & $c zzq Write-Output; zzq 'x'":
        Simplified(keeps=("'x'",), gains=("Write-Output 'x'",), lacks=('Set-Alias', 'zzq', '$c')),
    "Set-Alias zzq Write-Output; Invoke-Expression 'Set-Alias zzq Write-Host'; zzq 'x'":
        Simplified(
            keeps=("'x'",),
            gains=("Write-Host 'x'",),
            lacks=('Set-Alias', 'zzq', 'Invoke-Expression'),
        ),
    "$h = @{ k = 'Set-Alias zzq Write-Host' }; Set-Alias zzq Write-Output; iex $h.k; zzq 'x'":
        Simplified(
            keeps=("'x'",),
            gains=("Write-Host 'x'",),
            lacks=('Set-Alias', 'iex', 'Invoke-Expression', '$h'),
        ),
    '$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x':
        Simplified(keeps=('Write-Output',), gains=('($Null, 2, 3)',)),
    '$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (1, 2, 3)',), lacks=('Copy',)),
    '$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (1, 2, 3)',), lacks=('CopyTo',)),
    '$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output 1', 'Write-Output 3'),
            lacks=('for',),
        ),
    "function Get-Zqfrob { Write-Output 'hit' }; Zqfrob":
        Simplified(keeps=("Write-Output 'hit'",), lacks=('function ', 'zqfrob')),
    "function Get-Zqfrob { Write-Output 'p' }; function Zqfrob { Write-Output 'b' }; Zqfrob":
        Simplified(keeps=("Write-Output 'b'",), lacks=('function ', 'zqfrob', "'p'")),
    "function Get-Get-Zqfrob { Write-Output 'hit' }; Get-Zqfrob":
        Simplified(keeps=('Get-Zqfrob',), lacks=('function ',)),
    "function Get-Zq-Frob { Write-Output 'hit' }; Zq-Frob":
        Simplified(keeps=('Zq-Frob',), lacks=('function ',)),
    "$env:zzq = '7'; function Get-Item { Write-Output 'from-function' }; item env:zzq":
        Simplified(
            keeps=("$env:zzq = '7'", "Write-Output 'from-function'"),
            lacks=('function ', 'item env'),
        ),
    "$x = 'a'; function f { Write-Host (variable x -ValueOnly) }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=('variable x', "'c'")),
    "$x = 'a'; function f { Write-Host (item variable:x).Value }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=('variable:x', "'c'")),
    "$x = 'a'; function f { Write-Host (Get-Item variable:x).Value }; f; $x = 'c'":
        Simplified(keeps=("'a'",), gains=("Write-Host 'a'",), lacks=('variable:x', "'c'")),
    '$x = 1, 2, 3; $y = if ($True) { $x }; $x[0] = 9; Write-Output $y[0]':
        Simplified(keeps=('Write-Output',), gains=('Write-Output 1',), lacks=('$y',)),
    '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output (1, 2, 3)',),
            lacks=('$x |', 'Set-Variable', '$y'),
        ),
    '& { Write-Output $local:ShellId }':
        Simplified(keeps=('Write-Output',), gains=("'Microsoft.PowerShell'",), lacks=('ShellId',)),
    'Write-Output $script:ShellId':
        Simplified(keeps=('Write-Output',), gains=("'Microsoft.PowerShell'",), lacks=('ShellId',)),
    "class C { $P = [int]::TryParse('42', [ref]$script:x) }; $x = 0; $o = [C]::new(); "
    'Write-Output $x':
        Simplified(keeps=('Write-Output',), lacks=('$o',)),
    'class C { $P = ($script:x = 5) }; $x = 0; $o = [C]::new(); Write-Output $x':
        Simplified(keeps=('Write-Output',), lacks=('$o',)),
    '$b = 0, 0; $p = [Runtime.InteropServices.Marshal]::AllocHGlobal(2); '
    '[Runtime.InteropServices.Marshal]::WriteByte($p, 0, 7); '
    '[Runtime.InteropServices.Marshal]::Copy($p, $b, 0, 2); '
    '[Runtime.InteropServices.Marshal]::FreeHGlobal($p); Write-Output $b[0]':
        Simplified(
            keeps=('AllocHGlobal', 'WriteByte', '::Copy(', 'FreeHGlobal'),
            gains=('Write-Output 0',),
            lacks=('$b',),
        ),
    "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    '$x = 1, 2, 3; $a = $null; $a = $a + $x; $a[0] = 9; Write-Output $x[0]':
        Simplified(keeps=('Write-Output',), gains=('Write-Output 9',), lacks=('$a',)),
    "$x = 'a'; if ($true) { trap { Write-Output $local:x; continue }; throw 'e' }":
        Simplified(keeps=("throw 'e'",), lacks=("$x = 'a'",)),
    '$x = Get-Random -Maximum 1; Write-Output $script:x; $x = 5; Write-Output $x':
        Simplified(
            keeps=('Get-Random -Maximum 1', 'Write-Output $script:x'),
            gains=('Write-Output 5',),
            lacks=('$x = 5',),
        ),
    "function K { $Null = 1 }; Write-Error 'e'; K; Write-Host $?":
        Simplified(keeps=("Write-Error 'e'", 'Write-Host $?'), lacks=('$Null = 1',)),
    'function K { $Null = 1 }; K; Write-Host ($function:K -ne $Null)':
        Simplified(keeps=('function K', 'Write-Host'), lacks=('$Null = 1',)),
    "$Null = (Get-Command K).Name; function K { $Null = 1 }; K; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('function K',)),
    "function vnMTH { $Null = 1 }; vnMTH; $Null = (Get-Command *vnMT*).Name; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('function ',)),
    'function Measure-Object { $Null = 1 }; Measure-Object; 1, 2, 3 | measure':
        Simplified(keeps=('Measure-Object',), lacks=('$Null = 1',)),
    "$n = 'q'; function K { $Null = 1 }; Set-Alias $n K; q; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('function', 'Set-Alias', '$n')),
    "function K { [Alias('q')] param() $Null = 1 }; q; Write-Host 'A'":
        Simplified(keeps=("Write-Host 'A'",), lacks=('$Null = 1',)),
    "Write-Host 'abc'.Length":
        Simplified(gains=('Write-Host 3',), lacks=('Length',)),
    "foreach ($i in 1..2) { Write-Output $($c = $c + 'x'; $c) }":
        Simplified(
            keeps=('Write-Output',),
            gains=("Write-Output 'x'", "Write-Output 'xx'"),
            lacks=('foreach',),
        ),
    'foreach ($i in 1..2) { Write-Output $(if (0) { $m = \'A\' }; $o = "${m}"; $m = \'B\'; $o) }':
        Simplified(
            keeps=('Write-Output',),
            gains=("Write-Output ''", "Write-Output 'B'"),
            lacks=('foreach', 'if (0)'),
        ),
    "Set-Alias q1 -V Write-Output; q1 'x'":
        Simplified(keeps=("'x'",), gains=("Write-Output 'x'",), lacks=('Set-Alias', 'q1')),
    "Set-Alias q2 -v Write-Output; q2 'y'":
        Simplified(keeps=("'y'",), gains=("Write-Output 'y'",), lacks=('Set-Alias', 'q2')),
    '$o = [pscustomobject]@{}; Add-Member -Type NoteProperty k v -InputObject $o; $o.k':
        Simplified(gains=("'v'",), lacks=('Add-Member',)),
    "Get-Date -c; Write-Output 'ran'":
        Simplified(keeps=("Write-Output 'ran'",), lacks=('Get-Date',)),
    "$b = 'a'; $v = Get-Variable; ($v | Where-Object Name -eq 'b').Value = 'b'; Write-Output $b":
        Simplified(keeps=('Write-Output',), gains=("Write-Output 'b'",), lacks=('Get-Variable',)),
    "$b = 'a'; (Get-Variable b).Value = 'b'; Write-Output $b":
        Simplified(keeps=('Write-Output',), gains=("Write-Output 'b'",), lacks=('Get-Variable',)),
    "$x = 'a'; Write-Host $x; $c = @('Write-Host $x')[(Get-Random -Maximum 1)]; iex $c":
        Simplified(
            keeps=("$x = 'a'", "'Write-Host $x'"),
            gains=("Write-Host 'a'",),
            lacks=('iex ',),
        ),
    "$x = $($y = 'a'; 'v'); Write-Output $x; Write-Output ((Get-Variable | Where-Object Name -eq "
    "'y').Value)":
        Simplified(keeps=("'a'", "'v'", 'Write-Output', 'Write-Output'), lacks=('$(',)),
    "$x = 1, 2, 3; $c = @('$x[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; function f { "
    'iex $c }; f; Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $y = $x; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; "
    'f; Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; function f { iex "
    '$c }; f; Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    '$o = New-Object PSObject; $x = 1, 2, 3; $o | Add-Member -NotePropertyName k '
    "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output "
    '$x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    '$o = New-Object PSObject; $x = 1, 2, 3; Add-Member -InputObject $o -NotePropertyName k '
    "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output "
    '$x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $o = New-Object PSObject -Property @{ k = $x }; $c = @('$o.k[0] = "
    "9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; ,$l | ForEach-Object -MemberName Add '
    "-ArgumentList (,$x) | Out-Null; $c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); $c = @('$l[0][0] = "
    "9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $w = [Collections.ArrayList]::Adapter($x); $c = @('$w[0] = 9')[(Get-Random "
    '-Maximum 1)]; iex $c; Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; [AppDomain]::CurrentDomain.SetData('k', $x); $c = "
    "@('[AppDomain]::CurrentDomain.GetData(''k'')[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    "$x = 1, 2, 3; $y = Sort-Object -InputObject $x; $c = @('$y[0] = 9')[(Get-Random -Maximum "
    '1)]; iex $c; Write-Output $x':
        Simplified(keeps=('Write-Output $x',), lacks=('iex ',)),
    '$all = @(); 1..2 | ForEach-Object { if ($h) { $h.k[0] = 9 }; $x = 1, 2, 3; $h = @{ k = $x }; '
    '$all += ,$x }; Write-Output $all[0]':
        Simplified(keeps=('Write-Output',), lacks=('..',)),
    '$x = 1, 2, 3; $w = ($z = $y = $x)[0]; $z[0] = 9; Write-Output $x':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (9, 2, 3)',), lacks=('$w',)),
    "$x = 'a'; $v = Get-Variable x -ValueOnly:$false; $v.Value = 'b'; Write-Output $x":
        Simplified(keeps=('Write-Output',), gains=("Write-Output 'b'",), lacks=('Get-Variable',)),
    "$x = 'a'; $v = Get-ChildItem variable:\\; ($v | Where-Object Name -eq 'x').Value = 'b'; "
    'Write-Output $x':
        Simplified(keeps=('Write-Output',), gains=("Write-Output 'b'",), lacks=('Get-ChildItem',)),
    "trap { continue }; trap { Write-Host 'p' }; $u = [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=("[int]'a'", '$u')),
    "try { trap { continue }; [int]'a'; Write-Host 'tail' } catch { }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'tail'", "Write-Host 'after'"), lacks=("[int]'a'", 'trap')),
    "try { [int]'a'; Write-Host 'tail' } catch { }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('try', "'tail'")),
    "trap { continue }; if ($true) { trap { break }; if ($true) { trap { continue }; [int]'a'; "
    "Write-Host 'tail' }; Write-Host 'mid' }; Write-Host 'after'":
        Simplified(
            keeps=("Write-Host 'tail'", "Write-Host 'mid'", "Write-Host 'after'"),
            lacks=('trap', "[int]'a'"),
        ),
    "trap { continue }; if ($true) { trap { break }; if ($true) { [int]'a'; Write-Host 'tail' }; "
    "Write-Host 'mid' }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('break',)),
    "trap { continue }; if ($true) { trap { continue }; [int]'a'; Write-Host 'tail' }; Write-Host "
    "'after'":
        Simplified(keeps=("Write-Host 'tail'", "Write-Host 'after'"), lacks=('trap', "[int]'a'")),
    'trap { continue }; foreach ($q in 1, 2) { trap { continue }; [int]\'a\'; Write-Host "tail '
    '$q" }; Write-Host \'after\'':
        Simplified(keeps=("Write-Host 'after'", 'Write-Host "tail '), lacks=('trap', "[int]'a'")),
    "$ErrorActionPreference = 'Stop'; trap { }; trap { continue }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("[int]'a'",), lacks=('continue',)),
    "$ErrorActionPreference = 'Stop'; trap { continue }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=("[int]'a'",)),
    "trap { continue }; trap { Write-Host 'p' }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=("[int]'a'",)),
    "trap { break }; trap { continue }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("[int]'a'", 'break'), lacks=('continue',)),
    "trap { continue }; trap { break }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', "[int]'a'")),
    'trap { continue }; trap [System.Management.Automation.RuntimeException] { break }; $z = 0; '
    "1/$z; Write-Host 'after'":
        Simplified(keeps=('1 / ', 'break'), lacks=('$z', 'continue')),
    "trap { continue }; $s = [string][char]256 + 'b'; $k = [char[]]$s | ForEach-Object { "
    '[byte][char]$_ }; Write-Host "count=$($k.Count) key=$($k -join \',\')"':
        Simplified(keeps=('Write-Host "count=',), lacks=('$s',)),
    "$s = [string][char]256 + 'b'; $k = [char[]]$s | ForEach-Object { [byte][char]$_ }; "
    'Write-Host "count=$($k.Count) key=$($k -join \',\')"':
        Simplified(keeps=('Write-Host "count=',), lacks=('$s',)),
    'trap { continue }; if ((Get-Date).Year -gt 2000) { trap [System.IO.IOException] { continue '
    "}; $v = [int]'a' }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', "[int]'a'")),
    "trap { continue }; if ((Get-Date).Year -gt 2000) { foreach ($q in 1, 2) { [int]'a'; "
    'Write-Host "t $q" }; trap { break } }; Write-Host \'after\'':
        Simplified(keeps=("[int]'a'", "Write-Host 'after'"), lacks=('break',)),
    "trap { continue }; try { $v = [int]'a'; trap { break } } finally { }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', 'try', "[int]'a'")),
    "trap { continue }; try { trap [System.IO.IOException] { continue }; $v = [int]'a' } finally "
    "{ }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', 'try', "[int]'a'")),
    "try { trap { continue }; [int]'a'; try { throw 'x' } catch { Write-Host 'caught' } } catch { "
    "}; Write-Host 'after'":
        Simplified(
            keeps=("Write-Host 'caught'", "Write-Host 'after'"),
            lacks=('trap', "[int]'a'", 'throw'),
        ),
    "& { foreach ($i in 1..2) { try { throw 'x' } catch { Write-Host 'a'; $null = [int]'b'; trap "
    '{ break } }; trap { continue } } }':
        Simplified(keeps=("Write-Host 'a'",), lacks=('trap', 'throw', "[int]'b'")),
    "foreach ($i in 1, 2) { try { trap { continue }; [int]'a'; break } catch { }; Write-Host "
    '"after $i" }':
        Simplified(keeps=('break', 'Write-Host "after '), lacks=('trap', "[int]'a'")),
    'trap { continue }; if ($true) { trap [System.IO.IOException] { continue }; if ($true) { trap '
    "{ continue }; [int]'a' }; Write-Host 'mid' }; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'mid'", "Write-Host 'after'"), lacks=('trap', "[int]'a'")),
    "$ErrorActionPreference = 'Stop'; trap [System.IO.IOException] { continue }; trap [Exception] "
    "{ continue }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('IOException', "[int]'a'")),
    "try { throw 'x' } catch { if ($false) { } elseif ([int]'a') { }; Write-Host 'rest' }; "
    "Write-Host 'after'":
        Simplified(keeps=("[int]'a'", "Write-Host 'after'"), lacks=('$false', 'elseif')),
    "Invoke-Expression '$ErrorActionPreference = 0'; if ($Host) { throw 'vm'; exit }; Write-Host "
    "'payload'":
        Simplified(keeps=("throw 'vm'", "Write-Host 'payload'"), lacks=('Invoke-Expression',)),
    "Set-Variable -Name ('Error' + 'ActionPreference') -Value 0; throw 'boom'; Write-Host 'after'":
        Simplified(
            keeps=("throw 'boom'", "Write-Host 'after'"),
            gains=('$ErrorActionPreference = 0',),
            lacks=('Set-Variable',),
        ),
    "$null = Get-Random -SetSeed 7; try { throw 'x' } catch { (Get-Random).GetHashCode() | "
    "Out-Null; Write-Host 'rest' }; Write-Host (Get-Random -Maximum 1000)":
        Simplified(
            keeps=("Write-Host 'rest'", 'Get-Random -SetSeed 7', '(Get-Random).GetHashCode()'),
            lacks=('try', 'throw'),
        ),
    "$p = @('a'); function f1 { $null = [int]$p[0]; Write-Host 'm1' }; trap { continue }; f1; "
    "Write-Host 'm2'":
        Simplified(keeps=("Write-Host 'm2'",), lacks=('$p = ', '$p[')),
    "$x = 'a'; try { try { throw 'x' } finally { $x = 'b' } } catch { Write-Host $x }":
        Simplified(keeps=("throw 'x'",), gains=("Write-Host 'b'",), lacks=('$x',)),
    'trap { continue }; iex \'throw "e"; Write-Host "tail"\'; Write-Host \'next\'':
        Simplified(keeps=("Write-Host 'next'",), lacks=('iex ',)),
    'trap { continue }; iex \'$null = [int]$Host.Name; Write-Host "tail"\'; Write-Host \'next\'':
        Simplified(keeps=("Write-Host 'next'",), lacks=('iex ',)),
    "'a', 1, $null, @(1, 2), (New-Object Object) | Out-Null; Write-Output 'after'":
        Simplified(keeps=("Write-Output 'after'",), lacks=('Out-Null',)),
    "try { $null = Get-Process; Write-Output 'ok' } catch { Write-Output 'caught' }":
        Simplified(keeps=("Write-Output 'ok'",), lacks=('Get-Process',)),
    '$k = 1, 2, 3; $h = @{ k = $k }; if ((Get-Random -Maximum 1) -eq 0) { $buf = 0, 0 } else { '
    '$buf = 1, 1 }; $buf[0] = 7; Write-Output $k':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (1, 2, 3)',), lacks=('$k', '$h')),
    "$b = 'Write-Host', 'hi'; $z = 0, 0; $z[0] = 1; iex ([string]::Join(' ', $b)); $n = "
    "@('Write-Host $b')[(Get-Random -Maximum 1)]; iex $n":
        Simplified(keeps=("'Write-Host $b'",), gains=('Write-Host hi',), lacks=('Join', 'iex ')),
    "[int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=("[int]'a'",)),
    "trap { continue }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', "[int]'a'")),
    "trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        Simplified(keeps=("throw 'e'", "Write-Host 'next'"), lacks=('tail', 'if (')),
    "trap { continue }; foreach ($i in 1..2) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        Simplified(keeps=("throw 'e'", "Write-Host 'next'"), lacks=("'tail'",)),
    "trap { continue }; switch (1) { 1 { throw 'e'; Write-Host 'tail' } }; Write-Host 'next'":
        Simplified(keeps=("throw 'e'", "Write-Host 'next'"), lacks=('switch', "'tail'")),
    "trap { continue }; 1/0; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', '1/0', '1 / 0')),
    'trap { continue }; $x = "$(1/0)$(Set-Alias zzq Write-Output)"; zzq \'hi\'':
        Simplified(keeps=("zzq 'hi'",), lacks=('$x',)),
    "trap { }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', "[int]'a'")),
    "trap { continue }; Get-Item nope -ErrorAction Stop; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', 'Get-Item')),
    "Get-Item nope -ErrorAction Continue; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('Get-Item',)),
    "Get-Item nope -e Stop; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('Get-Item',)),
    "trap { continue }; iex 'throw 1'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'", 'throw 1'), lacks=('iex',)),
    "trap { continue }; $s = { throw 'x' }; [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('trap', "[int]'a'", '$s')),
    "New-Variable ErrorActionPreference Stop -Force; trap { continue }; [int]'a'; Write-Host "
    "'after'":
        Simplified(keeps=("Write-Host 'after'", 'New-Variable'), lacks=("[int]'a'",)),
    "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; Get-Item nope; "
    "Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=('Get-Item',)),
    "throw 'e'; Write-Host 'after'":
        Simplified(keeps=("throw 'e'",), lacks=("'after'",)),
    "$(trap { continue }); [int]'a'; Write-Host 'after'":
        Simplified(keeps=("Write-Host 'after'",), lacks=("[int]'a'",)),
    "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z":
        Simplified(keeps=("$env:z = '7'",), gains=("Write-Host '7'",), lacks=('$ok',)),
    "Write-Host (Get-Item nope -ErrorAction Stop); Write-Host 'after'; Write-Output (1 + 1)":
        Simplified(keeps=('Get-Item nope -ErrorAction Stop',), lacks=('1 + 1',)),
    "$ErrorActionPreference = 'Stop'; Write-Host (Get-Item nope); Write-Host 'after'; "
    'Write-Output (1 + 1)':
        Simplified(keeps=('Get-Item nope',), lacks=('1 + 1',)),
    "$ErrorActionPreference = 'Stop'; Write-Host ([int]'a'); Write-Host 'after'; Write-Output (1 "
    '+ 1)':
        Simplified(keeps=("[int]'a'",), lacks=('1 + 1',)),
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }":
        Simplified(keeps=("'a'", "'b'", 'Write-Output'), lacks=('ForEach-Object', '$t')),
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), lacks=('ForEach-Object', '$t')),
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('ForEach-Object', '$t'),
        ),
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output (,$t)":
        Simplified(
            keeps=('Write-Output (,',),
            gains=("'a', 'b', 'c'",),
            lacks=('-split', 'ForEach-Object', '$t'),
        ),
    "$t = [char[]]'ABC'; Write-Output (,$t); Write-Output $t.Count":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 3',),
            lacks=('$t',),
        ),
    "$t = 'ABC'.ToCharArray(); Write-Output (,$t); Write-Output $t.Count":
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 3',),
            lacks=('$t', 'ToCharArray'),
        ),
    "Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')":
        Simplified(gains=("Write-Output 'r5'", "Write-Output 'r5'"), lacks=('+',)),
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')":
        Simplified(keeps=('Write-Output',), gains=('Write-Output 66',), lacks=('[char]65',)),
    "Write-Output ('a,b' -split [char]44); Write-Output ('a,b' -split ',')":
        Simplified(gains=("Write-Output ('a', 'b')", "Write-Output ('a', 'b')"), lacks=('-split',)),
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }':
        Simplified(keeps=('[char]65', 'Write-Output'), lacks=('$c',)),
    'Write-Output ((5).PSTypeNames)':
        Simplified(
            keeps=('Write-Output',),
            gains=("'System.Int32', 'System.ValueType', 'System.Object'",),
            lacks=('PSTypeNames',),
        ),
    "Write-Output (('AB').PSTypeNames)":
        Simplified(
            keeps=('Write-Output',),
            gains=("'System.String', 'System.Object'",),
            lacks=('PSTypeNames',),
        ),
    '$t = (5).Rank; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), gains=('$Null',), lacks=('Rank', '$t')),
    "$t = 'AB'.Zqnope; Write-Output (,$t)":
        Simplified(keeps=('Write-Output (,',), gains=('$Null',), lacks=('Zqnope', '$t')),
    '$t = (5).Zqnope; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), gains=('$Null',), lacks=('Zqnope', '$t')),
    '$a = $null; $b = 5; $t = $a * $b; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), lacks=('$t', '$a', '$b', '*')),
    '$a = $null; $t = $a * 5; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), lacks=('$t', '$a', '*')),
    '$t = $null * 1; Write-Output (,$t)':
        Simplified(keeps=('Write-Output (,',), lacks=('$t', '*')),
    'Write-Output "abc".Length':
        Simplified(gains=('Write-Output 3',), lacks=('Length',)),
    "Write-Output 'abc'.Length":
        Simplified(gains=('Write-Output 3',), lacks=('Length',)),
    '$t = @(@(1, 2)); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('$t',),
        ),
    '$t = @((1, 2)); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('$t',),
        ),
    '$t = @(@(1, 2), 3); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('$t',),
        ),
    '$t = ,(1, 2); Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 1',),
            lacks=('$t',),
        ),
    '$t = (1, 2), 3; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('$t',),
        ),
    'function f { ,$args }; $t = f 1 2; Write-Output (,$t); Write-Output $t.Count':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('Write-Output 2',),
            lacks=('function', '$t', '$args'),
        ),
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t':
        Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('$v', '$t = ', '(,$t)')),
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t':
        Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('$v', '$t = ', '(,$t)')),
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count':
        Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('$t = ', '(,$t)', '$t.Count')),
    '$z = 1.100d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('$z', '$t')),
    '$z = 1.50d; $t = $z + 1.50d; Write-Output (,$t); Write-Output $t':
        Simplified(
            keeps=('Write-Output', 'Write-Output'),
            gains=('3.00d',),
            lacks=('$z', '$t', '+'),
        ),
    'function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        Simplified(keeps=('1, 2',), lacks=('seen:', 'ForEach-Object')),
    'function f { [void]$input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        Simplified(keeps=('Write-Host "seen:', '1, 2'), lacks=('[void]',)),
    "Set-Alias zzq Write-Output; (Get-Alias | Where-Object { $_.Name -eq 'zzq' }).Definition":
        Simplified(
            keeps=('Set-Alias zzq Write-Output',),
            gains=("'Write-Output'",),
            lacks=('Get-Alias',),
        ),
    "Set-Alias zq3 Write-Output; ${alias:zq3} = 'Write-Host'; zq3 'z'":
        Simplified(keeps=("'z'",), gains=("Write-Host 'z'",), lacks=('Set-Alias', 'zq3')),
    '$x = 1, 2, 3; class C { static [object] M() { return $script:x } }; $y = [C]::M(); $y[0] = '
    '9; Write-Output $x[0]':
        Simplified(keeps=('class C',), gains=('Write-Output 9',), lacks=('Write-Output $x',)),
    '$x = 1, 2, 3; $y = @([object[]]$x); $y[0] = 9; Write-Output $x':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (9, 2, 3)',), lacks=('$y',)),
    '$x = 1, 2, 3; [Array]::Reverse(@([object[]]$x)); Write-Output $x':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output (3, 2, 1)',),
            lacks=('Write-Output $x',),
        ),
    'function f { [object[]]$a = 1, 2; [Array]::Reverse(@($a)); Write-Output $a }; f':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output (2, 1)',),
            lacks=('Write-Output $a',),
        ),
    '$x = 1, 2, 3; $b = 7, 8; $null = (. { $b = $x }), ($b[0] = 9); Write-Output $x':
        Simplified(keeps=('Write-Output',), gains=('Write-Output (9, 2, 3)',), lacks=('$b',)),
    'Set-Alias zzq Write-Output; ${alias:zzq}':
        KeptAsWritten(),
    '$x = 1, 2, 3; function f { if ((Get-Random -Maximum 1) -eq 1) { $o = 0, 0 }; $o[0] = 9 }; '
    'function g($p) { $o = $p; f }; g $x; Write-Output $x':
        KeptAsWritten(),
    '$x = 1, 2, 3; $y = 0, 0; if ((Get-Random -Maximum 1) -eq 0) { $y = $x }; $y[0] = 9; '
    'Write-Output $x':
        KeptAsWritten(),
    "trap { continue }; if ($true) { trap [System.IO.IOException] { continue }; [int]'a'; "
    "Write-Host 'tail' }; Write-Host 'after'":
        KeptAsWritten(),
    "if ($true) { trap [System.IO.IOException] { continue }; [int]'a'; Write-Host 'tail' }; "
    "Write-Host 'after'":
        KeptAsWritten(),
    "$ErrorActionPreference = 'Stop'; trap { }; $null = [int]'a'; Write-Host 'after'":
        KeptAsWritten(),
    "trap { continue }; if ($true) { [int]'a'; Write-Host 'tail' }; Write-Host 'after'":
        KeptAsWritten(),
    "trap { continue }; $a = @('x', '5'); for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }; "
    'Write-Host "y=$y"':
        KeptAsWritten(),
    '$a = @(\'x\', \'5\'); for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }; Write-Host "y=$y"':
        KeptAsWritten(),
    'trap { continue }; $out = New-Object byte[] 3; for ($i = 0; $i -lt 3; $i++) { $out[$i] = 7 '
    '-bxor $k[$i % $k.Length] }; Write-Host "out=$($out -join \',\')"':
        KeptAsWritten(),
    '$out = New-Object byte[] 3; for ($i = 0; $i -lt 3; $i++) { $out[$i] = 7 -bxor $k[$i % '
    '$k.Length] }; Write-Host "out=$($out -join \',\')"':
        KeptAsWritten(),
    "trap { continue }; if ((Get-Date).Year -gt 2000) { $v = [int]'a'; Write-Host 't' }; "
    "Write-Host 'after'":
        KeptAsWritten(),
    "try { $null = [int]'a'; Write-Host 'rest' } finally { }; Write-Host 'after'":
        KeptAsWritten(),
    "try { throw 'x' } catch { $null = [int]'a'; Write-Host 'c-rest' }; Write-Host 'after'":
        KeptAsWritten(),
    "try { $x = 'one'; $null = [int]'a'; $x = 'two' } finally { }; Write-Host $x":
        KeptAsWritten(),
    "try { throw 'x' } catch { $x = 'two'; $null = [int]'a'; $x = 'three' }; Write-Host $x":
        KeptAsWritten(),
    "trap { continue }; if ($Host) { $x = 'one'; $null = [int]'a'; $x = 'two' }; Write-Host $x":
        KeptAsWritten(),
    "$x = 'one'; try { $x = 'two'; $null = [int]'a'; $x = 'three' } catch [System.IO.IOException] "
    '{ }; Write-Host $x':
        KeptAsWritten(),
    "function f { try { $null = [int]'a'; Write-Host 'f-rest' } finally { }; Write-Host 'f-after' "
    "}; f; Write-Host 'after'":
        KeptAsWritten(),
    'foreach ($i in 1, 2) { try { $null = [int]\'a\'; Write-Host "rest $i" } finally { }; '
    'Write-Host "next $i" }; Write-Host \'after\'':
        KeptAsWritten(),
    "try { try { $null = [int]'a'; Write-Host 'inner-rest' } finally { Write-Host 'f1' }; "
    "Write-Host 'outer-rest' } finally { Write-Host 'f2' }; Write-Host 'after'":
        KeptAsWritten(),
    "if ($Host) { try { $null = [int]'a'; Write-Host 'rest' } finally { }; Write-Host 'if-rest' "
    "}; Write-Host 'after'":
        KeptAsWritten(),
    '$null = Get-Random -SetSeed 7; Get-Random | Out-Null; Write-Host (Get-Random -Maximum 1000)':
        KeptAsWritten(),
    '$ExecutionContext.InvokeCommand.PreCommandLookupAction = { param($n, $e) if ($n -eq '
    "'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }; try { throw 'x' } catch { "
    "Get-Random; Write-Host 'rest' }; Write-Host 'after'":
        KeptAsWritten(),
    "$x = 'one'; try { throw 'q' } catch { $x = 'two'; & { $null = [int]'a' }; $x = 'three' }; "
    'Write-Host $x':
        KeptAsWritten(),
    "function f { $script:x = 'one'; $null = [int]'a'; $script:x = 'two' }; try { f } catch { }; "
    'Write-Host $script:x':
        KeptAsWritten(),
    "try { try { $null = [int]'a' } finally { }; Write-Host 'rest' } finally { }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "trap { continue }; if ($Host) { trap [System.IO.IOException] { continue }; $null = [int]'a'; "
    "Write-Host 'rest' }; Write-Host 'after'":
        KeptAsWritten(),
    "try { try { throw 'x' } finally { $null = [int]'a' } } finally { }; Write-Host 'after'":
        KeptAsWritten(),
    "try { throw 'x' } catch { if ($Host) { $null = [int]'a'; Write-Host 'rest' } }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "try { throw 'y' } catch { try { throw 'x' } finally { $null = [int]'a' } }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "try { $null = [int]'a' } finally { Write-Host $? }":
        KeptAsWritten(),
    "try { $null = [int]'a' } catch [System.Management.Automation.RuntimeException] { Write-Host "
    "'R' } catch [System.InvalidCastException] { Write-Host 'I' }; Write-Host 'after'":
        KeptAsWritten(),
    "try { $null = [int]'a' } catch [System.Management.Automation.RuntimeException] { Write-Host "
    "'R' } catch [System.Exception] { Write-Host 'E' }; Write-Host 'after'":
        KeptAsWritten(),
    "try { foreach ($i in 1, 2) { Write-Host 'm'; $null = [int]'a' } } catch { }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "try { try { return } finally { $null = [int]'a' } } catch { }; Write-Host 'after'":
        KeptAsWritten(),
    "foreach ($i in 1, 2) { try { try { continue } finally { $null = [int]'a' } } catch { }; "
    'Write-Host "m$i" }; Write-Host \'after\'':
        KeptAsWritten(),
    "function f { try { try { return 'r' } finally { $null = [int]'a' } } catch { }; 'tail' }; "
    'Write-Host (f)':
        KeptAsWritten(),
    "try { try { if ($Host) { exit } } finally { $null = [int]'a' } } catch { }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "function g { $null = [int]'a'; Write-Host 'in' }; try { throw 'x' } catch { g }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "try { throw 'x' } catch { & { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'":
        KeptAsWritten(),
    "try { throw 'x' } catch { 1 | ForEach-Object { $null = [int]'a'; Write-Host 'in' } }; "
    "Write-Host 'after'":
        KeptAsWritten(),
    "function f { $null = [int]'b' }; trap { Write-Host 'T'; $null = [int]'a'; continue }; f; "
    "Write-Host 'after'":
        KeptAsWritten(),
    "trap { Write-Host 'T'; $null = [int]'a'; continue }; & { $null = [int]'b' }; Write-Host "
    "'after'":
        KeptAsWritten(),
    "trap { continue }; try { if ($Host) { return } } finally { $null = [int]'a' }; Write-Host "
    "'after'":
        KeptAsWritten(),
    '$s = $env:COMPUTERNAME; try { trap { $null = [int]$s; continue }; Invoke-Nonexistent; '
    "Write-Host 'rest' } catch { Write-Host 'caught' }":
        KeptAsWritten(),
    '$s = $env:COMPUTERNAME; trap { $null = [int]$s; continue }; Invoke-Nonexistent; Write-Host '
    "'rest'":
        KeptAsWritten(),
    '$s = $env:COMPUTERNAME; $t = $env:USERNAME; try { trap { $null = [int]$s; continue }; if '
    "([int]$t) { Write-Host 'x' }; Write-Host 'rest' } catch { Write-Host 'caught' }":
        KeptAsWritten(),
    "trap { Write-Host 'T'; $null = [int]'a'; continue }; Get-Item -BogusParam foo; Write-Host "
    "'after'":
        KeptAsWritten(),
    "try { $null = 1, 2 | Select-Object -First -1; Write-Output 'ok' } catch { Write-Output "
    "'caught' }":
        KeptAsWritten(),
    "Set-StrictMode -Version 1; $v = 1; Remove-Variable v; try { $null = $v; Write-Output 'read' "
    "} catch { Write-Output 'caught' }":
        KeptAsWritten(),
    "$ErrorActionPreference = 'SilentlyContinue'; if ($true) { trap [System.IO.IOException] { "
    "continue }; throw 'x' }; Write-Output 'after'":
        KeptAsWritten(),
    "[int]$v1 = 1; if ($args.Count -ge 0) { trap { Write-Output 'T'; continue }; $v1 = 'abc' }; "
    "Write-Output 'after'":
        KeptAsWritten(),
    "trap { continue }; if ($True) { $null = [int]$env:COMPUTERNAME; Write-Host 'tail' }; "
    "Write-Host 'next'":
        KeptAsWritten(),
    'trap { continue }; for ($i = 0; $True; $i++) { $null = [int]$env:COMPUTERNAME; Write-Host '
    "'tail'; break }; Write-Host 'next'":
        KeptAsWritten(),
    "trap { continue }; switch (1) { 1 { $null = [int]$env:COMPUTERNAME; Write-Host 'tail' } }; "
    "Write-Host 'next'":
        KeptAsWritten(),
    "try { $x = 1; $x = [int]$env:COMPUTERNAME } catch { Write-Host 'caught' }; Write-Host $x":
        KeptAsWritten(),
    "$ErrorActionPreference = 'Stop'; $x = 'a'; try { trap { }; $x = 'b'; $null = [int]'z'; $x = "
    "'c' } catch { Write-Host 'caught' }; Write-Host $x":
        KeptAsWritten(),
    '$x = 0; try { . { $x = 1; $null = [int]$Host.Name; $x = 2 } } catch { }; Write-Host $x':
        KeptAsWritten(),
    "foreach ($l in @(@(), @(1), @($null), (,1), (1, 'a', $null, @(2, 3)))) { Write-Output "
    "$l.GetType().FullName; [array]::Reverse($l) }; Write-Output 'after'":
        KeptAsWritten(),
    "$PSDefaultParameterValues = @{ 'Get-Random:Maximum' = 0 }; $t = Get-Random; Write-Output "
    '($null -eq $t)':
        KeptAsWritten(),
    "if ($true) { trap { continue }; Write-Host 'in'; throw 'e' }; Write-Host 'after'":
        KeptAsWritten(),
    "trap { Write-Host 'outer'; continue }; if ($true) { trap { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        KeptAsWritten(),
    "trap { Write-Host 'outer'; continue }; if ($true) { trap [System.IO.IOException] { "
    "Write-Host 'inner'; continue }; throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        KeptAsWritten(),
    '$x = 1, 2, 3; Write-Output -NoEnumerate $x | Set-Variable z; $y = $x; $y[0] = 9; '
    'Write-Output $z':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output (9, 2, 3)',),
            lacks=('Set-Variable',),
        ),
    '$x = 1, 2, 3; Write-Output -NoEnumerate $script:x | Set-Variable z; $z[0] = 9; Write-Output '
    '$x':
        Simplified(
            keeps=('Write-Output',),
            gains=('Write-Output (9, 2, 3)',),
            lacks=('Set-Variable',),
        ),
}

_NOT_YET_DISPATCHED: tuple[str, ...] = (
    'try body, finally / cast / Continue',
    'catch body / cast / Continue',
    'finally body, error / cast / Continue',
    'subexpression / cast / Continue',
    'try in a try body / cast / Continue',
    'loop in a try body / cast / Continue',
    'finally body, error, in a catch body / cast / Continue',
    'trap body, run from a try / cast / Continue',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / Continue',
    'try body, catch [RuntimeException] or [Exception] / cast / Continue',
    'try body, catch [untyped] / cast / Continue',
    'try body, catch [RuntimeException] / cast / Continue',
    'try body, catch [InvalidCastException] / cast / Continue',
    'try body, catch [IOException] / cast / Continue',
    'function in a try body / cast / Continue',
    'function in a catch body / cast / Continue',
    'function under a trap / cast / Continue',
    'script block in a catch body / cast / Continue',
    'return through a finally / cast / Continue',
    'continue through a finally / cast / Continue',
    'exit through a finally / cast / Continue',
    'return through a finally, function / cast / Continue',
    'preference written to Stop / cast / Continue',
    'try body, finally / cast / SilentlyContinue',
    'catch body / cast / SilentlyContinue',
    'finally body, error / cast / SilentlyContinue',
    'subexpression / cast / SilentlyContinue',
    'try in a try body / cast / SilentlyContinue',
    'loop in a try body / cast / SilentlyContinue',
    'finally body, error, in a catch body / cast / SilentlyContinue',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / SilentlyContinue',
    'try body, catch [RuntimeException] or [Exception] / cast / SilentlyContinue',
    'try body, catch [untyped] / cast / SilentlyContinue',
    'under a trapped block, continue [untyped] / cast / SilentlyContinue',
    'under a trapped block, runs off [untyped] / cast / SilentlyContinue',
    'try body, catch [RuntimeException] / cast / SilentlyContinue',
    'under a trapped block, continue [RuntimeException] / cast / SilentlyContinue',
    'under a trapped block, runs off [RuntimeException] / cast / SilentlyContinue',
    'try body, catch [InvalidCastException] / cast / SilentlyContinue',
    'under a trapped block, continue [InvalidCastException] / cast / SilentlyContinue',
    'under a trapped block, runs off [InvalidCastException] / cast / SilentlyContinue',
    'try body, catch [IOException] / cast / SilentlyContinue',
    'under a trapped block, continue [IOException] / cast / SilentlyContinue',
    'under a trapped block, runs off [IOException] / cast / SilentlyContinue',
    'function in a try body / cast / SilentlyContinue',
    'function in a catch body / cast / SilentlyContinue',
    'function under a trap / cast / SilentlyContinue',
    'script block in a catch body / cast / SilentlyContinue',
    'return through a finally / cast / SilentlyContinue',
    'continue through a finally / cast / SilentlyContinue',
    'exit through a finally / cast / SilentlyContinue',
    'return through a finally, function / cast / SilentlyContinue',
    'preference written to Stop / cast / SilentlyContinue',
    'top / cast / Stop',
    'loop / cast / Stop',
    'try body, finally / cast / Stop',
    'catch body / cast / Stop',
    'finally body / cast / Stop',
    'finally body, error / cast / Stop',
    'trap body / cast / Stop',
    'subexpression / cast / Stop',
    'try in a try body / cast / Stop',
    'loop in a try body / cast / Stop',
    'finally body, error, in a catch body / cast / Stop',
    'trap body, run from a try / cast / Stop',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / Stop',
    'try body, catch [RuntimeException] or [Exception] / cast / Stop',
    'try body, catch [untyped] / cast / Stop',
    'under a trapped block, continue [untyped] / cast / Stop',
    'under a trapped block, runs off [untyped] / cast / Stop',
    'try body, catch [RuntimeException] / cast / Stop',
    'under a trapped block, continue [RuntimeException] / cast / Stop',
    'under a trapped block, runs off [RuntimeException] / cast / Stop',
    'try body, catch [InvalidCastException] / cast / Stop',
    'under a trapped block, continue [InvalidCastException] / cast / Stop',
    'under a trapped block, runs off [InvalidCastException] / cast / Stop',
    'try body, catch [IOException] / cast / Stop',
    'under a trapped block, continue [IOException] / cast / Stop',
    'under a trapped block, runs off [IOException] / cast / Stop',
    'function at script scope / cast / Stop',
    'function in a try body / cast / Stop',
    'function in a catch body / cast / Stop',
    'function under a trap / cast / Stop',
    'script block in a catch body / cast / Stop',
    'return through a finally / cast / Stop',
    'continue through a finally / cast / Stop',
    'exit through a finally / cast / Stop',
    'return through a finally, function / cast / Stop',
    'preference written to Stop / cast / Stop',
    'under a trapped block, continue [untyped] / throw / SilentlyContinue',
    'under a trapped block, runs off [untyped] / throw / SilentlyContinue',
    'under a trapped block, continue [RuntimeException] / throw / SilentlyContinue',
    'under a trapped block, runs off [RuntimeException] / throw / SilentlyContinue',
    'under a trapped block, continue [InvalidCastException] / throw / SilentlyContinue',
    'under a trapped block, runs off [InvalidCastException] / throw / SilentlyContinue',
    'under a trapped block, continue [IOException] / throw / SilentlyContinue',
    'under a trapped block, runs off [IOException] / throw / SilentlyContinue',
    'under a trapped block, continue [untyped] / throw / Stop',
    'under a trapped block, runs off [untyped] / throw / Stop',
    'under a trapped block, continue [RuntimeException] / throw / Stop',
    'under a trapped block, runs off [RuntimeException] / throw / Stop',
    'under a trapped block, continue [InvalidCastException] / throw / Stop',
    'under a trapped block, runs off [InvalidCastException] / throw / Stop',
    'under a trapped block, continue [IOException] / throw / Stop',
    'under a trapped block, runs off [IOException] / throw / Stop',
    'failing store / Continue',
    'failing store under a resuming trap / Continue',
    'failing store in a function / Continue',
    'failing store / SilentlyContinue',
    'failing store under a resuming trap / SilentlyContinue',
    'failing store in a function / SilentlyContinue',
    'failing store / Stop',
    'failing store under a resuming trap / Stop',
    'failing store in a function / Stop',
)

NOT_YET_SIMPLIFIED: frozenset[str] = frozenset({
    'for ($i = 0; $i -lt 2; $i++) { 1 }',
    'function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f',
    'function f { [void]$input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f',
    "Set-Alias zzq Write-Output; (Get-Alias | Where-Object { $_.Name -eq 'zzq' }).Definition",
    "Set-Alias zq3 Write-Output; ${alias:zq3} = 'Write-Host'; zq3 'z'",
    "$h = @{ k = 'Set-Alias zzq Write-Host' }; Set-Alias zzq Write-Output; iex $h.k; zzq 'x'",
    '$x = 1, 2, 3; Write-Output $x[0]; $x[0] = 9; Write-Output $x[0]',
    '$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]',
    '$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y',
    '$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y',
    '$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }',
    "$q, $r = 'abc', 'd'; Write-Output $q.SUBSTRING(1, 1); Write-Output $r",
    "$q = 'abc'; [int]$q = 5; Write-Output $q.GetType().FullName",
    "function Get-Zqfrob { Write-Output 'hit' }; Zqfrob",
    "function Get-Zqfrob { Write-Output 'p' }; function Zqfrob { Write-Output 'b' }; Zqfrob",
    "$env:zzq = '7'; function Get-Item { Write-Output 'from-function' }; item env:zzq",
    "$x = 'a'; function f { Write-Host (variable x -ValueOnly) }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (item variable:x).Value }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (Get-Item variable:x).Value }; f; $x = 'c'",
    '$x = 1, 2, 3; $y = $x -as [array]; $y[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x',
    '$x = 1, 2, 3; $y = if ($True) { $x }; $x[0] = 9; Write-Output $y[0]',
    '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z',
    '$x = 1, 2, 3; Write-Output -NoEnumerate $x | Set-Variable z; $y = $x; $y[0] = 9; '
    'Write-Output $z',
    '$x = 1, 2, 3; Write-Output -NoEnumerate $script:x | Set-Variable z; $z[0] = 9; Write-Output '
    '$x',
    '$x = 1, 2, 3; class C { static [object] M() { return $script:x } }; $y = [C]::M(); $y[0] = '
    '9; Write-Output $x[0]',
    '$x = 1, 2, 3; $a = $null; $a = $a + $x; $a[0] = 9; Write-Output $x[0]',
    "function Get-Language { $Null = 668 }; language; Write-Host 'A'",
    "trap { continue }; zzq0000=5; Write-Host 'after'",
    "foreach ($i in 1..2) { Write-Output $($c = $c + 'x'; $c) }",
    'foreach ($i in 1..2) { Write-Output $(if (0) { $m = \'A\' }; $o = "${m}"; $m = \'B\'; $o) }',
    'Set-Variable q 5; function fq { $q + 1 }; Write-Output (fq)',
    '$o = [pscustomobject]@{}; Add-Member -Type NoteProperty k v -InputObject $o; $o.k',
    "$b = 'a'; $v = Get-Variable; ($v | Where-Object Name -eq 'b').Value = 'b'; Write-Output $b",
    '$x = 1, 2, 3; $b, $c = $x; [Array]::Reverse($x); Write-Output $b',
    '$x = 1, 2, 3; $y = @([object[]]$x); $y[0] = 9; Write-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse(@([object[]]$x)); Write-Output $x',
    'function f { [object[]]$a = 1, 2; [Array]::Reverse(@($a)); Write-Output $a }; f',
    '$x = 1, 2, 3; $b = 7, 8; $null = (. { $b = $x }), ($b[0] = 9); Write-Output $x',
    '$x = 1, 2, 3; $w = ($z = $y = $x)[0]; $z[0] = 9; Write-Output $x',
    "$x = 'a'; $v = Get-Variable x -ValueOnly:$false; $v.Value = 'b'; Write-Output $x",
    "$x = 'a'; $v = Get-ChildItem variable:\\; ($v | Where-Object Name -eq 'x').Value = 'b'; "
    'Write-Output $x',
    "$p = @('a'); function f1 { $null = [int]$p[0]; Write-Host 'm1' }; trap { continue }; f1; "
    "Write-Host 'm2'",
    '$b = 0; foreach ($i in 1) { $b = 1 }; while ($b -ne 2) { switch ($b) { 0 { Write-Host '
    "'zero'; $b = 2 } 1 { Write-Host 'one'; $b = 2 } } }",
    "$s = 0; while ($s -ne -1) { switch ($s) { 0 { Write-Host 'a'; $s = -1 } default { break } } "
    '}; Write-Host $s',
    '$t = [array]::Reverse((1, 2, 3, 4)); Write-Output ($null -eq $t)',
    'function dec($d, $k) { $o = @(0) * $d.Length; for ($i = 0; $i -lt $d.Length; $i++) { $o[$i] '
    '= $d[$i] -bxor $k[$i % $k.Length] }; $o }; $key = 1, 2, 3; Write-Output (dec (4, 5, 6) $key)',
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'",
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'",
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'",
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v',
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i",
    '$v = \'a\'; . ([ScriptBlock]::Create(\'$v = "b"\')); Write-Output $v; Write-Output (1 + 1)',
    '$t = [decimal]::MaxValue + 1; Write-Output (,$t); Write-Output $t',
    '$t = 0.50000000000000000000000000001d; Write-Output (,$t); Write-Output $t',
    '$t = 9.9999999999999999999999999999d; Write-Output (,$t); Write-Output $t',
    "$t = 16 + 'file'; Write-Output (,$t); Write-Output $t",
    '$t = [int64]::MaxValue * 2; Write-Output (,$t); Write-Output $t',
    '$t = [double]::PositiveInfinity; Write-Output (,$t); Write-Output $t',
    '$t = [double]::NaN; Write-Output (,$t); Write-Output $t',
    '$t = ([char]65).ToUpper(); Write-Output (,$t); Write-Output $t',
    '$t = ([char]65).Substring(0); Write-Output (,$t); Write-Output $t',
    "$t = [double]'1,5'; Write-Output (,$t); Write-Output $t",
    "$t = -bnot 'abc'; Write-Output (,$t); Write-Output $t",
    '$t = -bnot 3000000000.0; Write-Output (,$t); Write-Output $t',
    "$t = 'ab' * 0xFFFFFFFF; Write-Output (,$t); Write-Output $t",
    '$t = [byte]300; Write-Output (,$t); Write-Output $t',
    '$t = [byte]-1; Write-Output (,$t); Write-Output $t',
    '$t = [int]2147483648; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5; Write-Output (,$t); Write-Output $t',
    '$t = [char]65536; Write-Output (,$t); Write-Output $t',
    '$t = [char]-1; Write-Output (,$t); Write-Output $t',
    "$t = [int]'abc'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1e3'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'1e3'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1_0'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0b1010'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'   '; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1,000'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'1kb'; Write-Output (,$t); Write-Output $t",
    "$t = [int]'0o17'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'-1'; Write-Output (,$t); Write-Output $t",
    "$t = [byte]'0x100'; Write-Output (,$t); Write-Output $t",
    "$t = [char]'AB'; Write-Output (,$t); Write-Output $t",
    "$t = [char]''; Write-Output (,$t); Write-Output $t",
    "$t = 'a' + @(1, 2); Write-Output (,$t); Write-Output $t",
    "$t = [double]'1.5'; Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('0x10'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('1_0'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('7.5'); Write-Output (,$t); Write-Output $t",
    "$t = [Convert]::ToInt32('-10', 16); Write-Output (,$t); Write-Output $t",
    "$t = 'abc' -as [int]; Write-Output (,$t); Write-Output $t",
    '$t = 300 -as [byte]; Write-Output (,$t); Write-Output $t',
    "$t = switch ('1') { 1 { 'number' } }; Write-Output (,$t); Write-Output $t",
    "$t = switch (1) { '1' { 'text' } }; Write-Output (,$t); Write-Output $t",
    "$t = switch ('0x10') { 16 { 'hex' } }; Write-Output (,$t); Write-Output $t",
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t",
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t',
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t',
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = @('1') -contains 1; Write-Output (,$t); Write-Output $t",
    "$t = @(1) -contains '1'; Write-Output (,$t); Write-Output $t",
    "$t = 'a*' -like 'a`*'; Write-Output (,$t); Write-Output $t",
    "$t = 'ab' -like 'a`*'; Write-Output (,$t); Write-Output $t",
    "$t = 'b' -like '[!a]'; Write-Output (,$t); Write-Output $t",
    "$t = '1_0' -band 15; Write-Output (,$t); Write-Output $t",
    '$t = [byte]400; Write-Output (,$t); Write-Output $t',
    '$t = [byte](200 * 2); Write-Output (,$t); Write-Output $t',
    "$t = 'ſ' -match 's'; Write-Output (,$t); Write-Output $t",
    "$t = 'ſ' -cmatch 's'; Write-Output (,$t); Write-Output $t",
    "$t = 1 + '1e400'; Write-Output (,$t); Write-Output $t",
    '$t = [decimal]::MaxValue % 1.5d; Write-Output (,$t); Write-Output $t',
    '$t = [decimal]::MaxValue % 1; Write-Output (,$t); Write-Output $t',
    '$t = 1d + 0.1; Write-Output (,$t); Write-Output $t',
    '$t = 1d - 0.1; Write-Output (,$t); Write-Output $t',
    '$t = [byte]1 -shl 4; Write-Output (,$t); Write-Output $t',
    '$t = [byte]1 -shl -1; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5 -shl 1; Write-Output (,$t); Write-Output $t',
    '$t = $null -band [uint32]1; Write-Output (,$t); Write-Output $t',
    '$t = 1.5 / -0.0; Write-Output (,$t); Write-Output $t',
    "$t = 'ab' * 1.5; Write-Output (,$t); Write-Output $t",
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t',
    '$t = [single]1.5 + 1; Write-Output (,$t); Write-Output $t',
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t',
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t',
    '$t = $true * 2; Write-Output (,$t); Write-Output $t',
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count',
    '$t = [bool](0.0 / 0.0); Write-Output (,$t); Write-Output $t',
    "$t = if ([char]0) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = if ('0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = if (@(@())) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = if ((,[char]0)) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = - 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = if (- '0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    '$t = - @(); Write-Output (,$t); Write-Output $t',
    "$t = if (- '5') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t",
    "$t = '10' -lt '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -lt 9; Write-Output (,$t); Write-Output $t",
    "$t = 10 -lt '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -ge 9; Write-Output (,$t); Write-Output $t",
    "$t = 10 -ge '9'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -gt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -cgt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = 'B' -igt 'a'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -cle '9'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -lt 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -gt 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -eq 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -ne 'abc'; Write-Output (,$t); Write-Output $t",
    "$t = 1 -lt '5'; Write-Output (,$t); Write-Output $t",
    '$t = 79228162514264337593543950335d + 1d; Write-Output (,$t); Write-Output $t',
    '$t = 79228162514264337593543950335d - -1d; Write-Output (,$t); Write-Output $t',
    '$t = 1d / 0d; Write-Output (,$t); Write-Output $t',
    "$t = [char]48 * '1'; Write-Output (,$t); Write-Output $t",
    "$t = $true * '1'; Write-Output (,$t); Write-Output $t",
    '$t = [char]48 * 2; Write-Output (,$t); Write-Output $t',
    '$t = $true - 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = $true + 1.0d; Write-Output (,$t); Write-Output $t',
    '$t = $true / 1.0d; Write-Output (,$t); Write-Output $t',
    "$t = 'ss' -eq [char]0x00DF; Write-Output (,$t); Write-Output $t",
    "$t = [char]0x00DF -eq 'ss'; Write-Output (,$t); Write-Output $t",
    "$t = '2' -lt '10'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -le '9'; Write-Output (,$t); Write-Output $t",
    "$t = '10' -gt 9; Write-Output (,$t); Write-Output $t",
    '$t = 9.9999999999999999999999999999d + 0d; Write-Output (,$t); Write-Output $t',
    "$t = 'x' + [decimal]'1.0'; Write-Output (,$t); Write-Output $t",
    "$t = [Text.StringBuilder]::new('ab').ToString(); Write-Output (,$t); Write-Output $t",
    *(_dispatched(name) for name in _NOT_YET_DISPATCHED),
})
