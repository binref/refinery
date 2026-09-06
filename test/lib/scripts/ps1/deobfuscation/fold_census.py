"""
What the deobfuscator makes of every corpus row it rewrites, recorded so that a fold cannot be lost
without a diff saying so.

A row is here when the output differs from the *canonical* input — the corpus row parsed and
synthesized again — so a change in spelling alone is not a fold and does not enter. A row the
deobfuscator leaves alone is absent, which is why a fold that stops being taken shows up as a key
that went missing rather than as a value that quietly agrees.

Nothing here is a claim that a fold is correct. `test_oracle` holds the measurements that say so.
This says only which folds exist, so that a commit that means to change one has to say which.
"""
from __future__ import annotations

FOLDS: dict[str, str] = {
    'if ($a) { 1 }':
        '',
    '1 + 2':
        '3',
    'while ($a) { break }':
        '',
    'while ($a) { continue }':
        '',
    'do { 1 } while ($a)':
        '',
    'foreach ($i in $a) { 1 }':
        'foreach ($i in $a) {}',
    'for ($i = 0; $i -lt 2; $i++) { 1 }':
        '$i = 2',
    'if ($a) { 1 } elseif ($b) { 2 } else { 3 }':
        '',
    '(1)':
        '1',
    '1..2':
        '1, 2',
    'switch ($a) { 1 { "x" } default { "y" } }':
        'switch ($a) {\n  1 {}\n  default {}\n}',
    'trap [E] { 1 }':
        '',
    'try { 1 } catch { 2 } finally { 3 }':
        'try {\n  1\n} catch {\n  2\n} finally {}',
    '-not $x':
        '$True',
    'while ($a) { 1 }':
        '',
    'echo a < b':
        'Write-Output a < b',
    '$x > out.txt':
        '>\nout.txt',
    '$x = 3..5':
        '$x = 3, 4, 5',
    '$x = 1e3.5':
        '$x = $Null',
    '$x = (1).5':
        '$x = $Null',
    "('a')":
        "'a'",
    "'a' + 'b'":
        "'ab'",
    "'{0}-{1}' -f 'a', 'b'":
        "'a-b'",
    "$x = 'hello'; $x":
        "'hello'",
    "('a', 'b', 'c') -join ''":
        "'abc'",
    "[string]::Join('', ('a', 'b'))":
        "'ab'",
    "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGk='))":
        "'hi'",
    "if ($true) { 'yes' } else { 'no' }":
        "'yes'",
    '1..3 | ForEach-Object { $_ * 2 }':
        '2, 4, 6',
    '$a = 1; $b = 2; $a + $b':
        '3',
    "'ABC'.ToLower()":
        "'abc'",
    "$x = @('a', 'b'); $x[1]":
        "'b'",
    "switch ('b') { 'a' { 'first' } 'b' { 'second' } }":
        "'second'",
    "[int]'42' + 1":
        '43',
    "'a' * 3":
        "'aaa'",
    '$null -eq $undefined':
        '$True',
    "Write-Host 'a'; return; Write-Host 'b'":
        "Write-Host 'a'\nreturn",
    "&('Write' + '-Output') 'indirect'":
        "Write-Output 'indirect'",
    "$s = 'abc'; $s.Substring(1, 2)":
        "'bc'",
    "'a{0}c' -f 'b'":
        "'abc'",
    "function echo { 'from-function' }; echo 'from-alias'":
        "Write-Output 'from-alias'",
    "Set-Alias zzq Write-Output; zzq 'resolved'":
        "Write-Output 'resolved'",
    "Set-Alias zzq iex; zzq 'Write-Output loaded'":
        'Write-Output loaded',
    "Set-Alias -Na zzq -Val Write-Output; zzq 'abbreviated'":
        "Write-Output 'abbreviated'",
    "Set-Alias zzq Write-Output; $n = 'zzq'; & $n 'dispatched'":
        "Write-Output 'dispatched'",
    "Set-Alias zzq Write-Output; $n = 'zzq'; (Get-Alias $n).Definition":
        "Set-Alias zzq Write-Output\n(Get-Alias 'zzq').Definition",
    "Set-Alias zzq Write-Output; (Get-Alias | Where-Object { $_.Name -eq 'zzq' }).Definition":
        "Set-Alias zzq Write-Output\n(Get-Alias | Where-Object {\n  $_.Name -Eq 'zzq'\n}).Definition",
    'Set-Alias zzq Write-Output; (alias zzq).Definition':
        'Set-Alias zzq Write-Output\n(Get-Alias zzq).Definition',
    'Set-Alias zzq Write-Output; ${alias:zzq}':
        'Set-Alias zzq Write-Output\n$alias:zzq',
    "Set-Alias zzq Write-Output; zzq 'exported'; Export-ModuleMember -Alias zzq":
        "Set-Alias zzq Write-Output\nWrite-Output 'exported'\nExport-ModuleMember -Alias zzq",
    "Set-Alias -Value Write-Output -Name zzq; zzq 'named-out-of-order'":
        "Write-Output 'named-out-of-order'",
    "Set-Alias -N zzq -V Write-Output; zzq 'one-letter'":
        "Write-Output 'one-letter'",
    "function alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        "'from-function'",
    "function Get-Alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        "'from-function'",
    "$env:zzq = '7'; (item env:zzq).Value":
        "$env:zzq = '7'\n(Get-Item env:zzq).Value",
    "$n = 'zq2'; Set-Alias zq2 Write-Host; Set-Alias $n Write-Output; zq2 'y'":
        "Write-Output 'y'",
    "Set-Alias zzq Write-Host; $c = 'Set-Alias'; & $c zzq Write-Output; zzq 'x'":
        "Write-Output 'x'",
    "Set-Alias zq3 Write-Output; ${alias:zq3} = 'Write-Host'; zq3 'z'":
        "Set-Alias zq3 Write-Output\n$alias:zq3 = 'Write-Host'\nzq3 'z'",
    "Set-Alias zzq Write-Output; Invoke-Expression 'Set-Alias zzq Write-Host'; zzq 'x'":
        "Write-Host 'x'",
    "$h = @{ k = 'Set-Alias zzq Write-Host' }; Set-Alias zzq Write-Output; iex $h.k; zzq 'x'":
        "$h = @{\n  k = 'Set-Alias zzq Write-Host'\n}\nSet-Alias zzq Write-Output\nInvoke-Expression $h.k\nzzq 'x'",
    '$x = 1, 2, 3; Write-Output $x[0]; [Array]::Reverse($x); Write-Output $x[0]':
        '$x = 1, 2, 3\nWrite-Output 1\n[Array]::Reverse($x)\nWrite-Output 3',
    '$x = 1, 2, 3; Write-Output $x[0]; $x[0] = 9; Write-Output $x[0]':
        '$x = 1, 2, 3\nWrite-Output 1\n$x[0] = 9\nWrite-Output $x[0]',
    '$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]':
        '$x = 1, 2, 3\n$y = $x\nWrite-Output $y[0]\n[Array]::Reverse($x)\nWrite-Output 3',
    "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x":
        '$x = 7, 8, 9\n[Array]::Reverse($x)\nWrite-Output (9, 8, 7)',
    '$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x':
        '$x = 1, 2, 3\n$Null = [Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Clear($x, 0, 1)\nWrite-Output ($Null, 2, 3)',
    '$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y':
        '$y = 0, 0, 0\n[Array]::Copy((1, 2, 3), $y, 3)\nWrite-Output $y',
    '$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 2)\nWrite-Output (2, 1, 3)',
    '$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y':
        '$y = 0, 0, 0\n(1, 2, 3).CopyTo($y, 0)\nWrite-Output $y',
    '$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }':
        '$x = 1, 2, 3\nfor ($i = 0; $i -LT 2; $i++) {\n  Write-Output $x[0]\n  [Array]::Reverse($x)\n}',
    '$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse(($x))\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; [Array]::Reverse($script:x); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($script:x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; $y = $x; $x = 9, 9, 9; Write-Output $y':
        'Write-Output (1, 2, 3)',
    "[string]$q = 'abc'; Write-Output $q.Substring(1, 1)":
        "Write-Output 'b'",
    '[int]$q = 5; Write-Output $q.ToString()':
        "Write-Output '5'",
    "$q, $r = 'abc', 'd'; Write-Output $q.SUBSTRING(1, 1); Write-Output $r":
        "$q, $r = 'abc', 'd'\nWrite-Output $q.Substring(1, 1)\nWrite-Output $r",
    '$q = [string]5; $q = 1, 2, 3; Write-Output (,$q)':
        'Write-Output (,(1, 2, 3))',
    "$q = 'abc'; [int]$q = 5; Write-Output $q.GetType().FullName":
        'Write-Output (5).GetType().FullName',
    "function Get-Zqfrob { Write-Output 'hit' }; Zqfrob":
        "function Get-Zqfrob {\n  Write-Output 'hit'\n}\nGet-zqfrob",
    "function Get-Zqfrob { Write-Output 'p' }; function Zqfrob { Write-Output 'b' }; Zqfrob":
        "function Zqfrob {\n  Write-Output 'b'\n}\nZqfrob",
    "function Get-Get-Zqfrob { Write-Output 'hit' }; Get-Zqfrob":
        'Get-Zqfrob',
    "function Get-Zq-Frob { Write-Output 'hit' }; Zq-Frob":
        'Zq-Frob',
    "$env:zzq = '7'; function Get-Item { Write-Output 'from-function' }; item env:zzq":
        "$env:zzq = '7'\nfunction Get-Item {\n  Write-Output 'from-function'\n}\nGet-Item env:zzq",
    "$x = 'a'; function f { Write-Host (variable x -ValueOnly) }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host ($x)\n}\nf",
    "$x = 'a'; function f { Write-Host (item variable:x).Value }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$x = 'a'; function f { Write-Host (Get-Item variable:x).Value }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$env:z = 'v'; Write-Output $env:z":
        "Write-Output 'v'",
    "$script:s = 'x'; Write-Output $s":
        "Write-Output 'x'",
    '$x = 1, 2, 3; $y = $x; $y = 9, 9, 9; [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output (9, 9, 9)',
    "$s = 'abcd'; $t = $s; $t = 1, 2, 3; [Array]::Reverse($t); Write-Output $s.Length":
        '$t = 1, 2, 3\n[Array]::Reverse($t)\nWrite-Output 4',
    '$x = 1, 2, 3; $y = $x -as [array]; $y[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$y = $x -As [array]\n$y[0] = 9\nWrite-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($x -As [array])\nWrite-Output $x',
    "$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); Write-Output $x[0]":
        '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output 3',
    "[string]$q = 5; [System.String]$q = 'ab'; Write-Output $q":
        "Write-Output 'ab'",
    "[string]$q = 5; $q += 'a'; Write-Output (,$q)":
        "Write-Output (,'5a')",
    '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; $a, $b = $x, 9; $a[0] = 7; Write-Output $x[0]':
        '$x = 1, 2, 3\n$a, $b = $x, 9\n$a[0] = 7\nWrite-Output 1',
    '$x = 1, 2, 3; $y = $x; & { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n$y = $x\n& {\n  $y = 9, 9, 9\n}\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; [Array]::Reverse($h['k']); Write-Output $x":
        "$x = 1, 2, 3\n$h = @{}\n$h['k'] = $x\n[Array]::Reverse($h['k'])\nWrite-Output (1, 2, 3)",
    '$p = @(@(1, 2), @(3, 4)); foreach ($e in $p) { [Array]::Reverse($e) }; Write-Output $p[0]':
        'foreach ($e in (@(1, 2), @(3, 4))) {\n  [Array]::Reverse($e)\n}\nWrite-Output (1, 2)',
    '$x = 1, 2, 3; $y = if ($True) { $x }; $x[0] = 9; Write-Output $y[0]':
        '$x = 1, 2, 3\n$y = if ($True) {\n  (1, 2, 3)\n}\n$x[0] = 9\nWrite-Output $y[0]',
    'function f($a) { $script:k = $a }; $x = 1, 2, 3; f $x; $x[0] = 9; Write-Output $k[0]':
        'function f {\n  Param($a)\n  $script:k = $a\n}\n$x = 1, 2, 3\nf (1, 2, 3)\n$x[0] = 9\nWrite-Output $k[0]',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; Write-Output $h['k']":
        "$h = @{}\n$h['k'] = (1, 2, 3)\nWrite-Output $h['k']",
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; Write-Output $o.P':
        '$o = [pscustomobject]@{\n  P = 0\n}\n$o.P = (1, 2, 3)\nWrite-Output $o.P',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; Write-Output $a[0]':
        '$a = 0, 0\n$a[0] = (1, 2, 3)\nWrite-Output $a[0]',
    '$x = 1, 2, 3; $h = @{ k = $x }; Write-Output $h.k':
        '$h = @{\n  k = (1, 2, 3)\n}\nWrite-Output $h.k',
    '$x = 1, 2, 3; $a, $b = $x, 9; Write-Output $a':
        '$a, $b = (1, 2, 3), 9\nWrite-Output $a',
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; $o.P[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$o = [pscustomobject]@{\n  P = 0\n}\n$o.P = $x\n$o.P[0] = 9\nWrite-Output (1, 2, 3)',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; $a[0][0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$a = 0, 0\n$a[0] = $x\n$a[0][0] = 9\nWrite-Output (1, 2, 3)',
    '$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); $l[0][0] = 9; Write-Output $x':
        '$l = New-Object Collections.ArrayList\n[void]$l.Add((1, 2, 3))\n$l[0][0] = 9\nWrite-Output (1, 2, 3)',
    '$x = 1, 2, 3; $h = @{ k = $x }; $h.k[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$h = @{\n  k = $x\n}\n$h.k[0] = 9\nWrite-Output (1, 2, 3)',
    "$x = 1, 2, 3; $h = @{ k = $x }; $y = $h['k']; $y[0] = 9; Write-Output $x":
        "$x = 1, 2, 3\n$h = @{\n  k = $x\n}\n$y = $h['k']\n$y[0] = 9\nWrite-Output (1, 2, 3)",
    '$p = @(@(1, 2), @(3, 4)); $q = $p[0]; $q[0] = 9; Write-Output $p[0][0]':
        '$q = (1, 2)\n$q[0] = 9\nWrite-Output 1',
    '$p = @(@(1, 2), @(3, 4)); $p | ForEach-Object { [Array]::Reverse($_) }; Write-Output $p[0]':
        '(@(1, 2), @(3, 4)) | ForEach-Object {\n  [Array]::Reverse($_)\n}\nWrite-Output (1, 2)',
    '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; Write-Output $p[0]':
        '$p = @(@(1, 2), @(3, 4))\nfor ($i = 0; $i -LT 1; $i++) {\n  [Array]::Reverse($p[$i])\n}\nWrite-Output $p[0]',
    'function f($a) { [Array]::Reverse($a) }; $x = 1, 2, 3; f $x; Write-Output $x':
        'function f {\n  Param($a)\n  [Array]::Reverse($a)\n}\nf (1, 2, 3)\nWrite-Output (1, 2, 3)',
    '$sb = { param($a) [Array]::Reverse($a) }; $x = 1, 2, 3; & $sb $x; Write-Output $x':
        '$sb = {\n  Param($a)\n  [Array]::Reverse($a)\n}\n& $sb (1, 2, 3)\nWrite-Output (1, 2, 3)',
    '$x = 1, 2, 3; $a, $b = $x, 9; [Array]::Reverse($a); Write-Output $x':
        '$x = 1, 2, 3\n$a, $b = $x, 9\n[Array]::Reverse($a)\nWrite-Output (1, 2, 3)',
    "Set-Variable global:y 'b'; Write-Host $global:y":
        'Write-Host $global:y',
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        "$False -and ($x = 'b')\nWrite-Host 'b'",
    "$x = 'a'; $true -or ($x = 'b'); Write-Host $x":
        "$True -or ($x = 'b')\nWrite-Host 'b'",
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$v = 'a'; & { Write-Host $v }; $v = 'c'":
        "& {\n  Write-Host 'a'\n}",
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        "& {\n  Write-Host $script:x\n}\n$x = 'b'",
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        "function f {\n  Write-Host $script:x\n}\nf\n$x = 'b'",
    "$x = 'a'; $sb = { Write-Host $x }; & $sb; $x = 'c'":
        "$x = 'a'\n$sb = {\n  Write-Host $x\n}\n& $sb",
    "$x = 'a'; $sb = { Write-Host $x }; $x = 'c'; & $sb":
        "$x = 'a'\n$sb = {\n  Write-Host $x\n}\n& $sb",
    "$x = 'a'; $sb = { Write-Host $x }; $sb.Invoke(); $x = 'c'":
        "$x = 'a'\n$sb = {\n  Write-Host $x\n}\n$sb.Invoke()",
    "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'":
        "Write-Host 'a'",
    "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'":
        "1, 2 | ForEach-Object {\n  Write-Host 'a'\n}",
    "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'":
        "Write-Host 'a'",
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'":
        "$c = 'Write-Host $x'\nfunction f {\n  Invoke-Expression $c\n}\nf",
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host ($x)\n}\nf",
    "$x = 'a'; Write-Host (Get-Variable x* | ForEach-Object Value); $x = 'c'":
        'Write-Host (Get-Variable x* | ForEach-Object Value)',
    "$x = 'a'; Get-Variable x; $x = 'c'":
        "Get-Variable x\n$x = 'c'",
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v':
        '$v = 41\n& {\n  $v++\n  Write-Host $v\n}\nWrite-Host 41',
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i":
        "$i = 0\n$Null = [int]::TryParse('42', [ref]$script:i)\nWrite-Host $i",
    "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z":
        "$env:z = '7'\n$Null = [int]::TryParse('42', [ref]$env:z)\nWrite-Host '7'",
    '% { Write-Host 1 }':
        'ForEach-Object {\n  Write-Host 1\n}',
    '$x = \'a\'; $c = \'$script:x = "b"\'; function f { iex $c }; f; Write-Host $x':
        '$c = \'$script:x = "b"\'\nfunction f {\n  Invoke-Expression $c\n}\nf\nWrite-Host \'a\'',
    '$x = \'a\'; &(\'i\' + \'ex\') \'$x = "b"\'; Write-Host $x':
        "Write-Host 'a'",
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output (,$t); Write-Output $t":
        "Write-Output (,('a', 'b'))\nWrite-Output ('a', 'b')",
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')":
        "Write-Output 'a-b'",
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }":
        "foreach ($e in ('a', 'b')) {\n  Write-Output $e\n}",
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output (,$t)':
        "Write-Output (,('A', 'B'))",
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        "Write-Output 2\nWrite-Output ('A', 'B')",
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output (,$t)":
        "Write-Output (,('a', 'b', 'c'))",
    '$t = [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = [char[]](72, 73); Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char[]](72, 73))\nWrite-Output ([char[]](72, 73))',
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        'Write-Output ($False)\nWrite-Output ($True)',
    "$t = [char[]]'ABC'; Write-Output (,$t); Write-Output $t.Count":
        "Write-Output (,[char[]]'ABC')\nWrite-Output 3",
    "$t = 'ABC'[0]; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    "Write-Output ('x' -replace 'x', [char]65); Write-Output ('x' -replace 'x', 'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')":
        "Write-Output 'r5'\nWrite-Output 'r5'",
    "Write-Output ([char]65 + 1); Write-Output ('A' + 1)":
        "Write-Output 'A1'\nWrite-Output 'A1'",
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')":
        "Write-Output 66\nWrite-Output (1 + 'A')",
    "Write-Output ('A' * 3)":
        "Write-Output 'AAA'",
    "Write-Output (([char]65).ToString()); Write-Output (('A').ToString())":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output ('a,b' -split [char]44); Write-Output ('a,b' -split ',')":
        "Write-Output ('a', 'b')\nWrite-Output ('a', 'b')",
    "Write-Output ('xyx'.Replace([char]120, [char]122)); Write-Output ('xyx'.Replace('x', 'z'))":
        "Write-Output 'zyz'\nWrite-Output 'zyz'",
    "Write-Output ('{0}' -f [char]65); Write-Output ('{0}' -f 'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output (([char]65, [char]66) -join ''); Write-Output (('A', 'B') -join '')":
        "Write-Output 'AB'\nWrite-Output 'AB'",
    "Write-Output ([string][char]65); Write-Output ([string]'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    '$c = [char]65; $s = \'A\'; Write-Output "$c"; Write-Output "$s"':
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])":
        'Write-Output ($True)\nWrite-Output ($False)',
    "Write-Output (([char]65).Length); Write-Output (('A').Length)":
        'Write-Output 1\nWrite-Output 1',
    "Write-Output (([char]65).Count); Write-Output (('A').Count)":
        'Write-Output 1\nWrite-Output 1',
    "Write-Output ([char]65 -eq 'A'); Write-Output ('A' -eq 'A')":
        'Write-Output ($True)\nWrite-Output ($True)',
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }':
        'foreach ($e in [char]65) {\n  Write-Output $e\n}',
    "$t = 'AB'.Count; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    '$t = (5).Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = (5).Length; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    "$t = 1 + 'AB'.Count; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    '$t = @(1, 2, 3).Rank; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = @(1, 2, 3).Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3)\nWrite-Output 3',
    '$t = @(1, 2, 3).Length; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3)\nWrite-Output 3',
    "$t = 'AB'.Length; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    'Write-Output ((5).PSTypeNames)':
        "Write-Output ('System.Int32', 'System.ValueType', 'System.Object')",
    "Write-Output (('AB').PSTypeNames)":
        "Write-Output ('System.String', 'System.Object')",
    '$t = (5).Rank; Write-Output (,$t)':
        'Write-Output (,$Null)',
    "$t = 'AB'.Zqnope; Write-Output (,$t)":
        'Write-Output (,$Null)',
    '$t = (5).Zqnope; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = $null.Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = @(); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    '$t = , 1; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,1))\nWrite-Output 1',
    '$t = 0xFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFF)\nWrite-Output 0xFF',
    '$s = 0xFF; $t = "$s"; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'255')\nWrite-Output '255'",
    '$t = 0x7FFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x7FFFFFFF)\nWrite-Output 0x7FFFFFFF',
    '$t = 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFF)\nWrite-Output 0xFFFFFFFF',
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-91)\nWrite-Output (-91)',
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFFFFFFFFFF)\nWrite-Output 0xFFFFFFFFFFFFFFFF',
    '$t = 1kb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1kb)\nWrite-Output 1kb',
    '$t = 1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = 10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10d)\nWrite-Output 10d',
    '$t = 0xFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1L)\nWrite-Output (-1L)',
    '$t = 1kb + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1024)\nWrite-Output 1024',
    '$t = 1L + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = 10d + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10d)\nWrite-Output 10d',
    '$t = 2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648)\nWrite-Output 2147483648',
    '$t = 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5)\nWrite-Output 1.5',
    '$t = -0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-0.0)\nWrite-Output (-0.0)',
    '$t = 1e3; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1e3)\nWrite-Output 1e3',
    "$t = 'a' + 1.5; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1.5')\nWrite-Output 'a1.5'",
    '$t = [string]1.5; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.5')\nWrite-Output '1.5'",
    '$t = [string]1E20; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1E+20')\nWrite-Output '1E+20'",
    '$t = [string]0.0000001; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1E-07')\nWrite-Output '1E-07'",
    '$t = [string]1.5E-7; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.5E-07')\nWrite-Output '1.5E-07'",
    '$t = 4gb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,4gb)\nWrite-Output 4gb',
    '$t = 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$t = 10D; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10D)\nWrite-Output 10D',
    '$t = 1l; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1l)\nWrite-Output 1l',
    '$t = 0xFFL; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFL)\nWrite-Output 0xFFL',
    '$t = 0x100000000; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x100000000)\nWrite-Output 0x100000000',
    '$t = 0x7FFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x7FFFFFFFFFFFFFFF)\nWrite-Output 0x7FFFFFFFFFFFFFFF',
    '$t = 9223372036854775807; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9223372036854775807)\nWrite-Output 9223372036854775807',
    '$t = 9223372036854775808; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9223372036854775808)\nWrite-Output 9223372036854775808',
    '$t = 100000000000000000000000000000000; Write-Output (,$t); Write-Output $t':
        'Write-Output (,100000000000000000000000000000000)\nWrite-Output 100000000000000000000000000000000',
    '$t = 007; Write-Output (,$t); Write-Output $t':
        'Write-Output (,007)\nWrite-Output 007',
    '$t = 0xFFFFFFFFL; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFFL)\nWrite-Output 0xFFFFFFFFL',
    '$t = 1lkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1lkb)\nWrite-Output 1lkb',
    '$t = 1dkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1dkb)\nWrite-Output 1dkb',
    '$t = 0x0000000000000001; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x0000000000000001)\nWrite-Output 0x0000000000000001',
    '$t = -2147483649; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483649)\nWrite-Output (-2147483649)',
    '$t = 1.5L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5L)\nWrite-Output 1.5L',
    '$t = 2.5L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.5L)\nWrite-Output 2.5L',
    '$t = -(2147483648); Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648L)\nWrite-Output (-2147483648L)',
    '$t = -(2147483647); Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483647)\nWrite-Output (-2147483647)',
    '$t = - 2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648L)\nWrite-Output (-2147483648L)',
    '$t = - 2147483647; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483647)\nWrite-Output (-2147483647)',
    '$t = 1.5kb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5kb)\nWrite-Output 1.5kb',
    '$t = 0xFFkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFkb)\nWrite-Output 0xFFkb',
    '$t = 10 - $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10)\nWrite-Output 10',
    '$t = $null + 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    '$t = $null - 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = 10 - $null + 3; Write-Output (,$t); Write-Output $t':
        'Write-Output (,13)\nWrite-Output 13',
    '$t = $null -band 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$a = $null; $b = 5; $t = $a * $b; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$a = $null; $t = $a * 5; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = $null * 1; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = 2147483647 + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = 512MB * 512MB; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.8823037615171174e+17)\nWrite-Output 2.8823037615171174e+17',
    '$t = 9223372036854775807 + 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = 100000000000000d * 100000000000000d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10000000000000000000000000000d)\nWrite-Output 10000000000000000000000000000d',
    '$t = 10000000000000000000000000000d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10000000000000000000000000000d)\nWrite-Output 10000000000000000000000000000d',
    '$t = 1E+28d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1E+28d)\nWrite-Output 1E+28d',
    "$t = 12 + '0xabc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2760)\nWrite-Output 2760',
    "$t = 5 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,10)\nWrite-Output 10',
    "$t = '5' + 5; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'55')\nWrite-Output '55'",
    "$t = [int]'0x10'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,16)\nWrite-Output 16',
    '$t = -2147483647 - 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    '$t = -2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    '$t = 10, 20, 30, 20, 10 -ne 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(10, 30, 10))\nWrite-Output (10, 30, 10)',
    '$t = 10, 20, 30 -eq 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(,20))\nWrite-Output (,20)',
    '$t = 10 -ne 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [string]('a', 'b'); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a b')\nWrite-Output 'a b'",
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        "$OFS = '-'\nWrite-Output 'a-b'",
    '$OFS = \'-\'; Write-Output "$(1, 2)"':
        "$OFS = '-'\nWrite-Output '1-2'",
    "$t = ('A').ToUpper(); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'A')\nWrite-Output 'A'",
    "$t = ('A').Substring(0); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'A')\nWrite-Output 'A'",
    '$t = ([char]65).ToString(); Write-Output (,$t); Write-Output $t':
        "Write-Output (,'A')\nWrite-Output 'A'",
    '$t = [int][char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48)\nWrite-Output 48',
    "$t = [int]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = 1 + '2147483648'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2147483649L)\nWrite-Output 2147483649L',
    "$t = 1 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,6)\nWrite-Output 6',
    "$t = 1 + '1e3'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1001.0)\nWrite-Output 1001.0',
    '$t = -bnot 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = -bnot 0xFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-256)\nWrite-Output (-256)',
    '$t = -bnot [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-6)\nWrite-Output (-6)',
    '$t = -bnot [uint32]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]4294967288)\nWrite-Output ([uint32]4294967288)',
    '$t = -bnot 1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2L)\nWrite-Output (-2L)',
    '$t = -bnot 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-3)\nWrite-Output (-3)',
    '$t = -bnot $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    "$t = -bnot '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-6)\nWrite-Output (-6)',
    "$t = -bnot 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = -BNot 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = -bnot [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-66)\nWrite-Output (-66)',
    '$t = -bnot $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2)\nWrite-Output (-2)',
    '$t = -bnot 10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-11)\nWrite-Output (-11)',
    '$t = -bnot 3000000000.0; Write-Output (,$t); Write-Output $t':
        '$t = -BNot 3000000000.0\nWrite-Output (,$t)\nWrite-Output $t',
    'Write-Output "abc".Length':
        'Write-Output 3',
    "Write-Output 'abc'.Length":
        'Write-Output 3',
    '$t = @(@(1, 2)); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@(@(1, 2)))\nWrite-Output 2',
    '$t = @((1, 2)); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@((1, 2)))\nWrite-Output 2',
    '$t = @(@(1, 2), 3); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(@(1, 2), 3))\nWrite-Output 2',
    '$t = ,(1, 2); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,(1, 2)))\nWrite-Output 1',
    '$t = (1, 2), 3; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,((1, 2), 3))\nWrite-Output 2',
    "$t = 'a', 1; Write-Output (,$t); Write-Output $t":
        "Write-Output (,('a', 1))\nWrite-Output ('a', 1)",
    '$t = [int]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    '$t = [long]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    '$t = [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[byte]5)\nWrite-Output ([byte]5)',
    '$t = [sbyte]-5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[sbyte]-5)\nWrite-Output ([sbyte]-5)',
    '$t = [int16]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[int16]7)\nWrite-Output ([int16]7)',
    '$t = [uint16]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint16]7)\nWrite-Output ([uint16]7)',
    '$t = [uint32]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]7)\nWrite-Output ([uint32]7)',
    '$t = [uint64]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint64]7)\nWrite-Output ([uint64]7)',
    '$t = [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint64]18446744073709551615)\nWrite-Output ([uint64]18446744073709551615)',
    '$t = [int]1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [int]2.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [int]1.4; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = [int]-1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2)\nWrite-Output (-2)',
    '$t = [long]1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2L)\nWrite-Output 2L',
    '$t = [double]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5.0)\nWrite-Output 5.0',
    '$t = [decimal]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5d)\nWrite-Output 5d',
    '$t = [double]1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5)\nWrite-Output 1.5',
    '$t = [int]10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10)\nWrite-Output 10',
    '$t = [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]0)\nWrite-Output ([char]0)',
    '$t = [char]65535; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65535)\nWrite-Output ([char]65535)',
    '$t = [int][char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,65)\nWrite-Output 65',
    '$t = [bool]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [bool]''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool]'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [int]$true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = [string]5; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'5')\nWrite-Output '5'",
    '$t = [string]$true; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'True')\nWrite-Output 'True'",
    '$t = [string]10d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'10')\nWrite-Output '10'",
    "$t = [int]'5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]' 5 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [int]'+7'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,7)\nWrite-Output 7',
    "$t = [int]'007'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,7)\nWrite-Output 7',
    "$t = [int]'.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [int]'5.'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    '$t = [int]"`t`r5`n"; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]'7.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,8)\nWrite-Output 8',
    "$t = [int]'2.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    "$t = [byte]'0x80'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[byte]128)\nWrite-Output ([byte]128)',
    "$t = [sbyte]'0x80'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[sbyte]-128)\nWrite-Output ([sbyte]-128)',
    "$t = [uint16]'0xFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[uint16]65535)\nWrite-Output ([uint16]65535)',
    "$t = [int]'0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1)\nWrite-Output (-1)',
    "$t = [char]'A'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    "$t = [bool]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [string]'foo'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'foo')\nWrite-Output 'foo'",
    '$t = [int]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = [string]$null; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'')\nWrite-Output ''",
    '$t = [bool]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]0)\nWrite-Output ([char]0)',
    "$t = 'a' + $null; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a')\nWrite-Output 'a'",
    "$t = 'a' + $true; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aTrue')\nWrite-Output 'aTrue'",
    "$t = 'a' + 1.50d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1.50')\nWrite-Output 'a1.50'",
    "$t = [Convert]::ToInt32('FFFFFFFF', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1)\nWrite-Output (-1)',
    "$t = [Convert]::ToInt32('80000000', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    "$t = [Convert]::ToInt32(' 5 '); Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [Convert]::ToInt32('017', 8); Write-Output (,$t); Write-Output $t":
        'Write-Output (,15)\nWrite-Output 15',
    "$t = [Convert]::ToByte('FF', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,[byte]255)\nWrite-Output ([byte]255)',
    '$t = [Convert]::ToInt64(5); Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    '$t = [Convert]::ToInt32(1.5); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [Convert]::ToInt32(1.5d); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [Convert]::ToInt32($null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = [Convert]::ToChar(65); Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    "$t = 'abc' -as [int]; Write-Output (,$t); Write-Output $t":
        "$t = 'abc' -As [int]\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 5 -as [long]; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    '$t = 300 -as [byte]; Write-Output (,$t); Write-Output $t':
        '$t = 300 -As [byte]\nWrite-Output (,$t)\nWrite-Output $t',
    'function f { ,$args }; $t = f 1 2; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2))\nWrite-Output 2',
    "$t = 'abc' -replace '(?<x>b)', '[${x}]'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a[b]c')\nWrite-Output 'a[b]c'",
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t":
        "$Null = 'abc' -Match '(b)'\n$t = $Matches[1]\nWrite-Output (,$t)\nWrite-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t":
        "$a = 'a,b,c' -Split ',', '2'\n$t = $a.Count\nWrite-Output (,$t)\nWrite-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t":
        "$a = 'a,b,c' -Split ',', '2'\n$t = $a[1]\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'A' -ceq 'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 'A' -ieq 'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -ceq 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        '$i = 0\nif ($False -and ($i++)) {}\n$t = $i\nWrite-Output (,$t)\nWrite-Output $t',
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        '$i = 0\nif ($True -or ($i++)) {}\n$t = $i\nWrite-Output (,$t)\nWrite-Output $t',
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (@(0)) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if ((0, 0)) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    'function f { $i = 0; $i++; $i++; $i }; $t = f; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(0, 1, 2))\nWrite-Output (0, 1, 2)',
    "function f { $s = 'abc'; $s++; $s }; $t = f; Write-Output (,$t); Write-Output $t":
        'Write-Output (,(0, 1))\nWrite-Output (0, 1)',
    'function g { ,(1, 2) }; $t = @(g); Write-Output $t.Count; Write-Output (,$t[0])':
        'Write-Output 2\nWrite-Output (,1)',
    "$t = @('1') -contains 1; Write-Output (,$t); Write-Output $t":
        "$t = @('1') -Contains 1\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = @(1) -contains '1'; Write-Output (,$t); Write-Output $t":
        "$t = @(1) -Contains '1'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'a*' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        "$t = 'a*' -Like 'a`*'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'ab' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        "$t = 'ab' -Like 'a`*'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'b' -like '[!a]'; Write-Output (,$t); Write-Output $t":
        "$t = 'b' -Like '[!a]'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '1_0' -band 15; Write-Output (,$t); Write-Output $t":
        "$t = '1_0' -BAnd 15\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = [byte](200 * 2); Write-Output (,$t); Write-Output $t':
        '$t = [byte]400\nWrite-Output (,$t)\nWrite-Output $t',
    'function f { $null; 1; $null }; $t = f; Write-Output $t.Count; Write-Output (,$t)':
        'Write-Output 1\nWrite-Output (,1)',
    "$t = 'ſ' -match 's'; Write-Output (,$t); Write-Output $t":
        "$t = 'ſ' -Match 's'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 2147483647 * 2147483647; Write-Output (,$t); Write-Output $t':
        'Write-Output (,4.6116860141324206e+18)\nWrite-Output 4.6116860141324206e+18',
    '$t = 9223372036854775807L + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = 9223372036854775807L - -1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = -2147483648 - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-9.22337203900226e+18)\nWrite-Output (-9.22337203900226e+18)',
    '$t = -2147483648 % -1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = -2147483648 / -1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = 0 - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.8446744073709552e+19)\nWrite-Output (-1.8446744073709552e+19)',
    '$t = 1 + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.8446744073709552e+19)\nWrite-Output 1.8446744073709552e+19',
    '$t = [uint64]18446744073709551615 + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.8446744073709552e+19)\nWrite-Output 1.8446744073709552e+19',
    '$t = -1 * [uint64]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = 2147483647 * [uint32]4294967295; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372030412325e+18)\nWrite-Output 9.223372030412325e+18',
    '$t = -1 -band [uint32]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]1)\nWrite-Output ([uint32]1)',
    '$t = 1 / [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5.421010862427522e-20)\nWrite-Output 5.421010862427522e-20',
    '$t = 0 + [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,65)\nWrite-Output 65',
    '$t = [char]48 -band [byte]255; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48)\nWrite-Output 48',
    '$t = [char]48 -bxor [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = 1.5 * [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,72.0)\nWrite-Output 72.0',
    '$t = [char]48 - 0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48.0)\nWrite-Output 48.0',
    '$t = [char]65 -bxor 32; Write-Output (,$t); Write-Output $t':
        'Write-Output (,97)\nWrite-Output 97',
    "$t = 0 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = $true + ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    "$t = 1 + '0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = 1 + '1kb'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1025)\nWrite-Output 1025',
    "$t = 1 + '1.5L'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,3L)\nWrite-Output 3L',
    '$t = [byte]1 -shl 4; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl 4\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [byte]1 -shl -1; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl -1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [single]1.5 -shl 1; Write-Output (,$t); Write-Output $t':
        '$t = [single]1.5 -Shl 1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = 1L -shl 64; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = $true + 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = $null + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -band [uint32]1; Write-Output (,$t); Write-Output $t':
        '$t = $Null -BAnd [uint32]1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true * 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t':
        '$v = [single]1.5\n$t = $v -Shl 1\nWrite-Output (,$t)\nWrite-Output $t',
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t':
        '$t = $Null -BAnd [uint32]1\nWrite-Output (,$t)\nWrite-Output $t',
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl 4\nWrite-Output (,$t)\nWrite-Output $t',
    "$t = 1 + ' 7 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,8)\nWrite-Output 8',
    "$t = 1 + '+5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,6)\nWrite-Output 6',
    "$t = 1 + '  '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    "$t = '5' - 1; Write-Output (,$t); Write-Output $t":
        'Write-Output (,4)\nWrite-Output 4',
    "$t = 1 - '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-4)\nWrite-Output (-4)',
    "$t = '5' * 2; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'55')\nWrite-Output '55'",
    "$t = '10' -band 6; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    "$t = '5' / 2; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2.5)\nWrite-Output 2.5',
    "$t = '1e400' + 1; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'1e4001')\nWrite-Output '1e4001'",
    '$t = $true + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = 1 + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = $true - 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = 1 - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = $true * 2; Write-Output (,$t); Write-Output $t':
        '$t = $True * 2\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = 2 * $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = $true -band 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = $false + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true / 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true + 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.5)\nWrite-Output 2.5',
    '$t = $true -bxor $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = @(1, 2) + @(3, 4); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 3, 4))\nWrite-Output 4',
    '$t = @(1, 2) + 5; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 5))\nWrite-Output 3',
    '$t = @(1, 2) * 2; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 1, 2))\nWrite-Output 4',
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count':
        '$t = @(1, 2) -BAnd 1\nWrite-Output (,$t)\nWrite-Output $t.Count',
    '$t = @() + 1; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,1))\nWrite-Output 1',
    '$t = @(1, 2) + $null; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, $Null))\nWrite-Output 3',
    '$t = $null + @(1, 2); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2))\nWrite-Output 2',
    "$t = @(1, 2) + 'a'; Write-Output (,$t); Write-Output $t.Count":
        "Write-Output (,(1, 2, 'a'))\nWrite-Output 3",
    '$t = @(1, 2) * 0; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    "$t = $null + 'abc'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'abc')\nWrite-Output 'abc'",
    '$t = $null + [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = $null + 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$t = $true -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -and 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -and 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0 -or 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -xor $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 5 -xor 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'abc' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '' -or $false; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '0' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'false' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = ' ' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [char]'0' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 0.0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = -0.0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0.0d -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [uint64]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @() -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(0, 0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = @($false) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @($null) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(@()) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(1, 2) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool][char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool][char]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]-0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]0.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(0, 0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]@($false); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@($null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(@()); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool]' '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [bool]'false'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not @(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not @(0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = -not '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = -not [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,(,0)) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,(,@())) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,[char]0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (,'') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = (,' ') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,0.0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (,0.0d) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool](,(,0)); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,[char]0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not (,[char]0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = - '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = - '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-5)\nWrite-Output (-5)',
    "$t = if (- '0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (0) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = (,@(1, 2)) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,$true) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [byte]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0L -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 1.5d -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -and [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -and ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -and @(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]65 -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = @() * 5000; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    '$t = (,@()) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (,(,(,0))) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,1) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (,'a') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,[char]65) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = @(1, 2, 3) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,@()); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool](,1); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = - 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = - 0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0.0)\nWrite-Output 0.0',
    '$t = - 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.5)\nWrite-Output (-1.5)',
    '$t = - $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    '$t = - $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-65)\nWrite-Output (-65)',
    '$t = - [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.5d)\nWrite-Output (-1.5d)',
    '$t = - [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = - [uint32]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.0)\nWrite-Output (-1.0)',
    '$t = - (-2147483648); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-9223372036854775807L)\nWrite-Output (-9223372036854775807L)',
    '$t = - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.8446744073709552e+19)\nWrite-Output (-1.8446744073709552e+19)',
    "$t = - '1e3'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1000.0)\nWrite-Output (-1000.0)',
    "$t = - ' 5 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-5)\nWrite-Output (-5)',
    "$t = - ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    '$t = [bool][sbyte]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][int16]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][uint16]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][uint32]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,$null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool](,@(1, 2)); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]@(0, 0, 0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = -not (- '0'); Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (- '0') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = if (- '5') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (-5) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = $null -eq 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0 -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '' -eq 0; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '' -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $null -eq ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '' -eq $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '0' -eq 0; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 0 -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '1.0' -eq 1; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 1 -eq '1.0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -lt 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '10' -lt '9'; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LT '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -lt 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LT 9\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 10 -lt '9'; Write-Output (,$t); Write-Output $t":
        "$t = 10 -LT '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -ge 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -GE 9\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 10 -ge '9'; Write-Output (,$t); Write-Output $t":
        "$t = 10 -GE '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -ne 10; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 10 -ne '10'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 'B' -gt 'a'; Write-Output (,$t); Write-Output $t":
        "$t = 'B' -GT 'a'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = $true -eq 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -eq 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 2 -eq $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -eq 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'abc' -eq $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -eq ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $false -eq 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -ne 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -gt $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $false -lt 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $true -ge 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -ne 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -ne $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $null -lt 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -gt 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -ge 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -le 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -lt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 1 -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -le $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 1 -ge $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -ne $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'abc' -lt $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $false -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -eq $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0 -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -lt 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '' -gt $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $null -lt ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $false -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 1 -lt 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -LT 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 1 -gt 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -GT 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 1 -eq 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -Eq 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 1 -ne 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -NE 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 1 -lt '5'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -LT '5'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = -79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-79228162514264337593543950335d)\nWrite-Output (-79228162514264337593543950335d)',
    '$t = - 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-79228162514264337593543950335d)\nWrite-Output (-79228162514264337593543950335d)',
    '$t = 7922816251426433759354395033.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,7922816251426433759354395033.5d)\nWrite-Output 7922816251426433759354395033.5d',
    '$t = 1.2345678901234567890123456789d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.2345678901234567890123456789d)\nWrite-Output 1.2345678901234567890123456789d',
    '$t = 79228162514264337593543950335d - 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950334d)\nWrite-Output 79228162514264337593543950334d',
    '$t = 79228162514264337593543950334d + 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335d * 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335d / 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 1.2345678901234567890123456789d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.2345678901234567890123456789d)\nWrite-Output 1.2345678901234567890123456789d',
    '$t = 1.50d + 1.50d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.00d)\nWrite-Output 3.00d',
    '$t = 1d / 3d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0.3333333333333333333333333333d)\nWrite-Output 0.3333333333333333333333333333d',
    '$t = [string]1.50d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.50')\nWrite-Output '1.50'",
    '$t = [string]0.5d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'0.5')\nWrite-Output '0.5'",
    "$t = 'a' + 0.5d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a0.5')\nWrite-Output 'a0.5'",
    "$t = 'a' + $false; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aFalse')\nWrite-Output 'aFalse'",
    '$t = [string]$false; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'False')\nWrite-Output 'False'",
    "$t = 'a' + 1L; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1')\nWrite-Output 'a1'",
    '$t = [string]1L; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1')\nWrite-Output '1'",
    "$t = 'a' + 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a79228162514264337593543950335')\nWrite-Output 'a79228162514264337593543950335'",
    '$t = [string]79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'79228162514264337593543950335')\nWrite-Output '79228162514264337593543950335'",
    "$t = 'a' + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a18446744073709551615')\nWrite-Output 'a18446744073709551615'",
    '$t = [string][uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'18446744073709551615')\nWrite-Output '18446744073709551615'",
    "$t = 'a' + -1.50d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a-1.50')\nWrite-Output 'a-1.50'",
    '$t = [string]-1.50d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'-1.50')\nWrite-Output '-1.50'",
    "$t = 'a' + [char]65; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aA')\nWrite-Output 'aA'",
    '$t = - 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    '$t = - 0.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    '$t = 79228162514264337593543950335d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    "$t = '1000' -eq 1e3d; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'a' + 1e3d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1000')\nWrite-Output 'a1000'",
    "$t = 'x' + 1.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = $true * '1'; Write-Output (,$t); Write-Output $t":
        "$t = $True * '1'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 2 * [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,96)\nWrite-Output 96',
    '$t = $true - 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True - 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true + 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True + 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = 1.0d - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    "$t = [char]48 - '1'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,47)\nWrite-Output 47',
    '$t = $true - 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-0.5)\nWrite-Output (-0.5)',
    '$t = $true / 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True / 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    "$t = [char]48 -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]48 -eq 48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65 -eq [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65 -ceq [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]97 -lt [char]66; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]65 -lt [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'ss' -eq [char]0x00DF; Write-Output (,$t); Write-Output $t":
        "$t = 'ss' -Eq [char]223\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = [char]0x00DF -eq 'ss'; Write-Output (,$t); Write-Output $t":
        "$t = [char]223 -Eq 'ss'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = $true -lt 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -gt 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -lt -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -gt -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -le -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(1, 2) -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,@())\nWrite-Output @()',
    "$t = '2' -lt '10'; Write-Output (,$t); Write-Output $t":
        "$t = '2' -LT '10'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -le '9'; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LE '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -gt 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -GT 9\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 1.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.0d)\nWrite-Output 1.0d',
    '$t = [string]1.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.0')\nWrite-Output '1.0'",
    '$t = 1.0d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    "$t = 'x' + 1.10d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.10')\nWrite-Output 'x1.10'",
    '$t = [string]1.10d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.10')\nWrite-Output '1.10'",
    '$t = 1.10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.10d)\nWrite-Output 1.10d',
    '$t = [string]1.000d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.000')\nWrite-Output '1.000'",
    "$t = 'x' + 2.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x2')\nWrite-Output 'x2'",
    '$t = [string]2.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'2.0')\nWrite-Output '2.0'",
    '$t = [string]0.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'0.0')\nWrite-Output '0.0'",
    "$z = 1.0d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.0')\nWrite-Output 'x1.0'",
    "$z = 1.10d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.10')\nWrite-Output 'x1.10'",
    "$t = 'x' + 1.00d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 1.000d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 1.100d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.100')\nWrite-Output 'x1.100'",
    "$t = 'x' + 10.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x10')\nWrite-Output 'x10'",
    "$t = 'x' + 0.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x0')\nWrite-Output 'x0'",
    "$t = 'x' + 1.2300d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.2300')\nWrite-Output 'x1.2300'",
    "$z = 1.00d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.00')\nWrite-Output 'x1.00'",
    "$z = 1.000d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.000')\nWrite-Output 'x1.000'",
    "$z = 1.100d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.100')\nWrite-Output 'x1.100'",
    '$t = 1.00d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.000d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.10d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.10d)\nWrite-Output 1.10d',
    '$t = 1.100d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.100d)\nWrite-Output 1.100d',
    '$t = 1.0d - 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d * 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d / 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 2.50d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.50d)\nWrite-Output 2.50d',
    '$t = 1.500d + 1.500d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.000d)\nWrite-Output 3.000d',
    '$t = 1.0d + 2.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3d)\nWrite-Output 3d',
    '$z = 1.100d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.100d)\nWrite-Output 1.100d',
    '$z = 1.50d; $t = $z + 1.50d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.00d)\nWrite-Output 3.00d',
    '$t = - 1.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = - 1.00d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = - 1.10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.10d)\nWrite-Output (-1.10d)',
    '$t = [string]1.00d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.00')\nWrite-Output '1.00'",
    '$t = [string]1.100d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.100')\nWrite-Output '1.100'",
    "$t = 'x' + (1.0d); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "trap { continue }; [int]'a'; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'after'",
    "trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  continue\n}\nif ($True) {\n  throw 'e'\n  Write-Host 'tail'\n}"
        "\nWrite-Host 'next'",
    "trap { continue }; foreach ($i in 1..2) { throw 'e'; Write-Host 'tail' }; "
    "Write-Host 'next'":
        "trap {\n  continue\n}\nforeach ($i in 1, 2) {\n  throw 'e'\n  Write-Host 'tail'\n}"
        "\nWrite-Host 'next'",
    "if ($true) { trap { continue }; Write-Host 'in'; throw 'e' }; Write-Host 'after'":
        "if ($True) {\n  trap {\n    continue\n  }\n  Write-Host 'in'\n  throw 'e'\n}"
        "\nWrite-Host 'after'",
    "trap { Write-Host 'outer'; continue }; if ($true) { trap { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  Write-Host 'outer'\n  continue\n}\nif ($True) {\n  trap {"
        "\n    Write-Host 'inner'\n    continue\n  }\n  throw 'e'\n  Write-Host 'tail'\n}"
        "\nWrite-Host 'next'",
    "trap { Write-Host 'outer'; continue }; if ($true) { "
    "trap [System.IO.IOException] { Write-Host 'inner'; continue }; "
    "throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  Write-Host 'outer'\n  continue\n}\nif ($True) {"
        "\n  trap [System.IO.IOException] {\n    Write-Host 'inner'\n    continue\n  }"
        "\n  throw 'e'\n  Write-Host 'tail'\n}\nWrite-Host 'next'",
    "trap { }; [int]'a'; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'after'",
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'":
        "trap {\n  Write-Host 'e'\n  continue\n}\n[int]'a'\nSet-Alias c Write-Output\nWrite-Output 'hi'",
    "trap { continue }; 1/0; Write-Host 'after'":
        "1 / 0\nWrite-Host 'after'",
    "trap { continue }; $x = \"$(1/0)$(Set-Alias zzq Write-Output)\"; zzq 'hi'":
        "trap {\n  continue\n}\n$Null = \"$(1 / 0)$(Set-Alias zzq Write-Output)\"\nzzq 'hi'",
    "throw 'e'; Write-Host 'after'":
        "throw 'e'",
    "trap { continue }; iex 'throw 1'; Write-Host 'after'":
        'throw 1',
    "trap { continue }; $s = { throw 'x' }; [int]'a'; Write-Host 'after'":
        "trap {\n  continue\n}\n$Null = {\n  throw 'x'\n}\n[int]'a'\nWrite-Host 'after'",
    "New-Variable ErrorActionPreference Stop -Force; trap { continue }; [int]'a'; Write-Host 'after'":
        "New-Variable ErrorActionPreference Stop -Force\n[int]'a'\nWrite-Host 'after'",
    "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'; trap { continue }; Get-Item nope; Write-Host 'after'":
        "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'\nGet-Item nope\nWrite-Host 'after'",
    "function Raise { throw 'e' }; function Wrap { trap { continue }; Raise; Write-Host 'in' }; Wrap; Write-Host 'after'":
        "function Raise {\n  throw 'e'\n}\nfunction Wrap {\n  Raise\n  Write-Host 'in'\n}\nWrap\nWrite-Host 'after'",
    "function K { $Null = [Int]'abc' }; K; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = [Int]'abc'; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = 1 / 0; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = [Int]'42'; Write-Host 'A'":
        "Write-Host 'A'",
    "function K { param([int] $x = '42') }; K; Write-Host 'A'":
        "Write-Host 'A'",
    "function K { $Null = 1 }; Write-Error 'e'; K; Write-Host $?":
        "function K {}\nWrite-Error 'e'\nK\nWrite-Host $?",
    'function K { $Null = 1 }; K; Write-Host ($function:K -ne $Null)':
        'function K {}\nK\nWrite-Host ($function:K -NE $Null)',
    "function K { $Null = 1 }; K; $Null = (Get-Command K).Name; Write-Host 'A'":
        "$Null = (Get-Command K).Name\nWrite-Host 'A'",
    "function vnMTH { $Null = 1 }; vnMTH; $Null = (Get-Command *vnMT*).Name; Write-Host 'A'":
        "$Null = (Get-Command *vnMT*).Name\nWrite-Host 'A'",
    'function K { $Null = 1 }; K; $b = { K }; Write-Host $b':
        '$b = {}\nWrite-Host $b',
    'function Measure-Object { $Null = 1 }; Measure-Object; 1, 2, 3 | measure':
        'function Measure-Object {}\nMeasure-Object\n1, 2, 3 | Measure-Object',
    "function Get-Language { $Null = 668 }; language; Write-Host 'A'":
        "function Get-Language {}\nlanguage\nWrite-Host 'A'",
    "function q { $Null = 1 }; ${function:q} = { Write-Host 'P' }; q":
        "function q {}\n$function:q = {\n  Write-Host 'P'\n}\nq",
    "$n = 'q'; function K { $Null = 1 }; Set-Alias $n K; q; Write-Host 'A'":
        "Write-Host 'A'",
    "function K { [Alias('q')] param() $Null = 1 }; q; Write-Host 'A'":
        "q\nWrite-Host 'A'",
    "$env:B = 'function K { Write-Host P }'; Invoke-Expression $env:B; function K { 42 }; $x = K; Write-Output $x; $env:C = 'K'; Invoke-Expression $env:C":
        'function K {\n  Write-Host P\n}\nWrite-Output 42\nK',
    "$Null = (Get-Command K).Name; function K { $Null = 1 }; K; Write-Host 'A'":
        "$Null = (Get-Command K).Name\nWrite-Host 'A'",
    "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty -Value { Write-Host 'S' }; $Null = 'abc'.Zq; Write-Host 'A'":
        "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty -Value {\n  Write-Host 'S'\n}\nWrite-Host 'A'",
    "Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty -Value { 99 }; Write-Host 'abc'.Length":
        'Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty -Value {\n  99\n}\nWrite-Host 3',
    "$Null = 'abc'.Length; Write-Host 'A'":
        "Write-Host 'A'",
    "Write-Host 'abc'.Length":
        'Write-Host 3',
    "try { zzq0000=5; 'tail' } catch {}; 'next'":
        '',
    "try { zzq0000=5 } catch {}; 'next'":
        "'next'",
    "function zzqfoo1 { 'boom' }; zzqfoo1":
        "'boom'",
    "try { zzqq0 =5 } catch {}; Write-Host 'after'":
        "Write-Host 'after'",
    "try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }":
        "try {\n  Write-Host 'quiet'\n} catch {\n  Write-Host 'caught'\n}",
    'function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        'function f {\n  $Input\n  $Input | ForEach-Object {\n'
        '    Write-Host "seen:${_}"\n  }\n}\n1, 2 | f',
    'function f { [void]$input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        'function f {\n  [void]$Input\n  $Input | ForEach-Object {\n'
        '    Write-Host "seen:${_}"\n  }\n}\n1, 2 | f',
    "try { item =5 } catch {}; Write-Host 'after'":
        "try {\n  Get-Item =5\n} catch {}\nWrite-Host 'after'",
    "trap { continue }; zzq0000=5; Write-Host 'after'":
        "zzq0000=5\nWrite-Host 'after'",
    "function f { try { 'tail' } catch {} }; Write-Host (f)":
        "Write-Host 'tail'",
    '$n = 1; $n += 2; Write-Output $n':
        'Write-Output 3',
    '$n = 5; $n -= 2; Write-Output $n':
        'Write-Output 3',
    '$n = 1; $n++; Write-Output $n':
        'Write-Output 2',
    "$s = 'a'; $s += 'b'; $s += 'c'; Write-Output $s":
        "Write-Output 'abc'",
    "$c = 'Write-Out'; $c += 'put 5'; Invoke-Expression $c":
        'Write-Output 5',
}
