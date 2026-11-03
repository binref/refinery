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
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\nthrow 'x'\nWrite-Host 'rest'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "throw 'x'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "throw 'x'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "throw 'x'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\ntrap {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        '$p = @($Null, $True)\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @($null, $true)\n'
    "try { throw 'x' } catch { if ($p[1]) { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "$ErrorActionPreference = 'Stop'; $null = [int]$p[0]; Write-Host 'rest'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        "$ErrorActionPreference = 'Stop'\n"
        '$Null = [int]$p[0]\n'
        "Write-Host 'rest'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "$null = $($null = [int]$p[0]; Write-Host 'rest'); Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        '$Null = $($Null = [int]$p[0]\n'
        "Write-Host 'rest')\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n$p = @('a')\n$null = [int]$p[0]; Write-Host 'rest'":
        "$ErrorActionPreference = 'SilentlyContinue'\nWrite-Host 'rest'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "foreach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'foreach ($i in 1, 2) {\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\nfunction f1 {\n  Write-Host 'rest'\n}\nf1\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  f1\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "function f1 { try { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.IO.IOException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} finally {\n'
        "  Write-Host 'fin'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { Write-Host 't' } finally { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  Write-Host 't'\n"
        '} finally {\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { foreach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  foreach ($i in 1, 2) {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { & { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  & {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { try { $null = [int]$p[0] } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    $Null = [int]$p[0]\n'
        '  } finally {}\n'
        "  Write-Host 'rest'\n"
        '} finally {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { try { exit } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a')\n"
    "try { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\nWrite-Host 'rest'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        "$p = @('a', $True)\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "$p = @('a', $true)\n"
    "try { throw 'x' } catch { if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "$ErrorActionPreference = 'Stop'; throw 'x'; Write-Host 'rest'":
        "$ErrorActionPreference = 'SilentlyContinue'\n$ErrorActionPreference = 'Stop'\nthrow 'x'\nWrite-Host 'rest'",
    "$ErrorActionPreference = 'SilentlyContinue'\n$p = @()\n$null = $(throw 'x'; Write-Host 'rest'); Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n$Null = $(throw 'x'\nWrite-Host 'rest')\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "foreach ($i in 1, 2) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'foreach ($i in 1, 2) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  f1\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "function f1 { try { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n$p = @()\nthrow 'x'; Write-Host 'rest'":
        "$ErrorActionPreference = 'SilentlyContinue'\nthrow 'x'\nWrite-Host 'rest'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { Write-Host 't' } finally { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  Write-Host 't'\n"
        '} finally {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { foreach ($i in 1, 2) { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        '  foreach ($i in 1, 2) {\n'
        "    throw 'x'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { & { throw 'x'; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  & {\n'
        "    throw 'x'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        "    throw 'x'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\nWrite-Host 'c'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\nWrite-Host 'c'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        "  throw 'x'\n"
        '} finally {\n'
        "  Write-Host 'fin'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { try { exit } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        "    throw 'x'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    '$p = @()\n'
    "try { try { throw 'x' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {}\n'
        "  Write-Host 'rest'\n"
        '} finally {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'SilentlyContinue'; if ($true) { trap [System.IO.IOException] { continue }; throw 'x' }; Write-Output 'after'":
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Output 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @($null, $null, 'a')\n"
    "trap { throw 'x'; Write-Host 'trest'; continue }; $null = [int]$p[2]; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap {\n'
        "  throw 'x'\n"
        "  Write-Host 'trest'\n"
        '  continue\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap [System.IO.IOException] {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap [System.InvalidCastException] {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "throw 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        '$p = @($Null, $True)\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @($null, $true)\n'
    "try { throw 'x' } catch { if ($p[1]) { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "$ErrorActionPreference = 'Stop'; $null = [int]$p[0]; Write-Host 'rest'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        "$ErrorActionPreference = 'Stop'\n"
        '$Null = [int]$p[0]\n'
        "Write-Host 'rest'",
    "$ErrorActionPreference = 'Stop'\n$p = @('a')\n$null = $($null = [int]$p[0]; Write-Host 'rest'); Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        '$Null = $($Null = [int]$p[0]\n'
        "Write-Host 'rest')\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n$p = @('a')\n$null = [int]$p[0]; Write-Host 'rest'":
        "$ErrorActionPreference = 'Stop'\n$p = @('a')\n$Null = [int]$p[0]\nWrite-Host 'rest'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "foreach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'foreach ($i in 1, 2) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  f1\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "function f1 { try { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "trap { Write-Host 't'; $null = [int]$p[0]; continue }; try { throw 'x' } catch [System.IO.IOException] { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  $Null = [int]$p[0]\n'
        '  continue\n'
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.IO.IOException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} finally {\n'
        "  Write-Host 'fin'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { Write-Host 't' } finally { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        "  Write-Host 't'\n"
        '} finally {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { foreach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  foreach ($i in 1, 2) {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { & { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  & {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { throw 'x' } catch { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { try { $null = [int]$p[0] } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    $Null = [int]$p[0]\n'
        '  } finally {}\n'
        "  Write-Host 'rest'\n"
        '} finally {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { try { exit } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a')\n"
    "try { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $null, 'a')\n"
    "trap { $null = [int]$p[0]; Write-Host 'trest'; continue }; $null = [int]$p[2]; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $Null, 'a')\n"
        'trap {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'trest'\n"
        '  continue\n'
        '}\n'
        '$Null = [int]$p[2]\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n$Null = [int]'a'\nWrite-Host 'rest'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        "$p = @('a', $True)\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($p[1]) {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    "$p = @('a', $true)\n"
    "try { throw 'x' } catch { if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n$p = @()\n$ErrorActionPreference = 'Stop'; throw 'x'; Write-Host 'rest'":
        "$ErrorActionPreference = 'Stop'\n$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n$p = @()\n$null = $(throw 'x'; Write-Host 'rest'); Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n$Null = $(throw 'x'\nWrite-Host 'rest')\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "foreach ($i in 1, 2) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nforeach ($i in 1, 2) {\n  throw 'x'\n}\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n$p = @()\nfunction f1 { throw 'x'; Write-Host 'rest' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nfunction f1 {\n  throw 'x'\n}\nf1\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'function f1 {\n'
        "  throw 'x'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  f1\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "function f1 { try { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n$p = @()\nthrow 'x'; Write-Host 'rest'":
        "$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "trap { Write-Host 't'; throw 'x'; continue }; try { throw 'x' } catch [System.IO.IOException] { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'trap {\n'
        "  Write-Host 't'\n"
        "  throw 'x'\n"
        '  continue\n'
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { Write-Host 't' } finally { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  Write-Host 't'\n"
        '} finally {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}',
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { foreach ($i in 1, 2) { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        '  foreach ($i in 1, 2) {\n'
        "    throw 'x'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { & { throw 'x'; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  & {\n'
        "    throw 'x'\n"
        '  }\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x' } catch { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} finally {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}',
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nWrite-Host 'c'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\nWrite-Host 'c'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntry {\n  throw 'x'\n} finally {\n  Write-Host 'fin'\n}\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { try { exit } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        "    throw 'x'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'\n"
    '$p = @()\n'
    "try { try { throw 'x' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {}\n'
        "  Write-Host 'rest'\n"
        '} finally {}\n'
        "Write-Host 'after'",
    "$ErrorActionPreference = 'Stop'; trap [System.IO.IOException] { continue }; trap [Exception] { continue }; [int]'a'; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap [Exception] {\n  continue\n}\n[int]'a'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'; trap { }; $null = [int]'a'; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap {}\n$Null = [int]'a'\nWrite-Host 'after'",
    "$ErrorActionPreference = 'Stop'; trap { }; trap { continue }; [int]'a'; Write-Host 'after'":
        "$ErrorActionPreference = 'Stop'\ntrap {}\n[int]'a'\nWrite-Host 'after'",
    "$ExecutionContext.InvokeCommand.PreCommandLookupAction = { param($n, $e) if ($n -eq 'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }; try { throw 'x' } catch { Get-Random; Write-Host 'rest' }; Write-Host 'after'":
        '$ExecutionContext.InvokeCommand.PreCommandLookupAction = {\n'
        '  Param($n, $e)\n'
        "  if ($n -Eq 'Get-Random') {\n"
        '    $e.CommandScriptBlock = {\n'
        "      throw 'hijack'\n"
        '    }\n'
        '  }\n'
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  Get-Random\n'
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'Stop'); trap { continue }; [int]'a'; Write-Output 'after'":
        "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'Stop')\n"
        "[int]'a'\n"
        "Write-Output 'after'",
    "$Null = 'abc'.Length; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = (Get-Command K).Name; function K { $Null = 1 }; K; Write-Host 'A'":
        "$Null = (Get-Command K).Name\nWrite-Host 'A'",
    "$Null = 1 / 0; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = [Int]'42'; Write-Host 'A'":
        "Write-Host 'A'",
    "$Null = [Int]'abc'; Write-Host 'A'":
        "Write-Host 'A'",
    "$OFS = '-'; $t = [string]('a', 'b'); Write-Output $t":
        "$OFS = '-'\nWrite-Output 'a-b'",
    '$OFS = \'-\'; Write-Output "$(1, 2)"':
        "$OFS = '-'\nWrite-Output '1-2'",
    "$PSDefaultParameterValues = @{ 'Get-Random:Maximum' = 0 }; $t = Get-Random; Write-Output ($null -eq $t)":
        "$PSDefaultParameterValues = @{\n  'Get-Random:Maximum' = 0\n}\n$t = Get-Random\nWrite-Output ($Null -Eq $t)",
    '$_ = 5; switch (1) { default { Write-Output $_ } }':
        '$_ = 5\nWrite-Output $_',
    '$a = $null; $b = 5; $t = $a * $b; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$a = $null; $t = $a * 5; Write-Output (,$t)':
        'Write-Output (,$Null)',
    "$a = 'a,b,c' -split ',', 2; $t = $a.Count; Write-Output (,$t); Write-Output $t":
        "$a = 'a,b,c' -Split ',', '2'\n$t = $a.Count\nWrite-Output (,$t)\nWrite-Output $t",
    "$a = 'a,b,c' -split ',', 2; $t = $a[1]; Write-Output (,$t); Write-Output $t":
        "$a = 'a,b,c' -Split ',', '2'\n$t = $a[1]\nWrite-Output (,$t)\nWrite-Output $t",
    '$a = 1; $b = 2; $a + $b':
        '3',
    "$a = @('x', '5'); for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }; Write-Host \"y=$y\"":
        "$a = @('x', '5')\nfor ($i = 0; $i -LT 2; $i++) {\n  $y = [int]$a[$i]\n}\nWrite-Host \"y=${y}\"",
    "$a = @(0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (@(0)) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    "$a = @(0, 0); $t = if ($a) { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if ((0, 0)) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    '$all = @(); 1..2 | ForEach-Object { if ($h) { $h.k[0] = 9 }; $x = 1, 2, 3; $h = @{ k = $x }; $all += ,$x }; Write-Output $all[0]':
        '$all = @()\n'
        '1, 2 | ForEach-Object {\n'
        '  if ($h) {\n'
        '    $h.k[0] = 9\n'
        '  }\n'
        '  $x = 1, 2, 3\n'
        '  $h = @{\n'
        '    k = $x\n'
        '  }\n'
        '  $all += ,$x\n'
        '}\n'
        'Write-Output $all[0]',
    "$b = 'Write-Host', 'hi'; $z = 0, 0; $z[0] = 1; iex ([string]::Join(' ', $b)); $n = @('Write-Host $b')[(Get-Random -Maximum 1)]; iex $n":
        "$b = 'Write-Host', 'hi'\n"
        '$z = 0, 0\n'
        '$z[0] = 1\n'
        'Write-Host hi\n'
        "$n = @('Write-Host $b')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $n',
    "$b = 'a'; $v = Get-Variable b -ValueOnly; $v = 'x'; Write-Output $b":
        "Write-Output 'a'",
    "$b = 'a'; $v = Get-Variable; ($v | Where-Object Name -eq 'b').Value = 'b'; Write-Output $b":
        "$b = 'a'\n"
        '$v = Get-Variable\n'
        "($v | Where-Object Name -EQ 'b').Value = 'b'\n"
        'Write-Output $b',
    "$b = 'a'; (Get-Variable b).Value = 'b'; Write-Output $b":
        "Write-Output 'b'",
    "$b = 'a'; Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('b'); $b = 'c'; Write-Output $b":
        "$b = 'a'\n"
        "Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('b')\n"
        "Write-Output 'c'",
    '$b = 0, 0; $p = [Runtime.InteropServices.Marshal]::AllocHGlobal(2); [Runtime.InteropServices.Marshal]::WriteByte($p, 0, 7); [Runtime.InteropServices.Marshal]::Copy($p, $b, 0, 2); [Runtime.InteropServices.Marshal]::FreeHGlobal($p); Write-Output $b[0]':
        '$p = [Runtime.InteropServices.Marshal]::AllocHGlobal(2)\n[Runtime.InteropServices.Marshal]::WriteByte($p, 0, 7)\n[Runtime.InteropServices.Marshal]::Copy($p, (0, 0), 0, 2)\n[Runtime.InteropServices.Marshal]::FreeHGlobal($p)\nWrite-Output 0',
    '$bytes = 72, 105; $s = [Text.Encoding]::ASCII.GetString($bytes); Write-Output $s; $buf = 0, 0; $buf[0] = 7':
        "Write-Output 'Hi'\n$buf = 0, 0\n$buf[0] = 7",
    "$c = 'Write-Out'; $c += 'put 5'; Invoke-Expression $c":
        'Write-Output 5',
    "$c = 'Write-Output $w'; $x = $($w = 'a'; 'v'); iex $c":
        "Write-Output 'a'",
    '$c = 1; function f { (Get-Variable c).Value++ }; f; Write-Output $c':
        'Write-Output 1',
    "$c = @('function Write-Host { $h.k[0] = 9 }')[(Get-Random -Maximum 1)]; iex $c; "
    "$x = 1, 2, 3; $h = @{ k = $x }; Write-Host 'hi'; Write-Output $x":
        "$c = @('function Write-Host { $h.k[0] = 9 }')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        '$x = 1, 2, 3\n'
        '$h = @{\n'
        '  k = (1, 2, 3)\n'
        '}\n'
        "Write-Host 'hi'\n"
        'Write-Output (1, 2, 3)',
    '$c = [char]65; $s = \'A\'; Write-Output "$c"; Write-Output "$s"':
        "Write-Output 'A'\nWrite-Output 'A'",
    '$c = [char]65; foreach ($e in $c) { Write-Output $e }':
        'foreach ($e in [char]65) {\n  Write-Output $e\n}',
    "$env:B = 'function K { Write-Host P }'; Invoke-Expression $env:B; function K { 42 }; $x = K; Write-Output $x; $env:C = 'K'; Invoke-Expression $env:C":
        'function K {\n  Write-Host P\n}\nWrite-Output 42\nK',
    "$env:z = '7'; $ok = [int]::TryParse('42', [ref]$env:z); Write-Host $env:z":
        "$env:z = '7'\n$Null = [int]::TryParse('42', [ref]$env:z)\nWrite-Host '7'",
    "$env:z = 'v'; Write-Output $env:z":
        "Write-Output 'v'",
    "$env:zzq = '7'; (item env:zzq).Value":
        "$env:zzq = '7'\n(Get-Item env:zzq).Value",
    "$env:zzq = '7'; function Get-Item { Write-Output 'from-function' }; item env:zzq":
        "$env:zzq = '7'\nfunction Get-Item {\n  Write-Output 'from-function'\n}\nGet-Item env:zzq",
    "$global:y = 'b'; Write-Output $global:y":
        "Write-Output 'b'",
    "$h = @{ k = 'Set-Alias zzq Write-Host' }; Set-Alias zzq Write-Output; iex $h.k; zzq 'x'":
        "$h = @{\n  k = 'Set-Alias zzq Write-Host'\n}\nSet-Alias zzq Write-Output\nInvoke-Expression $h.k\nzzq 'x'",
    "$i = 0; $null = [int]::TryParse('42', [ref]$script:i); Write-Host $i":
        "$i = 0\n$Null = [int]::TryParse('42', [ref]$script:i)\nWrite-Host $i",
    '$i = 0; if ($false -and ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        '$i = 0\nif ($False -and ($i++)) {}\n$t = $i\nWrite-Output (,$t)\nWrite-Output $t',
    '$i = 0; if ($true -or ($i++)) { }; $t = $i; Write-Output (,$t); Write-Output $t':
        '$i = 0\nif ($True -or ($i++)) {}\n$t = $i\nWrite-Output (,$t)\nWrite-Output $t',
    "$k = 'one'; try { $b = [Convert]::FromBase64String('!!'); $k = 'two' } catch { }; Write-Host $k":
        "Write-Host 'two'",
    '$k = 1, 2, 3; $h = @{ k = $k }; if ((Get-Random -Maximum 1) -eq 0) { $buf = 0, 0 } else { $buf = 1, 1 }; $buf[0] = 7; Write-Output $k':
        'if ((Get-Random -Maximum 1) -Eq 0) {\n'
        '  $buf = 0, 0\n'
        '} else {\n'
        '  $buf = 1, 1\n'
        '}\n'
        '$buf[0] = 7\n'
        'Write-Output (1, 2, 3)',
    '$l = [byte]1; $r = 4; $t = $l -shl $r; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl 4\nWrite-Output (,$t)\nWrite-Output $t',
    "$m = 'Reverse'; $x = 1, 2, 3; [Array]::$m($x); Write-Output $x[0]":
        '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output 3',
    "$n = 'q'; function K { $Null = 1 }; Set-Alias $n K; q; Write-Host 'A'":
        "Write-Host 'A'",
    "$n = 'zq2'; Set-Alias zq2 Write-Host; Set-Alias $n Write-Output; zq2 'y'":
        "Write-Output 'y'",
    '$n = 1; $n += 2; Write-Output $n':
        'Write-Output 3',
    '$n = 1; $n++; Write-Output $n':
        'Write-Output 2',
    '$n = 5; $n -= 2; Write-Output $n':
        'Write-Output 3',
    '$null -eq $undefined':
        '$True',
    "$null = 'abc' -match '(b)'; $t = $Matches[1]; Write-Output (,$t); Write-Output $t":
        "$Null = 'abc' -Match '(b)'\n$t = $Matches[1]\nWrite-Output (,$t)\nWrite-Output $t",
    '$null = Get-Random -SetSeed 7; Get-Random | Out-Null; Write-Host (Get-Random -Maximum 1000)':
        '$Null = Get-Random -SetSeed 7\nGet-Random | Out-Null\nWrite-Host (Get-Random -Maximum 1000)',
    "$null = Get-Random -SetSeed 7; try { throw 'x' } catch { (Get-Random).GetHashCode() | Out-Null; Write-Host 'rest' }; Write-Host (Get-Random -Maximum 1000)":
        '$Null = Get-Random -SetSeed 7\n'
        '(Get-Random).GetHashCode() | Out-Null\n'
        "Write-Host 'rest'\n"
        'Write-Host (Get-Random -Maximum 1000)',
    "$o = New-Object PSObject; $x = 1, 2, 3; $o | Add-Member -NotePropertyName k "
    "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        '$o = New-Object PSObject\n'
        '$x = 1, 2, 3\n'
        '$o | Add-Member -NotePropertyName k -NotePropertyValue $x\n'
        "$c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    "$o = New-Object PSObject; $x = 1, 2, 3; Add-Member -InputObject $o -NotePropertyName k "
    "-NotePropertyValue $x; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        '$o = New-Object PSObject\n'
        '$x = 1, 2, 3\n'
        'Add-Member -InputObject $o -NotePropertyName k -NotePropertyValue $x\n'
        "$c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$o = [pscustomobject]@{}; Add-Member -Type NoteProperty k v -InputObject $o; $o.k':
        '$o = [pscustomobject]@{}\nAdd-Member -MemberType NoteProperty k v -InputObject $o\n$o.k',
    "$out = New-Object byte[] 3; for ($i = 0; $i -lt 3; $i++) { $out[$i] = 7 -bxor $k[$i % $k.Length] }; Write-Host \"out=$($out -join ',')\"":
        '$out = New-Object byte[] 3\n'
        'for ($i = 0; $i -LT 3; $i++) {\n'
        '  $out[$i] = 7 -BXor $k[$i % $k.Length]\n'
        '}\n'
        "Write-Host \"out=$($out -Join ',')\"",
    "$p = @($null, $null, 'a')\n"
    "trap { throw 'x'; Write-Host 'trest'; continue }; $null = [int]$p[2]; Write-Host 'after'":
        "trap {\n  throw 'x'\n  Write-Host 'trest'\n  continue\n}\n$Null = [int]'a'\nWrite-Host 'after'",
    "$p = @($null, $true)\nif ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "throw 'x'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  throw 'x'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @($null, $true)\nif ($p[1]) { trap { Write-Host 't' }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "if ($True) {\n  trap {\n    Write-Host 't'\n  }\n  throw 'x'\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; break }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "if ($True) {\n  trap {\n    Write-Host 't'\n    break\n  }\n  throw 'x'\n}\nWrite-Host 'after'",
    '$p = @($null, $true)\n'
    "if ($p[1]) { trap { Write-Host 't'; continue }; throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap [System.IO.IOException] {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    '$p = @($null, $true)\n'
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap [System.InvalidCastException] {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    '$p = @($null, $true)\n'
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap [System.Management.Automation.RuntimeException] {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    '$p = @($null, $true)\n'
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  throw 'x'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @($null, $true)\ntrap { Write-Host 't' }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap {\n  Write-Host 't'\n}\nif ($True) {\n  throw 'x'\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; break }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap {\n  Write-Host 't'\n  break\n}\nthrow 'x'",
    '$p = @($null, $true)\n'
    "trap { Write-Host 't'; continue }; if ($p[1]) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "trap {\n  Write-Host 't'\n  continue\n}\nif ($True) {\n  throw 'x'\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @($null, $true)\ntry { throw 'x' } catch { if ($p[1]) { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "throw 'x'",
    "$p = @('a')\n$ErrorActionPreference = 'Stop'; $null = [int]$p[0]; Write-Host 'rest'":
        "$p = @('a')\n$ErrorActionPreference = 'Stop'\n$Null = [int]$p[0]\nWrite-Host 'rest'",
    "$p = @('a')\n$null = $($null = [int]$p[0]; Write-Host 'rest'); Write-Host 'after'":
        "$p = @('a')\n$Null = $($Null = [int]$p[0]\nWrite-Host 'rest')\nWrite-Host 'after'",
    "$p = @('a')\n$null = [int]$p[0]; Write-Host 'rest'":
        "Write-Host 'rest'",
    "$p = @('a')\nforeach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "foreach ($i in 1, 2) {\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @('a')\n"
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        "$p = @('a')\n"
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\nfunction f1 { $null = [int]$p[0]; Write-Host 'rest' }; f1; Write-Host 'after'":
        "function f1 {\n  Write-Host 'rest'\n}\nf1\nWrite-Host 'after'",
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "function f1 { $null = [int]$p[0]; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  f1\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "function f1 { try { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        "$p = @('a')\n"
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        '      $Null = [int]$p[0]\n'
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "trap { Write-Host 't'; $null = [int]$p[0]; continue }; try { throw 'x' } catch [System.IO.IOException] { }; Write-Host 'after'":
        "$p = @('a')\n"
        'trap {\n'
        "  Write-Host 't'\n"
        '  $Null = [int]$p[0]\n'
        '  continue\n'
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.IO.IOException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { $null = [int]$p[0]; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { $null = [int]$p[0]; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { $null = [int]$p[0]; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'rest'\n"
        '} finally {\n'
        "  Write-Host 'fin'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { Write-Host 't' } finally { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "try {\n  Write-Host 't'\n} finally {\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @('a')\n"
    "try { foreach ($i in 1, 2) { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  foreach ($i in 1, 2) {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { throw 'x' } catch { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "$p = @('a')\ntry {\n  throw 'x'\n} catch {\n  $Null = [int]$p[0]\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @('a')\n"
    "try { throw 'x' } catch { & { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  & {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { throw 'x' } catch { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { try { $null = [int]$p[0] } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    $Null = [int]$p[0]\n'
        '  } finally {}\n'
        "  Write-Host 'rest'\n"
        '} finally {}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { try { exit } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$p = @('a')\ntry { try { return } finally { Write-Host 'f'; $null = [int]$p[0] } } catch { }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        '    $Null = [int]$p[0]\n'
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$p = @('a')\n"
    "try { try { throw 'x' } finally { $null = [int]$p[0]; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "$p = @('a')\n"
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        '    $Null = [int]$p[0]\n'
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a'); function f1 { $null = [int]$p[0]; Write-Host 'm1' }; trap { continue }; f1; Write-Host 'm2'":
        "$p = @('a')\n"
        'function f1 {\n'
        '  $Null = [int]$p[0]\n'
        "  Write-Host 'm1'\n"
        '}\n'
        'trap {\n'
        '  continue\n'
        '}\n'
        'f1\n'
        "Write-Host 'm2'",
    "$p = @('a', $null, 'a')\n"
    "trap { $null = [int]$p[0]; Write-Host 'trest'; continue }; $null = [int]$p[2]; Write-Host 'after'":
        "trap {\n  $Null = [int]'a'\n  Write-Host 'trest'\n  continue\n}\n$Null = [int]'a'\nWrite-Host 'after'",
    "$p = @('a', $true)\nif ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "Write-Host 'rest'\nWrite-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.IO.IOException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.InvalidCastException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.InvalidCastException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.Management.Automation.RuntimeException] {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't' }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; break }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    break\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "if ($p[1]) { trap { Write-Host 't'; continue }; $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap {\n'
        "    Write-Host 't'\n"
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.IO.IOException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.IO.IOException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.InvalidCastException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.InvalidCastException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  break\n'
        '}\n'
        "$Null = [int]'a'\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap [System.Management.Automation.RuntimeException] { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "trap { Write-Host 't' }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "trap {\n  Write-Host 't'\n}\nif ($True) {\n  $Null = [int]'a'\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; break }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        "trap {\n  Write-Host 't'\n  break\n}\n$Null = [int]'a'\nWrite-Host 'rest'\nWrite-Host 'after'",
    "$p = @('a', $true)\n"
    "trap { Write-Host 't'; continue }; if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' }; Write-Host 'after'":
        'trap {\n'
        "  Write-Host 't'\n"
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @('a', $true)\n"
    "try { throw 'x' } catch { if ($p[1]) { $null = [int]$p[0]; Write-Host 'rest' } }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch {\n  $Null = [int]'a'\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "$p = @()\n$ErrorActionPreference = 'Stop'; throw 'x'; Write-Host 'rest'":
        "$ErrorActionPreference = 'Stop'\nthrow 'x'",
    "$p = @()\n$null = $(throw 'x'; Write-Host 'rest'); Write-Host 'after'":
        "$Null = $(throw 'x'\nWrite-Host 'rest')\nWrite-Host 'after'",
    "$p = @()\nforeach ($i in 1, 2) { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "foreach ($i in 1, 2) {\n  throw 'x'\n}\nWrite-Host 'after'",
    '$p = @()\n'
    "foreach ($i in 1, 2) { try { try { continue } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'm' }; Write-Host 'after'":
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'm'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @()\nfunction f1 { throw 'x'; Write-Host 'rest' }; f1; Write-Host 'after'":
        "function f1 {\n  throw 'x'\n}\nf1\nWrite-Host 'after'",
    "$p = @()\nfunction f1 { throw 'x'; Write-Host 'rest' }; trap { Write-Host 't'; continue }; f1; Write-Host 'after'":
        "function f1 {\n  throw 'x'\n}\ntrap {\n  Write-Host 't'\n  continue\n}\nf1\nWrite-Host 'after'",
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { f1; Write-Host 't' } catch { Write-Host 'c' }; Write-Host 'after'":
        'function f1 {\n'
        "  throw 'x'\n"
        '}\n'
        'try {\n'
        '  f1\n'
        "  Write-Host 't'\n"
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @()\n'
    "function f1 { throw 'x'; Write-Host 'rest' }; try { throw 'x' } catch { f1; Write-Host 'c' }; Write-Host 'after'":
        "function f1 {\n  throw 'x'\n}\nf1\nWrite-Host 'c'\nWrite-Host 'after'",
    '$p = @()\n'
    "function f1 { try { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'tail' }; f1; Write-Host 'after'":
        'function f1 {\n'
        '  try {\n'
        '    try {\n'
        '      return\n'
        '    } finally {\n'
        "      Write-Host 'f'\n"
        "      throw 'x'\n"
        '    }\n'
        '  } catch {}\n'
        "  Write-Host 'tail'\n"
        '}\n'
        'f1\n'
        "Write-Host 'after'",
    "$p = @()\nthrow 'x'; Write-Host 'rest'":
        "throw 'x'",
    '$p = @()\n'
    "trap { Write-Host 't'; throw 'x'; continue }; try { throw 'x' } catch [System.IO.IOException] { }; Write-Host 'after'":
        'trap {\n'
        "  Write-Host 't'\n"
        "  throw 'x'\n"
        '  continue\n'
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.IO.IOException] {}\n'
        "Write-Host 'after'",
    "$p = @()\ntry { Write-Host 't' } finally { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "try {\n  Write-Host 't'\n} finally {\n  throw 'x'\n  Write-Host 'rest'\n}",
    '$p = @()\n'
    "try { foreach ($i in 1, 2) { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        "try {\n  foreach ($i in 1, 2) {\n    throw 'x'\n  }\n} catch {\n  Write-Host 'c'\n}\nWrite-Host 'after'",
    "$p = @()\ntry { throw 'x' } catch { & { throw 'x'; Write-Host 'rest' }; Write-Host 'c' }; Write-Host 'after'":
        "& {\n  throw 'x'\n}\nWrite-Host 'c'\nWrite-Host 'after'",
    "$p = @()\ntry { throw 'x' } catch { throw 'x'; Write-Host 'rest' }; Write-Host 'after'":
        "throw 'x'",
    '$p = @()\n'
    "try { throw 'x' } catch { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } }; Write-Host 'after'":
        "try {\n  throw 'x'\n} finally {\n  throw 'x'\n  Write-Host 'rest'\n}",
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.IO.IOException] { Write-Host 'c' }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch [System.IO.IOException] {\n  Write-Host 'c'\n}\nWrite-Host 'after'",
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.InvalidCastException] { Write-Host 'c' }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch [System.InvalidCastException] {\n  Write-Host 'c'\n}\nWrite-Host 'after'",
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'c' }; Write-Host 'after'":
        "Write-Host 'c'\nWrite-Host 'after'",
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.Exception] { Write-Host 'e' }; Write-Host 'after'":
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'e'\n"
        '}\n'
        "Write-Host 'after'",
    '$p = @()\n'
    "try { throw 'x'; Write-Host 'rest' } catch [System.Management.Automation.RuntimeException] { Write-Host 'r' } catch [System.InvalidCastException] { Write-Host 'i' }; Write-Host 'after'":
        'try {\n'
        "  throw 'x'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'r'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'i'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @()\ntry { throw 'x'; Write-Host 'rest' } catch { Write-Host 'c' }; Write-Host 'after'":
        "Write-Host 'c'\nWrite-Host 'after'",
    "$p = @()\ntry { throw 'x'; Write-Host 'rest' } finally { Write-Host 'fin' }; Write-Host 'after'":
        "try {\n  throw 'x'\n} finally {\n  Write-Host 'fin'\n}\nWrite-Host 'after'",
    "$p = @()\ntry { try { exit } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        'try {\n'
        '  try {\n'
        '    exit\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "$p = @()\ntry { try { return } finally { Write-Host 'f'; throw 'x' } } catch { }; Write-Host 'after'":
        'try {\n'
        '  try {\n'
        '    return\n'
        '  } finally {\n'
        "    Write-Host 'f'\n"
        "    throw 'x'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    '$p = @()\n'
    "try { try { throw 'x' } finally { throw 'x'; Write-Host 'rest' } } catch { Write-Host 'c' }; Write-Host 'after'":
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        "    throw 'x'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        '} catch {\n'
        "  Write-Host 'c'\n"
        '}\n'
        "Write-Host 'after'",
    "$p = @()\ntry { try { throw 'x' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "try {\n  try {\n    throw 'x'\n  } finally {}\n  Write-Host 'rest'\n} finally {}\nWrite-Host 'after'",
    '$p = @(@(1, 2), @(3, 4)); for ($i = 0; $i -lt 1; $i++) { [Array]::Reverse($p[$i]) }; Write-Output $p[0]':
        '$p = @(@(1, 2), @(3, 4))\nfor ($i = 0; $i -LT 1; $i++) {\n  [Array]::Reverse($p[$i])\n}\nWrite-Output $p[0]',
    "$private:x = 'a'; Write-Output $x":
        "Write-Output 'a'",
    "$q = 'a'; Write-Output $($q + 'b')":
        "Write-Output 'ab'",
    "$q = 'abc'; [int]$q = 5; Write-Output $q.GetType().FullName":
        'Write-Output (5).GetType().FullName',
    '$q = [string]5; $q = 1, 2, 3; Write-Output (,$q)':
        'Write-Output (,(1, 2, 3))',
    "$q, $r = 'abc', 'd'; Write-Output $q.SUBSTRING(1, 1); Write-Output $r":
        "$q, $r = 'abc', 'd'\nWrite-Output $q.Substring(1, 1)\nWrite-Output $r",
    "$s = $env:COMPUTERNAME; $t = $env:USERNAME; try { trap { $null = [int]$s; continue }; if ([int]$t) { Write-Host 'x' }; Write-Host 'rest' } catch { Write-Host 'caught' }":
        '$s = $env:ComputerName\n'
        '$t = $env:UserName\n'
        'try {\n'
        '  trap {\n'
        '    $Null = [int]$s\n'
        '    continue\n'
        '  }\n'
        '  if ([int]$t) {\n'
        "    Write-Host 'x'\n"
        '  }\n'
        "  Write-Host 'rest'\n"
        '} catch {\n'
        "  Write-Host 'caught'\n"
        '}',
    "$s = $env:COMPUTERNAME; trap { $null = [int]$s; continue }; Invoke-Nonexistent; Write-Host 'rest'":
        "$s = $env:ComputerName\ntrap {\n  $Null = [int]$s\n  continue\n}\nInvoke-Nonexistent\nWrite-Host 'rest'",
    "$s = $env:COMPUTERNAME; try { trap { $null = [int]$s; continue }; Invoke-Nonexistent; Write-Host 'rest' } catch { Write-Host 'caught' }":
        '$s = $env:ComputerName\n'
        'try {\n'
        '  trap {\n'
        '    $Null = [int]$s\n'
        '    continue\n'
        '  }\n'
        '  Invoke-Nonexistent\n'
        "  Write-Host 'rest'\n"
        '} catch {\n'
        "  Write-Host 'caught'\n"
        '}',
    "$s = 'a'; $s += 'b'; $s += 'c'; Write-Output $s":
        "Write-Output 'abc'",
    "$s = 'abc'; $s.Substring(1, 2)":
        "'bc'",
    "$s = 'abcd'; $t = $s; $t = 1, 2, 3; [Array]::Reverse($t); Write-Output $s.Length":
        '$t = 1, 2, 3\n[Array]::Reverse($t)\nWrite-Output 4',
    "$s = 'x'; Write-Output $script:s":
        "Write-Output 'x'",
    '$s = 0xFF; $t = "$s"; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'255')\nWrite-Output '255'",
    "$s = [string][char]256 + 'b'; $k = [char[]]$s | ForEach-Object { [byte][char]$_ }; Write-Host \"count=$($k.Count) key=$($k -join ',')\"":
        "$k = [char[]]'Āb' | ForEach-Object {\n"
        '  [byte][char]$_\n'
        '}\n'
        "Write-Host \"count=$($k.Count) key=$($k -Join ',')\"",
    "$sb = New-Object Text.StringBuilder -ArgumentList 'aGk='; $x = $sb.ToString(); "
    "$t = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
    ".Invoke($Null, @($x)); Write-Output (,$t); Write-Output $t":
        "$sb = New-Object Text.StringBuilder -ArgumentList 'aGk='\n$x = $sb.ToString()\n"
        "$t = [Convert]::FromBase64String($x)\nWrite-Output (,$t)\nWrite-Output $t",
    "$script:s = 'x'; Write-Output $s":
        "Write-Output 'x'",
    "$script:y = 'b'; Write-Output $script:y":
        "Write-Output 'b'",
    '$t = $false + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $false -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $false -eq 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $false -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $false -lt 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null * 1; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = $null + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $null + 'abc'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'abc')\nWrite-Output 'abc'",
    '$t = $null + 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$t = $null + 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    '$t = $null + @(1, 2); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2))\nWrite-Output 2',
    '$t = $null + [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = $null - 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = $null -band 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = $null -band [uint32]1; Write-Output (,$t); Write-Output $t':
        '$t = $Null -BAnd [uint32]1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $null -eq $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $null -eq ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -eq 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -ge 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -gt -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -gt 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -le -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -le 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $null -lt ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $null -lt 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -lt -5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -lt 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -lt 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -ne $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null -ne 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $null -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $null.Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    "$t = $true * '1'; Write-Output (,$t); Write-Output $t":
        "$t = $True * '1'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = $true * 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$t = $true * 2; Write-Output (,$t); Write-Output $t':
        '$t = $True * 2\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    "$t = $true + ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true + 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True + 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true + 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.5)\nWrite-Output 2.5',
    '$t = $true + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = $true + 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = $true - 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True - 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true - 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-0.5)\nWrite-Output (-0.5)',
    '$t = $true - 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = $true -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $true -and ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -and @(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -and [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -band 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true -bxor $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = $true -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -eq ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = $true -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $true -eq 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -eq 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -eq 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = $true -ge 'abc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -gt $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = $true -gt 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -lt 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -ne 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true -xor $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = $true / 1.0d; Write-Output (,$t); Write-Output $t':
        '$t = $True / 1.0d\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = $true / 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    "$t = ' ' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '' -eq $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '' -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '' -eq 0; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '' -gt $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '' -or $false; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '0' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '0' -eq 0; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '1.0' -eq 1; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '10' -band 6; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    "$t = '10' -ge 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -GE 9\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -gt 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -GT 9\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -le '9'; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LE '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -lt '9'; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LT '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -lt 9; Write-Output (,$t); Write-Output $t":
        "$t = '10' -LT 9\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '10' -ne 10; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = '1000' -eq 1e3d; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = '1_0' -band 15; Write-Output (,$t); Write-Output $t":
        "$t = '1_0' -BAnd 15\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '1e400' + 1; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'1e4001')\nWrite-Output '1e4001'",
    "$t = '2' -lt '10'; Write-Output (,$t); Write-Output $t":
        "$t = '2' -LT '10'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = '5' * 2; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'55')\nWrite-Output '55'",
    "$t = '5' + 5; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'55')\nWrite-Output '55'",
    "$t = '5' - 1; Write-Output (,$t); Write-Output $t":
        'Write-Output (,4)\nWrite-Output 4',
    "$t = '5' / 2; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2.5)\nWrite-Output 2.5',
    "$t = 'A' -ceq 'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 'A' -ieq 'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'AB'.Count; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    "$t = 'AB'.Length; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    "$t = 'AB'.Zqnope; Write-Output (,$t)":
        'Write-Output (,$Null)',
    "$t = 'ABC'.ToCharArray(); Write-Output (,$t); Write-Output $t.Count":
        "Write-Output (,[char[]]'ABC')\nWrite-Output 3",
    "$t = 'ABC'[0]; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    "$t = 'B' -gt 'a'; Write-Output (,$t); Write-Output $t":
        "$t = 'B' -GT 'a'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'a' + $false; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aFalse')\nWrite-Output 'aFalse'",
    "$t = 'a' + $null; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a')\nWrite-Output 'a'",
    "$t = 'a' + $true; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aTrue')\nWrite-Output 'aTrue'",
    "$t = 'a' + -1.50d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a-1.50')\nWrite-Output 'a-1.50'",
    "$t = 'a' + 0.5d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a0.5')\nWrite-Output 'a0.5'",
    "$t = 'a' + 1.50d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1.50')\nWrite-Output 'a1.50'",
    "$t = 'a' + 1.5; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1.5')\nWrite-Output 'a1.5'",
    "$t = 'a' + 1L; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1')\nWrite-Output 'a1'",
    "$t = 'a' + 1e3d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a1000')\nWrite-Output 'a1000'",
    "$t = 'a' + 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a79228162514264337593543950335')\nWrite-Output 'a79228162514264337593543950335'",
    "$t = 'a' + [char]65; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'aA')\nWrite-Output 'aA'",
    "$t = 'a' + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a18446744073709551615')\nWrite-Output 'a18446744073709551615'",
    "$t = 'a', 1; Write-Output (,$t); Write-Output $t":
        "Write-Output (,('a', 1))\nWrite-Output ('a', 1)",
    "$t = 'a*' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        "$t = 'a*' -Like 'a`*'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'a-b-c' -split '-' | ForEach-Object { $_ }; Write-Output (,$t)":
        "Write-Output (,('a', 'b', 'c'))",
    "$t = 'ab' -like 'a`*'; Write-Output (,$t); Write-Output $t":
        "$t = 'ab' -Like 'a`*'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'abc' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'abc' -as [int]; Write-Output (,$t); Write-Output $t":
        "$t = 'abc' -As [int]\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'abc' -eq $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 'abc' -lt $null; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 'abc' -replace '(?<x>b)', '[${x}]'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a[b]c')\nWrite-Output 'a[b]c'",
    "$t = 'b' -like '[!a]'; Write-Output (,$t); Write-Output $t":
        "$t = 'b' -Like '[!a]'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'false' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 'ss' -eq [char]0x00DF; Write-Output (,$t); Write-Output $t":
        "$t = 'ss' -Eq [char]223\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 'x' + (1.0d); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 0.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x0')\nWrite-Output 'x0'",
    "$t = 'x' + 1.000d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 1.00d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 1.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1')\nWrite-Output 'x1'",
    "$t = 'x' + 1.100d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.100')\nWrite-Output 'x1.100'",
    "$t = 'x' + 1.10d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.10')\nWrite-Output 'x1.10'",
    "$t = 'x' + 1.2300d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.2300')\nWrite-Output 'x1.2300'",
    "$t = 'x' + 10.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x10')\nWrite-Output 'x10'",
    "$t = 'x' + 2.0d; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x2')\nWrite-Output 'x2'",
    "$t = 'ſ' -match 's'; Write-Output (,$t); Write-Output $t":
        "$t = 'ſ' -Match 's'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = ('A').Substring(0); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'A')\nWrite-Output 'A'",
    "$t = ('A').ToUpper(); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'A')\nWrite-Output 'A'",
    '$t = (,$true) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (,' ') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (,'') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = (,'a') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,(,(,0))) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,(,0)) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,(,@())) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,0.0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (,0.0d) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (,1) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,@()) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (,@(1, 2)) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,[char]0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = (,[char]65) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = (- '0') -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = (1, 2), 3; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,((1, 2), 3))\nWrite-Output 2',
    '$t = (5).Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = (5).Length; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = (5).Rank; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = (5).Zqnope; Write-Output (,$t)':
        'Write-Output (,$Null)',
    '$t = ([char]65).ToString(); Write-Output (,$t); Write-Output $t':
        "Write-Output (,'A')\nWrite-Output 'A'",
    '$t = , 1; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,1))\nWrite-Output 1',
    '$t = ,(1, 2); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,(1, 2)))\nWrite-Output 1',
    '$t = - $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    "$t = - ' 5 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-5)\nWrite-Output (-5)',
    "$t = - ''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = - '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = - '1e3'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1000.0)\nWrite-Output (-1000.0)',
    "$t = - '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = - (-2147483648); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = - 0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0.0)\nWrite-Output 0.0',
    '$t = - 0.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    '$t = - 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    '$t = - 1.00d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = - 1.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = - 1.10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.10d)\nWrite-Output (-1.10d)',
    '$t = - 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.5)\nWrite-Output (-1.5)',
    '$t = - 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.5d)\nWrite-Output (-1.5d)',
    '$t = - 2147483647; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483647)\nWrite-Output (-2147483647)',
    '$t = - 2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648L)\nWrite-Output (-2147483648L)',
    '$t = - 5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = - 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-79228162514264337593543950335d)\nWrite-Output (-79228162514264337593543950335d)',
    '$t = - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-9223372036854775807L)\nWrite-Output (-9223372036854775807L)',
    '$t = - [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-5)\nWrite-Output (-5)',
    '$t = - [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = - [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-65)\nWrite-Output (-65)',
    '$t = - [uint32]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.0)\nWrite-Output (-1.0)',
    '$t = - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.8446744073709552e+19)\nWrite-Output (-1.8446744073709552e+19)',
    '$t = -(2147483647); Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483647)\nWrite-Output (-2147483647)',
    '$t = -(2147483648); Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648L)\nWrite-Output (-2147483648L)',
    '$t = -0.0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = -0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-0.0)\nWrite-Output (-0.0)',
    '$t = -1 * [uint64]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1d)\nWrite-Output (-1d)',
    '$t = -1 -band [uint32]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]1)\nWrite-Output ([uint32]1)',
    '$t = -2147483647 - 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    '$t = -2147483648 % -1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = -2147483648 - 9223372036854775807L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-9.22337203900226e+18)\nWrite-Output (-9.22337203900226e+18)',
    '$t = -2147483648 / -1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = -2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    '$t = -2147483649; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2147483649)\nWrite-Output (-2147483649)',
    '$t = -79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-79228162514264337593543950335d)\nWrite-Output (-79228162514264337593543950335d)',
    '$t = -bnot $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    '$t = -bnot $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2)\nWrite-Output (-2)',
    "$t = -bnot '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-6)\nWrite-Output (-6)',
    "$t = -bnot 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = -BNot 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = -bnot 0xFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-256)\nWrite-Output (-256)',
    '$t = -bnot 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = -bnot 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-3)\nWrite-Output (-3)',
    '$t = -bnot 10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-11)\nWrite-Output (-11)',
    '$t = -bnot 1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2L)\nWrite-Output (-2L)',
    '$t = -bnot 3000000000.0; Write-Output (,$t); Write-Output $t':
        '$t = -BNot 3000000000.0\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = -bnot [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-6)\nWrite-Output (-6)',
    '$t = -bnot [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-66)\nWrite-Output (-66)',
    '$t = -bnot [uint32]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]4294967288)\nWrite-Output ([uint32]4294967288)',
    "$t = -not '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = -not (,[char]0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = -not (- '0'); Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not @(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not @(0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = -not [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 0 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    '$t = 0 + [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,65)\nWrite-Output 65',
    '$t = 0 - [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1.8446744073709552e+19)\nWrite-Output (-1.8446744073709552e+19)',
    '$t = 0 -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 0 -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 0 -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 0 -or 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0.0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0.0d -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0.50000000000000000000000000000d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0.50000000000000000000000000000d)\nWrite-Output 0.50000000000000000000000000000d',
    '$t = 007; Write-Output (,$t); Write-Output $t':
        'Write-Output (,007)\nWrite-Output 007',
    '$t = 0L -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 0x0000000000000001; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x0000000000000001)\nWrite-Output 0x0000000000000001',
    '$t = 0x100000000; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x100000000)\nWrite-Output 0x100000000',
    '$t = 0x7FFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x7FFFFFFF)\nWrite-Output 0x7FFFFFFF',
    '$t = 0x7FFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0x7FFFFFFFFFFFFFFF)\nWrite-Output 0x7FFFFFFFFFFFFFFF',
    '$t = 0xFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFF)\nWrite-Output 0xFF',
    '$t = 0xFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1)\nWrite-Output (-1)',
    '$t = 0xFFFFFFFF -bxor 0x5A; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-91)\nWrite-Output (-91)',
    '$t = 0xFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFF)\nWrite-Output 0xFFFFFFFF',
    '$t = 0xFFFFFFFFFFFFFFFF + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-1L)\nWrite-Output (-1L)',
    '$t = 0xFFFFFFFFFFFFFFFF; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFFFFFFFFFF)\nWrite-Output 0xFFFFFFFFFFFFFFFF',
    '$t = 0xFFFFFFFFL; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFFFFFFFL)\nWrite-Output 0xFFFFFFFFL',
    '$t = 0xFFL; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFL)\nWrite-Output 0xFFL',
    '$t = 0xFFkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0xFFkb)\nWrite-Output 0xFFkb',
    '$t = 1 + $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    "$t = 1 + '  '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1)\nWrite-Output 1',
    "$t = 1 + ' 7 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,8)\nWrite-Output 8',
    "$t = 1 + '+5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,6)\nWrite-Output 6',
    "$t = 1 + '0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = 1 + '1.5L'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,3L)\nWrite-Output 3L',
    "$t = 1 + '1e3'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1001.0)\nWrite-Output 1001.0',
    "$t = 1 + '1kb'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,1025)\nWrite-Output 1025',
    "$t = 1 + '2147483648'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2147483649L)\nWrite-Output 2147483649L',
    "$t = 1 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,6)\nWrite-Output 6',
    "$t = 1 + 'AB'.Count; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    '$t = 1 + [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.8446744073709552e+19)\nWrite-Output 1.8446744073709552e+19',
    '$t = 1 - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    "$t = 1 - '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-4)\nWrite-Output (-4)',
    '$t = 1 -and 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 1 -and 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -ceq 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 1 -eq '1.0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 1 -eq 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -Eq 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 1 -ge $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1 -gt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 1 -gt 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -GT 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 1 -le $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 1 -lt $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = 1 -lt '5'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -LT '5'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 1 -lt 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -LT 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 1 -ne $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = 1 -ne 'abc'; Write-Output (,$t); Write-Output $t":
        "$t = 1 -NE 'abc'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = 1 / [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5.421010862427522e-20)\nWrite-Output 5.421010862427522e-20',
    '$t = 1.000d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.00d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d * 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d + 2.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3d)\nWrite-Output 3d',
    '$t = 1.0d - $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0d)\nWrite-Output 0d',
    '$t = 1.0d - 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d / 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1d)\nWrite-Output 1d',
    '$t = 1.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.0d)\nWrite-Output 1.0d',
    '$t = 1.100d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.100d)\nWrite-Output 1.100d',
    '$t = 1.10d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.10d)\nWrite-Output 1.10d',
    '$t = 1.10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.10d)\nWrite-Output 1.10d',
    '$t = 1.2345678901234567890123456789d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.2345678901234567890123456789d)\nWrite-Output 1.2345678901234567890123456789d',
    '$t = 1.2345678901234567890123456789d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.2345678901234567890123456789d)\nWrite-Output 1.2345678901234567890123456789d',
    '$t = 1.5 * [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,72.0)\nWrite-Output 72.0',
    '$t = 1.500d + 1.500d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.000d)\nWrite-Output 3.000d',
    '$t = 1.50d + 1.50d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.00d)\nWrite-Output 3.00d',
    '$t = 1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5)\nWrite-Output 1.5',
    '$t = 1.5L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5L)\nWrite-Output 1.5L',
    '$t = 1.5d -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5d)\nWrite-Output 1.5d',
    '$t = 1.5kb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5kb)\nWrite-Output 1.5kb',
    '$t = 10 - $null + 3; Write-Output (,$t); Write-Output $t':
        'Write-Output (,13)\nWrite-Output 13',
    '$t = 10 - $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10)\nWrite-Output 10',
    "$t = 10 -ge '9'; Write-Output (,$t); Write-Output $t":
        "$t = 10 -GE '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 10 -lt '9'; Write-Output (,$t); Write-Output $t":
        "$t = 10 -LT '9'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = 10 -ne '10'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 10 -ne 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 10, 20, 30 -eq 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(,20))\nWrite-Output (,20)',
    '$t = 10, 20, 30, 20, 10 -ne 20; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(10, 30, 10))\nWrite-Output (10, 30, 10)',
    '$t = 100000000000000000000000000000000; Write-Output (,$t); Write-Output $t':
        'Write-Output (,100000000000000000000000000000000)\nWrite-Output 100000000000000000000000000000000',
    '$t = 10000000000000000000000000000d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10000000000000000000000000000d)\nWrite-Output 10000000000000000000000000000d',
    '$t = 100000000000000d * 100000000000000d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10000000000000000000000000000d)\nWrite-Output 10000000000000000000000000000d',
    '$t = 10D; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10D)\nWrite-Output 10D',
    '$t = 10d + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10d)\nWrite-Output 10d',
    '$t = 10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10d)\nWrite-Output 10d',
    "$t = 12 + '0xabc'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2760)\nWrite-Output 2760',
    '$t = 1E+28d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1E+28d)\nWrite-Output 1E+28d',
    '$t = 1L + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = 1L -shl 64; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = 1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1L)\nWrite-Output 1L',
    '$t = 1d / 0.1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10d)\nWrite-Output 10d',
    '$t = 1d / 3d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0.3333333333333333333333333333d)\nWrite-Output 0.3333333333333333333333333333d',
    '$t = 1dkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1dkb)\nWrite-Output 1dkb',
    '$t = 1e3; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1e3)\nWrite-Output 1e3',
    '$t = 1kb + 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1024)\nWrite-Output 1024',
    '$t = 1kb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1kb)\nWrite-Output 1kb',
    '$t = 1l; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1l)\nWrite-Output 1l',
    '$t = 1lkb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1lkb)\nWrite-Output 1lkb',
    '$t = 2 * $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = 2 * [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,96)\nWrite-Output 96',
    '$t = 2 -eq $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = 2.50d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.50d)\nWrite-Output 2.50d',
    '$t = 2.5L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.5L)\nWrite-Output 2.5L',
    '$t = 2147483647 * 2147483647; Write-Output (,$t); Write-Output $t':
        'Write-Output (,4.6116860141324206e+18)\nWrite-Output 4.6116860141324206e+18',
    '$t = 2147483647 * [uint32]4294967295; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372030412325e+18)\nWrite-Output 9.223372030412325e+18',
    '$t = 2147483647 + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648.0)\nWrite-Output 2147483648.0',
    '$t = 2147483648; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2147483648)\nWrite-Output 2147483648',
    '$t = 300 -as [byte]; Write-Output (,$t); Write-Output $t':
        '$t = 300 -As [byte]\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = 4gb; Write-Output (,$t); Write-Output $t':
        'Write-Output (,4gb)\nWrite-Output 4gb',
    "$t = 5 + '5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,10)\nWrite-Output 10',
    '$t = 5 -as [long]; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    '$t = 5 -xor 0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = 512MB * 512MB; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2.8823037615171174e+17)\nWrite-Output 2.8823037615171174e+17',
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output $t.Count; Write-Output $t':
        'Write-Output 2\nWrite-Output ([char]65, [char]66)',
    '$t = 65, 66 | ForEach-Object { [char]$_ }; Write-Output (,$t)':
        'Write-Output (,([char]65, [char]66))',
    '$t = 7922816251426433759354395033.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,7922816251426433759354395033.5d)\nWrite-Output 7922816251426433759354395033.5d',
    '$t = 79228162514264337593543950334d + 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335.00d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335.00d)\nWrite-Output 79228162514264337593543950335.00d',
    '$t = 79228162514264337593543950335d * 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335d + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335d - 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950334d)\nWrite-Output 79228162514264337593543950334d',
    '$t = 79228162514264337593543950335d / 1d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,79228162514264337593543950335d)\nWrite-Output 79228162514264337593543950335d',
    '$t = 9223372036854775807 + 2; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = 9223372036854775807; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9223372036854775807)\nWrite-Output 9223372036854775807',
    '$t = 9223372036854775807L + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = 9223372036854775807L - -1L; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9.223372036854776e+18)\nWrite-Output 9.223372036854776e+18',
    '$t = 9223372036854775808; Write-Output (,$t); Write-Output $t':
        'Write-Output (,9223372036854775808)\nWrite-Output 9223372036854775808',
    '$t = @($false) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @($null) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = @('1') -contains 1; Write-Output (,$t); Write-Output $t":
        "$t = @('1') -Contains 1\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output ($t -join '-')":
        "Write-Output 'a-b'",
    "$t = @('a', 'b') | ForEach-Object { $_ }; Write-Output (,$t); Write-Output $t":
        "Write-Output (,('a', 'b'))\nWrite-Output ('a', 'b')",
    "$t = @('a', 'b') | ForEach-Object { $_ }; foreach ($e in $t) { Write-Output $e }":
        "foreach ($e in ('a', 'b')) {\n  Write-Output $e\n}",
    '$t = @((1, 2)); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@((1, 2)))\nWrite-Output 2',
    '$t = @() * 5000; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    '$t = @() + 1; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(,1))\nWrite-Output 1',
    '$t = @() -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    '$t = @(0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(0, 0) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = @(1) -contains '1'; Write-Output (,$t); Write-Output $t":
        "$t = @(1) -Contains '1'\nWrite-Output (,$t)\nWrite-Output $t",
    '$t = @(1, 2) * 0; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@())\nWrite-Output 0',
    '$t = @(1, 2) * 2; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 1, 2))\nWrite-Output 4',
    '$t = @(1, 2) + $null; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, $Null))\nWrite-Output 3',
    "$t = @(1, 2) + 'a'; Write-Output (,$t); Write-Output $t.Count":
        "Write-Output (,(1, 2, 'a'))\nWrite-Output 3",
    '$t = @(1, 2) + 5; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 5))\nWrite-Output 3',
    '$t = @(1, 2) + @(3, 4); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2, 3, 4))\nWrite-Output 4',
    '$t = @(1, 2) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = @(1, 2) -band 1; Write-Output (,$t); Write-Output $t.Count':
        '$t = @(1, 2) -BAnd 1\nWrite-Output (,$t)\nWrite-Output $t.Count',
    '$t = @(1, 2) -eq $null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,@())\nWrite-Output @()',
    '$t = @(1, 2, 3) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = @(1, 2, 3).Count; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3)\nWrite-Output 3',
    '$t = @(1, 2, 3).Length; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3)\nWrite-Output 3',
    '$t = @(1, 2, 3).Rank; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = @(@()) -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = @(@(1, 2)); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,@(@(1, 2)))\nWrite-Output 2',
    '$t = @(@(1, 2), 3); Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(@(1, 2), 3))\nWrite-Output 2',
    "$t = [Convert].GetMethod('FromBase64String', [type[]]@([string]))"
    ".Invoke($Null, @('aGk=')); Write-Output (,$t); Write-Output $t":
        'Write-Output (,(0x68, 0x69))\nWrite-Output (0x68, 0x69)',
    "$t = [Convert]::ToByte('FF', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,[byte]255)\nWrite-Output ([byte]255)',
    '$t = [Convert]::ToChar(65); Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = [Convert]::ToInt32($null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [Convert]::ToInt32(' 5 '); Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [Convert]::ToInt32('017', 8); Write-Output (,$t); Write-Output $t":
        'Write-Output (,15)\nWrite-Output 15',
    "$t = [Convert]::ToInt32('80000000', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,-2147483648)\nWrite-Output (-2147483648)',
    "$t = [Convert]::ToInt32('FFFFFFFF', 16); Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1)\nWrite-Output (-1)',
    '$t = [Convert]::ToInt32(1.5); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [Convert]::ToInt32(1.5d); Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [Convert]::ToInt64(5); Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    '$t = [array]::Reverse((1, 2, 3, 4)); Write-Output ($null -eq $t)':
        '$t = [array]::Reverse((1, 2, 3, 4))\nWrite-Output ($Null -Eq $t)',
    '$t = [bool]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool]' '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [bool]''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [bool]'a'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [bool]'false'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,$null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool](,(,0)); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,1); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,@()); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool](,@(1, 2)); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool](,[char]0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]-0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]0.0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]@($false); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@($null); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool]@(0, 0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]@(0, 0, 0); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool]@(@()); Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [bool][char]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [bool][char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][int16]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][sbyte]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][uint16]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [bool][uint32]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    "$t = [byte]'0x80'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[byte]128)\nWrite-Output ([byte]128)',
    '$t = [byte](200 * 2); Write-Output (,$t); Write-Output $t':
        '$t = [byte]400\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [byte]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [byte]1 -shl -1; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl -1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [byte]1 -shl 4; Write-Output (,$t); Write-Output $t':
        '$t = [byte]1 -Shl 4\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [byte]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[byte]5)\nWrite-Output ([byte]5)',
    "$t = [char[]]'ABC'; Write-Output (,$t); Write-Output $t.Count":
        "Write-Output (,[char[]]'ABC')\nWrite-Output 3",
    '$t = [char[]](72, 73); Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char[]](72, 73))\nWrite-Output ([char[]](72, 73))',
    '$t = [char]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]0)\nWrite-Output ([char]0)',
    "$t = [char]'0' -and $true; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    "$t = [char]'A'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = [char]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]0)\nWrite-Output ([char]0)',
    "$t = [char]0x00DF -eq 'ss'; Write-Output (,$t); Write-Output $t":
        "$t = [char]223 -Eq 'ss'\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = [char]48 - '1'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,47)\nWrite-Output 47',
    '$t = [char]48 - 0.0; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48.0)\nWrite-Output 48.0',
    '$t = [char]48 -band [byte]255; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48)\nWrite-Output 48',
    '$t = [char]48 -bxor [char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [char]48 -eq '0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]48 -eq 48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65 -and $true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65 -bxor 32; Write-Output (,$t); Write-Output $t':
        'Write-Output (,97)\nWrite-Output 97',
    '$t = [char]65 -ceq [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [char]65 -eq [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65 -lt [char]97; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$True)\nWrite-Output $True',
    '$t = [char]65535; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65535)\nWrite-Output ([char]65535)',
    '$t = [char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[char]65)\nWrite-Output ([char]65)',
    '$t = [char]97 -lt [char]66; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [decimal]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5d)\nWrite-Output 5d',
    '$t = [double]1.5d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.5)\nWrite-Output 1.5',
    '$t = [double]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5.0)\nWrite-Output 5.0',
    '$t = [int16]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[int16]7)\nWrite-Output ([int16]7)',
    '$t = [int]"`t`r5`n"; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    '$t = [int]$null; Write-Output (,$t); Write-Output $t':
        'Write-Output (,0)\nWrite-Output 0',
    '$t = [int]$true; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    "$t = [int]' 5 '; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]''; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [int]'+7'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,7)\nWrite-Output 7',
    "$t = [int]'.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [int]'0'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,0)\nWrite-Output 0',
    "$t = [int]'007'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,7)\nWrite-Output 7',
    "$t = [int]'0x10'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,16)\nWrite-Output 16',
    "$t = [int]'0xFFFFFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,-1)\nWrite-Output (-1)',
    "$t = [int]'2.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,2)\nWrite-Output 2',
    "$t = [int]'5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]'5.'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,5)\nWrite-Output 5',
    "$t = [int]'7.5'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,8)\nWrite-Output 8',
    '$t = [int]-1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,-2)\nWrite-Output (-2)',
    '$t = [int]1.4; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1)\nWrite-Output 1',
    '$t = [int]1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [int]10d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,10)\nWrite-Output 10',
    '$t = [int]2.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2)\nWrite-Output 2',
    '$t = [int]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5)\nWrite-Output 5',
    '$t = [int][char]48; Write-Output (,$t); Write-Output $t':
        'Write-Output (,48)\nWrite-Output 48',
    '$t = [int][char]65; Write-Output (,$t); Write-Output $t':
        'Write-Output (,65)\nWrite-Output 65',
    '$t = [long]1.5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,2L)\nWrite-Output 2L',
    '$t = [long]5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,5L)\nWrite-Output 5L',
    "$t = [sbyte]'0x80'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[sbyte]-128)\nWrite-Output ([sbyte]-128)',
    '$t = [sbyte]-5; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[sbyte]-5)\nWrite-Output ([sbyte]-5)',
    '$t = [single]1.5 -shl 1; Write-Output (,$t); Write-Output $t':
        '$t = [single]1.5 -Shl 1\nWrite-Output (,$t)\nWrite-Output $t',
    '$t = [string]$false; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'False')\nWrite-Output 'False'",
    '$t = [string]$null; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'')\nWrite-Output ''",
    '$t = [string]$true; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'True')\nWrite-Output 'True'",
    "$t = [string]'foo'; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'foo')\nWrite-Output 'foo'",
    "$t = [string]('a', 'b'); Write-Output (,$t); Write-Output $t":
        "Write-Output (,'a b')\nWrite-Output 'a b'",
    '$t = [string]-1.50d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'-1.50')\nWrite-Output '-1.50'",
    '$t = [string]0.0000001; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1E-07')\nWrite-Output '1E-07'",
    '$t = [string]0.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'0.0')\nWrite-Output '0.0'",
    '$t = [string]0.5d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'0.5')\nWrite-Output '0.5'",
    '$t = [string]1.000d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.000')\nWrite-Output '1.000'",
    '$t = [string]1.00d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.00')\nWrite-Output '1.00'",
    '$t = [string]1.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.0')\nWrite-Output '1.0'",
    '$t = [string]1.100d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.100')\nWrite-Output '1.100'",
    '$t = [string]1.10d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.10')\nWrite-Output '1.10'",
    '$t = [string]1.50d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.50')\nWrite-Output '1.50'",
    '$t = [string]1.5; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.5')\nWrite-Output '1.5'",
    '$t = [string]1.5E-7; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1.5E-07')\nWrite-Output '1.5E-07'",
    '$t = [string]10d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'10')\nWrite-Output '10'",
    '$t = [string]1E20; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1E+20')\nWrite-Output '1E+20'",
    '$t = [string]1L; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'1')\nWrite-Output '1'",
    '$t = [string]2.0d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'2.0')\nWrite-Output '2.0'",
    '$t = [string]5; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'5')\nWrite-Output '5'",
    '$t = [string]79228162514264337593543950335d; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'79228162514264337593543950335')\nWrite-Output '79228162514264337593543950335'",
    '$t = [string][uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        "Write-Output (,'18446744073709551615')\nWrite-Output '18446744073709551615'",
    "$t = [uint16]'0xFFFF'; Write-Output (,$t); Write-Output $t":
        'Write-Output (,[uint16]65535)\nWrite-Output ([uint16]65535)',
    '$t = [uint16]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint16]7)\nWrite-Output ([uint16]7)',
    '$t = [uint32]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint32]7)\nWrite-Output ([uint32]7)',
    '$t = [uint64]0 -or $false; Write-Output (,$t); Write-Output $t':
        'Write-Output (,$False)\nWrite-Output $False',
    '$t = [uint64]18446744073709551615 + 1; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.8446744073709552e+19)\nWrite-Output 1.8446744073709552e+19',
    '$t = [uint64]18446744073709551615; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint64]18446744073709551615)\nWrite-Output ([uint64]18446744073709551615)',
    '$t = [uint64]7; Write-Output (,$t); Write-Output $t':
        'Write-Output (,[uint64]7)\nWrite-Output ([uint64]7)',
    "$t = if (- '0') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (0) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    "$t = if (- '5') { 'yes' } else { 'no' }; Write-Output (,$t); Write-Output $t":
        "$t = if (-5) {\n  'yes'\n} else {\n  'no'\n}\nWrite-Output (,$t)\nWrite-Output $t",
    '$v = $null; $t = $v -band [uint32]1; Write-Output (,$t); Write-Output $t':
        '$t = $Null -BAnd [uint32]1\nWrite-Output (,$t)\nWrite-Output $t',
    '$v = \'a\'; & ([ScriptBlock]::Create(\'$v + "b"\')); Write-Output (1 + 1)':
        'Write-Output 2',
    '$v = \'a\'; & ([ScriptBlock]::Create(\'$v = "b"\')); Write-Output $v; Write-Output (1 + 1)':
        "Write-Output 'a'\nWrite-Output 2",
    "$v = 'a'; & { Write-Host $v }; $v = 'c'":
        "& {\n  Write-Host 'a'\n}",
    '$v = \'a\'; . ([ScriptBlock]::Create(\'$v = "b"\')); Write-Output $v; Write-Output (1 + 1)':
        '$v = \'a\'\n. ([ScriptBlock]::Create(\'$v = "b"\'))\nWrite-Output $v\nWrite-Output 2',
    '$v = 41; & { $v++; Write-Host $v }; Write-Host $v':
        '$v = 41\n& {\n  $v++\n  Write-Host $v\n}\nWrite-Host 41',
    "$v = Get-Variable ErrorActionPreference; $v.Value = 'Stop'; trap { continue }; [int]'a'; Write-Output 'after'":
        '$v = Get-Variable ErrorActionPreference\n'
        "$v.Value = 'Stop'\n"
        "[int]'a'\n"
        "Write-Output 'after'",
    '$v = [single]1.5; $t = $v -shl 1; Write-Output (,$t); Write-Output $t':
        '$v = [single]1.5\n$t = $v -Shl 1\nWrite-Output (,$t)\nWrite-Output $t',
    '$x = $($r = [byte]77; $r); Write-Output ($x -is [byte])':
        'Write-Output ($True)',
    '$x = $($r = [char]66; $r); Write-Output ($x -is [char])':
        'Write-Output ($True)',
    "$x = $($w = 'a'; 'v'); Write-Output $w":
        "Write-Output 'a'",
    "$x = $($y = 'a'; 'v'); Write-Output $x; Write-Output ((Get-Variable | Where-Object Name -eq 'y').Value)":
        "$y = 'a'\n"
        "$x = 'v'\n"
        'Write-Output $x\n'
        "Write-Output ((Get-Variable | Where-Object Name -EQ 'y').Value)",
    "$x = 'a'; $ExecutionContext.InvokeCommand.InvokeScript('Write-Host $x'); $x = 'c'":
        "Write-Host 'a'",
    '$x = \'a\'; $c = \'$script:x = "b"\'; function f { iex $c }; f; Write-Host $x':
        "$x = 'a'\n"
        '$c = \'$script:x = "b"\'\n'
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        "Write-Host 'a'",
    "$x = 'a'; $c = 'Write-Host $x'; function f { iex $c }; f; $x = 'c'":
        "$x = 'a'\n$c = 'Write-Host $x'\nfunction f {\n  Invoke-Expression $c\n}\nf\n$x = 'c'",
    "$x = 'a'; $c = @('$script:x = 5')[(Get-Random -Maximum 1)]; & ([scriptblock]::Create($c)); Write-Output $x":
        "$x = 'a'\n"
        "$c = @('$script:x = 5')[(Get-Random -Maximum 1)]\n"
        '& ([scriptblock]::Create($c))\n'
        "Write-Output 'a'",
    "$x = 'a'; $c = @('function Write-Host { $script:x = 5 }')[(Get-Random -Maximum 1)]; iex $c; "
    "$x = 'b'; Write-Host 'hi'; Write-Output $x":
        "$x = 'a'\n"
        "$c = @('function Write-Host { $script:x = 5 }')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        "$x = 'b'\n"
        "Write-Host 'hi'\n"
        "Write-Output 'b'",
    "$x = 'a'; $false -and ($x = 'b'); Write-Host $x":
        "$False -and ($x = 'b')\nWrite-Host 'b'",
    "$x = 'a'; $true -or ($x = 'b'); Write-Host $x":
        "$True -or ($x = 'b')\nWrite-Host 'b'",
    "$x = 'a'; $v = Get-ChildItem variable:\\; ($v | Where-Object Name -eq 'x').Value = 'b'; Write-Output $x":
        "$x = 'a'\n"
        '$v = Get-ChildItem variable:\\\n'
        "($v | Where-Object Name -EQ 'x').Value = 'b'\n"
        'Write-Output $x',
    "$x = 'a'; $v = Get-Variable x -ValueOnly:$false; $v.Value = 'b'; Write-Output $x":
        "$x = 'a'\n$v = Get-Variable x -ValueOnly:$False\n$v.Value = 'b'\nWrite-Output $x",
    "$x = 'a'; & { $ExecutionContext.SessionState.PSVariable.Remove('x') }; Write-Output $x":
        "& {\n  $ExecutionContext.SessionState.PSVariable.Remove('x')\n}\nWrite-Output 'a'",
    "$x = 'a'; & { Write-Host $script:x }; $x = 'b'":
        "& {\n  Write-Host 'a'\n}",
    "$x = 'a'; &('i' + 'ex') '$x = \"b\"'; Write-Host $x":
        'Write-Host "b"',
    "$x = 'a'; . { $local:x = 'b' }; Write-Output $x":
        ". {\n  $local:x = 'b'\n}\nWrite-Output 'a'",
    "$x = 'a'; . { Write-Output $local:x }; $x = 'b'":
        '. {\n  Write-Output $local:x\n}',
    "$x = 'a'; 1 | ForEach-Object { $local:x = 'b' }; Write-Output $x":
        "1 | ForEach-Object {\n  $local:x = 'b'\n}\nWrite-Output 'a'",
    "$x = 'a'; 1 | ForEach-Object { Write-Output $local:x }; $x = 'b'":
        '1 | ForEach-Object {\n  Write-Output $local:x\n}',
    "$x = 'a'; 1..2 | ForEach-Object { Write-Host $x }; $x = 'c'":
        "1, 2 | ForEach-Object {\n  Write-Host 'a'\n}",
    "$x = 'a'; Invoke-Command -ScriptBlock { Write-Host $x }; $x = 'c'":
        "Write-Host 'a'",
    "$x = 'a'; Write-Host $x; $c = @('Write-Host $x')[(Get-Random -Maximum 1)]; iex $c":
        "$x = 'a'\n"
        "Write-Host 'a'\n"
        "$c = @('Write-Host $x')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c',
    "$x = 'a'; Write-Output (Get-Variable x -OutVariable v).Value; Write-Output $v.Name":
        "Write-Output 'a'\nWrite-Output $v.Name",
    "$x = 'a'; function f { $ExecutionContext.SessionState.PSVariable.Remove('x') }; f; Write-Output $x":
        'function f {\n'
        "  $ExecutionContext.SessionState.PSVariable.Remove('x')\n"
        '}\n'
        'f\n'
        "Write-Output 'a'",
    "$x = 'a'; function f { Remove-Item variable:x }; f; Write-Output $x":
        "function f {\n  Remove-Item variable:x\n}\nf\nWrite-Output 'a'",
    "$x = 'a'; function f { Write-Host $script:x }; f; $x = 'b'":
        "$x = 'a'\nfunction f {\n  Write-Host $script:x\n}\nf",
    "$x = 'a'; function f { Write-Host $x }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$x = 'a'; function f { Write-Host (Get-Item variable:x).Value }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$x = 'a'; function f { Write-Host (Get-Variable x -ValueOnly) }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host ($x)\n}\nf",
    "$x = 'a'; function f { Write-Host (item variable:x).Value }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host $x\n}\nf",
    "$x = 'a'; function f { Write-Host (variable x -ValueOnly) }; f; $x = 'c'":
        "$x = 'a'\nfunction f {\n  Write-Host ($x)\n}\nf",
    "$x = 'a'; function f { iex $c }; $c = @('$script:x = 5')[(Get-Random -Maximum 1)]; f; Write-Output $x":
        "$x = 'a'\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        "$c = @('$script:x = 5')[(Get-Random -Maximum 1)]\n"
        'f\n'
        "Write-Output 'a'",
    "$x = 'a'; if ($true) { trap { Write-Output $local:x; continue }; throw 'e' }":
        "if ($True) {\n  trap {\n    Write-Output $local:x\n    continue\n  }\n  throw 'e'\n}",
    "$x = 'hello'; $x":
        "'hello'",
    "$x = 'one'; try { $x = 'two'; $null = [int]'a'; $x = 'three' } catch [System.IO.IOException] { }; Write-Host $x":
        "$x = 'one'\n"
        'try {\n'
        "  $x = 'two'\n"
        "  $Null = [int]'a'\n"
        "  $x = 'three'\n"
        '} catch [System.IO.IOException] {}\n'
        'Write-Host $x',
    "$x = 'one'; try { throw 'q' } catch { $x = 'two'; & { $null = [int]'a' }; $x = 'three' }; Write-Host $x":
        "$x = 'one'\n"
        'try {\n'
        "  throw 'q'\n"
        '} catch {\n'
        "  $x = 'two'\n"
        '  & {\n'
        "    $Null = [int]'a'\n"
        '  }\n'
        "  $x = 'three'\n"
        '}\n'
        'Write-Host $x',
    '$x = (1).5':
        '$x = $Null',
    '$x = 1, 2, 3; $a = $null; $a = $a + $x; $a[0] = 9; Write-Output $x[0]':
        '$x = 1, 2, 3\n$a = $Null\n$a = $Null + $x\n$a[0] = 9\nWrite-Output $x[0]',
    '$x = 1, 2, 3; $a = 0, 0; $a[0] = $x; Write-Output $a[0]':
        '$a = 0, 0\n$a[0] = (1, 2, 3)\nWrite-Output $a[0]',
    '$x = 1, 2, 3; $a, $b = $x, 9; Write-Output $a':
        '$a, $b = (1, 2, 3), 9\nWrite-Output $a',
    '$x = 1, 2, 3; $a, $b = ,$x; Write-Output ([object]::ReferenceEquals($x, $a))':
        '$a, $b = ,(1, 2, 3)\nWrite-Output ([Object]::ReferenceEquals((1, 2, 3), $a))',
    '$x = 1, 2, 3; $b = $null; $b += $x; Write-Output ([object]::ReferenceEquals($x, $b))':
        'Write-Output ([Object]::ReferenceEquals((1, 2, 3), (1, 2, 3)))',
    '$x = 1, 2, 3; $b = 7, 8; $null = (. { $b = $x }), ($b[0] = 9); Write-Output $x':
        '$x = 1, 2, 3\n$b = 7, 8\n$Null = (. {\n  $b = $x\n}), ($b[0] = 9)\nWrite-Output $x',
    '$x = 1, 2, 3; $b = @(([object[]]$x)); Write-Output ([object]::ReferenceEquals($x, $b))':
        '$b = @(([Object[]](1, 2, 3)))\nWrite-Output ([Object]::ReferenceEquals((1, 2, 3), $b))',
    '$x = 1, 2, 3; $b, $c = $x; [Array]::Reverse($x); Write-Output $b':
        '$x = 1, 2, 3\n$b, $c = (1, 2, 3)\n[Array]::Reverse($x)\nWrite-Output $b',
    "$x = 1, 2, 3; $c = '$x = 7, 8, 9'; iex $c; [Array]::Reverse($x); Write-Output $x":
        '$x = 7, 8, 9\n[Array]::Reverse($x)\nWrite-Output (9, 8, 7)',
    "$x = 1, 2, 3; $c = @('$x[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; Write-Output $x":
        '$x = 1, 2, 3\n'
        "$c = @('$x[0] = 9')[(Get-Random -Maximum 1)]\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        'Write-Output $x',
    "$x = 1, 2, 3; $c = @('$x[0] = 9')[(Get-Random -Maximum 1)]; & ([scriptblock]::Create($c)); Write-Output $x":
        '$x = 1, 2, 3\n'
        "$c = @('$x[0] = 9')[(Get-Random -Maximum 1)]\n"
        '& ([scriptblock]::Create($c))\n'
        'Write-Output (1, 2, 3)',
    "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; $ExecutionContext.InvokeCommand.InvokeScript($c) | Out-Null; Write-Output $x[1]":
        '$x = 1, 2, 3\n'
        "$c = @('$x[1] = 9')[(Get-Random -Maximum 1)]\n"
        '$ExecutionContext.InvokeCommand.InvokeScript($c) | Out-Null\n'
        'Write-Output 2',
    "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; & { iex $c }; Write-Output $x[1]":
        '$x = 1, 2, 3\n'
        "$c = @('$x[1] = 9')[(Get-Random -Maximum 1)]\n"
        '& {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'Write-Output 2',
    "$x = 1, 2, 3; $c = @('$x[1] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; Write-Output $x[1]":
        '$x = 1, 2, 3\n'
        "$c = @('$x[1] = 9')[(Get-Random -Maximum 1)]\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        'Write-Output 2',
    "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$h = @{\n'
        '  k = $x\n'
        '}\n'
        "$c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        'Write-Output $x',
    "$x = 1, 2, 3; $h = @{ k = $x }; $c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$h = @{\n'
        '  k = $x\n'
        '}\n'
        "$c = @('$h.k[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $h = @{ k = $x }; Write-Output $h.k':
        '$h = @{\n  k = (1, 2, 3)\n}\nWrite-Output $h.k',
    "$x = 1, 2, 3; $h = @{ k = $x }; Write-Output ($x -join (& { $h.k[0] = 9; ',' }))":
        '$x = 1, 2, 3\n'
        '$h = @{\n'
        '  k = $x\n'
        '}\n'
        'Write-Output ((1, 2, 3) -Join (& {\n'
        '  $h.k[0] = 9\n'
        "  ','\n"
        '}))',
    "$x = 1, 2, 3; $h = @{}; $h['k'] = $x; Write-Output $h['k']":
        "$h = @{}\n$h['k'] = (1, 2, 3)\nWrite-Output $h['k']",
    "$x = 1, 2, 3; $l = New-Object Collections.ArrayList; "
    ",$l | ForEach-Object -MemberName Add -ArgumentList (,$x) | Out-Null; "
    "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$l = New-Object Collections.ArrayList\n'
        ',$l | ForEach-Object -MemberName Add -ArgumentList (,$x) | Out-Null\n'
        "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    "$x = 1, 2, 3; $l = New-Object Collections.ArrayList; [void]$l.Add($x); "
    "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$l = New-Object Collections.ArrayList\n'
        '[void]$l.Add($x)\n'
        "$c = @('$l[0][0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    "$x = 1, 2, 3; $o = New-Object PSObject -Property @{ k = $x }; $c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$o = New-Object PSObject -Property @{\n'
        '  k = $x\n'
        '}\n'
        "$c = @('$o.k[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $o = [pscustomobject]@{ P = 0 }; $o.P = $x; Write-Output $o.P':
        '$o = [pscustomobject]@{\n  P = 0\n}\n$o.P = (1, 2, 3)\nWrite-Output $o.P',
    '$x = 1, 2, 3; $r = [Array]::Reverse($x); Write-Output $x':
        '$x = 1, 2, 3\n$Null = [Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; $w = ($z = $y = $x)[0]; $z[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$Null = ($z = $y = $x)[0]\n$z[0] = 9\nWrite-Output $x',
    "$x = 1, 2, 3; $w = [Collections.ArrayList]::Adapter($x); $c = @('$w[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$w = [Collections.ArrayList]::Adapter($x)\n'
        "$c = @('$w[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $x.get_SyncRoot()[0] = 9; Write-Output $x[0]':
        '(1, 2, 3).get_SyncRoot()[0] = 9\nWrite-Output 1',
    '$x = 1, 2, 3; $y = $($x); [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n$y = $x\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; $y = $x -as [array]; $y[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$y = $x -As [array]\n$y[0] = 9\nWrite-Output $x',
    "$x = 1, 2, 3; $y = $x; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$y = $x\n'
        "$c = @('$y[0] = 9')[(Get-Random -Maximum 1)]\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $y = $x; $x = 9, 9, 9; Write-Output $y':
        'Write-Output (1, 2, 3)',
    '$x = 1, 2, 3; $y = $x; $x | Set-Variable z; $y[0] = 9; Write-Output $z':
        '$x = 1, 2, 3\n$y = $x\n(1, 2, 3) | Set-Variable z\n$y[0] = 9\nWrite-Output $z',
    '$x = 1, 2, 3; $y = $x; $y = 9, 9, 9; [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n[Array]::Reverse($x)\nWrite-Output (9, 9, 9)',
    '$x = 1, 2, 3; $y = $x; & { $y = 9, 9, 9 }; [Array]::Reverse($x); Write-Output $y':
        '$x = 1, 2, 3\n$y = $x\n& {\n  $y = 9, 9, 9\n}\n[Array]::Reverse($x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; $y = $x; Write-Output $y[0]; [Array]::Reverse($x); Write-Output $y[0]':
        '$x = 1, 2, 3\n$y = $x\nWrite-Output $y[0]\n[Array]::Reverse($x)\nWrite-Output 3',
    "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; function f { iex $c }; f; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$y = & {\n'
        '  ,$x\n'
        '}\n'
        "$c = @('$y[0] = 9')[(Get-Random -Maximum 1)]\n"
        'function f {\n'
        '  Invoke-Expression $c\n'
        '}\n'
        'f\n'
        'Write-Output $x',
    "$x = 1, 2, 3; $y = & { ,$x }; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$y = & {\n'
        '  ,$x\n'
        '}\n'
        "$c = @('$y[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $y = 0, 0, 0; $x.CopyTo($y, 0); Write-Output $y':
        '$y = 0, 0, 0\n(1, 2, 3).CopyTo($y, 0)\nWrite-Output $y',
    '$x = 1, 2, 3; $y = 0, 0, 0; [Array]::Copy($x, $y, 3); Write-Output $y':
        '$y = 0, 0, 0\n[Array]::Copy((1, 2, 3), $y, 3)\nWrite-Output $y',
    '$x = 1, 2, 3; $y = 0, 0; if ((Get-Random -Maximum 1) -eq 0) { $y = $x }; $y[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n'
        '$y = 0, 0\n'
        'if ((Get-Random -Maximum 1) -Eq 0) {\n'
        '  $y = $x\n'
        '}\n'
        '$y[0] = 9\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $y = @([object[]]$x); $y[0] = 9; Write-Output $x':
        '$x = 1, 2, 3\n$y = @([Object[]]$x)\n$y[0] = 9\nWrite-Output $x',
    "$x = 1, 2, 3; $y = Sort-Object -InputObject $x; $c = @('$y[0] = 9')[(Get-Random -Maximum 1)]; iex $c; Write-Output $x":
        '$x = 1, 2, 3\n'
        '$y = Sort-Object -InputObject $x\n'
        "$c = @('$y[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; $y = if ($True) { $x }; $x[0] = 9; Write-Output $y[0]':
        '$x = 1, 2, 3\n$y = if ($True) {\n  (1, 2, 3)\n}\n$x[0] = 9\nWrite-Output $y[0]',
    "$x = 1, 2, 3; (,$x).ForEach('SetValue', 9, 0); Write-Output $x[0]":
        "$x = 1, 2, 3\n(,(1, 2, 3)).ForEach('SetValue', 9, 0)\nWrite-Output 1",
    '$x = 1, 2, 3; ,$x | ForEach-Object SetValue 9 0; Write-Output $x[0]':
        ',(1, 2, 3) | ForEach-Object SetValue 9 0\nWrite-Output 1',
    '$x = 1, 2, 3; Write-Output $x[0]; $x[0] = 9; Write-Output $x[0]':
        '$x = 1, 2, 3\nWrite-Output 1\n$x[0] = 9\nWrite-Output $x[0]',
    '$x = 1, 2, 3; Write-Output $x[0]; [Array]::Reverse($x); Write-Output $x[0]':
        '$x = 1, 2, 3\nWrite-Output 1\n[Array]::Reverse($x)\nWrite-Output 3',
    "$x = 1, 2, 3; [AppDomain]::CurrentDomain.SetData('k', $x); "
    "$c = @('[AppDomain]::CurrentDomain.GetData(''k'')[0] = 9')[(Get-Random -Maximum 1)]; iex $c; "
    'Write-Output $x':
        '$x = 1, 2, 3\n'
        "[AppDomain]::CurrentDomain.SetData('k', $x)\n"
        "$c = @('[AppDomain]::CurrentDomain.GetData(''k'')[0] = 9')[(Get-Random -Maximum 1)]\n"
        'Invoke-Expression $c\n'
        'Write-Output $x',
    '$x = 1, 2, 3; [Array]::Clear($x, 0, 1); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Clear($x, 0, 1)\nWrite-Output ($Null, 2, 3)',
    '$x = 1, 2, 3; [Array]::Reverse($script:x); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($script:x)\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; [Array]::Reverse($x -as [array]); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($x -As [array])\nWrite-Output $x',
    '$x = 1, 2, 3; [Array]::Reverse($x, 0, 2); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse($x, 0, 2)\nWrite-Output (2, 1, 3)',
    '$x = 1, 2, 3; [Array]::Reverse(($x)); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse(($x))\nWrite-Output (3, 2, 1)',
    '$x = 1, 2, 3; [Array]::Reverse(@([object[]]$x)); Write-Output $x':
        '$x = 1, 2, 3\n[Array]::Reverse(@([Object[]]$x))\nWrite-Output $x',
    '$x = 1, 2, 3; [Collections.ArrayList]::Adapter($x).set_Item(0, 9); Write-Output $x[0]':
        '[Collections.ArrayList]::Adapter((1, 2, 3)).set_Item(0, 9)\nWrite-Output 1',
    '$x = 1, 2, 3; class C { static [object] M() { return $script:x } }; $y = [C]::M(); $y[0] = 9; Write-Output $x[0]':
        '$x = 1, 2, 3\nclass C {\n  static [Object] M() {\n    return $script:x\n  }\n}\n$y = [C]::M()\n$y[0] = 9\nWrite-Output $x[0]',
    '$x = 1, 2, 3; for ($i = 0; $i -lt 2; $i++) { Write-Output $x[0]; [Array]::Reverse($x) }':
        '$x = 1, 2, 3\nfor ($i = 0; $i -LT 2; $i++) {\n  Write-Output $x[0]\n  [Array]::Reverse($x)\n}',
    '$x = 1, 2, 3; function f { if ((Get-Random -Maximum 1) -eq 1) { $o = 0, 0 }; $o[0] = 9 }; function g($p) { $o = $p; f }; g $x; Write-Output $x':
        '$x = 1, 2, 3\n'
        'function f {\n'
        '  if ((Get-Random -Maximum 1) -Eq 1) {\n'
        '    $o = 0, 0\n'
        '  }\n'
        '  $o[0] = 9\n'
        '}\n'
        'function g {\n'
        '  Param($p)\n'
        '  $o = $p\n'
        '  f\n'
        '}\n'
        'g $x\n'
        'Write-Output $x',
    '$x = 1, 2; $y = Sort-Object -InputObject $x; Write-Output ([object]::ReferenceEquals($x, $y))':
        '$y = Sort-Object -InputObject (1, 2)\nWrite-Output ([Object]::ReferenceEquals((1, 2), $y))',
    '$x = 1, 2; Write-Output ([object]::ReferenceEquals($x, $x))':
        'Write-Output ([Object]::ReferenceEquals((1, 2), (1, 2)))',
    "$x = 1, 2; [AppDomain]::CurrentDomain.SetData('k', $x); "
    "Write-Output ([object]::ReferenceEquals($x, [AppDomain]::CurrentDomain.GetData('k')))":
        "[AppDomain]::CurrentDomain.SetData('k', (1, 2))\n"
        "Write-Output ([Object]::ReferenceEquals((1, 2), [AppDomain]::CurrentDomain.GetData('k')))",
    '$x = 1e3.5':
        '$x = $Null',
    '$x = 3..5':
        '$x = 3, 4, 5',
    "$x = @('a', 'b'); $x[1]":
        "'b'",
    '$x = Get-Random -Maximum 1; Write-Output $script:x; $x = 5; Write-Output $x':
        '$x = Get-Random -Maximum 1\nWrite-Output $script:x\nWrite-Output 5',
    "$y = 'b'; $x = 'a'; Copy-Item variable:y variable:x; Write-Output $x":
        "Copy-Item variable:y variable:x\nWrite-Output 'a'",
    "$y = 'b'; $x = 'a'; Remove-Variable x; Rename-Item variable:y x; Write-Output $x":
        "$x = 'a'\nRemove-Variable x\nRename-Item variable:y x\nWrite-Output $x",
    '$y = 1, 2; $n = 1; $z = $y * $n; Write-Output ([object]::ReferenceEquals($y, $z))':
        'Write-Output ([Object]::ReferenceEquals((1, 2), (1, 2)))',
    '$y = 1, 2; $z = $y * 1.4; Write-Output ([object]::ReferenceEquals($y, $z))':
        '$z = (1, 2) * 1.4\nWrite-Output ([Object]::ReferenceEquals((1, 2), $z))',
    '$y = 1, 2; $z = $y * 1; Write-Output ([object]::ReferenceEquals($y, $z))':
        'Write-Output ([Object]::ReferenceEquals((1, 2), (1, 2)))',
    '$y = 1, 2; $z = $y * 2; $z[0] = 9; Write-Output $y':
        '$z = 1, 2, 1, 2\n$z[0] = 9\nWrite-Output (1, 2)',
    "$z = 1.000d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.000')\nWrite-Output 'x1.000'",
    "$z = 1.00d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.00')\nWrite-Output 'x1.00'",
    "$z = 1.0d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.0')\nWrite-Output 'x1.0'",
    '$z = 1.100d; $t = $z + 0d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,1.100d)\nWrite-Output 1.100d',
    "$z = 1.100d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.100')\nWrite-Output 'x1.100'",
    "$z = 1.10d; $t = 'x' + $z; Write-Output (,$t); Write-Output $t":
        "Write-Output (,'x1.10')\nWrite-Output 'x1.10'",
    '$z = 1.50d; $t = $z + 1.50d; Write-Output (,$t); Write-Output $t':
        'Write-Output (,3.00d)\nWrite-Output 3.00d',
    '% { Write-Host 1 }':
        'ForEach-Object {\n  Write-Host 1\n}',
    '& { Write-Output $local:ShellId }':
        "& {\n  Write-Output 'Microsoft.PowerShell'\n}",
    "& { foreach ($i in 1..2) { try { throw 'x' } catch { Write-Host 'a'; $null = [int]'b'; trap { break } }; trap { continue } } }":
        "& {\n  foreach ($i in 1, 2) {\n    Write-Host 'a'\n  }\n}",
    "&('Write' + '-Output') 'indirect'":
        "Write-Output 'indirect'",
    "'ABC'.ToLower()":
        "'abc'",
    "'a' * 3":
        "'aaa'",
    "'a' + 'b'":
        "'ab'",
    "'a', 1, $null, @(1, 2), (New-Object Object) | Out-Null; Write-Output 'after'":
        "Write-Output 'after'",
    "'a{0}c' -f 'b'":
        "'abc'",
    "'{0}-{1}' -f 'a', 'b'":
        "'a-b'",
    "('a')":
        "'a'",
    "('a', 'b', 'c') -join ''":
        "'abc'",
    '(1)':
        '1',
    '-not $x':
        '$True',
    '1 + 2':
        '3',
    '1..2':
        '1, 2',
    '1..3 | ForEach-Object { $_ * 2 }':
        '2, 4, 6',
    "Get-Command zzqnope -ErrorAction SilentlyContinue; Set-Alias zzq Write-Output; $?":
        'Get-Command zzqnope -ErrorAction SilentlyContinue\nSet-Alias zzq Write-Output',
    "Get-Item nope -ErrorAc Stop; Write-Host 'after'":
        "Get-Item nope -ErrorAction Stop\nWrite-Host 'after'",
    "Get-Item nope -e Stop; Write-Host 'after'":
        "Get-Item nope -Exclude Stop\nWrite-Host 'after'",
    "Get-Item nope -errora Stop; Write-Host 'after'":
        "Get-Item nope -ErrorAction Stop\nWrite-Host 'after'",
    "Invoke-Expression '$ErrorActionPreference = 0'; if ($Host) { throw 'vm'; exit }; Write-Host 'payload'":
        "$ErrorActionPreference = 0\nif ($Host) {\n  throw 'vm'\n  exit\n}\nWrite-Host 'payload'",
    "Set-Alias -N zzq -V Write-Output; zzq 'one-letter'":
        "Write-Output 'one-letter'",
    "Set-Alias -Na zzq -Val Write-Output; zzq 'abbreviated'":
        "Write-Output 'abbreviated'",
    "Set-Alias -Value Write-Output -Name zzq; zzq 'named-out-of-order'":
        "Write-Output 'named-out-of-order'",
    "Set-Alias q1 -V Write-Output; q1 'x'":
        "Write-Output 'x'",
    "Set-Alias q2 -v Write-Output; q2 'y'":
        "Write-Output 'y'",
    "Set-Alias zq3 Write-Output; ${alias:zq3} = 'Write-Host'; zq3 'z'":
        "Set-Alias zq3 Write-Output\n$alias:zq3 = 'Write-Host'\nzq3 'z'",
    "Set-Alias zzq Write-Host; $c = 'Set-Alias'; & $c zzq Write-Output; zzq 'x'":
        "Write-Output 'x'",
    "Set-Alias zzq Write-Output; $n = 'zzq'; & $n 'dispatched'":
        "Write-Output 'dispatched'",
    "Set-Alias zzq Write-Output; $n = 'zzq'; (Get-Alias $n).Definition":
        "Set-Alias zzq Write-Output\n(Get-Alias 'zzq').Definition",
    'Set-Alias zzq Write-Output; ${alias:zzq}':
        'Set-Alias zzq Write-Output\n$alias:zzq',
    "Set-Alias zzq Write-Output; (Get-Alias | Where-Object { $_.Name -eq 'zzq' }).Definition":
        "Set-Alias zzq Write-Output\n(Get-Alias | Where-Object {\n  $_.Name -Eq 'zzq'\n}).Definition",
    'Set-Alias zzq Write-Output; (alias zzq).Definition':
        'Set-Alias zzq Write-Output\n(Get-Alias zzq).Definition',
    "Set-Alias zzq Write-Output; Invoke-Expression 'Set-Alias zzq Write-Host'; zzq 'x'":
        "Write-Host 'x'",
    "Set-Alias zzq Write-Output; zzq 'exported'; Export-ModuleMember -Alias zzq":
        "Set-Alias zzq Write-Output\nWrite-Output 'exported'\nExport-ModuleMember -Alias zzq",
    "Set-Alias zzq Write-Output; zzq 'resolved'":
        "Write-Output 'resolved'",
    "Set-Alias zzq iex; zzq 'Write-Output loaded'":
        'Write-Output loaded',
    "Set-StrictMode -Version 1; $v = 1; Remove-Variable v; try { $null = $v; Write-Output 'read' } catch { Write-Output 'caught' }":
        'Set-StrictMode -Version 1\n'
        '$v = 1\n'
        'Remove-Variable v\n'
        'try {\n'
        '  $Null = $v\n'
        "  Write-Output 'read'\n"
        '} catch {\n'
        "  Write-Output 'caught'\n"
        '}',
    "Set-Variable -Name ('Error' + 'ActionPreference') -Value 0; throw 'boom'; Write-Host 'after'":
        "$ErrorActionPreference = 0\nthrow 'boom'\nWrite-Host 'after'",
    "Set-Variable global:y 'b'; Write-Host $global:y":
        'Write-Host $global:y',
    'Set-Variable q 5; function fq { $q + 1 }; Write-Output (fq)':
        '$q = 5\nfunction fq {\n  $q + 1\n}\nWrite-Output (fq)',
    "Set-Variable s 'A'; Write-Output $($s + 'B')":
        "Write-Output 'AB'",
    "Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty -Value { 99 }; Write-Host 'abc'.Length":
        'Update-TypeData -Force -TypeName System.String -MemberName Length -MemberType ScriptProperty -Value {\n  99\n}\nWrite-Host 3',
    "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty -Value { Write-Host 'S' }; $Null = 'abc'.Zq; Write-Host 'A'":
        "Update-TypeData -TypeName System.String -MemberName Zq -MemberType ScriptProperty -Value {\n  Write-Host 'S'\n}\nWrite-Host 'A'",
    "Write-Host 'a'; return; Write-Host 'b'":
        "Write-Host 'a'\nreturn",
    "Write-Host 'abc'.Length":
        'Write-Host 3',
    "Write-Host ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVs!bG8=')))":
        "Write-Host 'Hello'",
    'Write-Output "abc".Length':
        'Write-Output 3',
    "Write-Output $($r = ''; foreach ($e in 'a', 'b') { $r = $r + $e }; $r)":
        "Write-Output 'ab'",
    "Write-Output $($w = 'x'; $w); Write-Output $w":
        "Write-Output 'x'\nWrite-Output 'x'",
    "Write-Output $(foreach ($e in 'a', 'b') { $e })":
        "Write-Output $('a', 'b')",
    'Write-Output $script:ShellId':
        "Write-Output 'Microsoft.PowerShell'",
    "Write-Output 'abc'.Length":
        'Write-Output 3',
    "Write-Output ('A' * 3)":
        "Write-Output 'AAA'",
    "Write-Output ('a,b' -split [char]44); Write-Output ('a,b' -split ',')":
        "Write-Output ('a', 'b')\nWrite-Output ('a', 'b')",
    "Write-Output ('x' -replace 'x', [char]65); Write-Output ('x' -replace 'x', 'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output ('xyx'.Replace([char]120, [char]122)); Write-Output ('xyx'.Replace('x', 'z'))":
        "Write-Output 'zyz'\nWrite-Output 'zyz'",
    "Write-Output ('{0}' -f [char]65); Write-Output ('{0}' -f 'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output (('AB').PSTypeNames)":
        "Write-Output ('System.String', 'System.Object')",
    'Write-Output ((5).PSTypeNames)':
        "Write-Output ('System.Int32', 'System.ValueType', 'System.Object')",
    "Write-Output (([char]65).Count); Write-Output (('A').Count)":
        'Write-Output 1\nWrite-Output 1',
    "Write-Output (([char]65).Length); Write-Output (('A').Length)":
        'Write-Output 1\nWrite-Output 1',
    "Write-Output (([char]65).ToString()); Write-Output (('A').ToString())":
        "Write-Output 'A'\nWrite-Output 'A'",
    "Write-Output (([char]65, [char]66) -join ''); Write-Output (('A', 'B') -join '')":
        "Write-Output 'AB'\nWrite-Output 'AB'",
    "Write-Output (1 + [char]65); Write-Output (1 + 'A')":
        "Write-Output 66\nWrite-Output (1 + 'A')",
    'Write-Output (Get-Date -Y 2020 -Month 1 -Day 1).Year':
        'Write-Output (Get-Date -Year 2020 -Month 1 -Day 1).Year',
    "Write-Output ([Text.Encoding].GetProperty('UTF8').GetValue($Null))":
        'Write-Output ([Text.Encoding]::UTF8)',
    "Write-Output ([Text.Encoding].GetProperty('UTF8').GetValue($Null, $Null))":
        'Write-Output ([Text.Encoding]::UTF8)',
    "Write-Output ([char[]](72, 73) -is [string]); Write-Output ('HI' -is [string])":
        'Write-Output ($False)\nWrite-Output ($True)',
    "Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')":
        "Write-Output 'r5'\nWrite-Output 'r5'",
    "Write-Output ([char]65 + 1); Write-Output ('A' + 1)":
        "Write-Output 'A1'\nWrite-Output 'A1'",
    "Write-Output ([char]65 -eq 'A'); Write-Output ('A' -eq 'A')":
        'Write-Output ($True)\nWrite-Output ($True)',
    "Write-Output ([char]65 -is [char]); Write-Output ('A' -is [char])":
        'Write-Output ($True)\nWrite-Output ($False)',
    "Write-Output ([object]::ReferenceEquals([Text.Encoding].GetProperty('UTF8').GetValue($Null), [Text.Encoding]::UTF8))":
        'Write-Output ([Object]::ReferenceEquals([Text.Encoding]::UTF8, [Text.Encoding]::UTF8))',
    "Write-Output ([string][char]65); Write-Output ([string]'A')":
        "Write-Output 'A'\nWrite-Output 'A'",
    "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGk='))":
        "'hi'",
    '[int]$q = 5; Write-Output $q.ToString()':
        "Write-Output '5'",
    "[int]$v1 = 1; if ($args.Count -ge 0) { trap { Write-Output 'T'; continue }; $v1 = 'abc' }; Write-Output 'after'":
        '[int]$v1 = 1\n'
        'if ($args.Count -GE 0) {\n'
        '  trap {\n'
        "    Write-Output 'T'\n"
        '    continue\n'
        '  }\n'
        "  $v1 = 'abc'\n"
        '}\n'
        "Write-Output 'after'",
    "[int]'42' + 1":
        '43',
    "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string]); iex 'Write-Host ([System.Math].FullName)'":
        "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string])\n"
        'Write-Host ([System.Math].FullName)',
    "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string]); iex 'try { throw ''x'' } catch { $k = [System.Math]::Sqrt(36); Write-Host ''rest'' }; Write-Host ''after'''":
        "[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Add('System.Math', [string])\n"
        "Write-Host 'rest'\n"
        "Write-Host 'after'",
    "[string]$q = 'abc'; Write-Output $q.Substring(1, 1)":
        "Write-Output 'b'",
    "[string]$q = 5; $q += 'a'; Write-Output (,$q)":
        "Write-Output (,'5a')",
    "[string]$q = 5; [System.String]$q = 'ab'; Write-Output $q":
        "Write-Output 'ab'",
    "[string]::Join('', ('a', 'b'))":
        "'ab'",
    'class C { $P = ($script:x = 5) }; $x = 0; $o = [C]::new(); Write-Output $x':
        'class C {\n  $P = ($script:x = 5)\n}\n$x = 0\n$Null = [C]::new()\nWrite-Output $x',
    "class C { $P = [int]::TryParse('42', [ref]$script:x) }; $x = 0; $o = [C]::new(); Write-Output $x":
        "class C {\n  $P = [int]::TryParse('42', [ref]$script:x)\n}\n$x = 0\n$Null = [C]::new()\nWrite-Output $x",
    'do { 1 } while ($a)':
        '1',
    'echo a < b':
        'Write-Output a < b',
    'for ($i = 0; $i -lt 2; $i++) { 1 }':
        'for ($i = 0; $i -LT 2; $i++) {\n  1\n}',
    "foreach ($i in 1, 2) { try { $null = [int]'a'; Write-Host \"rest $i\" } finally { }; Write-Host \"next $i\" }; Write-Host 'after'":
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        "    $Null = [int]'a'\n"
        '    Write-Host "rest ${i}"\n'
        '  } finally {}\n'
        '  Write-Host "next ${i}"\n'
        '}\n'
        "Write-Host 'after'",
    "foreach ($i in 1, 2) { try { try { continue } finally { $null = [int]'a' } } catch { }; Write-Host \"m$i\" }; Write-Host 'after'":
        'foreach ($i in 1, 2) {\n'
        '  try {\n'
        '    try {\n'
        '      continue\n'
        '    } finally {\n'
        "      $Null = [int]'a'\n"
        '    }\n'
        '  } catch {}\n'
        '  Write-Host "m${i}"\n'
        '}\n'
        "Write-Host 'after'",
    "foreach ($i in 1..2) { Write-Output $($c = $c + 'x'; $c) }":
        "foreach ($i in 1, 2) {\n  Write-Output $($c = $c + 'x'\n  $c)\n}",
    'foreach ($i in 1..2) { Write-Output $(if (0) { $m = \'A\' }; $o = "${m}"; $m = \'B\'; $o) }':
        'foreach ($i in 1, 2) {\n  Write-Output $(if (0) {\n    $m = \'A\'\n  }\n  $o = "${m}"\n  $m = \'B\'\n  $o)\n}',
    "foreach ($l in @(@(), @(1), @($null), (,1), (1, 'a', $null, @(2, 3)))) { Write-Output $l.GetType().FullName; [array]::Reverse($l) }; Write-Output 'after'":
        "foreach ($l in @(@(), @(1), @($Null), (,1), (1, 'a', $Null, @(2, 3)))) {\n"
        '  Write-Output $l.GetType().FullName\n'
        '  [array]::Reverse($l)\n'
        '}\n'
        "Write-Output 'after'",
    "function Get-Alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        "'from-function'",
    "function Get-Get-Zqfrob { Write-Output 'hit' }; Get-Zqfrob":
        'Get-Zqfrob',
    "function Get-Language { $Null = 668 }; language; Write-Host 'A'":
        "function Get-Language {}\nlanguage\nWrite-Host 'A'",
    "function Get-Zq-Frob { Write-Output 'hit' }; Zq-Frob":
        'Zq-Frob',
    "function Get-Zqfrob { Write-Output 'hit' }; Zqfrob":
        "function Get-Zqfrob {\n  Write-Output 'hit'\n}\nGet-zqfrob",
    "function Get-Zqfrob { Write-Output 'p' }; function Zqfrob { Write-Output 'b' }; Zqfrob":
        "function Zqfrob {\n  Write-Output 'b'\n}\nZqfrob",
    "function K { $Null = 1 }; K; $Null = (Get-Command K).Name; Write-Host 'A'":
        "$Null = (Get-Command K).Name\nWrite-Host 'A'",
    'function K { $Null = 1 }; K; $b = { K }; Write-Host $b':
        'function K {}\nK\n$b = {\n  K\n}\nWrite-Host $b',
    'function K { $Null = 1 }; K; Write-Host ($function:K -ne $Null)':
        'function K {}\nK\nWrite-Host ($function:K -NE $Null)',
    "function K { $Null = 1 }; Write-Error 'e'; K; Write-Host $?":
        "function K {}\nWrite-Error 'e'\nK\nWrite-Host $?",
    "function K { $Null = [Int]'abc' }; K; Write-Host 'A'":
        "Write-Host 'A'",
    "function K { [Alias('q')] param() $Null = 1 }; q; Write-Host 'A'":
        "function K {\n  [Alias('q')]\n  Param()\n}\nq\nWrite-Host 'A'",
    "function K { param([int] $x = '42') }; K; Write-Host 'A'":
        "Write-Host 'A'",
    'function Measure-Object { $Null = 1 }; Measure-Object; 1, 2, 3 | measure':
        'function Measure-Object {}\nMeasure-Object\n1, 2, 3 | Measure-Object',
    "function alias { 'from-function' }; Set-Alias zzq Write-Output; alias zzq":
        "'from-function'",
    'function dec($d) { $o = New-Object byte[] 2; $o[0] = $d; $o[1] = 1; $o }; Write-Output (dec 5)':
        'Write-Output (5, 1)',
    'function dec($d, $k) { $o = @(0) * $d.Length; for ($i = 0; $i -lt $d.Length; $i++) { $o[$i] = $d[$i] -bxor $k[$i % $k.Length] }; $o }; $key = 1, 2, 3; Write-Output (dec (4, 5, 6) $key)':
        'function dec {\n'
        '  Param($d, $k)\n'
        '  $o = @(0) * $d.Length\n'
        '  for ($i = 0; $i -LT $d.Length; $i++) {\n'
        '    $o[$i] = $d[$i] -BXor $k[$i % $k.Length]\n'
        '  }\n'
        '  $o\n'
        '}\n'
        'Write-Output (dec (4, 5, 6) (1, 2, 3))',
    "function echo { 'from-function' }; echo 'from-alias'":
        "Write-Output 'from-alias'",
    'function f { $i = 0; $i++; $i++; $i }; $t = f; Write-Output (,$t); Write-Output $t':
        'Write-Output (,(0, 1, 2))\nWrite-Output (0, 1, 2)',
    'function f { $input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        'function f {\n  $Input\n  $Input | ForEach-Object {\n    Write-Host "seen:${_}"\n  }\n}\n1, 2 | f',
    "function f { $null = [int]'b' }; trap { Write-Host 'T'; $null = [int]'a'; continue }; f; Write-Host 'after'":
        'function f {\n'
        "  $Null = [int]'b'\n"
        '}\n'
        'trap {\n'
        "  Write-Host 'T'\n"
        "  $Null = [int]'a'\n"
        '  continue\n'
        '}\n'
        'f\n'
        "Write-Host 'after'",
    'function f { $null; 1; $null }; $t = f; Write-Output $t.Count; Write-Output (,$t)':
        'Write-Output 1\nWrite-Output (,1)',
    "function f { $s = 'abc'; $s++; $s }; $t = f; Write-Output (,$t); Write-Output $t":
        'Write-Output (,(0, 1))\nWrite-Output (0, 1)',
    "function f { $script:x = 'one'; $null = [int]'a'; $script:x = 'two' }; try { f } catch { }; Write-Host $script:x":
        'function f {\n'
        "  $script:x = 'one'\n"
        "  $Null = [int]'a'\n"
        "  $script:x = 'two'\n"
        '}\n'
        'try {\n'
        '  f\n'
        '} catch {}\n'
        'Write-Host $script:x',
    "function f { $x }; & { $x = 'a'; f }":
        "& {\n  $x = 'a'\n}",
    'function f { ,$args }; $t = f 1 2; Write-Output (,$t); Write-Output $t.Count':
        'Write-Output (,(1, 2))\nWrite-Output 2',
    "function f { [CmdletBinding()] param(); $null = [int]'a'; Write-Host 'f-rest' }; f -ErrorAction Stop; Write-Host 'after'":
        'function f {\n'
        '  [CmdletBinding()]\n'
        '  Param()\n'
        "  Write-Host 'f-rest'\n"
        '}\n'
        'f -ErrorAction Stop\n'
        "Write-Host 'after'",
    'function f { [object[]]$a = 1, 2; [Array]::Reverse(@($a)); Write-Output $a }; f':
        'function f {\n  [Object[]]$a = 1, 2\n  [Array]::Reverse(@($a))\n  Write-Output $a\n}\nf',
    'function f { [void]$input; $input | ForEach-Object { Write-Host "seen:$_" } }; 1, 2 | f':
        'function f {\n  [void]$Input\n  $Input | ForEach-Object {\n    Write-Host "seen:${_}"\n  }\n}\n1, 2 | f',
    "function f { try { $null = [int]'a'; Write-Host 'f-rest' } finally { }; Write-Host 'f-after' }; f; Write-Host 'after'":
        'function f {\n'
        '  try {\n'
        "    $Null = [int]'a'\n"
        "    Write-Host 'f-rest'\n"
        '  } finally {}\n'
        "  Write-Host 'f-after'\n"
        '}\n'
        'f\n'
        "Write-Host 'after'",
    "function f { try { 'tail' } catch {} }; Write-Host (f)":
        "Write-Host 'tail'",
    "function f { try { try { return 'r' } finally { $null = [int]'a' } } catch { }; 'tail' }; Write-Host (f)":
        'function f {\n'
        '  try {\n'
        '    try {\n'
        "      return 'r'\n"
        '    } finally {\n'
        "      $Null = [int]'a'\n"
        '    }\n'
        '  } catch {}\n'
        "  'tail'\n"
        '}\n'
        'Write-Host (f)',
    "function g { $null = [int]'a'; Write-Host 'in' }; try { throw 'x' } catch { g }; Write-Host 'after'":
        'function g {\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'in'\n"
        '}\n'
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  g\n'
        '}\n'
        "Write-Host 'after'",
    'function g { ,(1, 2) }; $t = @(g); Write-Output $t.Count; Write-Output (,$t[0])':
        'Write-Output 2\nWrite-Output (,1)',
    "function q { $Null = 1 }; ${function:q} = { Write-Host 'P' }; q":
        "function q {}\n$function:q = {\n  Write-Host 'P'\n}\nq",
    "function vnMTH { $Null = 1 }; vnMTH; $Null = (Get-Command *vnMT*).Name; Write-Host 'A'":
        "$Null = (Get-Command *vnMT*).Name\nWrite-Host 'A'",
    "function zzqfoo1 { 'boom' }; zzqfoo1":
        "'boom'",
    'iex \'$u = "U"\'; Write-Output $($u + \'x\')':
        "Write-Output 'Ux'",
    "if ($Host) { try { $null = [int]'a'; Write-Host 'rest' } finally { }; Write-Host 'if-rest' }; Write-Host 'after'":
        'if ($Host) {\n'
        '  try {\n'
        "    $Null = [int]'a'\n"
        "    Write-Host 'rest'\n"
        '  } finally {}\n'
        "  Write-Host 'if-rest'\n"
        '}\n'
        "Write-Host 'after'",
    'if ($a) { 1 }':
        '',
    'if ($a) { 1 } elseif ($b) { 2 } else { 3 }':
        '3',
    "if ($true) { 'yes' } else { 'no' }":
        "'yes'",
    "if ($true) { trap [System.IO.IOException] { continue }; [int]'a'; Write-Host 'tail' }; Write-Host 'after'":
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        '    continue\n'
        '  }\n'
        "  [int]'a'\n"
        "  Write-Host 'tail'\n"
        '}\n'
        "Write-Host 'after'",
    "if ($true) { trap { continue }; Write-Host 'in'; throw 'e' }; Write-Host 'after'":
        "if ($True) {\n  trap {\n    continue\n  }\n  Write-Host 'in'\n  throw 'e'\n}\nWrite-Host 'after'",
    "switch ('b') { 'a' { 'first' } 'b' { 'second' } }":
        "'second'",
    "throw 'e'; Write-Host 'after'":
        "throw 'e'",
    'trap [E] { 1 }':
        '',
    "trap { Write-Host 'T'; $null = [int]'a'; continue }; & { $null = [int]'b' }; Write-Host 'after'":
        "trap {\n  Write-Host 'T'\n  $Null = [int]'a'\n  continue\n}\n& {\n  $Null = [int]'b'\n}\nWrite-Host 'after'",
    "trap { Write-Host 'T'; $null = [int]'a'; continue }; Get-Item -BogusParam foo; Write-Host 'after'":
        "trap {\n  Write-Host 'T'\n  $Null = [int]'a'\n  continue\n}\nGet-Item -BogusParam foo\nWrite-Host 'after'",
    "trap { Write-Host 'e'; continue }; [int]'a'; Set-Alias c Write-Output; c 'hi'":
        "trap {\n  Write-Host 'e'\n  continue\n}\n[int]'a'\nSet-Alias c Write-Output\nWrite-Output 'hi'",
    "trap { Write-Host 'outer'; continue }; if ($true) { trap [System.IO.IOException] { Write-Host 'inner'; continue }; throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  Write-Host 'outer'\n  continue\n}\nif ($True) {\n  trap [System.IO.IOException] {\n    Write-Host 'inner'\n    continue\n  }\n  throw 'e'\n  Write-Host 'tail'\n}\nWrite-Host 'next'",
    "trap { Write-Host 'outer'; continue }; if ($true) { trap { Write-Host 'inner'; continue }; throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  Write-Host 'outer'\n  continue\n}\nif ($True) {\n  trap {\n    Write-Host 'inner'\n    continue\n  }\n  throw 'e'\n  Write-Host 'tail'\n}\nWrite-Host 'next'",
    "trap { break }; trap { continue }; [int]'a'; Write-Host 'after'":
        "trap {\n  break\n}\n[int]'a'\nWrite-Host 'after'",
    "trap { continue }; $a = @('x', '5'); for ($i = 0; $i -lt 2; $i++) { $y = [int]$a[$i] }; Write-Host \"y=$y\"":
        'trap {\n'
        '  continue\n'
        '}\n'
        "$a = @('x', '5')\n"
        'for ($i = 0; $i -LT 2; $i++) {\n'
        '  $y = [int]$a[$i]\n'
        '}\n'
        'Write-Host "y=${y}"',
    "trap { continue }; $out = New-Object byte[] 3; for ($i = 0; $i -lt 3; $i++) { $out[$i] = 7 -bxor $k[$i % $k.Length] }; Write-Host \"out=$($out -join ',')\"":
        'trap {\n'
        '  continue\n'
        '}\n'
        '$out = New-Object byte[] 3\n'
        'for ($i = 0; $i -LT 3; $i++) {\n'
        '  $out[$i] = 7 -BXor $k[$i % $k.Length]\n'
        '}\n'
        "Write-Host \"out=$($out -Join ',')\"",
    "trap { continue }; $s = [string][char]256 + 'b'; $k = [char[]]$s | ForEach-Object { [byte][char]$_ }; Write-Host \"count=$($k.Count) key=$($k -join ',')\"":
        'trap {\n'
        '  continue\n'
        '}\n'
        "$k = [char[]]'Āb' | ForEach-Object {\n"
        '  [byte][char]$_\n'
        '}\n'
        "Write-Host \"count=$($k.Count) key=$($k -Join ',')\"",
    "trap { continue }; $s = { throw 'x' }; [int]'a'; Write-Host 'after'":
        "$Null = {\n  throw 'x'\n}\n[int]'a'\nWrite-Host 'after'",
    'trap { continue }; $x = "$(1/0)$(Set-Alias zzq Write-Output)"; zzq \'hi\'':
        'trap {\n  continue\n}\n$Null = "$(1 / 0)$(Set-Alias zzq Write-Output)"\nzzq \'hi\'',
    "trap { continue }; 1/0; Write-Host 'after'":
        "1 / 0\nWrite-Host 'after'",
    "trap { continue }; [int]'a'; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'after'",
    "trap { continue }; for ($i = 0; $True; $i++) { $null = [int]$env:COMPUTERNAME; Write-Host 'tail'; break }; Write-Host 'next'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'for ($i = 0; $True; $i++) {\n'
        '  $Null = [int]$env:ComputerName\n'
        "  Write-Host 'tail'\n"
        '  break\n'
        '}\n'
        "Write-Host 'next'",
    "trap { continue }; foreach ($i in 1..2) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  continue\n}\nforeach ($i in 1, 2) {\n  throw 'e'\n}\nWrite-Host 'next'",
    "trap { continue }; foreach ($q in 1, 2) { trap { continue }; [int]'a'; Write-Host \"tail $q\" }; Write-Host 'after'":
        "foreach ($q in 1, 2) {\n  [int]'a'\n  Write-Host \"tail ${q}\"\n}\nWrite-Host 'after'",
    "trap { continue }; iex 'throw 1'; Write-Host 'after'":
        "trap {\n  continue\n}\nthrow 1\nWrite-Host 'after'",
    "trap { continue }; if ($Host) { $x = 'one'; $null = [int]'a'; $x = 'two' }; Write-Host $x":
        "trap {\n  continue\n}\nif ($Host) {\n  $x = 'one'\n  $Null = [int]'a'\n  $x = 'two'\n}\nWrite-Host $x",
    "trap { continue }; if ($Host) { trap [System.IO.IOException] { continue }; $null = [int]'a'; Write-Host 'rest' }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ($Host) {\n'
        '  trap [System.IO.IOException] {\n'
        '    continue\n'
        '  }\n'
        "  $Null = [int]'a'\n"
        "  Write-Host 'rest'\n"
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; if ($True) { $null = [int]$env:COMPUTERNAME; Write-Host 'tail' }; Write-Host 'next'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        '  $Null = [int]$env:ComputerName\n'
        "  Write-Host 'tail'\n"
        '}\n'
        "Write-Host 'next'",
    "trap { continue }; if ($true) { [int]'a'; Write-Host 'tail' }; Write-Host 'after'":
        "trap {\n  continue\n}\nif ($True) {\n  [int]'a'\n  Write-Host 'tail'\n}\nWrite-Host 'after'",
    "trap { continue }; if ($true) { throw 'e'; Write-Host 'tail' }; Write-Host 'next'":
        "trap {\n  continue\n}\nthrow 'e'\nWrite-Host 'next'",
    "trap { continue }; if ($true) { trap [System.IO.IOException] { continue }; [int]'a'; Write-Host 'tail' }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        '  trap [System.IO.IOException] {\n'
        '    continue\n'
        '  }\n'
        "  [int]'a'\n"
        "  Write-Host 'tail'\n"
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; if ($true) { trap [System.IO.IOException] { continue }; if ($true) { trap { continue }; [int]'a' }; Write-Host 'mid' }; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'mid'\nWrite-Host 'after'",
    "trap { continue }; if ($true) { trap { break }; if ($true) { [int]'a'; Write-Host 'tail' }; Write-Host 'mid' }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ($True) {\n'
        "  [int]'a'\n"
        "  Write-Host 'tail'\n"
        "  Write-Host 'mid'\n"
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; if ($true) { trap { break }; if ($true) { trap { continue }; [int]'a'; Write-Host 'tail' }; Write-Host 'mid' }; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'tail'\nWrite-Host 'mid'\nWrite-Host 'after'",
    "trap { continue }; if ($true) { trap { continue }; [int]'a'; Write-Host 'tail' }; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'tail'\nWrite-Host 'after'",
    "trap { continue }; if ((Get-Date).Year -gt 2000) { $v = [int]'a'; Write-Host 't' }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ((Get-Date).Year -GT 2000) {\n'
        "  $v = [int]'a'\n"
        "  Write-Host 't'\n"
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; if ((Get-Date).Year -gt 2000) { foreach ($q in 1, 2) { [int]'a'; Write-Host \"t $q\" }; trap { break } }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'if ((Get-Date).Year -GT 2000) {\n'
        '  foreach ($q in 1, 2) {\n'
        "    [int]'a'\n"
        '    Write-Host "t ${q}"\n'
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; if ((Get-Date).Year -gt 2000) { trap [System.IO.IOException] { continue }; $v = [int]'a' }; Write-Host 'after'":
        "if ((Get-Date).Year -GT 2000) {}\nWrite-Host 'after'",
    "trap { continue }; switch (1) { 1 { $null = [int]$env:COMPUTERNAME; Write-Host 'tail' } }; Write-Host 'next'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'switch (1) {\n'
        '  1 {\n'
        '    $Null = [int]$env:ComputerName\n'
        "    Write-Host 'tail'\n"
        '  }\n'
        '}\n'
        "Write-Host 'next'",
    "trap { continue }; switch (1) { 1 { throw 'e'; Write-Host 'tail' } }; Write-Host 'next'":
        "trap {\n  continue\n}\nthrow 'e'\nWrite-Host 'next'",
    "trap { continue }; trap [System.Management.Automation.RuntimeException] { break }; $z = 0; 1/$z; Write-Host 'after'":
        "trap [System.Management.Automation.RuntimeException] {\n  break\n}\n1 / 0\nWrite-Host 'after'",
    "trap { continue }; trap { Write-Host 'p' }; $u = [int]'a'; Write-Host 'after'":
        "trap {\n  continue\n}\ntrap {\n  Write-Host 'p'\n}\nWrite-Host 'after'",
    "trap { continue }; trap { break }; [int]'a'; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'after'",
    "trap { continue }; try { $v = [int]'a'; trap { break } } finally { }; Write-Host 'after'":
        "Write-Host 'after'",
    "trap { continue }; try { if ($Host) { return } } finally { $null = [int]'a' }; Write-Host 'after'":
        'trap {\n'
        '  continue\n'
        '}\n'
        'try {\n'
        '  if ($Host) {\n'
        '    return\n'
        '  }\n'
        '} finally {\n'
        "  $Null = [int]'a'\n"
        '}\n'
        "Write-Host 'after'",
    "trap { continue }; try { trap [System.IO.IOException] { continue }; $v = [int]'a' } finally { }; Write-Host 'after'":
        "Write-Host 'after'",
    "trap { continue }; zzq0000=5; Write-Host 'after'":
        "zzq0000=5\nWrite-Host 'after'",
    "trap { }; [int]'a'; Write-Host 'after'":
        "[int]'a'\nWrite-Host 'after'",
    "try { $null = 1, 2 | Select-Object -First -1; Write-Output 'ok' } catch { Write-Output 'caught' }":
        "try {\n  $Null = 1, 2 | Select-Object -First -1\n  Write-Output 'ok'\n} catch {\n  Write-Output 'caught'\n}",
    "try { $null = Get-Process; Write-Output 'ok' } catch { Write-Output 'caught' }":
        "try {\n  Write-Output 'ok'\n} catch {\n  Write-Output 'caught'\n}",
    "try { $null = [int]'a' } catch [System.Management.Automation.RuntimeException] { Write-Host 'R' } catch [System.Exception] { Write-Host 'E' }; Write-Host 'after'":
        'try {\n'
        "  $Null = [int]'a'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'R'\n"
        '} catch [System.Exception] {\n'
        "  Write-Host 'E'\n"
        '}\n'
        "Write-Host 'after'",
    "try { $null = [int]'a' } catch [System.Management.Automation.RuntimeException] { Write-Host 'R' } catch [System.InvalidCastException] { Write-Host 'I' }; Write-Host 'after'":
        'try {\n'
        "  $Null = [int]'a'\n"
        '} catch [System.Management.Automation.RuntimeException] {\n'
        "  Write-Host 'R'\n"
        '} catch [System.InvalidCastException] {\n'
        "  Write-Host 'I'\n"
        '}\n'
        "Write-Host 'after'",
    "try { $null = [int]'a' } finally { Write-Host $? }":
        "try {\n  $Null = [int]'a'\n} finally {\n  Write-Host $?\n}",
    "try { $null = [int]'a'; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "try {\n  $Null = [int]'a'\n  Write-Host 'rest'\n} finally {}\nWrite-Host 'after'",
    "try { $x = 'one'; $null = [int]'a'; $x = 'two' } finally { }; Write-Host $x":
        "try {\n  $x = 'one'\n  $Null = [int]'a'\n  $x = 'two'\n} finally {}\nWrite-Host $x",
    "try { $x = 1; $x = [int]$env:COMPUTERNAME } catch { Write-Host 'caught' }; Write-Host $x":
        "try {\n  $x = 1\n  $x = [int]$env:ComputerName\n} catch {\n  Write-Host 'caught'\n}\nWrite-Host $x",
    "try { [int]'a'; Write-Host 'tail' } catch { }; Write-Host 'after'":
        "Write-Host 'after'",
    "try { [void]$undefzz; Write-Host 'quiet' } catch { Write-Host 'caught' }":
        "try {\n  Write-Host 'quiet'\n} catch {\n  Write-Host 'caught'\n}",
    "try { foreach ($i in 1, 2) { Write-Host 'm'; $null = [int]'a' } } catch { }; Write-Host 'after'":
        "try {\n  foreach ($i in 1, 2) {\n    Write-Host 'm'\n    $Null = [int]'a'\n  }\n} catch {}\nWrite-Host 'after'",
    "try { item =5 } catch {}; Write-Host 'after'":
        "try {\n  Get-Item =5\n} catch {}\nWrite-Host 'after'",
    "try { throw 'x' } catch { $null = [int]'a'; Write-Host 'c-rest' }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch {\n  $Null = [int]'a'\n  Write-Host 'c-rest'\n}\nWrite-Host 'after'",
    "try { throw 'x' } catch { $x = 'two'; $null = [int]'a'; $x = 'three' }; Write-Host $x":
        "try {\n  throw 'x'\n} catch {\n  $x = 'two'\n  $Null = [int]'a'\n  $x = 'three'\n}\nWrite-Host $x",
    "try { throw 'x' } catch { & { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch {\n  & {\n    $Null = [int]'a'\n    Write-Host 'in'\n  }\n}\nWrite-Host 'after'",
    "try { throw 'x' } catch { 'caught' }":
        "'caught'",
    "try { throw 'x' } catch { 1 | ForEach-Object { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'":
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  1 | ForEach-Object {\n'
        "    $Null = [int]'a'\n"
        "    Write-Host 'in'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "try { throw 'x' } catch { if ($Host) { $null = [int]'a'; Write-Host 'rest' } }; Write-Host 'after'":
        'try {\n'
        "  throw 'x'\n"
        '} catch {\n'
        '  if ($Host) {\n'
        "    $Null = [int]'a'\n"
        "    Write-Host 'rest'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "try { throw 'x' } catch { if ($false) { } elseif ([int]'a') { }; Write-Host 'rest' }; Write-Host 'after'":
        "try {\n  throw 'x'\n} catch {\n  if ([int]'a') {}\n  Write-Host 'rest'\n}\nWrite-Host 'after'",
    "try { throw 'y' } catch { try { throw 'x' } finally { $null = [int]'a' } }; Write-Host 'after'":
        'try {\n'
        "  throw 'y'\n"
        '} catch {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {\n'
        "    $Null = [int]'a'\n"
        '  }\n'
        '}\n'
        "Write-Host 'after'",
    "try { trap { continue }; [int]'a'; try { throw 'x' } catch { Write-Host 'caught' } } catch { }; Write-Host 'after'":
        "try {\n  trap {\n    continue\n  }\n  [int]'a'\n  Write-Host 'caught'\n} catch {}\nWrite-Host 'after'",
    "try { try { $null = [int]'a' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'":
        "try {\n  try {\n    $Null = [int]'a'\n  } finally {}\n  Write-Host 'rest'\n} finally {}\nWrite-Host 'after'",
    "try { try { $null = [int]'a'; Write-Host 'inner-rest' } finally { Write-Host 'f1' }; Write-Host 'outer-rest' } finally { Write-Host 'f2' }; Write-Host 'after'":
        'try {\n'
        '  try {\n'
        "    $Null = [int]'a'\n"
        "    Write-Host 'inner-rest'\n"
        '  } finally {\n'
        "    Write-Host 'f1'\n"
        '  }\n'
        "  Write-Host 'outer-rest'\n"
        '} finally {\n'
        "  Write-Host 'f2'\n"
        '}\n'
        "Write-Host 'after'",
    "try { try { if ($Host) { exit } } finally { $null = [int]'a' } } catch { }; Write-Host 'after'":
        'try {\n'
        '  try {\n'
        '    if ($Host) {\n'
        '      exit\n'
        '    }\n'
        '  } finally {\n'
        "    $Null = [int]'a'\n"
        '  }\n'
        '} catch {}\n'
        "Write-Host 'after'",
    "try { try { return } finally { $null = [int]'a' } } catch { }; Write-Host 'after'":
        "try {\n  try {\n    return\n  } finally {\n    $Null = [int]'a'\n  }\n} catch {}\nWrite-Host 'after'",
    "try { try { throw 'x' } finally { $null = [int]'a' } } finally { }; Write-Host 'after'":
        "try {\n  try {\n    throw 'x'\n  } finally {\n    $Null = [int]'a'\n  }\n} finally {}\nWrite-Host 'after'",
    "try { zzq0000=5 } catch {}; 'next'":
        "'next'",
    "try { zzqq0 =5 } catch {}; Write-Host 'after'":
        "Write-Host 'after'",
    'while ($a) { 1 }':
        '',
    'while ($a) { break }':
        '',
    'while ($a) { continue }':
        '',
    "$x = 'a'; try { try { throw 'x' } finally { $x = 'b' } } catch { Write-Host $x }":
        'try {\n'
        '  try {\n'
        "    throw 'x'\n"
        '  } finally {}\n'
        '} catch {\n'
        "  Write-Host 'b'\n"
        '}',
    "$ErrorActionPreference = 'Stop'; $x = 'a'; try { trap { }; $x = 'b'; $null = [int]'z'; $x = 'c' } catch { Write-Host 'caught' }; Write-Host $x":
        "$ErrorActionPreference = 'Stop'\n"
        "$x = 'a'\n"
        'try {\n'
        '  trap {}\n'
        "  $x = 'b'\n"
        "  $Null = [int]'z'\n"
        "  $x = 'c'\n"
        '} catch {\n'
        "  Write-Host 'caught'\n"
        '}\n'
        'Write-Host $x',
    '$x = 0; try { . { $x = 1; $null = [int]$Host.Name; $x = 2 } } catch { }; Write-Host $x':
        '$x = 0\n'
        'try {\n'
        '  . {\n'
        '    $x = 1\n'
        '    $Null = [int]$Host.Name\n'
        '    $x = 2\n'
        '  }\n'
        '} catch {}\n'
        'Write-Host $x',
    'trap { continue }; iex \'throw "e"; Write-Host "tail"\'; Write-Host \'next\'':
        'trap {\n'
        '  continue\n'
        '}\n'
        'Invoke-Expression \'throw "e"; Write-Host "tail"\'\n'
        "Write-Host 'next'",
    'trap { continue }; iex \'$null = [int]$Host.Name; Write-Host "tail"\'; Write-Host \'next\'':
        'trap {\n'
        '  continue\n'
        '}\n'
        'Invoke-Expression \'$null = [int]$Host.Name; Write-Host "tail"\'\n'
        "Write-Host 'next'",
    "$b = 0; foreach ($i in 1) { $b = 1 }; while ($b -ne 2) { switch ($b) { 0 { Write-Host 'zero'; $b = 2 } 1 { Write-Host 'one'; $b = 2 } } }":
        '$b = 0\n'
        'foreach ($i in 1) {\n'
        '  $b = 1\n'
        '}\n'
        'while ($b -NE 2) {\n'
        '  switch ($b) {\n'
        '    0 {\n'
        "      Write-Host 'zero'\n"
        '      $b = 2\n'
        '    }\n'
        '    1 {\n'
        "      Write-Host 'one'\n"
        '      $b = 2\n'
        '    }\n'
        '  }\n'
        '}',
    "$s = 0; while ($s -ne -1) { switch ($s) { 0 { Write-Host 'a'; $s = -1 } default { break } } }; Write-Host $s":
        '$s = 0\n'
        'while ($s -NE -1) {\n'
        '  switch ($s) {\n'
        '    0 {\n'
        "      Write-Host 'a'\n"
        '      $s = -1\n'
        '    }\n'
        '    default {\n'
        '      break\n'
        '    }\n'
        '  }\n'
        '}\n'
        'Write-Host $s',
}
