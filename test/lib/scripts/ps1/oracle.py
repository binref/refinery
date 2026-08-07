"""
Windows PowerShell 5.1 as an oracle: what the language actually does, rather than what we believe
it does. Everything here is one primitive — hand a script to `powershell.exe` and read what it
wrote — with two uses built on it, `parse_reports` and `behaviour`.

SECURITY: `behaviour` executes PowerShell. It may only ever be given synthetic, small, safe
snippets: written by hand for the purpose, a few lines long, and doing nothing beyond printing.
Never a malware sample, never a fragment or derivative of one, never text read from a downloaded
file. The repository's samples are malware and running them is forbidden without exception; if a
question seems to need a snippet that breaks the rule, the question goes unanswered.

`parse_reports` does not execute its input. The snippet travels as base64 and is decoded into a
string inside a fixed script, so it never appears as PowerShell syntax. `[Parser]::ParseInput`
resolves names against already-loaded assemblies but loads nothing and runs nothing; the one input
class that reaches outside the process is `using module`, which touches the module path.
"""
from __future__ import annotations

import base64
import functools
import json
import shutil
import subprocess
import typing

from test.lib.scripts.ps1.corpus import BEHAVIOURS

#: Emitted before every script. The output encoding matters because 5.1 writes redirected output in
#: the OEM code page by default, which mangles the quote characters the lexer corpus exists to test.
#: Progress records matter because they are serialized to stderr as CLIXML and would otherwise be
#: the bulk of what a behaviour comparison saw.
_PREAMBLE = '\n'.join((
    '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false',
    "$ProgressPreference = 'SilentlyContinue'",
))

_PARSE_SCRIPT = R'''
$ErrorActionPreference = 'Stop'
$blob = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@PAYLOAD@'))
# ConvertFrom-Json hands the whole array down the pipeline as one object in 5.1 rather than
# enumerating it, so the sources are walked with foreach; a pipeline here silently concatenates
# every source into one string and reports a single result.
$sources = ConvertFrom-Json $blob
$reports = @(foreach ($source in $sources) {
    $errors = $null
    $tokens = $null
    try {
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $source, [ref]$tokens, [ref]$errors)
        @{
            failed = ''
            errors = @($errors | ForEach-Object { $_.ErrorId })
            tokens = @($tokens | ForEach-Object {
                @{ text = $_.Text; kind = "$($_.Kind)"; flags = "$($_.TokenFlags)" } })
        }
    } catch {
        @{ failed = $_.Exception.GetType().Name; errors = @(); tokens = @() }
    }
})
ConvertTo-Json @{ reports = $reports } -Depth 8 -Compress
'''

#: A snippet's whole observable effect is what it writes, so every stream is merged into one ordered
#: transcript and handed back as base64. What is recorded per item is deliberately structural rather
#: than rendered: PowerShell renders an error with the source line that raised it, which differs
#: between two spellings of the same program and would report every rewrite as a behaviour change —
#: and for a redirected stream it renders the *harness* line rather than the snippet's. So an error
#: contributes its identifier and exception type, and nothing positional.
_BEHAVIOUR_SCRIPT = R'''
$ErrorActionPreference = 'Continue'
$snippet = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@PAYLOAD@'))
$lines = New-Object System.Collections.ArrayList
function Add-Line([string] $text) { [void]$lines.Add($text) }
try {
    foreach ($item in (& ([ScriptBlock]::Create($snippet)) *>&1)) {
        if ($null -eq $item) {
            Add-Line "OUT`t`t<null>"
        } elseif ($item -is [System.Management.Automation.ErrorRecord]) {
            Add-Line "ERROR`t$($item.FullyQualifiedErrorId)`t$($item.Exception.GetType().FullName)"
        } elseif ($item -is [System.Management.Automation.WarningRecord]) {
            Add-Line "WARNING`t$($item.Message)"
        } elseif ($item -is [System.Management.Automation.VerboseRecord]) {
            Add-Line "VERBOSE`t$($item.Message)"
        } elseif ($item -is [System.Management.Automation.DebugRecord]) {
            Add-Line "DEBUG`t$($item.Message)"
        } elseif ($item -is [System.Management.Automation.InformationRecord]) {
            Add-Line "INFO`t$($item.MessageData)"
        } else {
            Add-Line "OUT`t$($item.GetType().FullName)`t$item"
        }
    }
} catch {
    Add-Line "THROW`t$($_.FullyQualifiedErrorId)`t$($_.Exception.GetType().FullName)"
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))
'''

#: Hands each source straight back, so that what the host received can be compared with what was
#: sent. Base64 in both directions, because a transport fault is exactly what this detects.
_ECHO_SCRIPT = R'''
$ErrorActionPreference = 'Stop'
$blob = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@PAYLOAD@'))
$sources = ConvertFrom-Json $blob
$echoed = @(foreach ($source in $sources) {
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
})
ConvertTo-Json @{ echoed = $echoed } -Depth 4 -Compress
'''

_HOST_SCRIPT = R'''
ConvertTo-Json @{
    version  = $PSVersionTable.PSVersion.ToString()
    major    = $PSVersionTable.PSVersion.Major
    minor    = $PSVersionTable.PSVersion.Minor
    edition  = "$($PSVersionTable.PSEdition)"
    language = "$($ExecutionContext.SessionState.LanguageMode)"
} -Compress
'''


class OracleError(RuntimeError):
    """
    The host could not be run, or wrote something that is not a report. Distinct from a snippet
    that PowerShell rejected, which is an ordinary result.
    """


class Token(typing.NamedTuple):
    text: str
    kind: str
    flags: str


class ParseReport(typing.NamedTuple):
    errors: tuple[str, ...]
    tokens: tuple[Token, ...]
    failed: str = ''

    @property
    def accepted(self) -> bool:
        return not self.errors and not self.failed


class Behaviour(typing.NamedTuple):
    output: str
    errors: str
    status: int


class HostInfo(typing.NamedTuple):
    version: str
    major: int
    minor: int
    edition: str
    language: str

    @property
    def usable(self) -> bool:
        return (
            self.edition == 'Desktop'
            and (self.major, self.minor) >= (5, 1)
            and self.language == 'FullLanguage'
        )


@functools.cache
def windows_powershell() -> str | None:
    """
    The path to Windows PowerShell, or `None`. Deliberately only a `PATH` lookup: this is called
    from a `skipIf` decorator, which runs at import time in every test worker, so it must not start
    a process. Whether the host is the right one is `host_info`'s question.
    """
    return shutil.which('powershell.exe')


def run(script: str, timeout: float = 120.0) -> Behaviour:
    """
    Run `script` and return what it wrote. The script travels as base64 of UTF-16LE via
    `-EncodedCommand`, which is what keeps quoting, code pages and line endings out of the design:
    a snippet arrives byte for byte. It is also a command rather than a file, so the execution
    policy does not gate it.
    """
    powershell = windows_powershell()
    if powershell is None:
        raise OracleError('Windows PowerShell is not on PATH')
    encoded = base64.b64encode(F'{_PREAMBLE}\n{script}'.encode('utf-16-le')).decode('ascii')
    try:
        done = subprocess.run(
            [powershell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as timedout:
        raise OracleError(F'the host did not finish within {timeout} seconds') from timedout
    return Behaviour(
        done.stdout.decode('utf-8', 'replace'),
        done.stderr.decode('utf-8', 'replace'),
        done.returncode,
    )


def host_info(timeout: float = 120.0) -> HostInfo:
    """
    What the host on `PATH` actually is. A host that is present but wrong — PowerShell 7 shadowing
    5.1, or a constrained language mode, which blocks the `ParseInput` call outright — must fail
    loudly rather than quietly measure a different language.
    """
    return HostInfo(**_decode(run(_HOST_SCRIPT, timeout)))


def parse_reports(sources: typing.Sequence[str], timeout: float = 120.0) -> list[ParseReport]:
    """
    What 5.1 makes of each source, without running any of it: the identifiers of the parse errors
    it reported, and the tokens it read. Every source is measured in one host, so a corpus costs
    one process rather than one process each.

    Error identifiers are reported rather than messages, which are localized and quote the value
    that offended.
    """
    if not sources:
        return []
    payload = base64.b64encode(json.dumps(list(sources)).encode('utf-8')).decode('ascii')
    decoded = _decode(run(_PARSE_SCRIPT.replace('@PAYLOAD@', payload), timeout))
    reports = decoded['reports']
    if len(reports) != len(sources):
        raise OracleError(F'asked about {len(sources)} sources and heard about {len(reports)}')
    return [
        ParseReport(
            errors=tuple(report['errors']),
            tokens=tuple(Token(t['text'], t['kind'], t['flags']) for t in report['tokens']),
            failed=report['failed'],
        )
        for report in reports
    ]


def behaviour(
    snippet: str,
    rewrite: typing.Callable[[str], str] | None = None,
    timeout: float = 120.0,
) -> str:
    """
    Run one snippet and return everything it wrote, as one ordered transcript. SECURITY: see this
    module's own documentation — synthetic, small, safe snippets only, and `snippet` must be one
    the corpus lists.

    A differential needs to run a *rewritten* snippet too, which cannot be listed in advance. It is
    reached by handing the rewrite in rather than its result: what runs is then always something
    derived from a reviewed snippet by a named transformation, and there is no way to run text that
    came from somewhere else.

    One process per snippet, which is what makes each one independent: sharing a host and reusing a
    runspace is faster and is not an isolation boundary, because functions survive a reset and
    `$env:` leaks between runspaces in the same process.
    """
    if snippet not in BEHAVIOURS:
        raise OracleError(
            'only a snippet listed in the corpus may be executed; add it there, which is where '
            'the judgement that it is synthetic, small and safe is recorded'
        )
    if rewrite is not None:
        snippet = rewrite(snippet)
    payload = base64.b64encode(snippet.encode('utf-8')).decode('ascii')
    result = run(_BEHAVIOUR_SCRIPT.replace('@PAYLOAD@', payload), timeout)
    if result.status != 0:
        raise OracleError(F'the host exited with {result.status}: {result.errors.strip()}')
    return base64.b64decode(result.output.strip()).decode('utf-8')


def echo(sources: typing.Sequence[str], timeout: float = 120.0) -> list[str]:
    """
    What the host received. Nothing here is executed or parsed; this exists so that a transport
    fault is a distinct failure from a disagreement about the language.
    """
    if not sources:
        return []
    payload = base64.b64encode(json.dumps(list(sources)).encode('utf-8')).decode('ascii')
    echoed = _decode(run(_ECHO_SCRIPT.replace('@PAYLOAD@', payload), timeout))['echoed']
    return [base64.b64decode(item).decode('utf-8') for item in echoed]


def _decode(result: Behaviour) -> dict:
    if result.status != 0:
        raise OracleError(F'the host exited with {result.status}: {result.errors.strip()}')
    try:
        return json.loads(result.output)
    except ValueError as broken:
        raise OracleError(F'the host wrote something that is not a report: {result.output[:200]}') \
            from broken
