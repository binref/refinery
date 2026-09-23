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
import concurrent.futures
import functools
import json
import re
import shutil
import subprocess
import typing

from samples import refuse_script_host_near_a_sample
from test.lib.scripts.ps1.corpus import executable

#: How many hosts may run at once. Kept small because the test suite is itself run across several
#: workers, and each host is a process of its own.
_HOSTS_AT_ONCE = 4

#: How many characters of JSON one batch of sources may come to. `-EncodedCommand` puts the whole
#: script on the command line, and Windows refuses one longer than 32767 characters: the script
#: travels as base64 of UTF-16LE, so each of its characters costs eight thirds of one there, and the
#: payload is base64 of the JSON at four thirds again. What is left over once the fixed part of the
#: script is paid for is a few thousand characters of source, which the corpus grew past — so a
#: payload carries a batch rather than the whole corpus and the reports are concatenated.
_BATCH_BUDGET = 5000

#: How a payload joins the sources in it. Compact, so that one source costs one separator and the
#: budget above is the bound it says it is: `json.dumps` pads with a space by default, which is a
#: character per source that `_batches` does not charge for and a batch of short sources is nearly
#: all of.
_JSON_SEPARATORS = (',', ':')

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
#: transcript. What is recorded per item is deliberately structural rather than rendered: PowerShell
#: renders an error with the source line that raised it, which differs between two spellings of the
#: same program and would report every rewrite as a behaviour change — and for a redirected stream it
#: renders the *harness* line rather than the snippet's. So an error record contributes its
#: identifier and exception type, and nothing positional.
#:
#: There is no top-level handler, because the two kinds of PowerShell error need opposite
#: dispositions and a handler has only one. A statement-terminating error — a failed cast, a division
#: by zero — is reported and stepped over, so the statement after it runs; a terminating error — a
#: `throw`, a command `-ErrorAction Stop`, a `Stop` preference, a `trap` that rethrows — ends the
#: run. A `try` or a `trap` wrapped around the snippet would catch both alike and report the first
#: kind as ending the run, which is the deployment it is not. So each classified line is written to
#: stdout as it is produced — a stepped-over error is an `ERROR` line and the tail still runs, and
#: output written before a terminating error survives — and the terminating error's identity is
#: recovered from stderr by `behaviour`, since it unwinds before the pipeline can classify it.
#:
#: The snippet is dot-sourced rather than called, so that its top level is the host's top level, as
#: it is in a script file or an encoded command. Called instead, it would run one scope deeper than
#: it ever really does, and `$script:` would name the harness rather than the snippet: measured that
#: way, `$x = 'a'; & { $script:x }` reads empty and `[ref]$script:i` throws.
#:
#: The transcript is streamed by a pipeline rather than gathered and printed at the end, because a
#: terminating error unwinds the script before an end-of-run print is reached: everything a snippet
#: wrote before it threw would be lost, and printing then throwing would be indistinguishable from
#: throwing alone. Each line travels as its own base64 token, one per line of stdout, so that a tab
#: or a newline inside a message cannot be mistaken for the structure around it.
#:
#: Dot-sourcing puts the snippet's variables in the same scope as this script's own, which is what
#: the `Oracle` in their names is for.
_BEHAVIOUR_SCRIPT = R'''
$ErrorActionPreference = 'Continue'
$OracleSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@PAYLOAD@'))
. ([ScriptBlock]::Create($OracleSource)) *>&1 | ForEach-Object {
    if ($null -eq $_) {
        $OracleLine = "OUT`t`t<null>"
    } elseif ($_ -is [System.Management.Automation.ErrorRecord]) {
        $OracleLine = "ERROR`t$($_.FullyQualifiedErrorId)`t$($_.Exception.GetType().FullName)"
    } elseif ($_ -is [System.Management.Automation.WarningRecord]) {
        $OracleLine = "WARNING`t$($_.Message)"
    } elseif ($_ -is [System.Management.Automation.VerboseRecord]) {
        $OracleLine = "VERBOSE`t$($_.Message)"
    } elseif ($_ -is [System.Management.Automation.DebugRecord]) {
        $OracleLine = "DEBUG`t$($_.Message)"
    } elseif ($_ -is [System.Management.Automation.InformationRecord]) {
        $OracleLine = "INFO`t$($_.MessageData)"
    } else {
        $OracleLine = "OUT`t$($_.GetType().FullName)`t$_"
    }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($OracleLine))
}
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

    A script too long for one command line is refused by `CreateProcess` rather than by the host,
    which surfaces as an `OSError` naming no script at all — on Windows a `FileNotFoundError` whose
    message reads as if `powershell.exe` were missing. It is reported as an `OracleError` like every
    other way the host cannot be run, so that a caller catching one catches this too.
    """
    refuse_script_host_near_a_sample('powershell')
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
    except OSError as refused:
        raise OracleError(
            F'the host could not be started for a command line of {len(encoded)} characters: '
            F'{refused}'
        ) from refused
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
    it reported, and the tokens it read. Sources are measured a batch at a time, so a corpus costs a
    few processes rather than one process each, and `timeout` bounds one of them — see `_reported`.

    Error identifiers are reported rather than messages, which are localized and quote the value
    that offended.
    """
    return [
        ParseReport(
            errors=tuple(report['errors']),
            tokens=tuple(Token(t['text'], t['kind'], t['flags']) for t in report['tokens']),
            failed=report['failed'],
        )
        for report in _reported(_PARSE_SCRIPT, sources, 'reports', timeout)
    ]


def command_names(
    sources: typing.Sequence[str],
    timeout: float = 120.0,
) -> list[tuple[str, ...]]:
    """
    What 5.1 read as a command name in each source. The flag is set by the parser rather than the
    lexer, so it reports the role a word was given and not how it was spelled: it is what settles
    where a command name ends, which is the question a path, a native switch and a keyword joined
    to more text all turn on.
    """
    return [
        tuple(token.text for token in report.tokens if 'CommandName' in token.flags)
        for report in parse_reports(sources, timeout)
    ]


def behaviour(
    snippet: str,
    rewrite: typing.Callable[[str], str] | None = None,
    timeout: float = 120.0,
) -> tuple[str, ...]:
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

    A non-zero exit is the ordinary shape of a snippet that ends in a terminating error rather than a
    sign the host could not be run: the error unwound before the transcript pipeline could classify
    it, so its `THROW` line is recovered from stderr and appended to what the snippet wrote before it.
    A non-zero exit stderr names no terminating error only when the host genuinely failed, and that
    stays an `OracleError`.
    """
    if snippet not in executable():
        raise OracleError(
            'only a snippet listed in the corpus may be executed; add it there, which is where '
            'the judgement that it is synthetic, small and safe is recorded'
        )
    if rewrite is not None:
        snippet = rewrite(snippet)
    payload = base64.b64encode(snippet.encode('utf-8')).decode('ascii')
    result = run(_BEHAVIOUR_SCRIPT.replace('@PAYLOAD@', payload), timeout)
    written = [
        base64.b64decode(stripped).decode('utf-8')
        for token in result.output.split('\n')
        if (stripped := token.strip())
    ]
    if result.status != 0:
        written.append(F'THROW\t{_terminating_error(result.errors)}')
    return tuple(written)


def behaviours(
    snippets: typing.Sequence[str],
    rewrite: typing.Callable[[str], str] | None = None,
    timeout: float = 120.0,
) -> list[tuple[str, ...]]:
    """
    What each of `snippets` writes. Still one host process per snippet, so nothing about the
    isolation changes; the hosts merely wait on each other rather than in turn, which is what makes
    a table of them affordable to check on every run.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=_HOSTS_AT_ONCE) as pool:
        return list(pool.map(lambda snippet: behaviour(snippet, rewrite, timeout), snippets))


def echo(sources: typing.Sequence[str], timeout: float = 120.0) -> list[str]:
    """
    What the host received. Nothing here is executed or parsed; this exists so that a transport
    fault is a distinct failure from a disagreement about the language.
    """
    return [
        base64.b64decode(item).decode('utf-8')
        for item in _reported(_ECHO_SCRIPT, sources, 'echoed', timeout)
    ]


def _reported(
    script: str,
    sources: typing.Sequence[str],
    field: str,
    timeout: float,
) -> list:
    """
    Every entry of `field` that one of the reporting scripts writes about `sources`, in order.

    The sources travel a batch at a time because `-EncodedCommand` puts the whole payload on the
    command line, and the hosts wait on each other rather than in turn, as `behaviours` does. So
    `timeout` bounds one host process and not the whole measurement, which is what it means
    everywhere else in this module.
    """
    batches = list(_batches(sources))
    with concurrent.futures.ThreadPoolExecutor(max_workers=_HOSTS_AT_ONCE) as pool:
        return [
            item
            for reported in pool.map(lambda batch: _ask(script, batch, field, timeout), batches)
            for item in reported
        ]


def _batches(sources: typing.Sequence[str]) -> typing.Iterator[list[str]]:
    """
    `sources` split into runs that each fit in one command line. A source larger than the budget on
    its own travels alone rather than being split: a source is the unit a report is about, and the
    oversized one then fails loudly against the command-line limit, which is the honest answer.

    What a source costs is exactly what it comes to in the payload `_ask` builds — its own JSON plus
    the one character that separates it from the next — so the budget is the bound it is documented
    to be rather than an estimate that drifts with the number of sources in a batch.
    """
    batch: list[str] = []
    size = 0
    for source in sources:
        cost = len(json.dumps(source)) + 1
        if batch and size + cost > _BATCH_BUDGET:
            yield batch
            batch, size = [], 0
        batch.append(source)
        size += cost
    if batch:
        yield batch


def _ask(script: str, batch: typing.Sequence[str], field: str, timeout: float) -> list:
    """
    Run one of the reporting scripts over one batch and return the field it reports, checked to be
    one entry per source: a host that answered about fewer sources than it was asked about would
    otherwise shift every later source's report onto the wrong one.
    """
    encoded = json.dumps(list(batch), separators=_JSON_SEPARATORS)
    payload = base64.b64encode(encoded.encode('utf-8')).decode('ascii')
    reported = _decode(run(script.replace('@PAYLOAD@', payload), timeout))[field]
    if len(reported) != len(batch):
        raise OracleError(F'asked about {len(batch)} sources and heard about {len(reported)}')
    return reported


#: The chunks a redirected error stream is serialized into. `powershell.exe` writes the error stream
#: as CLIXML when it is captured, and a terminating error the snippet did not handle is rendered into
#: it as a run of `<S S="Error">` strings — the formatted error display, not the record.
_CLIXML_ERROR = re.compile(r'<S S="Error">(?P<chunk>.*?)</S>', re.DOTALL)

#: The label the rendered error display gives its `FullyQualifiedErrorId` line. The host is gated to
#: `Desktop` / `FullLanguage` by `HostInfo.usable`, so the display is the one this label belongs to.
_FQEID_LINE = re.compile(r'FullyQualifiedErrorId\s*:\s*(?P<id>.+)')

#: How CLIXML encodes the characters it may not carry literally, and the XML entities it escapes.
_CLIXML_ESCAPES = (
    ('_x000D_', '\r'),
    ('_x000A_', '\n'),
    ('_x0009_', '\t'),
    ('&lt;', '<'),
    ('&gt;', '>'),
    ('&quot;', '"'),
    ('&amp;', '&'),
)


def _terminating_error(stderr: str) -> str:
    """
    The `FullyQualifiedErrorId` of the terminating error the host reported on stderr. A terminating
    error unwinds before the transcript pipeline can classify it, so its identity is read here from
    the CLIXML the host serializes the error display into — the identifier alone, since what reaches
    stderr is the formatted display rather than the record, and the exception category it shows there
    is lossy where the record's .NET type is not.

    A non-zero exit whose stderr names no such error is a host that genuinely failed, which is an
    `OracleError` like every other way the host cannot be run.
    """
    text = ''.join(match['chunk'] for match in _CLIXML_ERROR.finditer(stderr))
    for encoded, literal in _CLIXML_ESCAPES:
        text = text.replace(encoded, literal)
    identity = _FQEID_LINE.search(text)
    if identity is None:
        raise OracleError(F'the host exited non-zero without a terminating error: {stderr[:200]}')
    return identity['id'].strip()


def _decode(result: Behaviour) -> dict:
    if result.status != 0:
        raise OracleError(F'the host exited with {result.status}: {result.errors.strip()}')
    try:
        return json.loads(result.output)
    except ValueError as broken:
        raise OracleError(F'the host wrote something that is not a report: {result.output[:200]}') \
            from broken
