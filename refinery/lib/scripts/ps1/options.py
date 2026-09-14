"""
Caller-supplied options controlling PowerShell deobfuscation.

They sit above both the analysis and the transform layers because one run is configured once: the
analysis layer cannot import the transform layer, so an option held there would be a second place a
caller has to configure and a setting the two layers could disagree about.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Ps1DeobfuscationOptions:
    """
    Options that steer PowerShell deobfuscation. Each is the caller's answer to a question the file
    itself cannot settle, which is why neither is derived.

    *preserve_bare_output* selects what a statement that only writes a value to the success output
    stream is worth.

    - Stripping model (default, `preserve_bare_output=False`): such a statement is deleted wherever
      the analysis can prove three things: that evaluating it cannot raise, that its value reaches
      the process output and nothing more, and that no redirection moves it away. What is lost is
      text on a console nobody is watching, and what is bought is the removal of the junk an
      obfuscator pads a script with. The proof rests on one assumption no file can settle: that the
      input is a standalone script and not a library some other file imports, whose functions are
      then called from call sites this analysis never sees.

    - Preserving model (`preserve_bare_output=True`): no such statement is ever deleted. This is the
      answer for a script whose printed output *is* the artifact, and for a `.psm1` or any other
      fragment that runs as part of something larger.

    Neither model touches a statement whose value is captured, whose evaluation does anything, or
    that this analysis cannot read; those are kept under both, and the switch is not what protects
    them.

    *trust_eval* selects what code this analysis cannot read is assumed to do to the .NET type
    system and the command table — the two things
    `refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld` calls the world.

    - Suspecting model (default, `trust_eval=False`): every construct that runs code supplied as
      data opens the world where it stands, and every purity grant below it is refused. This is the
      only sound answer, because the code being run can do anything the runtime allows.

    - Trusting model (`trust_eval=True`): such a construct is assumed to leave both intact, so the
      junk written around it is removed as if it were not there. **This is unsound, deliberately.**
      Measured on Windows PowerShell 5.1, an `Invoke-Expression` payload can register a type
      accelerator named `System.Guid`, after which a later `[System.Guid]::NewGuid()` throws where
      the rewritten script computes a value; it can re-point a property through `Update-TypeData`,
      so `[Diagnostics.Process]::GetCurrentProcess().ProcessName` yields something else; and it can
      define `function Get-Date` in the calling scope. The switch is for triage, where reading the
      script matters more than being able to run the output.

    The trusting model assumes the same of what such code *reads*, which costs more than the type
    system does. A `function` this script defines and no statement in it calls is deleted, so a
    payload whose only job is to call one is left calling a name the output no longer defines; a
    bare value inside a function nothing but the console reads goes the same way, so a payload that
    captures the call gets nothing; and a fault the payload can arm — `Set-StrictMode` reaching a
    bare read below it — stops being reachable, so a statement that terminated the input runs on.
    None of the three is a change to the type system or the command table, and each is a way the
    output can behave differently from a payload that changed neither.

    What the trusting model does *not* excuse is a change the script performs in plain sight.
    `Add-Type`, `Update-TypeData`, `Add-Member`, `Import-Module`, `New-Module`, a `class` or `enum`
    definition, a type-accelerator remap and a PSObject member mutation still open the world under
    both models, and so does a statement that spells out both a command name it takes over and what
    it binds that name to — `New-Alias Get-Date Stop-Process`, `Set-Item function:Get-Date { ... }`.
    The assumption is about code that cannot be read, not about every way a script can reach the
    world.

    *preserve_env_stores* selects what a store to an environment variable that no statement in the
    file reads is worth. No liveness question inside the tree can settle it, because the environment
    is a device every child process reads rather than a variable of the script: an `$env:K = 'v'`
    ahead of a `Start-Process` is how a script hands that child a value.

    - Stripping model (default, `preserve_env_stores=False`): such a store is deleted as declared
      noise, which is what an obfuscator pads a script with; a real store ahead of a child process
      is kept only where something in the file reads it back.

    - Preserving model (`preserve_env_stores=True`): no such store is deleted, for an input whose
      environment writes are the artifact — a dropper passing values to its payload, or a fragment
      of a larger script whose children read what this file sets.
    """
    preserve_bare_output: bool = False
    trust_eval: bool = False
    preserve_env_stores: bool = False


def bare_output_is_preserved(options: object | None) -> bool:
    """
    Whether *options* asks for every write to the success output stream to be kept. Any value that
    is not a `Ps1DeobfuscationOptions` — a transformer run standalone, or one with no options
    attached — defaults to the stripping model, which is what the pipeline does unless told.
    """
    return isinstance(options, Ps1DeobfuscationOptions) and options.preserve_bare_output


def eval_is_trusted(options: object | None) -> bool:
    """
    Whether *options* asks for code this analysis cannot read to be assumed inert. Any value that is
    not a `Ps1DeobfuscationOptions` — a model built standalone, or one with no options attached —
    defaults to the suspecting model, which is the only sound one and what the pipeline does unless
    told.
    """
    return isinstance(options, Ps1DeobfuscationOptions) and options.trust_eval


def env_stores_are_preserved(options: object | None) -> bool:
    """
    Whether *options* asks for a store to an environment variable that no statement in the file
    reads to be kept. Any value that is not a `Ps1DeobfuscationOptions` — a transformer run
    standalone, or one with no options attached — defaults to the stripping model, which is what
    the pipeline does unless told.
    """
    return isinstance(options, Ps1DeobfuscationOptions) and options.preserve_env_stores
