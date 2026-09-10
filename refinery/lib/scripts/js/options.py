"""
Caller-supplied options controlling JavaScript deobfuscation.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from refinery.lib.scripts.js.analysis.environment import HostEnvironment

if TYPE_CHECKING:
    from refinery.lib.scripts.js.model import JsScript


@dataclass(frozen=True)
class DeobfuscationOptions:
    """
    Options that steer JavaScript deobfuscation. *module* selects the execution model the input — and
    therefore the deobfuscated output — is assumed to run under, which decides whether a top-level
    declaration reaches the global object:

    - Script model (default, `module=False`): a browser `<script>`, a Windows Script Host `.js`, or
      any classic global script. A top-level `var`/`function` becomes a property of the global object,
      so a global declaration produced by indirect `eval`, a string timer, or the `Function`
      constructor may be inlined as a plain top-level declaration without changing meaning.

    - Module model (`module=True`): an ES module or a CommonJS file run as `node file.js`. A top-level
      declaration is scoped to the module and never reaches the global object. Indirect eval and string
      timers still run in the global scope, so inlining a global declaration they produce into a plain
      top-level declaration would silently move it out of the global object; such inlinings are
      therefore declined to preserve semantics.

    *entrypoints* holds wildcard patterns naming top-level functions that a host invokes by name — a JXA
    `run`, a Windows Script Host handler, a browser event target. Such a function has no caller inside
    the file, so reachability computed over the file alone judges it dead and removes it, together with
    everything only it reached. Which names a host calls is not knowable from the file, so the analyst
    supplies them; each is matched case-sensitively, because JavaScript identifiers are.

    *environment* pins the host the input is assumed to run in, which decides whether a bare read of a
    name the program never declares resolves or throws a `ReferenceError`. The default `universal`
    asserts only the globals every host shares, so a read of a host-conditional name such as `window` or
    `global` is treated as possibly throwing and no pass drops it; naming the host recovers the folds
    that read enables. See `refinery.lib.scripts.js.analysis.environment.HostEnvironment`.
    """
    module: bool = False
    entrypoints: tuple[str, ...] = ()
    environment: HostEnvironment = HostEnvironment.universal

    def names_entrypoint(self, name: str) -> bool:
        return any(fnmatchcase(name, pattern) for pattern in self.entrypoints)


def module_execution(options: object | None) -> bool:
    """
    Whether *options* selects the module execution model, under which a top-level binding is scoped to
    the module and never reaches the global object. Any value that is not a `DeobfuscationOptions` — a
    transformer run standalone, or with no options attached — defaults to the script model.
    """
    return isinstance(options, DeobfuscationOptions) and options.module


def host_environment(options: object | None) -> HostEnvironment:
    """
    The host environment *options* pins, against which a bare global read is judged present or
    throwing. Any value that is not a `DeobfuscationOptions` — a transformer run standalone, or with no
    options attached — defaults to the `universal` environment, which asserts only the globals the
    language mandates, so an unpinned run is unchanged.
    """
    if isinstance(options, DeobfuscationOptions):
        return options.environment
    return HostEnvironment.universal


def runs_as_module(options: object | None, root: JsScript) -> bool:
    """
    Whether the file at *root* runs under the module execution model: *options* selects it, or the
    file spells module syntax, which no host loads as a script. Every reader of the model asks here,
    so that no file is judged under the script model by one pass and under the module model by
    another.
    """
    return module_execution(options) or root.module


def is_host_entrypoint(options: object | None, name: str) -> bool:
    """
    Whether *name* is a top-level function the analyst declared a host calls by name, so removing it
    would delete code that is reachable from outside the file. Any value that is not a
    `DeobfuscationOptions` names no entrypoints, which is the behavior of every caller that supplies
    none: reachability is then decided by the file alone, as before.
    """
    return isinstance(options, DeobfuscationOptions) and options.names_entrypoint(name)
