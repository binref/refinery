"""
Caller-supplied options controlling JavaScript deobfuscation.
"""
from __future__ import annotations

from dataclasses import dataclass


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
    """
    module: bool = False
