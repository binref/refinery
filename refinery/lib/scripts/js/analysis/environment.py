"""
The host environment a script is assumed to run in, and the set of global names that environment
guarantees a bare read resolves rather than throwing a `ReferenceError`.

A bare read of a name the program neither declares nor assigns reaches the host's global object. Which
names are there is not a language fact but a host one: `window` exists in a browser and throws under
Node, `global` the other way around. The deobfuscator's sound default asserts only what every host
shares — `GUARANTEED_GLOBALS`, the names the ECMAScript specification mandates — and answers every other
bare read may-throw, so no pass drops the `ReferenceError` an absent host raises. An analyst who knows
where a sample runs pins the host with the `js` unit's `-e` switch, and the reads that host guarantees
become certain, recovering the folds the sound default refuses.

This module is the single datum those decisions read. `HostEnvironment.provides` answers, from data
alone, whether a host resolves a name; `SemanticModel.read_may_throw` is the one seam that consults it.
The data is host-partitioned and, per host, built from the language floor (`GUARANTEED_GLOBALS`) plus a
conservative set of host-conditional globals: a name is listed only where its presence is certain, since
under-listing costs at most a fold a wider table would recover while over-listing would drop a real
throw. The `node` set was established by reading the globals out of Node v24 (benign introspection, no
sample executed); the `browser` and `worker` sets are the web-platform globals every implementation of
those scopes exposes.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

GUARANTEED_GLOBAL_TYPEOF: dict[str, str] = {
    'globalThis': 'object',
    'NaN': 'number',
    'Infinity': 'number',
    'undefined': 'undefined',
    'eval': 'function',
    'isFinite': 'function',
    'isNaN': 'function',
    'parseFloat': 'function',
    'parseInt': 'function',
    'decodeURI': 'function',
    'decodeURIComponent': 'function',
    'encodeURI': 'function',
    'encodeURIComponent': 'function',
    'Object': 'function',
    'Function': 'function',
    'Boolean': 'function',
    'Symbol': 'function',
    'BigInt': 'function',
    'Error': 'function',
    'AggregateError': 'function',
    'EvalError': 'function',
    'RangeError': 'function',
    'ReferenceError': 'function',
    'SyntaxError': 'function',
    'TypeError': 'function',
    'URIError': 'function',
    'Number': 'function',
    'Math': 'object',
    'Date': 'function',
    'String': 'function',
    'RegExp': 'function',
    'Array': 'function',
    'Int8Array': 'function',
    'Uint8Array': 'function',
    'Uint8ClampedArray': 'function',
    'Int16Array': 'function',
    'Uint16Array': 'function',
    'Int32Array': 'function',
    'Uint32Array': 'function',
    'Float32Array': 'function',
    'Float64Array': 'function',
    'BigInt64Array': 'function',
    'BigUint64Array': 'function',
    'Map': 'function',
    'Set': 'function',
    'WeakMap': 'function',
    'WeakSet': 'function',
    'WeakRef': 'function',
    'FinalizationRegistry': 'function',
    'ArrayBuffer': 'function',
    'DataView': 'function',
    'JSON': 'object',
    'Promise': 'function',
    'Reflect': 'object',
    'Proxy': 'function',
}
"""
Maps each `GUARANTEED_GLOBALS` name to the string its `typeof` yields. Because the name resolves in
every host to a value of a fixed type — a constructor or built-in function (`'function'`), a namespace
object such as `Math`/`JSON`/`Reflect` or `globalThis` itself (`'object'`), the two numeric constants
(`'number'`), or `undefined` — the operator's result is host-independent, unlike a host-conditional
alias (`window`, `self`, …) whose `typeof` is `'undefined'` where the host omits the name. This is what
lets a simplification fold `typeof globalThis !== 'undefined'` to `true` for a name it can prove
pristine; the values were established under Node 24. `GUARANTEED_GLOBALS` is the key set of this map, so
the two cannot drift.
"""

GUARANTEED_GLOBALS = frozenset(GUARANTEED_GLOBAL_TYPEOF)
"""
Names the ECMAScript specification mandates as properties of the global object and that every mainstream
engine exposes unconditionally, so a bare read of one is guaranteed to resolve rather than throw a
`ReferenceError`. This is an *existence* allowlist — distinct from the getter-purity and host-presence
sets in `refinery.lib.scripts.js.analysis.effects` — used to decide whether `<global-alias>.name` may be
collapsed to the bare `name` without turning the member read's `undefined` into a throw. It excludes host
and alias names (`window`, `self`, `global`, `top`, `frames`, `console`, timers, `Buffer`, …) that are not
universal, and `SharedArrayBuffer`/`Atomics`, which a conformant host may withhold outside a
cross-origin-isolated context. `GUARANTEED_GLOBAL_TYPEOF` additionally records the `typeof` of each. It is
the provide-set of the `UNIVERSAL` host and the language floor every pinned host builds on.
"""

_NODE_GLOBALS = frozenset({
    'global',
    'Buffer',
    'process',
    'console',
    'setTimeout',
    'setInterval',
    'setImmediate',
    'clearTimeout',
    'clearInterval',
    'clearImmediate',
    'queueMicrotask',
    'TextEncoder',
    'TextDecoder',
    'atob',
    'btoa',
    'URL',
    'URLSearchParams',
    'fetch',
    'structuredClone',
    'performance',
    'crypto',
    'SharedArrayBuffer',
    'Atomics',
    'WebAssembly',
    'Intl',
})
"""
Global names a current Node exposes beyond `GUARANTEED_GLOBALS`, read out of Node v24. `global` is Node's
same-realm global-object alias. The CommonJS wrapper locals `require`, `module`, `exports`, `__dirname`,
and `__filename` are deliberately absent: they are injected into a CommonJS file's function scope rather
than being properties of the global object, and an ES module does not see them at all, so whether a bare
read of one resolves is the module-versus-script question `DeobfuscationOptions.module` answers, not a
host-existence one.
"""

_BROWSER_GLOBALS = frozenset({
    'window',
    'self',
    'top',
    'parent',
    'frames',
    'document',
    'location',
    'navigator',
    'history',
    'screen',
    'localStorage',
    'sessionStorage',
    'console',
    'alert',
    'confirm',
    'prompt',
    'setTimeout',
    'setInterval',
    'clearTimeout',
    'clearInterval',
    'requestAnimationFrame',
    'cancelAnimationFrame',
    'queueMicrotask',
    'fetch',
    'XMLHttpRequest',
    'WebSocket',
    'URL',
    'URLSearchParams',
    'btoa',
    'atob',
    'TextEncoder',
    'TextDecoder',
    'performance',
    'crypto',
    'structuredClone',
    'Blob',
    'File',
    'FileReader',
    'FormData',
    'Headers',
    'Request',
    'Response',
    'Event',
    'CustomEvent',
    'MessageChannel',
    'AbortController',
    'Worker',
    'Image',
    'Intl',
    'WebAssembly',
})
"""
Global names a browser window exposes beyond `GUARANTEED_GLOBALS`. `window`, `self`, and `parent` are the
same-realm aliases of the window's own global object; `top` and `frames` resolve too, but in a framed
document they name another realm's global object, which is why the global-object finder keys its
substitution to `refinery.lib.scripts.js.analysis.model.SAME_REALM_GLOBAL_OBJECT_ALIASES` rather than to
mere existence. The set is conservative: a name is listed only where every browser provides it.
"""

_WORKER_GLOBALS = frozenset({
    'self',
    'location',
    'navigator',
    'console',
    'setTimeout',
    'setInterval',
    'clearTimeout',
    'clearInterval',
    'queueMicrotask',
    'fetch',
    'XMLHttpRequest',
    'WebSocket',
    'URL',
    'URLSearchParams',
    'btoa',
    'atob',
    'TextEncoder',
    'TextDecoder',
    'performance',
    'crypto',
    'structuredClone',
    'Blob',
    'File',
    'FileReader',
    'FormData',
    'Headers',
    'Request',
    'Response',
    'Event',
    'CustomEvent',
    'MessageChannel',
    'AbortController',
    'Worker',
    'importScripts',
    'Intl',
    'WebAssembly',
})
"""
Global names a worker global scope exposes beyond `GUARANTEED_GLOBALS`. `self` is the worker's own
same-realm global-object alias; the window-only names `window`, `top`, `parent`, `frames`, `document`,
and the DOM and storage surface are absent, because a worker has no document and no window to frame.
"""


@dataclass(frozen=True)
class _EnvironmentSpec:
    """
    The existence answer for one host: *provided* is every name a bare read resolves in it, and
    *mandated* is the subset the language guarantees, which the delete guard never retracts. A
    host-conditional global is a configurable, deletable property of the global object, so a program
    that deletes one makes a later bare read of it throw; a language-mandated name is treated as present
    regardless, preserving the sound default's behavior exactly where the host adds nothing.
    """
    provided: frozenset[str]
    mandated: frozenset[str]

    def provides(self, name: str) -> bool:
        return name in self.provided

    def withholds_on_delete(self, name: str) -> bool:
        return name in self.provided and name not in self.mandated


class HostEnvironment(enum.Enum):
    """
    The host a script is assumed to run in, selected by the `js` unit's `-e` switch. `universal` is the
    default and asserts only `GUARANTEED_GLOBALS`, so deobfuscation stays byte-identical to an unpinned
    run; each other member adds the globals that host guarantees, recovering the folds the sound default
    refuses for a name no universal host defines.
    """
    universal = 'universal'
    node = 'node'
    browser = 'browser'
    worker = 'worker'

    def provides(self, name: str) -> bool:
        """
        Whether a bare read of *name* is guaranteed to resolve in this host rather than throw a
        `ReferenceError`, judged from the host's global-name data alone.
        """
        return _SPECS[self].provides(name)

    def withholds_on_delete(self, name: str) -> bool:
        """
        Whether *name* is a host-conditional global whose presence a `delete` of it retracts, as opposed
        to a language-mandated name the guard leaves present. A name this answers `True` for is withheld
        program-wide once the program deletes it off a same-realm global alias anywhere, which over-keeps
        a read's throw rather than dropping one, and so stays sound.
        """
        return _SPECS[self].withholds_on_delete(name)


_SPECS: dict[HostEnvironment, _EnvironmentSpec] = {
    HostEnvironment.universal: _EnvironmentSpec(GUARANTEED_GLOBALS, GUARANTEED_GLOBALS),
    HostEnvironment.node: _EnvironmentSpec(GUARANTEED_GLOBALS | _NODE_GLOBALS, GUARANTEED_GLOBALS),
    HostEnvironment.browser: _EnvironmentSpec(GUARANTEED_GLOBALS | _BROWSER_GLOBALS, GUARANTEED_GLOBALS),
    HostEnvironment.worker: _EnvironmentSpec(GUARANTEED_GLOBALS | _WORKER_GLOBALS, GUARANTEED_GLOBALS),
}
