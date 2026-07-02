"""
Shared utilities for PHP deobfuscation transforms.

Only the primitives required by the parser and synthesizer are provided here. The AST-analysis
helpers needed by future deobfuscation passes are intentionally omitted until those passes exist.
"""
from __future__ import annotations

import re

_SINGLE_QUOTE_ESCAPE = re.compile(r"['\\]")
_DOUBLE_QUOTE_RESIDUE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

_DOUBLE_QUOTE_NAMED: dict[str, str] = {
    '\n' : '\\n',
    '\r' : '\\r',
    '\t' : '\\t',
    '\v' : '\\v',
    '\f' : '\\f',
    '\x1b': '\\e',
}


def escape_php_string(value: str, quote: str = "'") -> str:
    """
    Escape *value* for placement inside a PHP string literal delimited by *quote*, returning the
    escaped body without the surrounding quotes. Single-quoted literals only recognize `\\'` and
    `\\\\`; every other character is emitted verbatim. Double-quoted literals additionally encode the
    control characters and the `$` sigil that would otherwise trigger interpolation.
    """
    if quote == "'":
        return _SINGLE_QUOTE_ESCAPE.sub(lambda m: '\\' + m.group(), value)
    value = value.replace('\\', '\\\\')
    value = value.replace('"', '\\"')
    value = value.replace('$', '\\$')
    for raw, encoded in _DOUBLE_QUOTE_NAMED.items():
        value = value.replace(raw, encoded)
    return _DOUBLE_QUOTE_RESIDUE.sub(lambda m: F'\\x{ord(m.group()):02x}', value)
