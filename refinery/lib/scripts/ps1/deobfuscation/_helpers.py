"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import re

from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayLiteral,
    Ps1ExpandableString,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1StringLiteral,
)

_KNOWN_NAMES = {name.lower(): name for name in [
    '-BXor',
    '-Exec Bypass',
    '-NoLogo',
    '-NonInter',
    '-Replace',
    '-Windows Hidden',
    '.Invoke',
    'Assembly',
    'Byte',
    'Char',
    'ChildItem',
    'CreateThread',
    'Get-Variable',
    'GetType',
    'IntPtr',
    'Invoke-Expression',
    'Invoke',
    'Length',
    'Net.WebClient',
    'PowerShell',
    'PSVersionTable',
    'Set-Item',
    'Set-Variable',
    'Start-Sleep',
    'ToString',
    'Type',
    'Value',
    'Void',
]}

_SIMPLE_IDENT = re.compile(r'^[a-zA-Z_]\w*$')


def _string_value(node: Expression) -> str | None:
    if isinstance(node, Ps1StringLiteral):
        return node.value
    if isinstance(node, Ps1ExpandableString):
        if all(isinstance(p, Ps1StringLiteral) for p in node.parts):
            return ''.join(p.value for p in node.parts)
    return None


def _make_string_literal(value: str) -> Ps1StringLiteral:
    if "'" not in value:
        raw = F"'{value}'"
    elif '"' not in value and '$' not in value and '`' not in value:
        raw = F'"{value}"'
    else:
        raw = "'" + value.replace("'", "''") + "'"
    return Ps1StringLiteral(value=value, raw=raw)


def _collect_string_arguments(node: Expression) -> list[str] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            sv = _string_value(elem)
            if sv is None:
                return None
            result.append(sv)
        return result
    sv = _string_value(node)
    if sv is not None:
        return [sv]
    return None


def _collect_int_arguments(node: Expression) -> list[int] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            if not isinstance(elem, Ps1IntegerLiteral):
                return None
            result.append(elem.value)
        return result
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return _collect_int_arguments(node.expression)
    if isinstance(node, Ps1IntegerLiteral):
        return [node.value]
    return None


def _unwrap_paren_to_array(node: Expression) -> Expression:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return node.expression
    return node


def _case_normalize_name(name: str) -> str:
    lower = name.lower()
    canonical = _KNOWN_NAMES.get(lower)
    if canonical is not None:
        return canonical
    return name
