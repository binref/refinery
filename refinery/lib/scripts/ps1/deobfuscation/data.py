"""
Contains .NET type and PowerShell command database for deobfuscation. Generated via run-pwsh.ps1
from PowerShell 5.1 reflection data.
"""
from __future__ import annotations

import json
import operator
import re

from refinery.lib.resources import datapath

with datapath('pwsh.json').open('r') as _fp:
    _PWSH: dict[str, dict] = json.load(_fp)

TYPE_MEMBERS: dict[str, list[str]] = {}

for _full, _info in _PWSH['types'].items():
    TYPE_MEMBERS[_full.lower()] = sorted(set(_info['methods']) | set(_info['properties']))

PROPERTY_TYPES: dict[tuple[str, str], str] = {}

for _full, _info in _PWSH['types'].items():
    _tl = _full.lower()
    for _prop, _ret in _info['properties'].items():
        PROPERTY_TYPES[(_tl, _prop.lower())] = _ret.lower()

VARIABLE_TYPES: dict[str, str] = {
    k.lower(): v.lower() for k, v in _PWSH['variable_types'].items()
}

TYPE_ALIASES: dict[str, str] = {
    k.lower(): v.lower() for k, v in _PWSH['type_aliases'].items()
}

CANONICAL_TYPE_NAMES: dict[str, str] = {}

for _alias, _full in _PWSH['type_aliases'].items():
    _display = _full.removeprefix('System.')
    CANONICAL_TYPE_NAMES[_alias.lower()] = _display
    CANONICAL_TYPE_NAMES[_full.lower()] = _display
for _full in _PWSH['types']:
    _display = _full.removeprefix('System.')
    CANONICAL_TYPE_NAMES.setdefault(_full.lower(), _display)
    CANONICAL_TYPE_NAMES.setdefault(_full.lower().removeprefix('system.'), _display)

for _wmi in _PWSH['wmi_classes']:
    CANONICAL_TYPE_NAMES.setdefault(_wmi.lower(), _wmi)

CANONICAL_TYPE_NAMES.setdefault(
    'management.automation.sessionstateinternal',
    'Management.Automation.SessionStateInternal',
)

MEMBER_LOOKUP: dict[str, dict[str, str]] = {}

for _type_lower, _members in TYPE_MEMBERS.items():
    MEMBER_LOOKUP[_type_lower] = {m.lower(): m for m in _members}

WMI_CLASS_NAMES: dict[str, str] = {}

for _wmi_cls, _wmi_props in _PWSH['wmi_properties'].items():
    _wmi_lower = _wmi_cls.lower()
    WMI_CLASS_NAMES[_wmi_lower] = _wmi_cls
    MEMBER_LOOKUP.setdefault(_wmi_lower, {}).update({p.lower(): p for p in _wmi_props})


def _resolve_type_name(name: str) -> str | None:
    """
    Resolve a type name (as written in PowerShell) to its canonical lowercase full .NET name.
    Handles short names like 'String', qualified names like 'Net.WebClient', and full names like
    'System.Net.WebClient'.
    """
    lower = name.lower()
    if lower in TYPE_MEMBERS:
        return lower
    if lower in TYPE_ALIASES:
        return TYPE_ALIASES[lower]
    prefixed = F'system.{lower}'
    if prefixed in TYPE_MEMBERS:
        return prefixed
    return None


def is_type(name: str, canonical_lower: str) -> bool:
    """
    Check whether a type name (as written in PowerShell source) resolves to the given canonical
    lowercase .NET type name.
    """
    resolved = _resolve_type_name(name)
    return resolved == canonical_lower


KNOWN_ALIAS: dict[str, str] = _PWSH['command_aliases']
KNOWN_ALIAS.setdefault('childitem', 'Get-ChildItem')
KNOWN_ALIAS.setdefault('fhx', 'Format-Hex')
KNOWN_ALIAS.setdefault('gerr', 'Get-Error')
KNOWN_ALIAS.setdefault('item', 'Get-Item')
KNOWN_ALIAS.setdefault('member', 'Get-Member')
KNOWN_ALIAS.setdefault('variable', 'Get-Variable')

KNOWN_PS_OPERATORS: dict[str, str] = {name.lower(): name for name in [
    '-As',
    '-BAnd',
    '-BNot',
    '-BOr',
    '-BXor',
    '-Contains',
    '-CReplace',
    '-Eq',
    '-GE',
    '-GT',
    '-In',
    '-IReplace',
    '-Is',
    '-IsNot',
    '-Join',
    '-LE',
    '-Like',
    '-LT',
    '-Match',
    '-NE',
    '-Not',
    '-NotContains',
    '-NotIn',
    '-NotLike',
    '-NotMatch',
    '-Replace',
    '-Shl',
    '-Shr',
    '-Split',
    '-XOr',
]}

KNOWN_PS_SWITCHES: dict[str, str] = {name.lower(): name for name in [
    '-Command',
    '-EncodedCommand',
    '-Exec Bypass',
    '-ExecutionPolicy',
    '-File',
    '-InputFormat',
    '-NoExit',
    '-NoLogo',
    '-NoProfile',
    '-NonInter',
    '-OutputFormat',
    '-Sta',
    '-Version',
    '-Windows Hidden',
    '-WindowStyle',
]}

KNOWN_CMDLETS: dict[str, str] = {name.lower(): name for name in _PWSH['cmdlets']}
KNOWN_CMDLETS.setdefault('convertfrom-base64', 'ConvertFrom-Base64')
KNOWN_CMDLETS.setdefault('powershell', 'PowerShell')

for _n in KNOWN_ALIAS.values():
    KNOWN_CMDLETS.setdefault(_n.lower(), _n)

CMDLET_PARAMETERS: dict[str, list[str]] = {
    k.lower(): v for k, v in _PWSH['parameters'].items()
}

ALL_PARAMETER_NAMES: dict[str, str] = {}

for _params in CMDLET_PARAMETERS.values():
    for _p in _params:
        ALL_PARAMETER_NAMES.setdefault(_p.lower(), _p)

del _PWSH

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_]\w*$')

OBJ_COMMANDS = frozenset({
    'new-object',
})

WMI_COMMANDS = frozenset({
    'get-ciminstance',
    'get-wmiobject',
})

TYPE_ARG_COMMANDS = frozenset(OBJ_COMMANDS | WMI_COMMANDS)

GET_MEMBER_ALIASES = frozenset({'get-member', 'gm'})
GET_COMMAND_ALIASES = frozenset({'get-command', 'gcm'})

FOREACH_ALIASES = frozenset({'%', 'foreach', 'foreach-object'})

COMPARISON_OPS = {
    '-eq': operator.eq,
    '-ne': operator.ne,
    '-lt': operator.lt,
    '-le': operator.le,
    '-gt': operator.gt,
    '-ge': operator.ge,
}

ENCODING_MAP = {
    'ascii'            : 'ascii',            # noqa
    'bigendianunicode' : 'utf-16-be',        # noqa
    'default'          : 'latin-1',          # noqa
    'unicode'          : 'utf-16-le',        # noqa
    'utf7'             : 'utf-7',            # noqa
    'utf8'             : 'utf-8',            # noqa
    'utf32'            : 'utf-32-le',        # noqa
}

BUILTIN_VARIABLES = frozenset({'null', 'true', 'false'})

PS1_KNOWN_VARIABLES: dict[str, str] = {
    name.lower(): name for name in [
        'ConfirmPreference',
        'ConsoleFileName',
        'DebugPreference',
        'Error',
        'ErrorActionPreference',
        'ExecutionContext',
        'False',
        'ForEach',
        'FormatEnumerationLimit',
        'HOME',
        'Host',
        'InformationPreference',
        'Input',
        'Matches',
        'MaximumAliasCount',
        'MaximumDriveCount',
        'MaximumErrorCount',
        'MaximumFunctionCount',
        'MaximumHistoryCount',
        'MaximumVariableCount',
        'MyInvocation',
        'NestedPromptLevel',
        'Null',
        'OutputEncoding',
        'PID',
        'PROFILE',
        'ProgressPreference',
        'PSCommandPath',
        'PSCulture',
        'PSDefaultParameterValues',
        'PSEmailServer',
        'PSHome',
        'PSScriptRoot',
        'PSSessionApplicationName',
        'PSSessionConfigurationName',
        'PSSessionOption',
        'PSUICulture',
        'PSVersionTable',
        'PWD',
        'ShellID',
        'StackTrace',
        'This',
        'True',
        'VerbosePreference',
        'WarningPreference',
        'WhatIfPreference',
    ]
}

FORMAT_PATTERN = re.compile(r'\{\{|\}\}|\{(\d+)(?:,(-?\d+))?(?::([^}]+))?\}')
