"""
The command registry of the XLM macro language: the names the language knows, each with the
severity that decides at which output level a trace shows it.
"""
from __future__ import annotations

import enum


class XlmSeverity(enum.Enum):
    """
    The output level a macro command shows at: the commands that move execution print at
    level 0, ordinary commands at level 1, and the commands that matter for triage at level 2.
    """

    JUMP = 0
    NORMAL = 1
    IMPORTANT = 2


_JUMP_COMMANDS = frozenset(('GOTO', 'RUN'))

_IMPORTANT_COMMANDS = frozenset((
    'CALL',
    'FOPEN',
    'FWRITE',
    'FREAD',
    'REGISTER',
    'IF',
    'WHILE',
    'HALT',
    'CLOSE',
    'NEXT',
))

#: Every macro command a handler answers — including the three Kernel32 pseudo-commands the
#: CALL emulation installs and `_xlfn.ARABIC` — together with the names the severity sets spell
#: without a handler: FREAD, FILE.DELETE, and WORKBOOK.HIDE.
_COMMAND_NAMES = frozenset((
    'ABS',
    'ABSREF',
    'ACTIVE.CELL',
    'ADDRESS',
    'AND',
    'APP.MAXIMIZE',
    'CALL',
    'CHAR',
    'CLOSE',
    'CODE',
    'CONCATENATE',
    'COUNT',
    'COUNTA',
    'DAY',
    'DEFINE.NAME',
    'DIRECTORY',
    'END.IF',
    'ERROR',
    'FILES',
    'FILE.DELETE',
    'FOR.CELL',
    'FORMULA',
    'FORMULA.ARRAY',
    'FORMULA.FILL',
    'FOPEN',
    'FREAD',
    'FSIZE',
    'FWRITE',
    'FWRITELN',
    'GET.CELL',
    'GET.DOCUMENT',
    'GET.WINDOW',
    'GET.WORKSPACE',
    'GOTO',
    'HALT',
    'HLOOKUP',
    'IF',
    'INDEX',
    'INDIRECT',
    'INT',
    'ISERROR',
    'ISNUMBER',
    'Kernel32.RtlCopyMemory',
    'Kernel32.VirtualAlloc',
    'Kernel32.WriteProcessMemory',
    'LEN',
    'MAX',
    'MID',
    'MIN',
    'MOD',
    'NEXT',
    'NOT',
    'NOW',
    'OFFSET',
    'ON.TIME',
    'OR',
    'PRODUCT',
    'QUOTIENT',
    'RANDBETWEEN',
    'REGISTER',
    'REGISTER.ID',
    'RETURN',
    'ROUND',
    'ROUNDUP',
    'ROWS',
    'RUN',
    'SEARCH',
    'SELECT',
    'SET.NAME',
    'SET.VALUE',
    'SQRT',
    'SUM',
    'T',
    'TEXT',
    'TRUNC',
    'VALUE',
    'WHILE',
    'WORKBOOK.HIDE',
    '_xlfn.ARABIC',
))

#: The severity of every macro command the registry knows: GOTO and RUN move execution, the
#: commands of the triage set matter for triage, and everything else is ordinary — SET.VALUE,
#: FILE.DELETE, and WORKBOOK.HIDE included, ordinary although a triage reading of a listing
#: would expect them among the important ones.
XLM_COMMANDS: dict[str, XlmSeverity] = {
    name: (
        XlmSeverity.JUMP
        if name in _JUMP_COMMANDS
        else XlmSeverity.IMPORTANT
        if name in _IMPORTANT_COMMANDS
        else XlmSeverity.NORMAL
    )
    for name in _COMMAND_NAMES
}


#: The commands that only compute from their arguments and the values the workbook stores —
#: never the clock, randomness, the environment, or the state a run mutates. The constant
#: folding of the deobfuscation evaluates their calls statically; every command outside the
#: set reads or writes something no listing can decide.
PURE_COMMANDS = frozenset((
    'ABS',
    'ABSREF',
    'ADDRESS',
    'AND',
    'CHAR',
    'CODE',
    'CONCATENATE',
    'COUNT',
    'COUNTA',
    'HLOOKUP',
    'INDEX',
    'INDIRECT',
    'INT',
    'ISNUMBER',
    'LEN',
    'MAX',
    'MID',
    'MIN',
    'MOD',
    'NOT',
    'OR',
    'PRODUCT',
    'QUOTIENT',
    'ROUND',
    'ROUNDUP',
    'ROWS',
    'SEARCH',
    'SQRT',
    'SUM',
    'T',
    'TEXT',
    'TRUNC',
    'VALUE',
    '_xlfn.ARABIC',
))


def severity(command_name: str) -> XlmSeverity:
    """
    The severity of a macro command; a name outside the registry is ordinary.
    """
    return XLM_COMMANDS.get(command_name, XlmSeverity.NORMAL)
