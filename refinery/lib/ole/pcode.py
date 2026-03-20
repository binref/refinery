"""
VBA p-code disassembler for Microsoft Office documents.

This module is a port of pcodedmp by Vesselin Bontchev, adapted for the Binary Refinery project.
Since then, many bugs have been fixed and improvements made.

The original work is copyright (c) Vesselin Bontchev and licensed under GPL v3. The source code
has been modified to fit the code requirements of this project.

Regardless of the license used for the binary refinery, this code file is also subject to the
terms and conditions of the GNU General Public License version 3.

References:
    [pcodedmp] https://github.com/bontchev/pcodedmp
    [MS-OVBA]  https://docs.microsoft.com/en-us/openspecs/
"""
from __future__ import annotations

import codecs
import logging
import re
import struct as _struct

from dataclasses import dataclass, field
from typing import NamedTuple

from refinery.lib.ole.file import OleFile
from refinery.lib.ole.vba import _codepage_to_codec, _find_vba_projects, decompress_stream

logger = logging.getLogger(__name__)

_STRUCT_WORD: dict[str, _struct.Struct] = {
    '<': _struct.Struct('<H'),
    '>': _struct.Struct('>H'),
}
_STRUCT_DWORD: dict[str, _struct.Struct] = {
    '<': _struct.Struct('<L'),
    '>': _struct.Struct('>L'),
}

_VAR_TYPES_LONG: tuple[str, ...] = (
    'Var', '?', 'Int', 'Lng', 'Sng', 'Dbl', 'Cur', 'Date',
    'Str', 'Obj', 'Err', 'Bool', 'Var',
)
_SPECIALS: tuple[str, ...] = ('False', 'True', 'Null', 'Empty')
_OPTIONS: tuple[str, ...] = (
    'Base 0', 'Base 1', 'Compare Text', 'Compare Binary',
    'Explicit', 'Private Module',
)
_SUFFIX_TYPES: frozenset[str] = frozenset({
    'Integer', 'Long', 'Single', 'Double', 'Currency', 'String',
})
_SUFFIX_TYPE_IDS: frozenset[int] = frozenset({2, 3, 4, 5, 6, 8})


class Opcode(NamedTuple):
    mnem: str
    args: list[str] = []
    varg: bool = False


@dataclass
class TypeRef:
    name: str
    is_array: bool = False
    from_suffix: bool = False


@dataclass
class VarInfo:
    name: str
    type: TypeRef | None = None
    has_new: bool = False
    has_withevents: bool = False


@dataclass
class ArgInfo:
    name: str
    type: TypeRef | None = None
    is_byval: bool = False
    is_byref: bool = False
    is_optional: bool = False
    is_paramarray: bool = False
    default_value: str | None = None


@dataclass
class FuncInfo:
    scope: str
    is_static: bool
    kind: str
    name: str
    args: list[ArgInfo] = field(default_factory=list)
    return_type: TypeRef | None = None
    is_declare: bool = False
    is_ptrsafe: bool = False
    lib_name: str | None = None
    alias_name: str | None = None


@dataclass
class DimScope:
    keywords: list[str] = field(default_factory=list)


@dataclass
class CoerceType:
    type_short: str


@dataclass
class RecordInfo:
    text: str


OpcodeArg = str | TypeRef | VarInfo | ArgInfo | FuncInfo | DimScope | CoerceType | RecordInfo


class PCodeLine(NamedTuple):
    opcodes: list[tuple[str, list[OpcodeArg]]]


class PCodeModule(NamedTuple):
    """
    Structured representation of a disassembled VBA module.
    """
    path: str
    lines: list[PCodeLine]
    identifiers_stripped: bool = False


# VBA7 opcodes; VBA3, VBA5 and VBA6 will be upconverted to these.
Op = Opcode
OPCODES: dict[int, Opcode] = {
    0x000: Op('Imp'),
    0x001: Op('Eqv'),
    0x002: Op('Xor'),
    0x003: Op('Or'),
    0x004: Op('And'),
    0x005: Op('Eq'),
    0x006: Op('Ne'),
    0x007: Op('Le'),
    0x008: Op('Ge'),
    0x009: Op('Lt'),
    0x00A: Op('Gt'),
    0x00B: Op('Add'),
    0x00C: Op('Sub'),
    0x00D: Op('Mod'),
    0x00E: Op('IDiv'),
    0x00F: Op('Mul'),
    0x010: Op('Div'),
    0x011: Op('Concat'),
    0x012: Op('Like'),
    0x013: Op('Pwr'),
    0x014: Op('Is'),
    0x015: Op('Not'),
    0x016: Op('UMi'),
    0x017: Op('FnAbs'),
    0x018: Op('FnFix'),
    0x019: Op('FnInt'),
    0x01A: Op('FnSgn'),
    0x01B: Op('FnLen'),
    0x01C: Op('FnLenB'),
    0x01D: Op('Paren'),
    0x01E: Op('Sharp'),
    0x01F: Op('LdLHS', ['name']),
    0x020: Op('Ld', ['name']),
    0x021: Op('MemLd', ['name']),
    0x022: Op('DictLd', ['name']),
    0x023: Op('IndexLd', ['0x']),
    0x024: Op('ArgsLd', ['name', '0x']),
    0x025: Op('ArgsMemLd', ['name', '0x']),
    0x026: Op('ArgsDictLd', ['name', '0x']),
    0x027: Op('St', ['name']),
    0x028: Op('MemSt', ['name']),
    0x029: Op('DictSt', ['name']),
    0x02A: Op('IndexSt', ['0x']),
    0x02B: Op('ArgsSt', ['name', '0x']),
    0x02C: Op('ArgsMemSt', ['name', '0x']),
    0x02D: Op('ArgsDictSt', ['name', '0x']),
    0x02E: Op('Set', ['name']),
    0x02F: Op('Memset', ['name']),
    0x030: Op('Dictset', ['name']),
    0x031: Op('Indexset', ['0x']),
    0x032: Op('ArgsSet', ['name', '0x']),
    0x033: Op('ArgsMemSet', ['name', '0x']),
    0x034: Op('ArgsDictSet', ['name', '0x']),
    0x035: Op('MemLdWith', ['name']),
    0x036: Op('DictLdWith', ['name']),
    0x037: Op('ArgsMemLdWith', ['name', '0x']),
    0x038: Op('ArgsDictLdWith', ['name', '0x']),
    0x039: Op('MemStWith', ['name']),
    0x03A: Op('DictStWith', ['name']),
    0x03B: Op('ArgsMemStWith', ['name', '0x']),
    0x03C: Op('ArgsDictStWith', ['name', '0x']),
    0x03D: Op('MemSetWith', ['name']),
    0x03E: Op('DictSetWith', ['name']),
    0x03F: Op('ArgsMemSetWith', ['name', '0x']),
    0x040: Op('ArgsDictSetWith', ['name', '0x']),
    0x041: Op('ArgsCall', ['name', '0x']),
    0x042: Op('ArgsMemCall', ['name', '0x']),
    0x043: Op('ArgsMemCallWith', ['name', '0x']),
    0x044: Op('ArgsArray', ['name', '0x']),
    0x045: Op('Assert'),
    0x046: Op('BoS', ['0x']),
    0x047: Op('BoSImplicit'),
    0x048: Op('BoL'),
    0x049: Op('LdAddressOf', ['name']),
    0x04A: Op('MemAddressOf', ['name']),
    0x04B: Op('Case'),
    0x04C: Op('CaseTo'),
    0x04D: Op('CaseGt'),
    0x04E: Op('CaseLt'),
    0x04F: Op('CaseGe'),
    0x050: Op('CaseLe'),
    0x051: Op('CaseNe'),
    0x052: Op('CaseEq'),
    0x053: Op('CaseElse'),
    0x054: Op('CaseDone'),
    0x055: Op('Circle', ['0x']),
    0x056: Op('Close', ['0x']),
    0x057: Op('CloseAll'),
    0x058: Op('Coerce'),
    0x059: Op('CoerceVar'),
    0x05A: Op('Context', ['context_']),
    0x05B: Op('Debug'),
    0x05C: Op('DefType', ['0x', '0x']),
    0x05D: Op('Dim'),
    0x05E: Op('DimImplicit'),
    0x05F: Op('Do'),
    0x060: Op('DoEvents'),
    0x061: Op('DoUnitil'),
    0x062: Op('DoWhile'),
    0x063: Op('Else'),
    0x064: Op('ElseBlock'),
    0x065: Op('ElseIfBlock'),
    0x066: Op('ElseIfTypeBlock', ['imp_']),
    0x067: Op('End'),
    0x068: Op('EndContext'),
    0x069: Op('EndFunc'),
    0x06A: Op('EndIf'),
    0x06B: Op('EndIfBlock'),
    0x06C: Op('EndImmediate'),
    0x06D: Op('EndProp'),
    0x06E: Op('EndSelect'),
    0x06F: Op('EndSub'),
    0x070: Op('EndType'),
    0x071: Op('EndWith'),
    0x072: Op('Erase', ['0x']),
    0x073: Op('Error'),
    0x074: Op('EventDecl', ['func_']),
    0x075: Op('RaiseEvent', ['name', '0x']),
    0x076: Op('ArgsMemRaiseEvent', ['name', '0x']),
    0x077: Op('ArgsMemRaiseEventWith', ['name', '0x']),
    0x078: Op('ExitDo'),
    0x079: Op('ExitFor'),
    0x07A: Op('ExitFunc'),
    0x07B: Op('ExitProp'),
    0x07C: Op('ExitSub'),
    0x07D: Op('FnCurDir'),
    0x07E: Op('FnDir'),
    0x07F: Op('Empty0'),
    0x080: Op('Empty1'),
    0x081: Op('FnError'),
    0x082: Op('FnFormat'),
    0x083: Op('FnFreeFile'),
    0x084: Op('FnInStr'),
    0x085: Op('FnInStr3'),
    0x086: Op('FnInStr4'),
    0x087: Op('FnInStrB'),
    0x088: Op('FnInStrB3'),
    0x089: Op('FnInStrB4'),
    0x08A: Op('FnLBound', ['0x']),
    0x08B: Op('FnMid'),
    0x08C: Op('FnMidB'),
    0x08D: Op('FnStrComp'),
    0x08E: Op('FnStrComp3'),
    0x08F: Op('FnStringVar'),
    0x090: Op('FnStringStr'),
    0x091: Op('FnUBound', ['0x']),
    0x092: Op('For'),
    0x093: Op('ForEach'),
    0x094: Op('ForEachAs', ['imp_']),
    0x095: Op('ForStep'),
    0x096: Op('FuncDefn', ['func_']),
    0x097: Op('FuncDefnSave', ['func_']),
    0x098: Op('GetRec'),
    0x099: Op('GoSub', ['name']),
    0x09A: Op('GoTo', ['name']),
    0x09B: Op('If'),
    0x09C: Op('IfBlock'),
    0x09D: Op('TypeOf', ['imp_']),
    0x09E: Op('IfTypeBlock', ['imp_']),
    0x09F: Op('Implements', ['0x', '0x', '0x', '0x']),
    0x0A0: Op('Input'),
    0x0A1: Op('InputDone'),
    0x0A2: Op('InputItem'),
    0x0A3: Op('Label', ['name']),
    0x0A4: Op('Let'),
    0x0A5: Op('Line', ['0x']),
    0x0A6: Op('LineCont', [], True),
    0x0A7: Op('LineInput'),
    0x0A8: Op('LineNum', ['name']),
    0x0A9: Op('LitCy', ['0x', '0x', '0x', '0x']),
    0x0AA: Op('LitDate', ['0x', '0x', '0x', '0x']),
    0x0AB: Op('LitDefault'),
    0x0AC: Op('LitDI2', ['0x']),
    0x0AD: Op('LitDI4', ['0x', '0x']),
    0x0AE: Op('LitDI8', ['0x', '0x', '0x', '0x']),
    0x0AF: Op('LitHI2', ['0x']),
    0x0B0: Op('LitHI4', ['0x', '0x']),
    0x0B1: Op('LitHI8', ['0x', '0x', '0x', '0x']),
    0x0B2: Op('LitNothing'),
    0x0B3: Op('LitOI2', ['0x']),
    0x0B4: Op('LitOI4', ['0x', '0x']),
    0x0B5: Op('LitOI8', ['0x', '0x', '0x', '0x']),
    0x0B6: Op('LitR4', ['0x', '0x']),
    0x0B7: Op('LitR8', ['0x', '0x', '0x', '0x']),
    0x0B8: Op('LitSmallI2'),
    0x0B9: Op('LitStr', [], True),
    0x0BA: Op('LitVarSpecial'),
    0x0BB: Op('Lock'),
    0x0BC: Op('Loop'),
    0x0BD: Op('LoopUntil'),
    0x0BE: Op('LoopWhile'),
    0x0BF: Op('LSet'),
    0x0C0: Op('Me'),
    0x0C1: Op('MeImplicit'),
    0x0C2: Op('MemRedim', ['name', '0x', 'type_']),
    0x0C3: Op('MemRedimWith', ['name', '0x', 'type_']),
    0x0C4: Op('MemRedimAs', ['name', '0x', 'type_']),
    0x0C5: Op('MemRedimAsWith', ['name', '0x', 'type_']),
    0x0C6: Op('Mid'),
    0x0C7: Op('MidB'),
    0x0C8: Op('Name'),
    0x0C9: Op('New', ['imp_']),
    0x0CA: Op('Next'),
    0x0CB: Op('NextVar'),
    0x0CC: Op('OnError', ['name']),
    0x0CD: Op('OnGosub', [], True),
    0x0CE: Op('OnGoto', [], True),
    0x0CF: Op('Open', ['0x']),
    0x0D0: Op('Option'),
    0x0D1: Op('OptionBase'),
    0x0D2: Op('ParamByVal'),
    0x0D3: Op('ParamOmitted'),
    0x0D4: Op('ParamNamed', ['name']),
    0x0D5: Op('PrintChan'),
    0x0D6: Op('PrintComma'),
    0x0D7: Op('PrintEoS'),
    0x0D8: Op('PrintItemComma'),
    0x0D9: Op('PrintItemNL'),
    0x0DA: Op('PrintItemSemi'),
    0x0DB: Op('PrintNL'),
    0x0DC: Op('PrintObj'),
    0x0DD: Op('PrintSemi'),
    0x0DE: Op('PrintSpc'),
    0x0DF: Op('PrintTab'),
    0x0E0: Op('PrintTabComma'),
    0x0E1: Op('PSet', ['0x']),
    0x0E2: Op('PutRec'),
    0x0E3: Op('QuoteRem', ['0x'], True),
    0x0E4: Op('Redim', ['name', '0x', 'type_']),
    0x0E5: Op('RedimAs', ['name', '0x', 'type_']),
    0x0E6: Op('Reparse', [], True),
    0x0E7: Op('Rem', [], True),
    0x0E8: Op('Resume', ['name']),
    0x0E9: Op('Return'),
    0x0EA: Op('RSet'),
    0x0EB: Op('Scale', ['0x']),
    0x0EC: Op('Seek'),
    0x0ED: Op('SelectCase'),
    0x0EE: Op('SelectIs', ['imp_']),
    0x0EF: Op('SelectType'),
    0x0F0: Op('SetStmt'),
    0x0F1: Op('Stack', ['0x', '0x']),
    0x0F2: Op('Stop'),
    0x0F3: Op('Type', ['rec_']),
    0x0F4: Op('Unlock'),
    0x0F5: Op('VarDefn', ['var_']),
    0x0F6: Op('Wend'),
    0x0F7: Op('While'),
    0x0F8: Op('With'),
    0x0F9: Op('WriteChan'),
    0x0FA: Op('ConstFuncExpr'),
    0x0FB: Op('LbConst', ['name']),
    0x0FC: Op('LbIf'),
    0x0FD: Op('LbElse'),
    0x0FE: Op('LbElseIf'),
    0x0FF: Op('LbEndIf'),
    0x100: Op('LbMark'),
    0x101: Op('EndForVariable'),
    0x102: Op('StartForVariable'),
    0x103: Op('NewRedim'),
    0x104: Op('StartWithExpr'),
    0x105: Op('SetOrSt', ['name']),
    0x106: Op('EndEnum'),
    0x107: Op('Illegal'),
}

INTERNAL_NAMES: list[str] = [
    '<crash>',
    '0',
    'Abs',
    'Access',
    'AddressOf',
    'Alias',
    'And',
    'Any',
    'Append',
    'Array',
    'As',
    'Assert',
    'B',
    'Base',
    'BF',
    'Binary',
    'Boolean',
    'ByRef',
    'Byte',
    'ByVal',
    'Call',
    'Case',
    'CBool',
    'CByte',
    'CCur',
    'CDate',
    'CDec',
    'CDbl',
    'CDecl',
    'ChDir',
    'CInt',
    'Circle',
    'CLng',
    'Close',
    'Compare',
    'Const',
    'CSng',
    'CStr',
    'CurDir',
    'CurDir$',
    'CVar',
    'CVDate',
    'CVErr',
    'Currency',
    'Database',
    'Date',
    'Date$',
    'Debug',
    'Decimal',
    'Declare',
    'DefBool',
    'DefByte',
    'DefCur',
    'DefDate',
    'DefDec',
    'DefDbl',
    'DefInt',
    'DefLng',
    'DefObj',
    'DefSng',
    'DefStr',
    'DefVar',
    'Dim',
    'Dir',
    'Dir$',
    'Do',
    'DoEvents',
    'Double',
    'Each',
    'Else',
    'ElseIf',
    'Empty',
    'End',
    'EndIf',
    'Enum',
    'Eqv',
    'Erase',
    'Error',
    'Error$',
    'Event',
    'WithEvents',
    'Explicit',
    'F',
    'False',
    'Fix',
    'For',
    'Format',
    'Format$',
    'FreeFile',
    'Friend',
    'Function',
    'Get',
    'Global',
    'Go',
    'GoSub',
    'Goto',
    'If',
    'Imp',
    'Implements',
    'In',
    'Input',
    'Input$',
    'InputB',
    'InputB',
    'InStr',
    'InputB$',
    'Int',
    'InStrB',
    'Is',
    'Integer',
    'Left',
    'LBound',
    'LenB',
    'Len',
    'Lib',
    'Let',
    'Line',
    'Like',
    'Load',
    'Local',
    'Lock',
    'Long',
    'Loop',
    'LSet',
    'Me',
    'Mid',
    'Mid$',
    'MidB',
    'MidB$',
    'Mod',
    'Module',
    'Name',
    'New',
    'Next',
    'Not',
    'Nothing',
    'Null',
    'Object',
    'On',
    'Open',
    'Option',
    'Optional',
    'Or',
    'Output',
    'ParamArray',
    'Preserve',
    'Print',
    'Private',
    'Property',
    'PSet',
    'Public',
    'Put',
    'RaiseEvent',
    'Random',
    'Randomize',
    'Read',
    'ReDim',
    'Rem',
    'Resume',
    'Return',
    'RGB',
    'RSet',
    'Scale',
    'Seek',
    'Select',
    'Set',
    'Sgn',
    'Shared',
    'Single',
    'Spc',
    'Static',
    'Step',
    'Stop',
    'StrComp',
    'String',
    'String$',
    'Sub',
    'Tab',
    'Text',
    'Then',
    'To',
    'True',
    'Type',
    'TypeOf',
    'UBound',
    'Unload',
    'Unlock',
    'Unknown',
    'Until',
    'Variant',
    'WEnd',
    'While',
    'Width',
    'With',
    'Write',
    'Xor',
    '#Const',
    '#Else',
    '#ElseIf',
    '#End',
    '#If',
    'Attribute',
    'VB_Base',
    'VB_Control',
    'VB_Creatable',
    'VB_Customizable',
    'VB_Description',
    'VB_Exposed',
    'VB_Ext_Key',
    'VB_HelpID',
    'VB_Invoke_Func',
    'VB_Invoke_Property',
    'VB_Invoke_PropertyPut',
    'VB_Invoke_PropertyPutRef',
    'VB_MemberFlags',
    'VB_Name',
    'VB_PredecraredID',
    'VB_ProcData',
    'VB_TemplateDerived',
    'VB_VarDescription',
    'VB_VarHelpID',
    'VB_VarMemberFlags',
    'VB_VarProcData',
    'VB_UserMemID',
    'VB_VarUserMemID',
    'VB_GlobalNameSpace',
    ',',
    '.',
    '"',
    '_',
    '!',
    '#',
    '&',
    "'",
    '(',
    ')',
    '*',
    '+',
    '-',
    ' /',
    ':',
    ';',
    '<',
    '<=',
    '<>',
    '=',
    '=<',
    '=>',
    '>',
    '><',
    '>=',
    '?',
    '\\',
    '^',
    ':=',
]

DIM_TYPES: list[str] = [
    '', 'Null', 'Integer', 'Long', 'Single', 'Double', 'Currency',
    'Date', 'String', 'Object', 'Error', 'Boolean', 'Variant', '',
    'Decimal', '', '', 'Byte', '', '', 'LongLong', '', '', '',
    'Any',
]


def _get_word(buffer: bytes | bytearray | memoryview, offset: int, endian: str) -> int:
    return _STRUCT_WORD[endian].unpack_from(buffer, offset)[0]


def _get_dword(buffer: bytes | bytearray | memoryview, offset: int, endian: str) -> int:
    return _STRUCT_DWORD[endian].unpack_from(buffer, offset)[0]


def _skip_structure(
    buffer: bytes | bytearray | memoryview,
    offset: int,
    endian: str,
    is_length_dw: bool,
    element_size: int,
    check_minus_one: bool,
) -> int:
    if is_length_dw:
        length = _get_dword(buffer, offset, endian)
        offset += 4
        skip = check_minus_one and (length == 0xFFFFFFFF)
    else:
        length = _get_word(buffer, offset, endian)
        offset += 2
        skip = check_minus_one and (length == 0xFFFF)
    if not skip:
        offset += length * element_size
    return offset


def _get_var(
    buffer: bytes | bytearray | memoryview,
    offset: int,
    endian: str,
    is_dword: bool,
) -> tuple[int, int]:
    if is_dword:
        value = _get_dword(buffer, offset, endian)
        offset += 4
    else:
        value = _get_word(buffer, offset, endian)
        offset += 2
    return offset, value


def _get_type_and_length(
    buffer: bytes | bytearray | memoryview,
    offset: int,
    endian: str,
) -> tuple[int, int]:
    if endian == '>':
        return buffer[offset], buffer[offset + 1]
    else:
        return buffer[offset + 1], buffer[offset]


def _translate_opcode(opcode: int, vba_ver: int, is_64bit: bool) -> int:
    if vba_ver == 3:
        if 0 <= opcode <= 67:
            return opcode
        elif 68 <= opcode <= 70:
            return opcode + 2
        elif 71 <= opcode <= 111:
            return opcode + 4
        elif 112 <= opcode <= 150:
            return opcode + 8
        elif 151 <= opcode <= 164:
            return opcode + 9
        elif 165 <= opcode <= 166:
            return opcode + 10
        elif 167 <= opcode <= 169:
            return opcode + 11
        elif 170 <= opcode <= 238:
            return opcode + 12
        else:
            return opcode + 24
    elif vba_ver == 5:
        if 0 <= opcode <= 68:
            return opcode
        elif 69 <= opcode <= 71:
            return opcode + 1
        elif 72 <= opcode <= 112:
            return opcode + 3
        elif 113 <= opcode <= 151:
            return opcode + 7
        elif 152 <= opcode <= 165:
            return opcode + 8
        elif 166 <= opcode <= 167:
            return opcode + 9
        elif 168 <= opcode <= 170:
            return opcode + 10
        else:
            return opcode + 11
    elif not is_64bit:
        if 0 <= opcode <= 173:
            return opcode
        elif 174 <= opcode <= 175:
            return opcode + 1
        elif 176 <= opcode <= 178:
            return opcode + 2
        else:
            return opcode + 3
    else:
        return opcode


def _get_id(
    id_code: int,
    identifiers: list[str],
    vba_ver: int,
    is_64bit: bool,
) -> str:
    orig_code = id_code
    id_code >>= 1
    try:
        if id_code >= 0x100:
            id_code -= 0x100
            if vba_ver >= 7:
                id_code -= 4
                if is_64bit:
                    id_code -= 3
            return identifiers[id_code]
        else:
            if vba_ver >= 7:
                if id_code == 0xE9:
                    return 'PtrSafe'
                if id_code > 0xE9:
                    id_code -= 1
            if vba_ver >= 6 and id_code >= 0xC3:
                id_code -= 1
            return INTERNAL_NAMES[id_code]
    except (IndexError, KeyError):
        return F'id_{orig_code:04X}'


def _get_name(
    buffer: bytes | bytearray | memoryview,
    identifiers: list[str],
    offset: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    object_id = _get_word(buffer, offset, endian)
    return _get_id(object_id, identifiers, vba_ver, is_64bit)


def _get_type_name(type_id: int) -> str:
    type_flags = type_id & 0xE0
    type_id &= ~0xE0
    type_name = DIM_TYPES[type_id] if type_id < len(DIM_TYPES) else ''
    if type_flags & 0x80:
        if type_name == 'LongLong':
            type_name = 'Long'
        type_name += 'Ptr'
    return type_name


def _disasm_type(
    indirect_table: bytes | bytearray | memoryview,
    dword: int,
) -> str:
    type_id = indirect_table[dword + 6]
    type_name = _get_type_name(type_id)
    return type_name or F'type_{dword:08X}'


_VALID_INTERNAL_TYPE_NAMES = frozenset({
    'Boolean',
    'Name',
})


class DisassemblyContext:
    """
    Holds shared state for the disassembly of a single VBA module, eliminating repeated parameter
    threading through every helper function.
    """

    def __init__(
        self,
        indirect_table: bytes | bytearray | memoryview,
        object_table: bytes | bytearray | memoryview,
        declaration_table: bytes | bytearray | memoryview,
        identifiers: list[str],
        endian: str,
        vba_ver: int,
        is_64bit: bool,
        codec: str,
        version: int = 0,
        module_data: bytes | bytearray | memoryview | None = None,
        external_types: dict[int, str] | None = None,
    ):
        self.indirect_table = indirect_table
        self.object_table = object_table
        self.declaration_table = declaration_table
        self.identifiers = identifiers
        self.endian = endian
        self.vba_ver = vba_ver
        self.is_64bit = is_64bit
        self.codec = codec
        self.version = version
        self.module_data = module_data
        self.external_types: dict[int, str] = external_types or {}
        self._linecont_pending = False
        self._has_pa_bit = False

    def disasm_name(self, word: int, mnemonic: str, op_type: int) -> str:
        var_types = [
            '', '?', '%', '&', '!', '#', '@', '?', '$', '?', '?', '?', '?', '?',
        ]
        var_name = _get_id(word, self.identifiers, self.vba_ver, self.is_64bit)
        if op_type < len(var_types):
            str_type = var_types[op_type]
        else:
            str_type = ''
            if op_type == 32:
                var_name = F'[{var_name}]'
        if mnemonic == 'OnError':
            str_type = ''
            if op_type == 1:
                var_name = '(Resume Next)'
            elif op_type == 2:
                var_name = '(GoTo 0)'
        elif mnemonic == 'Resume':
            str_type = ''
            if op_type == 1:
                var_name = '(Next)'
            elif op_type != 0:
                var_name = ''
        return (var_name + str_type).rstrip()

    def disasm_imp(self, arg: str, word: int, mnemonic: str) -> str:
        if mnemonic != 'Open':
            if arg == 'imp_':
                shift = 3 if self.is_64bit else 2
                offs = (word >> shift) * 10
                if offs + 8 <= len(self.object_table):
                    hl_name = _get_word(self.object_table, offs + 6, self.endian)
                    if hl_name == 0:
                        return self.external_types.get(offs, '')
                    name = _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit)
                    if (hl_name >> 1) < 0x100 and name not in _VALID_INTERNAL_TYPE_NAMES:
                        return self.external_types.get(offs, '')
                    return name
            return F'{arg}{word:04X}'
        access_mode = ['Read', 'Write', 'Read Write']
        lock_mode = ['Read Write', 'Write', 'Read']
        mode = word & 0x00FF
        access = (word & 0x0F00) >> 8
        lock = (word & 0xF000) >> 12
        imp_name = '(For '
        if mode & 0x01:
            imp_name += 'Input'
        elif mode & 0x02:
            imp_name += 'Output'
        elif mode & 0x04:
            imp_name += 'Random'
        elif mode & 0x08:
            imp_name += 'Append'
        elif mode == 0x20:
            imp_name += 'Binary'
        if access and (access <= len(access_mode)):
            imp_name += F' Access {access_mode[access - 1]}'
        if lock:
            if lock & 0x04:
                imp_name += ' Shared'
            elif lock <= len(lock_mode):
                imp_name += F' Lock {lock_mode[lock - 1]}'
        imp_name += ')'
        return imp_name

    def disasm_rec(self, dword: int) -> str:
        object_name = _get_name(
            self.indirect_table, self.identifiers, dword + 2,
            self.endian, self.vba_ver, self.is_64bit)
        options = _get_word(self.indirect_table, dword + 18, self.endian)
        if (options & 1) == 0:
            object_name = F'(Private) {object_name}'
        else:
            object_name = F'(Public) {object_name}'
        return object_name

    def _resolve_udt_name(self, type_desc: int) -> str:
        """Resolve a user-defined type (type_id=0x1D) from the object table.

        The type descriptor at `type_desc` stores the object table reference word at
        offset +8 (instead of the usual +2 for non-builtin types).
        """
        if type_desc + 10 > len(self.indirect_table):
            return ''
        word = _get_word(self.indirect_table, type_desc + 8, self.endian)
        if self.is_64bit:
            offs = (word >> 3) * 10
            required = offs + 8
        else:
            offs = (word >> 2) * 10
            required = offs + 4
        if required > len(self.object_table):
            return ''
        hl_name = _get_word(self.object_table, offs + 6, self.endian)
        if hl_name == 0:
            return self.external_types.get(offs, '')
        return _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit)

    def disasm_object(self, offset: int) -> tuple[str, bool]:
        if self.is_64bit:
            type_desc = _get_dword(self.indirect_table, offset, self.endian)
            if type_desc + 4 > len(self.indirect_table):
                return '', False
            flags = _get_word(self.indirect_table, type_desc, self.endian)
            is_array = bool(flags & 0x0800)
            if flags & 0x02:
                type_id = self.indirect_table[type_desc + 6]
                if type_id == 0x1D:
                    name = self._resolve_udt_name(type_desc)
                    if name:
                        return name, is_array
                return _disasm_type(self.indirect_table, type_desc), is_array
            word = _get_word(self.indirect_table, type_desc + 2, self.endian)
            offs = (word >> 3) * 10
            if offs + 8 > len(self.object_table):
                return '', False
            hl_name = _get_word(self.object_table, offs + 6, self.endian)
            if hl_name == 0:
                ext = self.external_types.get(offs)
                return ext or '', is_array
            name = _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit)
            if (hl_name >> 1) < 0x100 and name not in _VALID_INTERNAL_TYPE_NAMES:
                ext = self.external_types.get(offs)
                return ext or '', is_array
            return name, is_array
        type_desc = _get_dword(self.indirect_table, offset, self.endian)
        flags = _get_word(self.indirect_table, type_desc, self.endian)
        is_array = bool(flags & 0x0800)
        if flags & 0x02:
            type_id = self.indirect_table[type_desc + 6]
            if type_id == 0x1D:
                name = self._resolve_udt_name(type_desc)
                if name:
                    return name, is_array
            return _disasm_type(self.indirect_table, type_desc), is_array
        word = _get_word(self.indirect_table, type_desc + 2, self.endian)
        offs = (word >> 2) * 10
        if offs + 4 > len(self.object_table):
            return '', False
        hl_name = _get_word(self.object_table, offs + 6, self.endian)
        if hl_name == 0:
            ext = self.external_types.get(offs)
            return ext or '', is_array
        name = _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit)
        if (hl_name >> 1) < 0x100 and name not in _VALID_INTERNAL_TYPE_NAMES:
            ext = self.external_types.get(offs)
            return ext or '', is_array
        return name, is_array

    def disasm_var(self, dword: int) -> VarInfo:
        b_flag1 = self.indirect_table[dword]
        b_flag2 = self.indirect_table[dword + 1]
        has_as = (b_flag1 & 0x20) != 0
        has_new = (b_flag2 & 0x20) != 0
        var_name = _get_name(
            self.indirect_table, self.identifiers, dword + 2,
            self.endian, self.vba_ver, self.is_64bit)
        type_ref: TypeRef | None = None
        if has_new or has_as:
            type_name = ''
            is_array = False
            if has_as:
                offs = 16 if self.is_64bit else 12
                word = _get_word(self.indirect_table, dword + offs + 2, self.endian)
                if word == 0xFFFF:
                    type_id = self.indirect_table[dword + offs]
                    type_name = _get_type_name(type_id)
                else:
                    type_name, is_array = self.disasm_object(dword + offs)
            if type_name:
                type_ref = TypeRef(type_name, is_array)
        else:
            offs = 16 if self.is_64bit else 12
            if len(self.indirect_table) >= dword + offs + 4:
                word = _get_word(self.indirect_table, dword + offs + 2, self.endian)
                if word == 0xFFFF:
                    type_id = self.indirect_table[dword + offs]
                    if (type_id & 0x40) and (b_flag1 & 0x10):
                        type_id &= ~0x40
                    if type_id in _SUFFIX_TYPE_IDS:
                        type_name = _get_type_name(type_id)
                        if type_name:
                            type_ref = TypeRef(type_name, from_suffix=True)
                else:
                    try:
                        type_name, is_array = self.disasm_object(dword + offs)
                    except Exception:
                        type_name = ''
                        is_array = False
                    if type_name in _SUFFIX_TYPES:
                        type_ref = TypeRef(type_name, is_array, from_suffix=True)
                    elif is_array:
                        var_name += '()'
        return VarInfo(var_name, type_ref, has_new)

    def disasm_arg(self, arg_offset: int) -> ArgInfo | None:
        flags = _get_word(self.indirect_table, arg_offset, self.endian)
        offs = 4 if self.is_64bit else 0
        name_word = _get_word(self.indirect_table, arg_offset + 2, self.endian)
        if name_word == 0xFFFE:
            return None
        arg_name = _get_name(
            self.indirect_table, self.identifiers, arg_offset + 2,
            self.endian, self.vba_ver, self.is_64bit)
        arg_type = _get_dword(self.indirect_table, arg_offset + offs + 12, self.endian)
        arg_opts = _get_word(self.indirect_table, arg_offset + offs + 24, self.endian)
        is_paramarray = bool(arg_opts & 0x0001)
        if is_paramarray:
            self._has_pa_bit = True
        is_byval = bool(arg_opts & 0x0004)
        is_byref = bool(arg_opts & 0x0002)
        is_optional = bool(arg_opts & 0x0200)
        type_ref: TypeRef | None = None
        if flags & 0x0020:
            arg_type_name = ''
            is_array = False
            if (arg_type & 0xFFFF0000) == 0xFFFF0000:
                arg_type_id = arg_type & 0x000000FF
                arg_type_name = _get_type_name(arg_type_id)
            elif self.is_64bit and arg_type < len(DIM_TYPES) and DIM_TYPES[arg_type]:
                arg_type_name = _get_type_name(arg_type)
            else:
                arg_type_name, is_array = self.disasm_object(arg_offset + offs + 12)
            if arg_type_name:
                type_ref = TypeRef(arg_type_name, is_array)
        elif (arg_type & 0xFFFF0000) == 0xFFFF0000:
            arg_type_id = arg_type & 0x000000FF
            if arg_type_id in _SUFFIX_TYPE_IDS:
                type_name = _get_type_name(arg_type_id)
                if type_name:
                    type_ref = TypeRef(type_name, from_suffix=True)
        elif self.is_64bit and arg_type < len(DIM_TYPES) and DIM_TYPES[arg_type]:
            if arg_type in _SUFFIX_TYPE_IDS:
                type_name = _get_type_name(arg_type)
                if type_name:
                    type_ref = TypeRef(type_name, from_suffix=True)
        else:
            try:
                type_name, is_array = self.disasm_object(arg_offset + offs + 12)
            except Exception:
                type_name = ''
                is_array = False
            if type_name in _SUFFIX_TYPES:
                type_ref = TypeRef(type_name, is_array, from_suffix=True)
            elif is_array:
                arg_name += '()'
        default_value: str | None = None
        if is_optional:
            default_tag_off = arg_offset + offs + 28
            default_val_off = arg_offset + offs + 32
            ind = self.indirect_table
            if default_tag_off + 2 <= len(ind) and default_val_off + 4 <= len(ind):
                vt_tag = _get_word(ind, default_tag_off, self.endian)
                value_dw = _get_dword(ind, default_val_off, self.endian)
                default_value = self._format_default_value(vt_tag, value_dw)
        return ArgInfo(
            arg_name, type_ref, is_byval, is_byref,
            is_optional, is_paramarray, default_value,
        )

    def _format_default_value(self, vt_tag: int, value_dw: int) -> str | None:
        VT_I2 = 2
        VT_I4 = 3
        VT_R4 = 4
        VT_R8 = 5
        VT_CY = 6
        VT_BSTR = 8
        VT_BOOL = 11
        VT_UI1 = 17
        ind = self.indirect_table
        if vt_tag == 0:
            return None
        elif vt_tag == VT_I2:
            val = value_dw & 0xFFFF
            return str(val - 0x10000 if val > 0x7FFF else val)
        elif vt_tag == VT_I4:
            return str(value_dw - 0x100000000 if value_dw > 0x7FFFFFFF else value_dw)
        elif vt_tag == VT_R4:
            val = _struct.unpack('<f', _struct.pack('<I', value_dw))[0]
            return str(int(val)) if val == int(val) and abs(val) < 1e15 else str(val)
        elif vt_tag == VT_R8:
            if value_dw + 8 <= len(ind):
                val = _struct.unpack('<d', bytes(ind[value_dw:value_dw + 8]))[0]
                return str(int(val)) if val == int(val) and abs(val) < 1e15 else str(val)
        elif vt_tag == VT_CY:
            val = value_dw / 10000
            return str(int(val)) if val == int(val) else str(val)
        elif vt_tag == VT_BSTR:
            if value_dw + 4 <= len(ind):
                str_len = _get_dword(ind, value_dw, self.endian)
                if str_len == 0:
                    return '""'
                if 0 < str_len < 0x10000 and value_dw + 4 + str_len <= len(ind):
                    s = bytes(ind[value_dw + 4:value_dw + 4 + str_len]).decode(self.codec, errors='replace')
                    return F'"{s}"'
        elif vt_tag == VT_BOOL:
            return 'True' if (value_dw & 0xFFFF) != 0 else 'False'
        elif vt_tag == VT_UI1:
            return str(value_dw & 0xFF)
        return None

    def _patch_64bit_defaults(self, arg_list: list[ArgInfo], func_name: str) -> None:
        md = self.module_data
        if md is None:
            return
        raw = bytes(md)
        need = sum(1 for a in arg_list if a.is_optional and a.default_value is None)
        if need == 0:
            return
        blocks: list[tuple[int, list[str]]] = []
        pos = 0
        while True:
            idx = raw.find(b'\xfa\x00\xb9\x00', pos)
            if idx < 0:
                break
            defaults: list[str] = []
            cur = idx + 2
            while cur + 4 <= len(raw) and raw[cur:cur + 2] == b'\xb9\x00':
                str_len = _get_word(raw, cur + 2, '<')
                if str_len <= 0 or str_len > 0x1000 or cur + 4 + str_len > len(raw):
                    break
                str_data = raw[cur + 4:cur + 4 + str_len]
                if not all(32 <= b < 127 or b in (9, 10, 13) for b in str_data):
                    break
                defaults.append(str_data.decode(self.codec, errors='replace'))
                cur = cur + 4 + str_len
            if defaults:
                blocks.append((idx, defaults))
            pos = idx + 4
        if not blocks:
            return
        func_bytes = func_name.encode(self.codec, errors='replace')
        func_pos = raw.find(func_bytes)
        if func_pos >= 0:
            best = min(blocks, key=lambda b: abs(b[0] - func_pos))
            defaults = best[1]
        elif len(blocks) == 1:
            defaults = blocks[0][1]
        else:
            return
        defaults = list(reversed(defaults))
        di = 0
        for arg in arg_list:
            if not arg.is_optional or arg.default_value is not None:
                continue
            if di >= len(defaults):
                break
            arg.default_value = F'"{defaults[di]}"'
            di += 1

    def _declare64(self, decl_offset: int, func_name: str) -> tuple[str, str | None]:
        """
        Extract Lib and Alias names from a 64-bit Declare entry in the declaration table.
        The 64-bit entry structure differs significantly from 32-bit: the lib name identifier
        word is not at a fixed offset within the entry header. Instead, we extract the lib name
        from VBA source text stored later in the declaration table, falling back to the binary
        structure when source text is not available.
        """
        decl = self.declaration_table
        decl_bytes = bytes(decl)
        lib_name = None
        alias_name = None
        # Strategy 1: Extract from VBA source text in the declaration table.
        # The source text may contain embedded null bytes, so strip them before matching.
        text = decl_bytes.replace(b'\x00', b'').decode('ascii', errors='replace')
        match = re.search(
            rf'(?:Function|Sub)\s+{re.escape(func_name)}\b.*?Lib\s+"([^"]+)"', text)
        if match:
            lib_name = match.group(1)
            after_lib = text[match.end():]
            alias_match = re.match(r'\s*Alias\s*"([^"]+)"', after_lib)
            if alias_match:
                alias_name = alias_match.group(1)
        # Strategy 2: Binary structure fallback. The alias string offset depends on version:
        # VBA7 version 0x0097 has 4 extra bytes of padding (alias at +0x20), later versions
        # use the standard offset (+0x1C).
        _alias_off = 0x20 if self.version <= 0x97 else 0x1C
        if lib_name is None and self.version > 0x97 and decl_offset >= 2:
            # For VBA7 versions after 0x97 the lib identifier word for each entry is stored
            # in the 2 bytes immediately preceding the entry header, placed there as trailing
            # data of the previous entry. This does not apply to the very first entry
            # (decl_offset == 0) or to versions <= 0x97 where the lib word sits at header +2.
            lib_word = _get_word(decl, decl_offset - 2, self.endian)
            if lib_word != 0 and lib_word != 0xFFFF:
                lib_name = _get_id(lib_word, self.identifiers, self.vba_ver, self.is_64bit)
        if lib_name is None:
            alias_start = decl_offset + _alias_off
            if alias_start < len(decl):
                alias_bytes_raw = bytes(decl[alias_start:])
                null_pos = alias_bytes_raw.find(0)
                if null_pos > 0 and all(32 <= b < 127 for b in alias_bytes_raw[:null_pos]):
                    abs_null = alias_start + null_pos
                    dword_aligned = (abs_null + 1 + 3) & ~3
                    lib_word_offset = dword_aligned + 2
                    if lib_word_offset + 2 <= len(decl):
                        lib_word = _get_word(decl, lib_word_offset, self.endian)
                        if lib_word != 0 and lib_word != 0xFFFF:
                            lib_name = _get_id(lib_word, self.identifiers, self.vba_ver, self.is_64bit)
        if lib_name is None:
            lib_word = _get_word(decl, decl_offset + 2, self.endian)
            if lib_word != 0:
                lib_name = _get_id(lib_word, self.identifiers, self.vba_ver, self.is_64bit)
        # Read alias from binary structure if not found via source text.
        if alias_name is None:
            alias_start = decl_offset + _alias_off
            if alias_start < len(decl):
                alias_bytes_raw = bytes(decl[alias_start:])
                null_pos = alias_bytes_raw.find(0)
                if null_pos > 0:
                    alias_name = alias_bytes_raw[:null_pos].decode(self.codec, errors='replace')
        return lib_name, alias_name

    def disasm_func(self, dword: int, op_type: int) -> FuncInfo:
        flags = _get_word(self.indirect_table, dword, self.endian)
        name_word = _get_word(self.indirect_table, dword + 2, self.endian)
        offs2 = 4 if self.vba_ver > 5 else 0
        if self.is_64bit:
            offs2 += 16
        self._linecont_pending = False
        sub_name = _get_id(name_word, self.identifiers, self.vba_ver, self.is_64bit)
        arg_offset = _get_dword(self.indirect_table, dword + offs2 + 36, self.endian)
        ret_type = _get_dword(self.indirect_table, dword + offs2 + 40, self.endian)
        decl_offset = _get_word(self.indirect_table, dword + offs2 + 44, self.endian)
        c_options_offset = 60 if self.is_64bit and self.version > 0x97 else 54
        c_options = self.indirect_table[dword + offs2 + c_options_offset]
        new_flags_offset = 63 if self.is_64bit and self.version > 0x97 else 57
        new_flags = self.indirect_table[dword + offs2 + new_flags_offset]
        scope = ''
        is_friend = False
        if self.vba_ver > 5:
            if (new_flags & 0x0002) == 0:
                scope = 'Private'
            elif op_type & 0x04:
                scope = 'Public'
            if new_flags & 0x0004:
                is_friend = True
        else:
            if (flags & 0x0008) == 0:
                scope = 'Private'
            elif op_type & 0x04:
                scope = 'Public'
        is_static = bool(flags & 0x0080)
        has_declare = (c_options & 0x90) == 0 and decl_offset != 0xFFFF
        is_ptrsafe = bool(self.vba_ver > 5 and new_flags & 0x20)
        has_as = (flags & 0x0020) != 0
        if flags & 0x1000:
            kind = 'Function' if op_type in (2, 6) else 'Sub'
        elif flags & 0x2000:
            kind = 'Property Get'
        elif flags & 0x4000:
            kind = 'Property Let'
        elif flags & 0x8000:
            kind = 'Property Set'
        else:
            kind = 'Sub'
        return_type: TypeRef | None = None
        if has_as:
            type_name = ''
            is_array = False
            if (ret_type & 0xFFFF0000) == 0xFFFF0000:
                type_id = ret_type & 0x000000FF
                type_name = _get_type_name(type_id)
            else:
                type_name, is_array = self.disasm_object(dword + offs2 + 40)
            if type_name:
                return_type = TypeRef(type_name, is_array)
        elif (ret_type & 0xFFFF0000) == 0xFFFF0000:
            ret_type_id = ret_type & 0x000000FF
            if ret_type_id in _SUFFIX_TYPE_IDS:
                type_name = _get_type_name(ret_type_id)
                if type_name:
                    return_type = TypeRef(type_name, from_suffix=True)
        lib_name: str | None = None
        alias_name: str | None = None
        if has_declare:
            if self.is_64bit:
                lib_name, alias_name = self._declare64(decl_offset, sub_name)
            else:
                lib_name = _get_name(
                    self.declaration_table, self.identifiers, decl_offset + 2,
                    self.endian, self.vba_ver, self.is_64bit)
                alias_offset = _get_word(
                    self.declaration_table, decl_offset + 4, self.endian)
                if alias_offset < len(self.declaration_table):
                    alias_bytes = bytes(self.declaration_table[alias_offset:])
                    null_pos = alias_bytes.find(0)
                    if null_pos > 0:
                        alias_name = alias_bytes[:null_pos].decode(
                            self.codec, errors='replace')
            if alias_name == sub_name:
                alias_name = None
        arg_list: list[ArgInfo] = []
        while (
            arg_offset != 0xFFFFFFFF
            and arg_offset != 0
            and arg_offset + 26 < len(self.indirect_table)
        ):
            arg = self.disasm_arg(arg_offset)
            if arg is not None:
                arg_list.append(arg)
            arg_offset = _get_dword(
                self.indirect_table,
                arg_offset + (24 if self.is_64bit else 20),
                self.endian,
            )
        if self.is_64bit and any(
            a.is_optional and a.default_value is None for a in arg_list
        ):
            self._patch_64bit_defaults(arg_list, sub_name)
        if (
            arg_list
            and not self._has_pa_bit
            and not any(a.is_paramarray for a in arg_list)
        ):
            last = arg_list[-1]
            _pa_candidate = (
                last.type is not None
                and last.type.is_array
                and (last.type.name == 'Variant' or last.type.name == '')
            ) or (
                last.type is None
                and last.name.endswith('()')
            )
            _pa_no_modifiers = not last.is_byval and not last.is_byref and not last.is_optional
            if _pa_candidate and _pa_no_modifiers:
                last.is_paramarray = True
        if is_friend:
            scope = 'Friend' if not scope else F'{scope} Friend'
        return FuncInfo(
            scope, is_static, kind, sub_name, arg_list,
            return_type, has_declare, is_ptrsafe, lib_name, alias_name,
        )

    def disasm_var_arg(
        self,
        module_data: bytes | bytearray | memoryview,
        offset: int,
        w_length: int,
        mnemonic: str,
    ) -> list[str]:
        substring = module_data[offset:offset + w_length]
        length_str = F'0x{w_length:04X}'
        if mnemonic in ('LitStr', 'QuoteRem', 'Rem', 'Reparse'):
            quoted = F'"{codecs.decode(substring, self.codec, "replace")}"'
            return [length_str, quoted]
        elif mnemonic in ('OnGosub', 'OnGoto'):
            offset1 = offset
            names: list[str] = []
            for _ in range(w_length // 2):
                offset1, word = _get_var(module_data, offset1, self.endian, False)
                names.append(_get_id(word, self.identifiers, self.vba_ver, self.is_64bit))
            return [length_str, ', '.join(names)]
        else:
            hex_dump = ' '.join(F'{c:02X}' for c in substring)
            return [length_str, hex_dump]

    def dump_line(
        self,
        module_data: bytes | bytearray | memoryview,
        line_start: int,
        line_length: int,
    ) -> list[tuple[str, list[OpcodeArg]]]:
        """
        Disassemble one p-code line into a list of (mnemonic, [arg, ...]) tuples.
        """
        self._linecont_pending = False

        result: list[tuple[str, list[OpcodeArg]]] = []
        if line_length <= 0:
            return result
        offset = line_start
        end_of_line = line_start + line_length
        while offset < end_of_line:
            offset, opcode = _get_var(module_data, offset, self.endian, False)
            op_type = (opcode & ~0x03FF) >> 10
            opcode &= 0x03FF
            translated = _translate_opcode(opcode, self.vba_ver, self.is_64bit)
            if translated not in OPCODES:
                return result
            instruction = OPCODES[translated]
            mnemonic = instruction.mnem
            if op_type == 8 and mnemonic in ('FnMid', 'FnMidB', 'FnCurDir', 'FnError', 'Mid', 'MidB'):
                mnemonic += '$'
            parts: list[OpcodeArg] = []
            if mnemonic in ('Coerce', 'CoerceVar', 'DefType'):
                if op_type < len(_VAR_TYPES_LONG):
                    parts.append(CoerceType(_VAR_TYPES_LONG[op_type]))
                elif op_type == 17:
                    parts.append(CoerceType('Byte'))
                else:
                    parts.append(CoerceType(str(op_type)))
            elif mnemonic in ('Dim', 'DimImplicit', 'Type'):
                dim_type: list[str] = []
                if op_type & 0x04:
                    dim_type.append('Global')
                elif op_type & 0x08:
                    dim_type.append('Public')
                elif op_type & 0x10:
                    dim_type.append('Private')
                elif op_type & 0x20:
                    dim_type.append('Static')
                if (op_type & 0x01) and (mnemonic != 'Type'):
                    dim_type.append('Const')
                if dim_type:
                    parts.append(DimScope(dim_type))
            elif mnemonic == 'LitVarSpecial':
                parts.append(_SPECIALS[op_type])
            elif mnemonic in ('ArgsCall', 'ArgsMemCall', 'ArgsMemCallWith'):
                if op_type < 16:
                    parts.append('(Call)')
                else:
                    op_type -= 16
            elif mnemonic == 'Option':
                parts.append(_OPTIONS[op_type])
            elif mnemonic in ('Redim', 'RedimAs'):
                if op_type & 16:
                    parts.append('(Preserve)')
            elif mnemonic in (
                'FnDir', 'FnFormat', 'FnStringVar', 'FnStringStr',
            ):
                parts.append(F'0x{op_type:04X}')
            elif mnemonic == 'LitSmallI2':
                parts.append(str(op_type))
            for arg in instruction.args:
                if arg == 'name':
                    offset, word = _get_var(module_data, offset, self.endian, False)
                    the_name = self.disasm_name(word, mnemonic, op_type)
                    parts.append(the_name)
                elif arg in ('0x', 'imp_'):
                    offset, word = _get_var(module_data, offset, self.endian, False)
                    the_imp = self.disasm_imp(arg, word, mnemonic)
                    parts.append(the_imp)
                elif arg in ('func_', 'var_', 'rec_', 'type_', 'context_'):
                    offset, dword = _get_var(module_data, offset, self.endian, True)
                    if (
                        arg == 'rec_'
                        and len(self.indirect_table) >= dword + 20
                    ):
                        parts.append(RecordInfo(self.disasm_rec(dword)))
                    elif (
                        arg == 'type_'
                        and len(self.indirect_table) >= dword + 7
                    ):
                        type_id = self.indirect_table[dword + 6]
                        if type_id == 0x1D:
                            the_type = self._resolve_udt_name(dword)
                        else:
                            the_type = ''
                        if not the_type:
                            the_type = _disasm_type(self.indirect_table, dword)
                        parts.append(TypeRef(the_type))
                    elif (
                        arg == 'var_'
                        and len(self.indirect_table) >= dword + 16
                    ):
                        var_info = self.disasm_var(dword)
                        if op_type & 0x20:
                            var_info.has_withevents = True
                        parts.append(var_info)
                        if op_type & 0x10:
                            word = _get_word(module_data, offset, self.endian)
                            offset += 2
                            parts.append(F'0x{word:04X}')
                    elif (
                        arg == 'func_'
                        and len(self.indirect_table) >= dword + 61
                    ):
                        parts.append(self.disasm_func(dword, op_type))
                    else:
                        parts.append(F'{arg}{dword:08X}')
                    if self.is_64bit and (arg == 'context_'):
                        offset, dword = _get_var(module_data, offset, self.endian, True)
                        parts.append(F'{dword:08X}')
            if instruction.varg:
                offset, w_length = _get_var(module_data, offset, self.endian, False)
                var_arg_parts = self.disasm_var_arg(
                    module_data, offset, w_length, mnemonic)
                parts.extend(var_arg_parts)
                offset += w_length
                if w_length & 1:
                    offset += 1
            result.append((mnemonic, parts))
            if mnemonic == 'LineCont':
                self._linecont_pending = True
        return result


# MS-OVBA specification offsets for module stream parsing
_OFFSET_DW_LENGTH = 0x0005
_OFFSET_VBA6_INDIRECT_START = 0x0011
_OFFSET_VBA6_32_DECL_LENGTH = 0x003F
_OFFSET_VBA6_32_DECL_DATA = 0x0043
_OFFSET_VBA6_64_DECL_LENGTH = 0x0043
_OFFSET_VBA6_64_DECL_DATA = 0x0047
_OFFSET_VBA6_64_LINE_START = 0x0019
_OFFSET_OBJECT_TABLE = 0x008A
_OFFSET_PCODE_LINES = 0x003C
_PCODE_MAGIC = 0xCAFE


def _parse_external_type_table(
    module_data: bytes | bytearray | memoryview,
    object_table: bytes | bytearray | memoryview,
    ot_start_in_module: int,
    endian: str,
    identifiers: list[str],
    vba_ver: int,
    is_64bit: bool,
) -> dict[int, str]:
    """Parse the external type table that follows the object table in module_data.

    For each external OT entry (hl_name == 0 or small internal name), the table
    stores a record with id_codes for the library name and type name. The structure is:
        +0: FFFF (separator)
        +2: 0101 (flags)
        +4: DWORD size of payload
        +8: payload containing one or more 8-byte type pairs:
            0200 <lib_id> <type_id> 0000
    A single record may contain multiple type pairs packed in its payload.
    """
    result: dict[int, str] = {}
    ot_len = len(object_table)
    if ot_len == 0:
        return result

    external_ot_offsets: list[int] = []
    extra_ot_offsets: list[int] = []
    for ot_idx in range(ot_len // 10):
        ot_offs = ot_idx * 10
        hl_name = _get_word(object_table, ot_offs + 6, endian)
        if hl_name == 0:
            external_ot_offsets.append(ot_offs)
        elif (hl_name >> 1) < 0x100:
            try:
                name = _get_id(hl_name, identifiers, vba_ver, is_64bit)
            except Exception:
                continue
            if name not in _VALID_INTERNAL_TYPE_NAMES:
                extra_ot_offsets.append(ot_offs)
    external_ot_offsets.extend(extra_ot_offsets)

    if not external_ot_offsets:
        return result

    pos = ot_start_in_module + ot_len
    ot_iter = iter(external_ot_offsets)
    try:
        while pos + 8 <= len(module_data):
            marker = _get_word(module_data, pos, endian)
            if marker != 0xFFFF:
                break
            pos += 2
            _flags = _get_word(module_data, pos, endian)
            pos += 2
            payload_size = _get_dword(module_data, pos, endian)
            pos += 4
            if payload_size < 6 or pos + payload_size > len(module_data):
                break
            payload_end = pos + payload_size
            while pos + 8 <= payload_end:
                _prefix = _get_word(module_data, pos, endian)
                lib_id = _get_word(module_data, pos + 2, endian)
                type_id = _get_word(module_data, pos + 4, endian)
                pos += 8
                ot_offs = next(ot_iter, None)
                if ot_offs is None:
                    break
                try:
                    lib_name = _get_id(lib_id, identifiers, vba_ver, is_64bit)
                except Exception:
                    continue
                try:
                    type_name = _get_id(type_id, identifiers, vba_ver, is_64bit)
                except Exception:
                    continue
                if lib_name and type_name:
                    result[ot_offs] = F'{lib_name}.{type_name}'
            pos = payload_end
    except Exception:
        pass
    return result


def _pcode_dump(
    module_data: bytes | bytearray | memoryview,
    vba_project_data: bytes | bytearray | memoryview,
    identifiers: list[str],
    is_64bit: bool,
    codec: str,
) -> list[PCodeLine]:
    """
    Disassemble p-code from a VBA module stream. Returns structured PCodeLine objects.
    """
    lines: list[PCodeLine] = []
    if _get_word(module_data, 2, '<') > 0xFF:
        endian = '>'
    else:
        endian = '<'
    vba_ver = 3
    try:
        version = _get_word(vba_project_data, 2, endian)
        if version >= 0x6B:
            if version >= 0x97:
                vba_ver = 7
            else:
                vba_ver = 6
            if is_64bit:
                dw_length = _get_dword(module_data, _OFFSET_VBA6_64_DECL_LENGTH, endian)
                declaration_table = module_data[
                    _OFFSET_VBA6_64_DECL_DATA:_OFFSET_VBA6_64_DECL_DATA + dw_length]
                dw_length = _get_dword(module_data, _OFFSET_VBA6_INDIRECT_START, endian)
                table_start = dw_length + 12
            else:
                dw_length = _get_dword(module_data, _OFFSET_VBA6_32_DECL_LENGTH, endian)
                declaration_table = module_data[
                    _OFFSET_VBA6_32_DECL_DATA:_OFFSET_VBA6_32_DECL_DATA + dw_length]
                dw_length = _get_dword(module_data, _OFFSET_VBA6_INDIRECT_START, endian)
                table_start = dw_length + 10
            dw_length = _get_dword(module_data, table_start, endian)
            table_start += 4
            indirect_table = module_data[
                table_start:table_start + dw_length]
            dw_length = _get_dword(module_data, _OFFSET_DW_LENGTH, endian)
            dw_length2 = dw_length + _OFFSET_OBJECT_TABLE
            dw_length = _get_dword(module_data, dw_length2, endian)
            dw_length2 += 4
            object_table = module_data[
                dw_length2:dw_length2 + dw_length]
            ot_module_start = dw_length2
            offset = _OFFSET_VBA6_64_LINE_START
        else:
            vba_ver = 5
            offset = 11
            dw_length = _get_dword(module_data, offset, endian)
            offs = offset + 4
            declaration_table = module_data[offs:offs + dw_length]
            offset = _skip_structure(module_data, offset, endian, True, 1, False)
            offset += 64
            offset = _skip_structure(module_data, offset, endian, False, 16, False)
            offset = _skip_structure(module_data, offset, endian, True, 1, False)
            offset += 6
            offset = _skip_structure(module_data, offset, endian, True, 1, False)
            offs = offset + 8
            dw_length = _get_dword(module_data, offs, endian)
            table_start = dw_length + 14
            offs = dw_length + 10
            dw_length = _get_dword(module_data, offs, endian)
            indirect_table = module_data[
                table_start:table_start + dw_length]
            dw_length = _get_dword(module_data, offset, endian)
            offs = dw_length + _OFFSET_OBJECT_TABLE
            dw_length = _get_dword(module_data, offs, endian)
            offs += 4
            object_table = module_data[offs:offs + dw_length]
            ot_module_start = offs
            offset += 77

        external_types = _parse_external_type_table(
            module_data, object_table, ot_module_start,
            endian, identifiers, vba_ver, is_64bit,
        )
        ctx = DisassemblyContext(
            indirect_table, object_table, declaration_table,
            identifiers, endian, vba_ver, is_64bit, codec, version,
            module_data=module_data, external_types=external_types)

        dw_length = _get_dword(module_data, offset, endian)
        offset = dw_length + _OFFSET_PCODE_LINES
        offset, magic = _get_var(module_data, offset, endian, False)
        if magic != _PCODE_MAGIC:
            return lines
        offset += 2
        offset, num_lines = _get_var(module_data, offset, endian, False)
        pcode_start = offset + num_lines * 12 + 10
        for _ in range(num_lines):
            offset += 4
            offset, line_length = _get_var(module_data, offset, endian, False)
            offset += 2
            offset, line_offset = _get_var(module_data, offset, endian, True)
            opcodes = ctx.dump_line(module_data, pcode_start + line_offset, line_length)
            lines.append(PCodeLine(opcodes))
    except Exception as exc:
        logger.warning(F'p-code disassembly error: {exc}')
    return lines


def _get_identifiers(
    vba_project_data: bytes | bytearray | memoryview,
    codec: str,
) -> list[str]:
    """
    Extract identifier names from the _VBA_PROJECT stream.
    """
    identifiers: list[str] = []
    try:
        magic = _get_word(vba_project_data, 0, '<')
        if magic != 0x61CC:
            return identifiers
        version = _get_word(vba_project_data, 2, '<')
        unicode_ref = ((version >= 0x5B)
            and (version not in (0x60, 0x62, 0x63))
            or (version == 0x4E)
        )
        unicode_name = ((version >= 0x59)
            and (version not in (0x60, 0x62, 0x63))
            or (version == 0x4E)
        )
        non_unicode_name = (((version <= 0x59) and (version != 0x4E))
            or (0x5F < version < 0x6B)
        )
        word = _get_word(vba_project_data, 5, '<')
        endian = '>' if word == 0x000E else '<'
        offset = 0x1E
        offset, num_refs = _get_var(vba_project_data, offset, endian, False)
        offset += 2
        for _ in range(num_refs):
            offset, ref_length = _get_var(vba_project_data, offset, endian, False)
            if ref_length == 0:
                offset += 6
            elif ref_length < 3 + 2 * unicode_ref:
                offset += ref_length
            else:
                if unicode_ref:
                    c = vba_project_data[offset + 4]
                else:
                    c = vba_project_data[offset + 2]
                offset += ref_length
                if chr(c) in ('C', 'D'):
                    offset = _skip_structure(vba_project_data, offset, endian, False, 1, False)
            offset += 10
            offset, word = _get_var(vba_project_data, offset, endian, False)
            if word:
                offset = _skip_structure(vba_project_data, offset, endian, False, 1, False)
                offset, w_length = _get_var(vba_project_data, offset, endian, False)
                if w_length:
                    offset += 2
                offset += w_length + 30
        offset = _skip_structure(vba_project_data, offset, endian, False, 2, False)
        offset = _skip_structure(vba_project_data, offset, endian, False, 4, False)
        offset += 2
        offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
        offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
        offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
        offset += 0x64
        offset, num_projects = _get_var(vba_project_data, offset, endian, False)
        for _ in range(num_projects):
            offset, w_length = _get_var(vba_project_data, offset, endian, False)
            if unicode_name:
                offset += w_length
            if non_unicode_name:
                if w_length:
                    offset, w_length = _get_var(vba_project_data, offset, endian, False)
                offset += w_length
            offset = _skip_structure(vba_project_data, offset, endian, False, 1, False)
            offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
            offset, _ = _get_var(vba_project_data, offset, endian, False)
            if version >= 0x6B:
                offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
            offset = _skip_structure(vba_project_data, offset, endian, False, 1, True)
            offset += 2
            if version != 0x51:
                offset += 4
            offset = _skip_structure(vba_project_data, offset, endian, False, 8, False)
            offset += 11
        offset += 6
        offset = _skip_structure(vba_project_data, offset, endian, True, 1, False)
        offset += 6
        offset, w0 = _get_var(vba_project_data, offset, endian, False)
        offset, num_ids = _get_var(vba_project_data, offset, endian, False)
        offset, w1 = _get_var(vba_project_data, offset, endian, False)
        offset += 4
        num_junk_ids = num_ids + w1 - w0
        num_ids = w0 - w1
        for _ in range(num_junk_ids):
            offset += 4
            id_type, id_length = _get_type_and_length(vba_project_data, offset, endian)
            offset += 2
            if id_type > 0x7F:
                offset += 6
            offset += id_length
        for _ in range(num_ids):
            is_kwd = False
            ident = ''
            id_type, id_length = _get_type_and_length(vba_project_data, offset, endian)
            offset += 2
            if (id_length == 0) and (id_type == 0):
                offset += 2
                id_type, id_length = _get_type_and_length(vba_project_data, offset, endian)
                offset += 2
                is_kwd = True
            if id_type & 0x80:
                offset += 6
            if id_length:
                ident = codecs.decode(
                    vba_project_data[offset:offset + id_length], codec, 'replace')
                offset += id_length
            identifiers.append(ident)
            if not is_kwd:
                offset += 4
    except Exception as exc:
        logger.warning(F'identifier extraction error: {exc}')
    return identifiers


def format_pcode_text(
    module_path: str,
    module_data_size: int,
    lines: list[PCodeLine],
) -> str:
    """
    Render structured PCodeLine data into pcodedmp-compatible text output.
    """
    output: list[str] = []
    output.append(F'{module_path} - {module_data_size:d} bytes')
    for line_num, pcode_line in enumerate(lines):
        output.append(F'Line #{line_num:d}:')
        for mnemonic, args in pcode_line.opcodes:
            text = F'\t{mnemonic} {" ".join(args)}'
            output.append(text)
    return '\n'.join(output) + '\n'


class PCodeDisassembler:
    """
    VBA p-code disassembler that produces structured PCodeModule output. The output is suitable for
    consumption by the decompiler for reconstruction to VBA source code.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self._data = data

    def iter_modules(self):
        """
        Yield PCodeModule objects for each VBA module.
        """
        for ole_data in self._get_ole_streams():
            ole = OleFile(ole_data)
            yield from self._iter_project_modules(ole)

    def _iter_project_modules(
        self,
        ole: OleFile,
    ):
        """
        Iterate over VBA modules in an OLE file, yielding PCodeModule per module.
        """
        vba_projects = _find_vba_projects(ole)
        if not vba_projects:
            return
        for vba_root, _, dir_path in vba_projects:
            codec, code_modules, is_64bit = self._process_dir(ole, dir_path)
            vba_project_path = vba_root + 'VBA/_VBA_PROJECT'
            vba_project_data = self._process_vba_project(ole, vba_project_path)
            identifiers = _get_identifiers(vba_project_data, codec)
            identifiers_stripped = not identifiers
            for module in code_modules:
                module_path = F'{vba_root}VBA/{module}'
                try:
                    module_data = ole.openstream(module_path).read()
                except Exception:
                    continue
                lines = _pcode_dump(
                    module_data, vba_project_data, identifiers, is_64bit, codec)
                yield PCodeModule(module_path, lines, identifiers_stripped)

    def _get_ole_streams(self) -> list[bytes | bytearray | memoryview]:
        """
        Extract OLE data from the input. If the input is already an OLE compound file, returns it
        directly. If it's a ZIP (OOXML), extracts all vbaProject.bin entries.
        """
        if self._data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return [self._data]
        if self._data[:2] == b'PK':
            import zipfile

            from refinery.lib.structures import MemoryFile
            results: list[bytes | bytearray] = []
            try:
                with zipfile.ZipFile(MemoryFile(self._data, bytes)) as zf:
                    for name in zf.namelist():
                        if name.lower().endswith('vbaproject.bin'):
                            results.append(zf.read(name))
            except zipfile.BadZipFile:
                pass
            return results
        return [self._data]

    def _process_dir(
        self,
        ole: OleFile,
        dir_path: str,
    ) -> tuple[str, list[str], bool]:
        """
        Parse the VBA dir stream to find module names and codepage. Returns (codec, code_modules,
        is_64bit).
        """
        dir_data_compressed = ole.openstream(dir_path).read()
        dir_data = decompress_stream(dir_data_compressed)
        stream_size = len(dir_data)
        code_modules: list[str] = []
        is_64bit = False
        codec = 'latin1'
        offset = 0
        while offset < stream_size:
            try:
                tag = _get_word(dir_data, offset, '<')
                w_length = _get_word(dir_data, offset + 2, '<')
                if tag == 9:
                    w_length = 6
                elif tag == 3:
                    w_length = 2
                offset += 6
                if w_length:
                    if tag == 3:
                        codepage = _get_word(dir_data, offset, '<')
                        codec = _codepage_to_codec(codepage)
                    elif tag == 50:
                        stream_name = codecs.decode(
                            dir_data[offset:offset + w_length], 'utf_16_le', errors='replace')
                        code_modules.append(stream_name)
                    elif tag == 1:
                        sys_kind = _get_dword(dir_data, offset, '<')
                        is_64bit = sys_kind == 3
                    offset += w_length
            except Exception:
                break
        return codec, code_modules, is_64bit

    def _process_vba_project(
        self,
        ole: OleFile,
        vba_project_path: str,
    ) -> bytes | bytearray | memoryview:
        """
        Read the _VBA_PROJECT stream (raw, not compressed).
        """
        return ole.openstream(vba_project_path).read()
