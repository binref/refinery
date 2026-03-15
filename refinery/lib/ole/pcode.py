"""
VBA p-code disassembler for Microsoft Office documents.

This module is a port of pcodedmp by Vesselin Bontchev, originally available at
https://github.com/bontchev/pcodedmp, adapted for the Binary Refinery project.

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

from struct import unpack_from
from typing import NamedTuple

from refinery.lib.ole.file import OleFile
from refinery.lib.ole.vba import _codepage_to_codec, _find_vba_projects, decompress_stream

logger = logging.getLogger(__name__)


class Opcode(NamedTuple):
    mnem: str
    args: list[str] = []
    varg: bool = False


class PCodeLine(NamedTuple):
    """
    Structured representation of one line of disassembled p-code.
    Each line contains a list of (mnemonic, [arg1, arg2, ...]) tuples.
    """
    opcodes: list[tuple[str, list[str]]]


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
    'Decimal', '', '', 'Byte',
]


def _get_word(buffer: bytes | bytearray | memoryview, offset: int, endian: str) -> int:
    return unpack_from(endian + 'H', buffer, offset)[0]


def _get_dword(buffer: bytes | bytearray | memoryview, offset: int, endian: str) -> int:
    return unpack_from(endian + 'L', buffer, offset)[0]


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
                if id_code > 0xBE:
                    id_code -= 1
            return identifiers[id_code]
        else:
            if vba_ver >= 7:
                if id_code >= 0xC3:
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
        type_name += 'Ptr'
    return type_name


def _disasm_type(
    indirect_table: bytes | bytearray | memoryview,
    dword: int,
) -> str:
    type_id = indirect_table[dword + 6]
    if type_id < len(DIM_TYPES):
        return DIM_TYPES[type_id]
    else:
        return F'type_{dword:08X}'


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
    ):
        self.indirect_table = indirect_table
        self.object_table = object_table
        self.declaration_table = declaration_table
        self.identifiers = identifiers
        self.endian = endian
        self.vba_ver = vba_ver
        self.is_64bit = is_64bit
        self.codec = codec
        self._linecont_pending = False

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
                    return _get_name(
                        self.object_table, self.identifiers, offs + 6,
                        self.endian, self.vba_ver, self.is_64bit)
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
        return object_name

    def disasm_object(self, offset: int) -> tuple[str, bool]:
        if self.is_64bit:
            type_desc = _get_dword(self.indirect_table, offset, self.endian)
            if type_desc + 4 > len(self.indirect_table):
                return '', False
            flags = _get_word(self.indirect_table, type_desc, self.endian)
            is_array = bool(flags & 0x0800)
            if flags & 0x02:
                return _disasm_type(self.indirect_table, type_desc), is_array
            word = _get_word(self.indirect_table, type_desc + 2, self.endian)
            if word == 0:
                return '', False
            offs = (word >> 3) * 10
            if offs + 8 > len(self.object_table):
                return '', False
            hl_name = _get_word(self.object_table, offs + 6, self.endian)
            return _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit), is_array
        type_desc = _get_dword(self.indirect_table, offset, self.endian)
        flags = _get_word(self.indirect_table, type_desc, self.endian)
        is_array = bool(flags & 0x0800)
        if flags & 0x02:
            return _disasm_type(self.indirect_table, type_desc), is_array
        word = _get_word(self.indirect_table, type_desc + 2, self.endian)
        if word == 0:
            return '', False
        offs = (word >> 2) * 10
        if offs + 4 > len(self.object_table):
            return '', False
        hl_name = _get_word(self.object_table, offs + 6, self.endian)
        return _get_id(hl_name, self.identifiers, self.vba_ver, self.is_64bit), is_array

    def disasm_var(self, dword: int) -> str:
        b_flag1 = self.indirect_table[dword]
        b_flag2 = self.indirect_table[dword + 1]
        has_as = (b_flag1 & 0x20) != 0
        has_new = (b_flag2 & 0x20) != 0
        var_name = _get_name(
            self.indirect_table, self.identifiers, dword + 2,
            self.endian, self.vba_ver, self.is_64bit)
        is_array = False
        if has_new or has_as:
            type_name = ''
            if has_as:
                offs = 16 if self.is_64bit else 12
                word = _get_word(self.indirect_table, dword + offs + 2, self.endian)
                if word == 0xFFFF:
                    type_id = self.indirect_table[dword + offs]
                    type_name = _get_type_name(type_id)
                else:
                    type_name, is_array = self.disasm_object(dword + offs)
            var_type = ''
            if has_as and len(type_name) > 0:
                var_type += 'As '
            if has_new:
                var_type += 'New '
            if has_as and len(type_name) > 0:
                var_type += type_name
            if is_array:
                var_name += '()'
            if len(var_type) > 0:
                var_name += F' ({var_type.rstrip()})'
        return var_name

    def disasm_arg(self, arg_offset: int) -> str | None:
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
        if arg_opts & 0x0004:
            arg_name = F'ByVal {arg_name}'
        if arg_opts & 0x0002:
            arg_name = F'ByRef {arg_name}'
        if arg_opts & 0x0200:
            arg_name = F'Optional {arg_name}'
        if flags & 0x0020:
            arg_type_name = ''
            is_array = False
            if (arg_type & 0xFFFF0000) == 0xFFFF0000:
                arg_type_id = arg_type & 0x000000FF
                arg_type_name = _get_type_name(arg_type_id)
            else:
                arg_type_name, is_array = self.disasm_object(arg_offset + offs + 12)
            if is_array:
                arg_name += '()'
            arg_name += ' As '
            arg_name += arg_type_name
        return arg_name

    def disasm_func(self, dword: int, op_type: int) -> str:
        func_decl = '('
        flags = _get_word(self.indirect_table, dword, self.endian)
        name_word = _get_word(self.indirect_table, dword + 2, self.endian)
        offs2 = 4 if self.vba_ver > 5 else 0
        if self.is_64bit:
            offs2 += 16
        if (
            self._linecont_pending
            and offs2 >= 4
            and self.indirect_table[dword + 4:dword + 8] == b'\xFF\xFF\xFF\xFF'
        ):
            name_word += 2
        self._linecont_pending = False
        sub_name = _get_id(name_word, self.identifiers, self.vba_ver, self.is_64bit)
        arg_offset = _get_dword(self.indirect_table, dword + offs2 + 36, self.endian)
        ret_type = _get_dword(self.indirect_table, dword + offs2 + 40, self.endian)
        decl_offset = _get_word(self.indirect_table, dword + offs2 + 44, self.endian)
        c_options_offset = 60 if self.is_64bit else 54
        c_options = self.indirect_table[dword + offs2 + c_options_offset]
        new_flags_offset = 63 if self.is_64bit else 57
        new_flags = self.indirect_table[dword + offs2 + new_flags_offset]
        has_declare = False
        if self.vba_ver > 5:
            if (new_flags & 0x0002) == 0:
                func_decl += 'Private '
            elif op_type & 0x04:
                func_decl += 'Public '
            if new_flags & 0x0004:
                func_decl += 'Friend '
        else:
            if (flags & 0x0008) == 0:
                func_decl += 'Private '
            elif op_type & 0x04:
                func_decl += 'Public '
        if flags & 0x0080:
            func_decl += 'Static '
        if (
            (c_options & 0x90) == 0
            and (decl_offset != 0xFFFF)
        ):
            has_declare = True
            func_decl += 'Declare '
        if self.vba_ver > 5:
            if new_flags & 0x20:
                func_decl += 'PtrSafe '
        has_as = (flags & 0x0020) != 0
        if flags & 0x1000:
            if op_type in (2, 6):
                func_decl += 'Function '
            else:
                func_decl += 'Sub '
        elif flags & 0x2000:
            func_decl += 'Property Get '
        elif flags & 0x4000:
            func_decl += 'Property Let '
        elif flags & 0x8000:
            func_decl += 'Property Set '
        func_decl += sub_name
        if has_declare:
            lib_name = _get_name(
                self.declaration_table, self.identifiers, decl_offset + 2,
                self.endian, self.vba_ver, self.is_64bit)
            func_decl += F' Lib "{lib_name}" '
        arg_list: list[str] = []
        while (
            arg_offset != 0xFFFFFFFF
            and arg_offset != 0
            and arg_offset + 26 < len(self.indirect_table)
        ):
            arg_name = self.disasm_arg(arg_offset)
            if arg_name is not None:
                arg_list.append(arg_name)
            arg_offset = _get_dword(self.indirect_table, arg_offset + (24 if self.is_64bit else 20), self.endian)
        func_decl += F'({", ".join(arg_list)})'
        if has_as:
            func_decl += ' As '
            type_name = ''
            if (ret_type & 0xFFFF0000) == 0xFFFF0000:
                type_id = ret_type & 0x000000FF
                type_name = _get_type_name(type_id)
            else:
                type_name, _ = self.disasm_object(dword + offs2 + 40)
            func_decl += type_name
        func_decl += ')'
        return func_decl

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
    ) -> list[tuple[str, list[str]]]:
        """
        Disassemble one p-code line into a list of (mnemonic, [arg, ...]) tuples.
        """
        self._linecont_pending = False
        var_types_long = [
            'Var', '?', 'Int', 'Lng', 'Sng', 'Dbl', 'Cur', 'Date',
            'Str', 'Obj', 'Err', 'Bool', 'Var',
        ]
        specials = ['False', 'True', 'Null', 'Empty']
        options = [
            'Base 0', 'Base 1', 'Compare Text', 'Compare Binary',
            'Explicit', 'Private Module',
        ]

        result: list[tuple[str, list[str]]] = []
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
            parts: list[str] = []
            if mnemonic in ('Coerce', 'CoerceVar', 'DefType'):
                if op_type < len(var_types_long):
                    parts.append(F'({var_types_long[op_type]})')
                elif op_type == 17:
                    parts.append('(Byte)')
                else:
                    parts.append(F'({op_type:d})')
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
                    parts.append(F'({" ".join(dim_type)})')
            elif mnemonic == 'LitVarSpecial':
                parts.append(F'({specials[op_type]})')
            elif mnemonic in ('ArgsCall', 'ArgsMemCall', 'ArgsMemCallWith'):
                if op_type < 16:
                    parts.append('(Call)')
                else:
                    op_type -= 16
            elif mnemonic == 'Option':
                parts.append(F'({options[op_type]})')
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
                        parts.append(self.disasm_rec(dword))
                    elif (
                        arg == 'type_'
                        and len(self.indirect_table) >= dword + 7
                    ):
                        the_type = _disasm_type(self.indirect_table, dword)
                        parts.append(F'(As {the_type})')
                    elif (
                        arg == 'var_'
                        and len(self.indirect_table) >= dword + 16
                    ):
                        if op_type & 0x20:
                            parts.append('(WithEvents)')
                        parts.append(self.disasm_var(dword))
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
            offset += 77

        ctx = DisassemblyContext(
            indirect_table, object_table, declaration_table,
            identifiers, endian, vba_ver, is_64bit, codec)

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
                identifiers.append(ident)
                offset += id_length
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
