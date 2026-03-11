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

from struct import unpack_from
from typing import NamedTuple

from refinery.lib.ole.vba import _codepage_to_codec, _find_vba_projects, decompress_stream
from refinery.lib.ole.file import OleFile


class Opcode(NamedTuple):
    mnem: str
    args: list[str] = []
    varg: bool = False


# VBA7 opcodes; VBA3, VBA5 and VBA6 will be upconverted to these.
O = Opcode
OPCODES: dict[int, Opcode] = {
    0x000: O('Imp'),
    0x001: O('Eqv'),
    0x002: O('Xor'),
    0x003: O('Or'),
    0x004: O('And'),
    0x005: O('Eq'),
    0x006: O('Ne'),
    0x007: O('Le'),
    0x008: O('Ge'),
    0x009: O('Lt'),
    0x00A: O('Gt'),
    0x00B: O('Add'),
    0x00C: O('Sub'),
    0x00D: O('Mod'),
    0x00E: O('IDiv'),
    0x00F: O('Mul'),
    0x010: O('Div'),
    0x011: O('Concat'),
    0x012: O('Like'),
    0x013: O('Pwr'),
    0x014: O('Is'),
    0x015: O('Not'),
    0x016: O('UMi'),
    0x017: O('FnAbs'),
    0x018: O('FnFix'),
    0x019: O('FnInt'),
    0x01A: O('FnSgn'),
    0x01B: O('FnLen'),
    0x01C: O('FnLenB'),
    0x01D: O('Paren'),
    0x01E: O('Sharp'),
    0x01F: O('LdLHS', ['name']),
    0x020: O('Ld', ['name']),
    0x021: O('MemLd', ['name']),
    0x022: O('DictLd', ['name']),
    0x023: O('IndexLd', ['0x']),
    0x024: O('ArgsLd', ['name', '0x']),
    0x025: O('ArgsMemLd', ['name', '0x']),
    0x026: O('ArgsDictLd', ['name', '0x']),
    0x027: O('St', ['name']),
    0x028: O('MemSt', ['name']),
    0x029: O('DictSt', ['name']),
    0x02A: O('IndexSt', ['0x']),
    0x02B: O('ArgsSt', ['name', '0x']),
    0x02C: O('ArgsMemSt', ['name', '0x']),
    0x02D: O('ArgsDictSt', ['name', '0x']),
    0x02E: O('Set', ['name']),
    0x02F: O('Memset', ['name']),
    0x030: O('Dictset', ['name']),
    0x031: O('Indexset', ['0x']),
    0x032: O('ArgsSet', ['name', '0x']),
    0x033: O('ArgsMemSet', ['name', '0x']),
    0x034: O('ArgsDictSet', ['name', '0x']),
    0x035: O('MemLdWith', ['name']),
    0x036: O('DictLdWith', ['name']),
    0x037: O('ArgsMemLdWith', ['name', '0x']),
    0x038: O('ArgsDictLdWith', ['name', '0x']),
    0x039: O('MemStWith', ['name']),
    0x03A: O('DictStWith', ['name']),
    0x03B: O('ArgsMemStWith', ['name', '0x']),
    0x03C: O('ArgsDictStWith', ['name', '0x']),
    0x03D: O('MemSetWith', ['name']),
    0x03E: O('DictSetWith', ['name']),
    0x03F: O('ArgsMemSetWith', ['name', '0x']),
    0x040: O('ArgsDictSetWith', ['name', '0x']),
    0x041: O('ArgsCall', ['name', '0x']),
    0x042: O('ArgsMemCall', ['name', '0x']),
    0x043: O('ArgsMemCallWith', ['name', '0x']),
    0x044: O('ArgsArray', ['name', '0x']),
    0x045: O('Assert'),
    0x046: O('BoS', ['0x']),
    0x047: O('BoSImplicit'),
    0x048: O('BoL'),
    0x049: O('LdAddressOf', ['name']),
    0x04A: O('MemAddressOf', ['name']),
    0x04B: O('Case'),
    0x04C: O('CaseTo'),
    0x04D: O('CaseGt'),
    0x04E: O('CaseLt'),
    0x04F: O('CaseGe'),
    0x050: O('CaseLe'),
    0x051: O('CaseNe'),
    0x052: O('CaseEq'),
    0x053: O('CaseElse'),
    0x054: O('CaseDone'),
    0x055: O('Circle', ['0x']),
    0x056: O('Close', ['0x']),
    0x057: O('CloseAll'),
    0x058: O('Coerce'),
    0x059: O('CoerceVar'),
    0x05A: O('Context', ['context_']),
    0x05B: O('Debug'),
    0x05C: O('DefType', ['0x', '0x']),
    0x05D: O('Dim'),
    0x05E: O('DimImplicit'),
    0x05F: O('Do'),
    0x060: O('DoEvents'),
    0x061: O('DoUnitil'),
    0x062: O('DoWhile'),
    0x063: O('Else'),
    0x064: O('ElseBlock'),
    0x065: O('ElseIfBlock'),
    0x066: O('ElseIfTypeBlock', ['imp_']),
    0x067: O('End'),
    0x068: O('EndContext'),
    0x069: O('EndFunc'),
    0x06A: O('EndIf'),
    0x06B: O('EndIfBlock'),
    0x06C: O('EndImmediate'),
    0x06D: O('EndProp'),
    0x06E: O('EndSelect'),
    0x06F: O('EndSub'),
    0x070: O('EndType'),
    0x071: O('EndWith'),
    0x072: O('Erase', ['0x']),
    0x073: O('Error'),
    0x074: O('EventDecl', ['func_']),
    0x075: O('RaiseEvent', ['name', '0x']),
    0x076: O('ArgsMemRaiseEvent', ['name', '0x']),
    0x077: O('ArgsMemRaiseEventWith', ['name', '0x']),
    0x078: O('ExitDo'),
    0x079: O('ExitFor'),
    0x07A: O('ExitFunc'),
    0x07B: O('ExitProp'),
    0x07C: O('ExitSub'),
    0x07D: O('FnCurDir'),
    0x07E: O('FnDir'),
    0x07F: O('Empty0'),
    0x080: O('Empty1'),
    0x081: O('FnError'),
    0x082: O('FnFormat'),
    0x083: O('FnFreeFile'),
    0x084: O('FnInStr'),
    0x085: O('FnInStr3'),
    0x086: O('FnInStr4'),
    0x087: O('FnInStrB'),
    0x088: O('FnInStrB3'),
    0x089: O('FnInStrB4'),
    0x08A: O('FnLBound', ['0x']),
    0x08B: O('FnMid'),
    0x08C: O('FnMidB'),
    0x08D: O('FnStrComp'),
    0x08E: O('FnStrComp3'),
    0x08F: O('FnStringVar'),
    0x090: O('FnStringStr'),
    0x091: O('FnUBound', ['0x']),
    0x092: O('For'),
    0x093: O('ForEach'),
    0x094: O('ForEachAs', ['imp_']),
    0x095: O('ForStep'),
    0x096: O('FuncDefn', ['func_']),
    0x097: O('FuncDefnSave', ['func_']),
    0x098: O('GetRec'),
    0x099: O('GoSub', ['name']),
    0x09A: O('GoTo', ['name']),
    0x09B: O('If'),
    0x09C: O('IfBlock'),
    0x09D: O('TypeOf', ['imp_']),
    0x09E: O('IfTypeBlock', ['imp_']),
    0x09F: O('Implements', ['0x', '0x', '0x', '0x']),
    0x0A0: O('Input'),
    0x0A1: O('InputDone'),
    0x0A2: O('InputItem'),
    0x0A3: O('Label', ['name']),
    0x0A4: O('Let'),
    0x0A5: O('Line', ['0x']),
    0x0A6: O('LineCont', [], True),
    0x0A7: O('LineInput'),
    0x0A8: O('LineNum', ['name']),
    0x0A9: O('LitCy', ['0x', '0x', '0x', '0x']),
    0x0AA: O('LitDate', ['0x', '0x', '0x', '0x']),
    0x0AB: O('LitDefault'),
    0x0AC: O('LitDI2', ['0x']),
    0x0AD: O('LitDI4', ['0x', '0x']),
    0x0AE: O('LitDI8', ['0x', '0x', '0x', '0x']),
    0x0AF: O('LitHI2', ['0x']),
    0x0B0: O('LitHI4', ['0x', '0x']),
    0x0B1: O('LitHI8', ['0x', '0x', '0x', '0x']),
    0x0B2: O('LitNothing'),
    0x0B3: O('LitOI2', ['0x']),
    0x0B4: O('LitOI4', ['0x', '0x']),
    0x0B5: O('LitOI8', ['0x', '0x', '0x', '0x']),
    0x0B6: O('LitR4', ['0x', '0x']),
    0x0B7: O('LitR8', ['0x', '0x', '0x', '0x']),
    0x0B8: O('LitSmallI2'),
    0x0B9: O('LitStr', [], True),
    0x0BA: O('LitVarSpecial'),
    0x0BB: O('Lock'),
    0x0BC: O('Loop'),
    0x0BD: O('LoopUntil'),
    0x0BE: O('LoopWhile'),
    0x0BF: O('LSet'),
    0x0C0: O('Me'),
    0x0C1: O('MeImplicit'),
    0x0C2: O('MemRedim', ['name', '0x', 'type_']),
    0x0C3: O('MemRedimWith', ['name', '0x', 'type_']),
    0x0C4: O('MemRedimAs', ['name', '0x', 'type_']),
    0x0C5: O('MemRedimAsWith', ['name', '0x', 'type_']),
    0x0C6: O('Mid'),
    0x0C7: O('MidB'),
    0x0C8: O('Name'),
    0x0C9: O('New', ['imp_']),
    0x0CA: O('Next'),
    0x0CB: O('NextVar'),
    0x0CC: O('OnError', ['name']),
    0x0CD: O('OnGosub', [], True),
    0x0CE: O('OnGoto', [], True),
    0x0CF: O('Open', ['0x']),
    0x0D0: O('Option'),
    0x0D1: O('OptionBase'),
    0x0D2: O('ParamByVal'),
    0x0D3: O('ParamOmitted'),
    0x0D4: O('ParamNamed', ['name']),
    0x0D5: O('PrintChan'),
    0x0D6: O('PrintComma'),
    0x0D7: O('PrintEoS'),
    0x0D8: O('PrintItemComma'),
    0x0D9: O('PrintItemNL'),
    0x0DA: O('PrintItemSemi'),
    0x0DB: O('PrintNL'),
    0x0DC: O('PrintObj'),
    0x0DD: O('PrintSemi'),
    0x0DE: O('PrintSpc'),
    0x0DF: O('PrintTab'),
    0x0E0: O('PrintTabComma'),
    0x0E1: O('PSet', ['0x']),
    0x0E2: O('PutRec'),
    0x0E3: O('QuoteRem', ['0x'], True),
    0x0E4: O('Redim', ['name', '0x', 'type_']),
    0x0E5: O('RedimAs', ['name', '0x', 'type_']),
    0x0E6: O('Reparse', [], True),
    0x0E7: O('Rem', [], True),
    0x0E8: O('Resume', ['name']),
    0x0E9: O('Return'),
    0x0EA: O('RSet'),
    0x0EB: O('Scale', ['0x']),
    0x0EC: O('Seek'),
    0x0ED: O('SelectCase'),
    0x0EE: O('SelectIs', ['imp_']),
    0x0EF: O('SelectType'),
    0x0F0: O('SetStmt'),
    0x0F1: O('Stack', ['0x', '0x']),
    0x0F2: O('Stop'),
    0x0F3: O('Type', ['rec_']),
    0x0F4: O('Unlock'),
    0x0F5: O('VarDefn', ['var_']),
    0x0F6: O('Wend'),
    0x0F7: O('While'),
    0x0F8: O('With'),
    0x0F9: O('WriteChan'),
    0x0FA: O('ConstFuncExpr'),
    0x0FB: O('LbConst', ['name']),
    0x0FC: O('LbIf'),
    0x0FD: O('LbElse'),
    0x0FE: O('LbElseIf'),
    0x0FF: O('LbEndIf'),
    0x100: O('LbMark'),
    0x101: O('EndForVariable'),
    0x102: O('StartForVariable'),
    0x103: O('NewRedim'),
    0x104: O('StartWithExpr'),
    0x105: O('SetOrSt', ['name']),
    0x106: O('EndEnum'),
    0x107: O('Illegal'),
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


def _disasm_name(
    word: int,
    identifiers: list[str],
    mnemonic: str,
    op_type: int,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    var_types = [
        '', '?', '%', '&', '!', '#', '@', '?', '$', '?', '?', '?', '?', '?',
    ]
    var_name = _get_id(word, identifiers, vba_ver, is_64bit)
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
    return var_name + str_type + ' '


def _disasm_imp(
    object_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    arg: str,
    word: int,
    mnemonic: str,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    if mnemonic != 'Open':
        if arg == 'imp_' and (len(object_table) >= word + 8):
            return _get_name(object_table, identifiers, word + 6, endian, vba_ver, is_64bit)
        else:
            return F'{arg}{word:04X} '
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


def _disasm_rec(
    indirect_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    dword: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    object_name = _get_name(indirect_table, identifiers, dword + 2, endian, vba_ver, is_64bit)
    options = _get_word(indirect_table, dword + 18, endian)
    if (options & 1) == 0:
        object_name = F'(Private) {object_name}'
    return object_name


def _get_type_name(type_id: int) -> str:
    dim_types = [
        '', 'Null', 'Integer', 'Long', 'Single', 'Double', 'Currency',
        'Date', 'String', 'Object', 'Error', 'Boolean', 'Variant', '',
        'Decimal', '', '', 'Byte',
    ]
    type_flags = type_id & 0xE0
    type_id &= ~0xE0
    if type_id < len(dim_types):
        type_name = dim_types[type_id]
    else:
        type_name = ''
    if type_flags & 0x80:
        type_name += 'Ptr'
    return type_name


def _disasm_type(
    indirect_table: bytes | bytearray | memoryview,
    dword: int,
) -> str:
    dim_types = [
        '',
        'Null',
        'Integer',
        'Long',
        'Single',
        'Double',
        'Currency',
        'Date',
        'String',
        'Object',
        'Error',
        'Boolean',
        'Variant',
        '',
        'Decimal',
        '',
        '',
        'Byte',
    ]
    type_id = indirect_table[dword + 6]
    if type_id < len(dim_types):
        return dim_types[type_id]
    else:
        return F'type_{dword:08X}'


def _disasm_object(
    indirect_table: bytes | bytearray | memoryview,
    object_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    offset: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    if is_64bit:
        return ''
    type_desc = _get_dword(indirect_table, offset, endian)
    flags = _get_word(indirect_table, type_desc, endian)
    if flags & 0x02:
        return _disasm_type(indirect_table, type_desc)
    word = _get_word(indirect_table, type_desc + 2, endian)
    if word == 0:
        return ''
    offs = (word >> 2) * 10
    if offs + 4 > len(object_table):
        return ''
    hl_name = _get_word(object_table, offs + 6, endian)
    return _get_id(hl_name, identifiers, vba_ver, is_64bit)


def _disasm_var(
    indirect_table: bytes | bytearray | memoryview,
    object_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    dword: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    b_flag1 = indirect_table[dword]
    b_flag2 = indirect_table[dword + 1]
    has_as = (b_flag1 & 0x20) != 0
    has_new = (b_flag2 & 0x20) != 0
    var_name = _get_name(indirect_table, identifiers, dword + 2, endian, vba_ver, is_64bit)
    if has_new or has_as:
        var_type = ''
        if has_new:
            var_type += 'New'
            if has_as:
                var_type += ' '
        if has_as:
            offs = 16 if is_64bit else 12
            word = _get_word(indirect_table, dword + offs + 2, endian)
            if word == 0xFFFF:
                type_id = indirect_table[dword + offs]
                type_name = _get_type_name(type_id)
            else:
                type_name = _disasm_object(
                    indirect_table, object_table, identifiers,
                    dword + offs, endian, vba_ver, is_64bit)
            if len(type_name) > 0:
                var_type += F'As {type_name}'
        if len(var_type) > 0:
            var_name += F' ({var_type})'
    return var_name


def _disasm_arg(
    indirect_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    arg_offset: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    flags = _get_word(indirect_table, arg_offset, endian)
    offs = 4 if is_64bit else 0
    arg_name = _get_name(indirect_table, identifiers, arg_offset + 2, endian, vba_ver, is_64bit)
    arg_type = _get_dword(indirect_table, arg_offset + offs + 12, endian)
    arg_opts = _get_word(indirect_table, arg_offset + offs + 24, endian)
    if arg_opts & 0x0004:
        arg_name = F'ByVal {arg_name}'
    if arg_opts & 0x0002:
        arg_name = F'ByRef {arg_name}'
    if arg_opts & 0x0200:
        arg_name = F'Optional {arg_name}'
    if flags & 0x0020:
        arg_name += ' As '
        arg_type_name = ''
        if arg_type & 0xFFFF0000:
            arg_type_id = arg_type & 0x000000FF
            arg_type_name = _get_type_name(arg_type_id)
        arg_name += arg_type_name
    return arg_name


def _disasm_func(
    indirect_table: bytes | bytearray | memoryview,
    declaration_table: bytes | bytearray | memoryview,
    identifiers: list[str],
    dword: int,
    op_type: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
) -> str:
    func_decl = '('
    flags = _get_word(indirect_table, dword, endian)
    sub_name = _get_name(indirect_table, identifiers, dword + 2, endian, vba_ver, is_64bit)
    offs2 = 4 if vba_ver > 5 else 0
    if is_64bit:
        offs2 += 16
    arg_offset = _get_dword(indirect_table, dword + offs2 + 36, endian)
    ret_type = _get_dword(indirect_table, dword + offs2 + 40, endian)
    decl_offset = _get_word(indirect_table, dword + offs2 + 44, endian)
    c_options = indirect_table[dword + offs2 + 54]
    new_flags = indirect_table[dword + offs2 + 57]
    has_declare = False
    if vba_ver > 5:
        if ((new_flags & 0x0002) == 0) and not is_64bit:
            func_decl += 'Private '
        if new_flags & 0x0004:
            func_decl += 'Friend '
    else:
        if (flags & 0x0008) == 0:
            func_decl += 'Private '
    if op_type & 0x04:
        func_decl += 'Public '
    if flags & 0x0080:
        func_decl += 'Static '
    if (
        (c_options & 0x90) == 0
        and (decl_offset != 0xFFFF)
        and not is_64bit
    ):
        has_declare = True
        func_decl += 'Declare '
    if vba_ver > 5:
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
            declaration_table, identifiers, decl_offset + 2,
            endian, vba_ver, is_64bit)
        func_decl += F' Lib "{lib_name}" '
    arg_list: list[str] = []
    while (
        arg_offset != 0xFFFFFFFF
        and arg_offset != 0
        and arg_offset + 26 < len(indirect_table)
    ):
        arg_name = _disasm_arg(
            indirect_table, identifiers, arg_offset,
            endian, vba_ver, is_64bit)
        arg_list.append(arg_name)
        arg_offset = _get_dword(indirect_table, arg_offset + 20, endian)
    func_decl += F'({", ".join(arg_list)})'
    if has_as:
        func_decl += ' As '
        type_name = ''
        if (ret_type & 0xFFFF0000) == 0xFFFF0000:
            type_id = ret_type & 0x000000FF
            type_name = _get_type_name(type_id)
        else:
            type_name = _get_name(
                indirect_table, identifiers, ret_type + 6,
                endian, vba_ver, is_64bit)
        func_decl += type_name
    func_decl += ')'
    return func_decl


def _disasm_var_arg(
    module_data: bytes | bytearray | memoryview,
    identifiers: list[str],
    offset: int,
    w_length: int,
    mnemonic: str,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
    codec: str,
) -> str:
    substring = module_data[offset:offset + w_length]
    var_arg_name = F'0x{w_length:04X} '
    if mnemonic in ('LitStr', 'QuoteRem', 'Rem', 'Reparse'):
        var_arg_name += F'"{codecs.decode(substring, codec, "replace")}"'
    elif mnemonic in ('OnGosub', 'OnGoto'):
        offset1 = offset
        names: list[str] = []
        for _ in range(w_length // 2):
            offset1, word = _get_var(module_data, offset1, endian, False)
            names.append(_get_id(word, identifiers, vba_ver, is_64bit))
        var_arg_name += ', '.join(names) + ' '
    else:
        hex_dump = ' '.join(F'{c:02X}' for c in substring)
        var_arg_name += hex_dump
    return var_arg_name


def _dump_line(
    module_data: bytes | bytearray | memoryview,
    line_start: int,
    line_length: int,
    endian: str,
    vba_ver: int,
    is_64bit: bool,
    identifiers: list[str],
    object_table: bytes | bytearray | memoryview,
    indirect_table: bytes | bytearray | memoryview,
    declaration_table: bytes | bytearray | memoryview,
    line: int,
    codec: str,
    output: list[str],
) -> None:
    var_types_long = [
        'Var', '?', 'Int', 'Lng', 'Sng', 'Dbl', 'Cur', 'Date',
        'Str', 'Obj', 'Err', 'Bool', 'Var',
    ]
    specials = ['False', 'True', 'Null', 'Empty']
    options = [
        'Base 0', 'Base 1', 'Compare Text', 'Compare Binary',
        'Explicit', 'Private Module',
    ]

    output.append(F'Line #{line:d}:')
    if line_length <= 0:
        return
    offset = line_start
    end_of_line = line_start + line_length
    while offset < end_of_line:
        offset, opcode = _get_var(module_data, offset, endian, False)
        op_type = (opcode & ~0x03FF) >> 10
        opcode &= 0x03FF
        translated = _translate_opcode(opcode, vba_ver, is_64bit)
        if translated not in OPCODES:
            output.append(F'\tUnrecognized opcode 0x{opcode:04X} at offset 0x{offset:08X}.')
            return
        instruction = OPCODES[translated]
        mnemonic = instruction.mnem
        parts: list[str] = ['\t', F'{mnemonic} ']
        if mnemonic in ('Coerce', 'CoerceVar', 'DefType'):
            if op_type < len(var_types_long):
                parts.append(F'({var_types_long[op_type]}) ')
            elif op_type == 17:
                parts.append('(Byte) ')
            else:
                parts.append(F'({op_type:d}) ')
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
                parts.append(F'({" ".join(dim_type)}) ')
        elif mnemonic == 'LitVarSpecial':
            parts.append(F'({specials[op_type]})')
        elif mnemonic in ('ArgsCall', 'ArgsMemCall', 'ArgsMemCallWith'):
            if op_type < 16:
                parts.append('(Call) ')
            else:
                op_type -= 16
        elif mnemonic == 'Option':
            parts.append(F' ({options[op_type]})')
        elif mnemonic in ('Redim', 'RedimAs'):
            if op_type & 16:
                parts.append('(Preserve) ')
        for arg in instruction.args:
            if arg == 'name':
                offset, word = _get_var(module_data, offset, endian, False)
                the_name = _disasm_name(word, identifiers, mnemonic, op_type, vba_ver, is_64bit)
                parts.append(the_name)
            elif arg in ('0x', 'imp_'):
                offset, word = _get_var(module_data, offset, endian, False)
                the_imp = _disasm_imp(
                    object_table, identifiers, arg, word, mnemonic, endian, vba_ver, is_64bit)
                parts.append(the_imp)
            elif arg in ('func_', 'var_', 'rec_', 'type_', 'context_'):
                offset, dword = _get_var(module_data, offset, endian, True)
                if (
                    arg == 'rec_'
                    and len(indirect_table) >= dword + 20
                ):
                    the_rec = _disasm_rec(
                        indirect_table, identifiers,
                        dword, endian, vba_ver, is_64bit)
                    parts.append(the_rec)
                elif (
                    arg == 'type_'
                    and len(indirect_table) >= dword + 7
                ):
                    the_type = _disasm_type(indirect_table, dword)
                    parts.append(F'(As {the_type})')
                elif (
                    arg == 'var_'
                    and len(indirect_table) >= dword + 16
                ):
                    if op_type & 0x20:
                        parts.append('(WithEvents) ')
                    the_var = _disasm_var(
                        indirect_table, object_table, identifiers,
                        dword, endian, vba_ver, is_64bit)
                    parts.append(the_var)
                    if op_type & 0x10:
                        word = _get_word(module_data, offset, endian)
                        offset += 2
                        parts.append(F' 0x{word:04X}')
                elif (
                    arg == 'func_'
                    and len(indirect_table) >= dword + 61
                ):
                    the_func = _disasm_func(
                        indirect_table, declaration_table, identifiers, dword, op_type,
                        endian, vba_ver, is_64bit)
                    parts.append(the_func)
                else:
                    parts.append(F'{arg}{dword:08X} ')
                if is_64bit and (arg == 'context_'):
                    offset, dword = _get_var(module_data, offset, endian, True)
                    parts.append(F'{dword:08X} ')
        if instruction.varg:
            offset, w_length = _get_var(module_data, offset, endian, False)
            the_var_arg = _disasm_var_arg(
                module_data, identifiers, offset, w_length,
                mnemonic, endian, vba_ver, is_64bit, codec)
            parts.append(the_var_arg)
            offset += w_length
            if w_length & 1:
                offset += 1
        output.append(''.join(parts))


def _pcode_dump(
    module_data: bytes | bytearray | memoryview,
    vba_project_data: bytes | bytearray | memoryview,
    identifiers: list[str],
    is_64bit: bool,
    codec: str,
    output: list[str],
) -> None:
    """
    Disassemble p-code from a VBA module stream.
    """
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
                dw_length = _get_dword(module_data, 0x0043, endian)
                declaration_table = module_data[0x0047:0x0047 + dw_length]
                dw_length = _get_dword(module_data, 0x0011, endian)
                table_start = dw_length + 12
            else:
                dw_length = _get_dword(module_data, 0x003F, endian)
                declaration_table = module_data[0x0043:0x0043 + dw_length]
                dw_length = _get_dword(module_data, 0x0011, endian)
                table_start = dw_length + 10
            dw_length = _get_dword(module_data, table_start, endian)
            table_start += 4
            indirect_table = module_data[
                table_start:table_start + dw_length]
            dw_length = _get_dword(module_data, 0x0005, endian)
            dw_length2 = dw_length + 0x8A
            dw_length = _get_dword(module_data, dw_length2, endian)
            dw_length2 += 4
            object_table = module_data[
                dw_length2:dw_length2 + dw_length]
            offset = 0x0019
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
            offs = dw_length + 0x008A
            dw_length = _get_dword(module_data, offs, endian)
            offs += 4
            object_table = module_data[offs:offs + dw_length]
            offset += 77
        dw_length = _get_dword(module_data, offset, endian)
        offset = dw_length + 0x003C
        offset, magic = _get_var(module_data, offset, endian, False)
        if magic != 0xCAFE:
            return
        offset += 2
        offset, num_lines = _get_var(module_data, offset, endian, False)
        pcode_start = offset + num_lines * 12 + 10
        for line_num in range(num_lines):
            offset += 4
            offset, line_length = _get_var(module_data, offset, endian, False)
            offset += 2
            offset, line_offset = _get_var(module_data, offset, endian, True)
            _dump_line(
                module_data, pcode_start + line_offset, line_length,
                endian, vba_ver, is_64bit, identifiers,
                object_table, indirect_table, declaration_table,
                line_num, codec, output)
    except Exception:
        pass


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
            or (0x5F > version > 0x6B)
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
            else:
                if ((unicode_ref and (ref_length < 5))
                    or ((not unicode_ref) and (ref_length < 3))
                ):
                    offset += ref_length
                else:
                    if unicode_ref:
                        c = vba_project_data[offset + 4]
                    else:
                        c = vba_project_data[offset + 2]
                    offset += ref_length
                    if chr(c) in ('C', 'D'):
                        offset = _skip_structure(
                            vba_project_data, offset,
                            endian, False, 1, False)
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
                ident = codecs.decode(vba_project_data[offset:offset + id_length], codec, 'replace')
                identifiers.append(ident)
                offset += id_length
            if not is_kwd:
                offset += 4
    except Exception:
        pass
    return identifiers


class PCodeDisassembler:
    """
    VBA p-code disassembler that produces pcodedmp-compatible text output. The output is suitable
    for consumption by pcode2code for decompilation back to VBA source code.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self._data = data

    def iter_modules(self) -> Iterator[tuple[str, str]]:
        """
        Yield (module_path, pcodedmp_text) for each VBA module.
        """
        for ole_data in self._get_ole_streams():
            ole = OleFile(ole_data)
            yield from self._iter_project_modules(ole)

    def _iter_project_modules(
        self,
        ole: OleFile,
    ):
        """
        Iterate over VBA modules in an OLE file, yielding (module_path, pcodedmp_text) per module.
        """
        vba_projects = _find_vba_projects(ole)
        if not vba_projects:
            return
        for vba_root, _, dir_path in vba_projects:
            codec, code_modules, is_64bit = self._process_dir(ole, dir_path)
            vba_project_path = vba_root + 'VBA/_VBA_PROJECT'
            vba_project_data = self._process_vba_project(ole, vba_project_path)
            identifiers = _get_identifiers(vba_project_data, codec)
            for module in code_modules:
                module_path = F'{vba_root}VBA/{module}'
                try:
                    module_data = ole.openstream(module_path).read()
                except Exception:
                    continue
                output: list[str] = []
                output.append(F'{module_path} - {len(module_data):d} bytes')
                _pcode_dump(module_data, vba_project_data, identifiers, is_64bit, codec, output)
                yield module_path, '\n'.join(output) + '\n'

    def disassemble(self) -> str:
        """
        Disassemble VBA p-code from the document and return pcodedmp-format text output. Supports
        both OLE compound files and OOXML (ZIP) documents containing vbaProject.bin.
        """
        output: list[str] = []
        for ole_data in self._get_ole_streams():
            ole = OleFile(ole_data)
            self._process_project(ole, output)
        return '\n'.join(output) + '\n' if output else ''

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

    def _process_project(
        self,
        ole: OleFile,
        output: list[str],
    ) -> None:
        """
        Process all VBA projects found in the OLE file.
        """
        vba_projects = _find_vba_projects(ole)
        if not vba_projects:
            return
        for vba_root, project_path, dir_path in vba_projects:
            output.append('=' * 79)
            codec, code_modules, is_64bit = self._process_dir(ole, dir_path)
            vba_project_path = vba_root + 'VBA/_VBA_PROJECT'
            vba_project_data = self._process_vba_project(ole, vba_project_path)
            identifiers = _get_identifiers(vba_project_data, codec)
            output.append('Module streams:')
            for module in code_modules:
                module_path = F'{vba_root}VBA/{module}'
                try:
                    module_data = ole.openstream(module_path).read()
                except Exception:
                    continue
                output.append(F'{module_path} - {len(module_data):d} bytes')
                _pcode_dump(module_data, vba_project_data, identifiers, is_64bit, codec, output)

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
