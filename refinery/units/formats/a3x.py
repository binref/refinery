from __future__ import annotations

import io
import math
import struct

from enum import Enum
from typing import Generator, Iterable, NamedTuple

from refinery.lib.id import buffer_contains
from refinery.lib.structures import MemoryFile, Struct, StructReader, StructReaderBits
from refinery.lib.tools import date_from_timestamp
from refinery.units.formats import PathExtractorUnit, UnpackResult

A3X_KEYWORDS = [
    '',
    'And',
    'Or',
    'Not',
    'If',
    'Then',
    'Else',
    'ElseIf',
    'EndIf',
    'While',
    'Wend',
    'Do',
    'Until',
    'For',
    'Next',
    'To',
    'Step',
    'In',
    'ExitLoop',
    'ContinueLoop',
    'Select',
    'Case',
    'EndSelect',
    'Switch',
    'EndSwitch',
    'ContinueCase',
    'Dim',
    'ReDim',
    'Local',
    'Global',
    'Const',
    'Static',
    'Func',
    'EndFunc',
    'Return',
    'Exit',
    'ByRef',
    'With',
    'EndWith',
    'True',
    'False',
    'Default',
    'Null',
    'Volatile',
    'Enum',
]

A3X_APICALLS = [
    'Abs',
    'Acos',
    'AdlibRegister',
    'AdlibUnRegister',
    'Asc',
    'AscW',
    'ASin',
    'Assign',
    'ATan',
    'AutoItSetOption',
    'AutoItWinGetTitle',
    'AutoItWinSetTitle',
    'Beep',
    'Binary',
    'BinaryLen',
    'BinaryMid',
    'BinaryToString',
    'BitAnd',
    'BitNot',
    'BitOR',
    'BitRotate',
    'BitShift',
    'BitXOR',
    'BlockInput',
    'Break',
    'Call',
    'CDTray',
    'Ceiling',
    'Chr',
    'ChrW',
    'ClipGet',
    'ClipPut',
    'ConsoleRead',
    'ConsoleWrite',
    'ConsoleWriteError',
    'ControlClick',
    'ControlCommand',
    'ControlDisable',
    'ControlEnable',
    'ControlFocus',
    'ControlGetFocus',
    'ControlGetHandle',
    'ControlGetPos',
    'ControlGetText',
    'ControlHide',
    'ControlListView',
    'ControlMove',
    'ControlSend',
    'ControlSetText',
    'ControlShow',
    'ControlTreeView',
    'Cos',
    'Dec',
    'DirCopy',
    'DirCreate',
    'DirGetSize',
    'DirMove',
    'DirRemove',
    'DllCall',
    'DllCallAddress',
    'DllCallbackFree',
    'DllCallbackGetPtr',
    'DllCallbackRegister',
    'DllClose',
    'DllOpen',
    'DllStructCreate',
    'DllStructGetData',
    'DllStructGetPtr',
    'DllStructGetSize',
    'DllStructSetData',
    'DriveGetDrive',
    'DriveGetFilesystem',
    'DriveGetLabel',
    'DriveGetSerial',
    'DriveGetType',
    'DriveMapAdd',
    'DriveMapDel',
    'DriveMapGet',
    'DriveSetLabel',
    'DriveSpaceFree',
    'DriveSpaceTotal',
    'DriveStatus',
    'DummySpeedTest',
    'EnvGet',
    'EnvSet',
    'EnvUpdate',
    'Eval',
    'Execute',
    'Exp',
    'FileChangeDir',
    'FileClose',
    'FileCopy',
    'FileCreateNTFSLink',
    'FileCreateShortcut',
    'FileDelete',
    'FileExists',
    'FileFindFirstFile',
    'FileFindNextFile',
    'FileFlush',
    'FileGetAttrib',
    'FileGetEncoding',
    'FileGetLongName',
    'FileGetPos',
    'FileGetShortcut',
    'FileGetShortName',
    'FileGetSize',
    'FileGetTime',
    'FileGetVersion',
    'FileInstall',
    'FileMove',
    'FileOpen',
    'FileOpenDialog',
    'FileRead',
    'FileReadLine',
    'FileReadToArray',
    'FileRecycle',
    'FileRecycleEmpty',
    'FileSaveDialog',
    'FileSelectFolder',
    'FileSetAttrib',
    'FileSetEnd',
    'FileSetPos',
    'FileSetTime',
    'FileWrite',
    'FileWriteLine',
    'Floor',
    'FtpSetProxy',
    'Funcname',
    'GUICreate',
    'GUICtrlCreateAvi',
    'GUICtrlCreateButton',
    'GUICtrlCreateCheckbox',
    'GUICtrlCreateCombo',
    'GUICtrlCreateContextMenu',
    'GUICtrlCreateDate',
    'GUICtrlCreateDummy',
    'GUICtrlCreateEdit',
    'GUICtrlCreateGraphic',
    'GUICtrlCreateGroup',
    'GUICtrlCreateIcon',
    'GUICtrlCreateInput',
    'GUICtrlCreateLabel',
    'GUICtrlCreateList',
    'GUICtrlCreateListView',
    'GUICtrlCreateListViewItem',
    'GUICtrlCreateMenu',
    'GUICtrlCreateMenuItem',
    'GUICtrlCreateMonthCal',
    'GUICtrlCreateObj',
    'GUICtrlCreatePic',
    'GUICtrlCreateProgress',
    'GUICtrlCreateRadio',
    'GUICtrlCreateSlider',
    'GUICtrlCreateTab',
    'GUICtrlCreateTabItem',
    'GUICtrlCreateTreeView',
    'GUICtrlCreateTreeViewItem',
    'GUICtrlCreateUpdown',
    'GUICtrlDelete',
    'GUICtrlGetHandle',
    'GUICtrlGetState',
    'GUICtrlRead',
    'GUICtrlRecvMsg',
    'GUICtrlRegisterListViewSort',
    'GUICtrlSendMsg',
    'GUICtrlSendToDummy',
    'GUICtrlSetBkColor',
    'GUICtrlSetColor',
    'GUICtrlSetCursor',
    'GUICtrlSetData',
    'GUICtrlSetDefBkColor',
    'GUICtrlSetDefColor',
    'GUICtrlSetFont',
    'GUICtrlSetGraphic',
    'GUICtrlSetImage',
    'GUICtrlSetLimit',
    'GUICtrlSetOnEvent',
    'GUICtrlSetPos',
    'GUICtrlSetResizing',
    'GUICtrlSetState',
    'GUICtrlSetStyle',
    'GUICtrlSetTip',
    'GUIDelete',
    'GUIGetCursorInfo',
    'GUIGetMsg',
    'GUIGetStyle',
    'GUIRegisterMsg',
    'GUISetAccelerators',
    'GUISetBkColor',
    'GUISetCoord',
    'GUISetCursor',
    'GUISetFont',
    'GUISetHelp',
    'GUISetIcon',
    'GUISetOnEvent',
    'GUISetState',
    'GUISetStyle',
    'GUIStartGroup',
    'GUISwitch',
    'Hex',
    'HotKeySet',
    'HttpSetProxy',
    'HttpSetUserAgent',
    'Hwnd',
    'InetClose',
    'InetGet',
    'InetGetInfo',
    'InetGetSize',
    'InetRead',
    'IniDelete',
    'IniRead',
    'IniReadSection',
    'IniReadSectionNames',
    'IniRenameSection',
    'IniWrite',
    'IniWriteSection',
    'InputBox',
    'Int',
    'IsAdmin',
    'IsArray',
    'IsBinary',
    'IsBool',
    'IsDeclared',
    'IsDllStruct',
    'IsFloat',
    'IsFunc',
    'IsHwnd',
    'IsInt',
    'IsKeyword',
    'IsMap',
    'IsNumber',
    'IsObj',
    'IsPtr',
    'IsString',
    'Log',
    'MapAppend',
    'MapExists',
    'MapKeys',
    'MapRemove',
    'MemGetStats',
    'Mod',
    'MouseClick',
    'MouseClickDrag',
    'MouseDown',
    'MouseGetCursor',
    'MouseGetPos',
    'MouseMove',
    'MouseUp',
    'MouseWheel',
    'MsgBox',
    'Number',
    'ObjCreate',
    'ObjCreateInterface',
    'ObjEvent',
    'ObjGet',
    'ObjName',
    'OnAutoItExitRegister',
    'OnAutoItExitUnRegister',
    'Opt',
    'Ping',
    'PixelChecksum',
    'PixelGetColor',
    'PixelSearch',
    'ProcessClose',
    'ProcessExists',
    'ProcessGetStats',
    'ProcessList',
    'ProcessSetPriority',
    'ProcessWait',
    'ProcessWaitClose',
    'ProgressOff',
    'Progresson',
    'ProgressSet',
    'Ptr',
    'Random',
    'RegDelete',
    'RegEnumKey',
    'RegEnumVal',
    'RegRead',
    'RegWrite',
    'Round',
    'Run',
    'RunAs',
    'RunAsWait',
    'RunWait',
    'Send',
    'SendKeepActive',
    'SetError',
    'SetExtended',
    'ShellExecute',
    'ShellExecuteWait',
    'Shutdown',
    'Sin',
    'Sleep',
    'SoundPlay',
    'SoundSetWaveVolume',
    'SplashImageOn',
    'SplashOff',
    'SplashTextOn',
    'Sqrt',
    'SRandom',
    'StatusBarGetText',
    'StderrRead',
    'StdinWrite',
    'StdioClose',
    'StdoutRead',
    'String',
    'StringAddCR',
    'StringCompare',
    'StringFormat',
    'StringFromASCIIArray',
    'StringInStr',
    'StringIsAlNum',
    'StringIsAlpha',
    'StringIsASCII',
    'StringIsDigit',
    'StringIsFloat',
    'StringIsInt',
    'StringIsLower',
    'StringIsSpace',
    'StringIsUpper',
    'StringIsXDigit',
    'StringLeft',
    'StringLen',
    'StringLower',
    'StringMid',
    'StringRegExp',
    'StringRegExpReplace',
    'StringReplace',
    'StringReverse',
    'StringRight',
    'StringSplit',
    'StringStripCR',
    'StringStripWS',
    'StringToASCIIArray',
    'StringToBinary',
    'StringTrimLeft',
    'StringTrimRight',
    'StringUpper',
    'Tan',
    'TCPAccept',
    'TCPCloseSocket',
    'TCPConnect',
    'TCPListen',
    'TCPNameToIP',
    'TCPRecv',
    'TCPSend',
    'TCPShutdown',
    'TCPStartup',
    'TimerDiff',
    'TimerInit',
    'ToolTip',
    'TrayCreateItem',
    'TrayCreateMenu',
    'TrayGetMsg',
    'TrayItemDelete',
    'TrayItemGetHandle',
    'TrayItemGetState',
    'TrayItemGetText',
    'TrayItemSetOnEvent',
    'TrayItemSetState',
    'TrayItemSetText',
    'TraySetClick',
    'TraySetIcon',
    'TraySetOnEvent',
    'TraySetPauseIcon',
    'TraySetState',
    'TraySetToolTip',
    'TrayTip',
    'UBound',
    'UDPBind',
    'UDPCloseSocket',
    'UDPOpen',
    'UDPRecv',
    'UDPSend',
    'UDPShutdown',
    'UDPStartup',
    'VarGetType',
    'WinActivate',
    'WinActive',
    'WinClose',
    'WinExists',
    'WinFlash',
    'WinGetCaretPos',
    'WinGetClassList',
    'WinGetClientSize',
    'WinGetHandle',
    'WinGetPos',
    'WinGetProcess',
    'WinGetState',
    'WinGetText',
    'WinGetTitle',
    'WinKill',
    'WinList',
    'WinMenuSelectItem',
    'WinMinimizeAll',
    'WinMinimizeAllUndo',
    'WinMove',
    'WinSetOnTop',
    'WinSetState',
    'WinSetTitle',
    'WinSetTrans',
    'WinWait',
    'WinWaitActive',
    'WinWaitClose',
    'WinWaitNotActive',
]

A3X_OPCODES = {
    0x00: R'{k}',  # KEYWORD
    0x01: R'{a}',  # API
    0x05: R'{i}',  # INT
    0x10: R'{q}',  # INT64
    0x20: R'{d}',  # DOUBLE
    0x30: R'{s}',  # CONSTRUCT
    0x31: R'{s}',  # COMMAND
    0x32: '@{s}',  # MACRO
    0x33: '${s}',  # VAR
    0x34: R'{s}',  # FUNC
    0x35: '.{s}',  # OBJECT
    0x36: R'{r}',  # STRING
    0x37: R'{s}',  # DIRECTIVE
    0x40: ',',
    0x41: '=',
    0x42: '>',
    0x43: '<',
    0x44: '<>',
    0x45: '>=',
    0x46: '<=',
    0x47: '(',
    0x48: ')',
    0x49: '+',
    0x4a: '-',
    0x4b: '/',
    0x4c: '*',
    0x4d: '&',
    0x4e: '[',
    0x4f: ']',
    0x50: '==',
    0x51: '^',
    0x52: '+=',
    0x53: '-=',
    0x54: '/=',
    0x55: '*=',
    0x56: '&=',
    0x57: '?',
    0x58: ':',
}

_PRETTY: dict[str, str] = {}
_PRETTY.update((name.lower(), name) for name in A3X_APICALLS)
_PRETTY.update((name.lower(), name) for name in A3X_KEYWORDS)


def a3x_number_representation(value: float | int) -> str:
    """
    The AutoIt3 compiler will emit constants for -inf/inf/nan. However, AutoIt3 itself has no
    keywords for these values; The output of this function is valid AutoIt3 code that will
    produce these constants.

    https://www.autoitscript.com/autoit3/docs/functions/Dec.htm
    """
    if isinstance(value, int):
        return str(value)
    elif math.isnan(value) or math.isinf(value):
        rep = struct.pack('>d', value).hex().upper()
        return RF'Dec("{rep}", 3)'
    else:
        return RF'{value!s}'


def a3x_decompile(bytecode: bytearray | memoryview) -> Generator[tuple[int, str]]:
    class _decompiler(dict):
        def __missing__(self, key):
            if key == 's':
                string = reader.read_length_prefixed_string()
                return _PRETTY.get(string.lower(), string)
            elif key == 'r':
                string = reader.read_length_prefixed_string()
                return '"{}"'.format(string.replace('"', '""'))
            elif key == 'k':
                return A3X_KEYWORDS[reader.u32()]
            elif key == 'a':
                return A3X_APICALLS[reader.u32()]
            elif key == 'i':
                number = reader.i32()
            elif key == 'q':
                number = reader.i64()
            elif key == 'd':
                number = reader.f64()
            else:
                raise KeyError(key)
            if number < 0 and tokens and tokens[~0] == '+':
                number = -number
                tokens[~0] = '-'
            return a3x_number_representation(number)

    decompiler = _decompiler()
    reader = A3xReader(memoryview(bytecode))
    num_lines = reader.u32()
    tokens: list[str] = []
    expected_terminators: list[str] = []
    line = 0

    while line < num_lines and not reader.eof:
        opc = reader.u8()
        if opc == 0x7f:
            if not tokens:
                continue
            indent = len(expected_terminators)
            lt = [t.lower() for t in tokens]
            if lt[0] == 'if' and lt[~0] == 'then':
                expected_terminators.append('endif')
            elif lt[0] == 'else':
                if not expected_terminators or expected_terminators[~0] != 'endif':
                    raise ValueError(F'Unexpected {tokens[0]} in line {line}.')
                indent -= 1
            elif lt[0] == 'case':
                if not expected_terminators or not expected_terminators[~0].startswith('ends'):
                    raise ValueError(F'Unexpected {tokens[0]} in line {line}.')
                indent -= 1
            elif lt[0] == 'while':
                expected_terminators.append('wend')
            elif lt[0] == 'do':
                expected_terminators.append('until')
            elif lt[0] == 'for':
                expected_terminators.append('next')
            elif lt[0] == 'select':
                expected_terminators.append('endselect')
            elif lt[0] == 'switch':
                expected_terminators.append('endswitch')
            elif lt[0] == 'func':
                expected_terminators.append('endfunc')
            elif lt[0] == 'with':
                expected_terminators.append('endwith')
            elif lt[0].startswith('end') or lt[0] in {'next', 'until', 'wend'}:
                try:
                    expected = expected_terminators.pop()
                except IndexError:
                    expected = None
                if lt[0] != expected:
                    expected = expected and F', expected {_PRETTY[expected]}' or ''
                    raise ValueError(
                        F'Unexpected {tokens[0]} in line {line}{expected}.')
                indent -= 1
            if not indent and len(expected_terminators) > 0:
                yield (0, '')
            output = io.StringIO()
            for k, token in enumerate(tokens):
                space = True
                space = space and k > 0
                space = space and token not in ')],'
                space = space and not (token in '([' and tokens[k - 1][~0].isalnum())
                space = space and tokens[k - 1] not in '(['
                space = space and not token.startswith('.')
                if space:
                    output.write(' ')
                output.write(token)
            yield (indent, output.getvalue())
            line += 1
            tokens.clear()
        else:
            opt = A3X_OPCODES[opc]
            if opc < 0x40:
                opt = opt.format_map(decompiler)
            tokens.append(opt)
    if expected_terminators:
        raise ValueError('Script truncated.')


def a3x_decompress(data: bytearray | memoryview, is_current: bool) -> bytearray:
    output = MemoryFile()
    cursor = 0
    view = memoryview(data)
    size = int.from_bytes(view[4:8], 'big')
    bit_reader = StructReaderBits(view[8:], bigendian=True)
    bits = bit_reader.read_integer
    while cursor < size:
        check = bits(1)
        if check == is_current:
            output.write_byte(bits(8))
            cursor += 1
            continue
        delta = 0
        offset = bits(15)
        length = bits(2)
        if length == 0b00000011:
            delta = 0x003
            length = bits(3)
            if length == 0b00000111:
                delta = 0x00A
                length = bits(5)
                if length == 0b00011111:
                    delta = 0x029
                    length = bits(8)
                    if length == 0b11111111:
                        delta = 0x128
                        length = bits(8)
        while length == 0b11111111:
            delta += 0xFF
            length = bits(8)
        length += delta + 3
        length &= 0xFFFFFFFF
        output.replay(offset, length)
        cursor += length
    return output.getvalue()


def a3x_decrypt_current(data: memoryview | bytearray, key: int) -> bytearray:
    a, b, t = 16, 6, []

    for _ in range(17):
        key = 1 - key * 0x53A9B4FB & 0xFFFFFFFF
        t.append(key)

    t.reverse()

    for _ in range(9):
        r = (t[a] << 9 | t[a] >> 23) + (t[b] << 13 | t[b] >> 19) & 0xFFFFFFFF
        t[a] = r
        a = (a + 1) % 17
        b = (b + 1) % 17

    def _decrypted():
        nonlocal a, b
        for v in data:
            x = t[a]
            y = t[b]
            t[a] = (x << 9 | x >> 23) + (y << 13 | y >> 19) & 0xFFFFFFFF
            a = (a + 1) % 17
            b = (b + 1) % 17
            x = t[a]
            y = t[b]
            r = (x << 9 | x >> 23) + (y << 13 | y >> 19) & 0xFFFFFFFF
            t[a] = r
            a = (a + 1) % 17
            b = (b + 1) % 17
            yield (r >> 24) ^ v

    return bytearray(_decrypted())


def a3x_decrypt_legacy(data: bytearray | memoryview, key: int) -> bytearray:
    a, b, t = 1, 0, []

    t.append(key)
    for i in range(1, 624):
        key = ((((key ^ key >> 30) * 0x6C078965) & 0xFFFFFFFF) + i) & 0xFFFFFFFF
        t.append(key)

    def _refactor_state():
        for i in range(0, 0xe3):
            x = t[i] ^ t[i + 1]
            x &= 0x7FFFFFFE
            x ^= t[i]
            x >>= 1
            y = 0x9908B0DF
            if (t[i + 1] % 2 == 0):
                y = 0
            x ^= y
            x ^= t[i + 397]
            t[i] = x

        for i in range(0xe3, 0x18c + 0xe3):
            x = t[i] ^ t[i + 1]
            x &= 0x7FFFFFFE
            x ^= t[i]
            x >>= 1
            y = 0x9908B0DF
            if (t[i + 1] % 2 == 0):
                y = 0
            x ^= y
            x ^= t[i - 227]
            t[i] = x

        x = t[0]
        y = t[0x18c + 0xe3] ^ x
        y &= 0x7FFFFFFE
        y ^= t[0x18c + 0xe3]
        y >>= 1
        if (x % 2 == 1):
            x = 0x9908B0DF
        else:
            x = 0
        y ^= x
        y ^= t[0x18c + 0xe3 - 227]
        t[0x18c + 0xe3] = y

    def _decrypted():
        nonlocal a, b
        for v in data:
            a -= 1
            b += 1
            if a == 0:
                a = 0x270
                b = 0
                _refactor_state()
            x = t[b]
            x = x ^ x >> 11
            y = ((x & 0xFF3A58AD) << 7) & 0xFFFFFFFF
            x ^= y
            y = ((x & 0xFFFFDF8C) << 15) & 0xFFFFFFFF
            x ^= y
            y = x ^ x >> 0x12
            yield ((y >> 1) ^ v) & 0xFF

    return bytearray(_decrypted())


def a3x_decrypt(data: memoryview | bytearray, key: int, is_current: bool = True) -> bytearray:
    if is_current:
        return a3x_decrypt_current(data, key)
    return a3x_decrypt_legacy(data, key)


class A3xType(str, Enum):
    UNICODE = 'AUTOIT UNICODE SCRIPT'
    SCRIPT = 'AUTOIT SCRIPT'
    NOEXEC = 'AUTOIT NO CMDEXECUTE'
    AHK_SCRIPT = 'AUTOHOTKEY SCRIPT'
    AHK_WITH_ICON = 'AHK WITH ICON'


class A3xEncryptionConstants(NamedTuple):
    version: bytes
    tag_size: int
    tag: int
    path_size: int
    path: int
    compressed_size: int
    decompressed_size: int
    checksum: int
    data: int
    is_current: bool


class A3xEncryptionType(A3xEncryptionConstants, Enum):
    EA06 = (b'AU3!EA06', 0xADBC, 0xB33F, 0xF820, 0xF479, 0x87BC, 0x87BC, 0xA685, 0x2477, True)
    EA05 = (b'AU3!EA05', 0x29BC, 0xA25E, 0x29AC, 0xF25E, 0x45AA, 0x45AA, 0xC3D2, 0x22AF, False)


class A3xReader(StructReader[memoryview]):

    def read_encrypted_data(self, size_key, seed, is_current=True):
        if is_current:
            size = 2 * (self.u32() ^ size_key)
            seed = int(size // 2) + seed
        else:
            size = (self.u32() ^ size_key)
            seed += size

        return a3x_decrypt(self.read_exactly(size), seed, is_current)

    def read_encrypted_string(self, size_key, seed, is_current=True):
        if is_current:
            return self.read_encrypted_data(size_key, seed).decode('utf-16le')
        return self.read_encrypted_data(size_key, seed, is_current=False).decode('utf-8')

    def read_time(self):
        H = self.u32()
        L = self.u32()
        T = (H << 32) | L
        return date_from_timestamp((T - 116444736000000000) / 10000000)

    def read_length_prefixed_string(self):
        length = self.i32()
        return ''.join(chr((self.u16() ^ length) & 0xFFFF) for _ in range(length))


class A3xRecord(Struct):
    MAGIC = b'\x6B\x43\xCA\x52'

    def __init__(self, reader: A3xReader, encryption_type: A3xEncryptionType):
        self.magic = reader.read(4)
        self.encryption_type = encryption_type
        self.type = reader.read_encrypted_string(
            encryption_type.tag_size,
            encryption_type.tag,
            encryption_type.is_current
        ).lstrip('>').rstrip('<')
        self.src_path = reader.read_encrypted_string(
            encryption_type.path_size,
            encryption_type.path,
            encryption_type.is_current
        )
        self.is_compressed = bool(reader.u8())
        self.is_encrypted = True
        self.size = reader.u32() ^ encryption_type.compressed_size
        self.size_decompressed = reader.u32() ^ encryption_type.decompressed_size
        self.checksum = reader.u32() ^ encryption_type.checksum
        self.created = reader.read_time()
        self.written = reader.read_time()
        self.data = reader.read_exactly(self.size)

    def __hash__(self):
        return hash((self.path, self.type))

    def __eq__(self, other):
        if not isinstance(other, A3xRecord):
            return False
        return self.path == other.path and self.type == other.type

    def extract(self) -> bytearray:
        output = MemoryFile()
        it = self.extract_linewise()
        output.write(next(it))
        for line in it:
            output.write_byte(10)
            output.write(line)
        return output.getvalue()

    def extract_linewise(self) -> Generator[bytes]:
        if self.is_encrypted:
            a3x.log_info('decryption:', self.path)
            if self.encryption_type.is_current:
                self.data = a3x_decrypt(self.data, self.encryption_type.data, self.encryption_type.is_current)
            else:
                seed = self.encryption_type.data + 0x849
                self.data = a3x_decrypt(self.data, seed, self.encryption_type.is_current)
            self.is_encrypted = False
        if self.is_compressed:
            a3x.log_info('decompress:', self.path)
            self.data = a3x_decompress(self.data, self.encryption_type.is_current)
            self.is_compressed = False
        if not self.is_script():
            yield self.data
            return
        a3x.log_info('decompiler:', self.path)
        for indent, line in a3x_decompile(self.data):
            yield F'{indent * 4 * " "}{line}'.encode(a3x.codec)

    def is_script(self):
        return self.type == A3xType.SCRIPT

    @property
    def path(self):
        try:
            tv = A3xType(self.type)
        except Exception:
            return self.type
        if tv is A3xType.SCRIPT:
            return 'script.au3'
        if tv is A3xType.UNICODE:
            return 'unicode-script.au3'
        if tv is A3xType.NOEXEC:
            return None
        if tv in (A3xType.AHK_WITH_ICON, A3xType.AHK_SCRIPT):
            return 'script.ahk'


class A3xScript(Struct):
    MAGIC = b'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D'
    WIDTH = 0x28

    def has_valid_magic(self):
        return self.magic == self.MAGIC

    def __init__(self, reader: A3xReader):
        self.magic = reader.read(0x10)
        self.type = bytes(reader.read(8))
        self._unk = reader.read(16)
        self.truncated = False
        if not self.type.startswith(B'AU3!'):
            self.body = []
            return
        self.body: list[A3xRecord] = []
        last_known_good_position = reader.tell()
        types = {at.version: at for at in A3xEncryptionType}
        while not reader.eof:
            pos = reader.tell()
            try:
                rt = types.get(self.type, A3xEncryptionType.EA06)
                self.body.append(A3xRecord(reader, rt))
            except (ValueError, EOFError):
                reader.seekset(pos)
                break
            else:
                last_known_good_position = pos
        if reader.read(8) != self.type:
            self.truncated = True
            reader.seekset(last_known_good_position)
            if self.body:
                self.body.pop()


class a3x(PathExtractorUnit):
    """
    Extracts embedded resources from compiled AutoIt scripts and decompiles the embedded script
    bytecode. The unit also works on compiled AutoIt executables.
    """

    def unpack(self, data: bytearray):
        view = memoryview(data)
        cursor = 0
        errors: dict[int, Exception] = {}
        script_count = 0
        truncated: set[A3xRecord] = set()
        intact: set[A3xRecord] = set()

        def _package(records: Iterable[A3xRecord]) -> Generator[UnpackResult]:
            for k, record in enumerate(records, 1):
                self.log_info(F'record {k} type:', record.type)
                self.log_info(F'record {k} path:', record.src_path)
                if record.path is None:
                    continue
                yield UnpackResult(
                    record.path,
                    record.extract,
                    srcpath=record.src_path,
                    created=record.created.isoformat(' ', 'seconds'),
                    written=record.written.isoformat(' ', 'seconds'),
                )

        while cursor < len(view):
            self.log_debug(F'searching at offset 0x{cursor:08X}')
            nc = data.find(A3xScript.MAGIC, cursor)
            if nc >= 0:
                cursor = nc
            else:
                rp = data.find(A3xRecord.MAGIC, cursor) - A3xScript.WIDTH
                if rp <= cursor:
                    break
                cursor = rp
            try:
                script = A3xScript.Parse(view[cursor:])
            except Exception as E:
                errors[cursor] = E
                cursor += 1
                continue
            else:
                valid = script.has_valid_magic()
                if valid:
                    _m = 'correct'
                else:
                    _m = 'invalid'
                if not script.body:
                    cursor += A3xScript.WIDTH
                    if not script.has_valid_magic():
                        cursor += len(A3xRecord.MAGIC)
                    continue
                if script.truncated:
                    _a = 'truncated'
                    truncated.update(script.body)
                else:
                    script_count += 1
                    _a = 'intact'
                    intact.update(script.body)
                self.log_info(
                    F'{_a} script of type', script.type,
                    F'and length 0x{len(script):08X}',
                    F'with {len(script.body)} records and {_m} magic:',
                    script.magic
                )
                cursor += len(script)
                if script.truncated:
                    if not script.has_valid_magic():
                        cursor += len(A3xRecord.MAGIC)
                    continue

            yield from _package(script.body)

        remaining = truncated - intact
        if remaining:
            self.log_warn('emitting records from truncated scripts')
            yield from _package(remaining)
            return
        elif truncated:
            self.log_debug('good news: intact scripts contained all records from truncated scripts')
        if script_count == 0:
            error = None
            for offset, error in errors.items():
                self.log_warn(F'error at offset 0x{offset:08X}:', error)
            if error:
                raise error

    @classmethod
    def handles(cls, data) -> bool | None:
        return buffer_contains(data, A3xScript.MAGIC) or buffer_contains(data, A3xRecord.MAGIC)
