#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import enum
import itertools
import re
import struct
import io
import dataclasses

import lzma
import zlib

from datetime import datetime

from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.structures import MemoryFile, Struct, StructReader, StreamDetour

from refinery.lib.thirdparty.pyflate import BZip2File, GZipFile
from refinery.lib.tools import exception_to_string
from refinery.lib.decompression import parse_lzma_properties

from typing import (
    BinaryIO,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Type,
)


class DeflateFile(io.RawIOBase):

    data: MemoryFile
    dc: zlib._Decompress

    def __new__(cls, data: MemoryFile):
        self = super().__new__(cls)
        self.data = data
        self.dc = zlib.decompressobj(-15)
        return io.BufferedReader(self)

    def readall(self) -> bytes:
        return self.read()

    def readinto(self, __buffer):
        data = self.read(len(__buffer))
        size = len(data)
        __buffer[:size] = data
        return size

    def read(self, size=-1):
        buffer = self.dc.unconsumed_tail or self.data.read(size)
        kwargs = {}
        if size > 0:
            kwargs.update(max_length=size)
        return self.dc.decompress(buffer, **kwargs)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def writable(self) -> bool:
        return False

    def write(self, __b):
        raise NotImplementedError


class NSMethod(str, enum.Enum):
    Copy = 'COPY'
    LZMA = 'LZMA'
    BZip2 = 'BZIP2'
    Deflate = 'DEFLATE'
    NSGzip = 'NsisGzip'


class Op(enum.IntEnum):
    INVALID_OPCODE     = 0              # noqa
    Ret                = enum.auto()    # noqa; Return
    Nop                = enum.auto()    # noqa; Nop, Goto
    Abort              = enum.auto()    # noqa; Abort
    Quit               = enum.auto()    # noqa; Quit
    Call               = enum.auto()    # noqa; Call, InitPluginsDir
    UpdateText         = enum.auto()    # noqa; DetailPrint
    Sleep              = enum.auto()    # noqa; Sleep
    BringToFront       = enum.auto()    # noqa; BringToFront
    SetDetailsView     = enum.auto()    # noqa; SetDetailsView
    SetFileAttributes  = enum.auto()    # noqa; SetFileAttributes
    CreateDirectory    = enum.auto()    # noqa; CreateDirectory, SetOutPath
    IfFileExists       = enum.auto()    # noqa; IfFileExists
    SetFlag            = enum.auto()    # noqa; SetRebootFlag, ...
    IfFlag             = enum.auto()    # noqa; IfAbort, IfSilent, IfErrors, IfRebootFlag
    GetFlag            = enum.auto()    # noqa; GetInstDirError, GetErrorLevel
    Rename             = enum.auto()    # noqa; Rename
    GetFullPathName    = enum.auto()    # noqa; GetFullPathName
    SearchPath         = enum.auto()    # noqa; SearchPath
    GetTempFileName    = enum.auto()    # noqa; GetTempFileName
    ExtractFile        = enum.auto()    # noqa; File
    DeleteFile         = enum.auto()    # noqa; Delete
    MessageBox         = enum.auto()    # noqa; MessageBox
    RmDir              = enum.auto()    # noqa; RMDir
    StrLen             = enum.auto()    # noqa; StrLen
    AssignVar          = enum.auto()    # noqa; StrCpy
    StrCmp             = enum.auto()    # noqa; StrCmp
    ReadEnvStr         = enum.auto()    # noqa; ReadEnvStr, ExpandEnvStrings
    IntCmp             = enum.auto()    # noqa; IntCmp, IntCmpU
    IntOp              = enum.auto()    # noqa; IntOp
    IntFmt             = enum.auto()    # noqa; IntFmt/Int64Fmt
    PushPop            = enum.auto()    # noqa; Push/Pop/Exchange
    FindWindow         = enum.auto()    # noqa; FindWindow
    SendMessage        = enum.auto()    # noqa; SendMessage
    IsWindow           = enum.auto()    # noqa; IsWindow
    GetDlgItem         = enum.auto()    # noqa; GetDlgItem
    SetCtlColors       = enum.auto()    # noqa; SetCtlColors
    SetBrandingImage   = enum.auto()    # noqa; SetBrandingImage / LoadAndSetImage
    CreateFont         = enum.auto()    # noqa; CreateFont
    ShowWindow         = enum.auto()    # noqa; ShowWindow, EnableWindow, HideWindow
    ShellExec          = enum.auto()    # noqa; ExecShell
    Execute            = enum.auto()    # noqa; Exec, ExecWait
    GetFileTime        = enum.auto()    # noqa; GetFileTime
    GetDLLVersion      = enum.auto()    # noqa; GetDLLVersion
#   GetFontVersion     = enum.auto()    # noqa; Park : 2.46.2
#   GetFontName        = enum.auto()    # noqa; Park : 2.46.3
    RegisterDll        = enum.auto()    # noqa; RegDLL, UnRegDLL, CallInstDLL
    CreateShortcut     = enum.auto()    # noqa; CreateShortcut
    CopyFiles          = enum.auto()    # noqa; CopyFiles
    Reboot             = enum.auto()    # noqa; Reboot
    WriteINI           = enum.auto()    # noqa; WriteINIStr, DeleteINISec, DeleteINIStr, FlushINI
    ReadINIStr         = enum.auto()    # noqa; ReadINIStr
    DelReg             = enum.auto()    # noqa; DeleteRegValue, DeleteRegKey
    WriteReg           = enum.auto()    # noqa; WriteRegStr, WriteRegExpandStr, WriteRegBin, WriteRegDWORD
    ReadRegStr         = enum.auto()    # noqa; ReadRegStr, ReadRegDWORD
    RegEnum            = enum.auto()    # noqa; EnumRegKey, EnumRegValue
    FileClose          = enum.auto()    # noqa; FileClose
    FileOpen           = enum.auto()    # noqa; FileOpen
    FileWrite          = enum.auto()    # noqa; FileWrite, FileWriteByte
    FileRead           = enum.auto()    # noqa; FileRead, FileReadByte
#   Park:
#   FileWriteW         = enum.auto()    # noqa; FileWriteUTF16LE, FileWriteWord
#   FileReadW          = enum.auto()    # noqa; FileReadUTF16LE, FileReadWord
    FileSeek           = enum.auto()    # noqa; FileSeek
    FindClose          = enum.auto()    # noqa; FindClose
    FindNext           = enum.auto()    # noqa; FindNext
    FindFirst          = enum.auto()    # noqa; FindFirst
    WriteUninstaller   = enum.auto()    # noqa; WriteUninstaller
#   Park : since 2.46.3 the log is enabled in main Park version
#   Log                = enum.auto()    # noqa; LogSet, LogText
    SectionSet         = enum.auto()    # noqa; Get*, Set*
    InstTypeSet        = enum.auto()    # noqa; InstTypeSetText, InstTypeGetText, SetCurInstType, GetCurInstType
#   Before NSIS v3.06: Instructions not actually implemented in exehead, but used in compiler.
#   GETLABELADDR       = enum.auto()    # noqa; both of these get converted to ASSIGNVAR
#   GETFUNCTIONADDR    = enum.auto()    # noqa
#   In NSIS v3.06 and later it was changed to:
    GetOSInfo          = enum.auto()    # noqa
    ReservedOpcode     = enum.auto()    # noqa
    LockWindow         = enum.auto()    # noqa; LockWindow
#   Two unicode commands available only in Unicode archive:
    FileWriteW         = enum.auto()    # noqa; FileWriteUTF16LE, FileWriteWord
    FileReadW          = enum.auto()    # noqa; FileReadUTF16LE, FileReadWord
#   Since NSIS v3.06 the fllowing IDs codes was moved here:
#   Opcodes listed here are not actually used in exehead.
#   No exehead opcodes should be present after these!
#   GetLabelAddr       = enum.auto()    # noqa; ASSIGNVAR
#   GetFunctionAddr    = enum.auto()    # noqa; ASSIGNVAR
#   The following IDs are not IDs in real order.
#   We just need some IDs to translate eny extended layout to main layout:
    Log                = enum.auto()    # noqa; LogSet, LogText
#   Park
    FindProc           = enum.auto()    # noqa; FindProc
    GetFontVersion     = enum.auto()    # noqa; GetFontVersion
    GetFontName        = enum.auto()    # noqa; GetFontName

    @classmethod
    def FromInt(cls, value: int):
        try:
            return cls(value)
        except ValueError:
            return cls.INVALID_OPCODE


_Op_PARAMETER_COUNT = {
    Op.INVALID_OPCODE    : 0,
    Op.Ret               : 0,
    Op.Nop               : 1,
    Op.Abort             : 1,
    Op.Quit              : 0,
    Op.Call              : 2,
    Op.UpdateText        : 6,
    Op.Sleep             : 1,
    Op.BringToFront      : 0,
    Op.SetDetailsView    : 2,
    Op.SetFileAttributes : 2,
    Op.CreateDirectory   : 3,
    Op.IfFileExists      : 3,
    Op.SetFlag           : 3,
    Op.IfFlag            : 4,
    Op.GetFlag           : 2,
    Op.Rename            : 4,
    Op.GetFullPathName   : 3,
    Op.SearchPath        : 2,
    Op.GetTempFileName   : 2,
    Op.ExtractFile       : 6,
    Op.DeleteFile        : 2,
    Op.MessageBox        : 6,
    Op.RmDir             : 2,
    Op.StrLen            : 2,
    Op.AssignVar         : 4,
    Op.StrCmp            : 5,
    Op.ReadEnvStr        : 3,
    Op.IntCmp            : 6,
    Op.IntOp             : 4,
    Op.IntFmt            : 4,
    Op.PushPop           : 6,
    Op.FindWindow        : 5,
    Op.SendMessage       : 6,
    Op.IsWindow          : 3,
    Op.GetDlgItem        : 3,
    Op.SetCtlColors      : 2,
    Op.SetBrandingImage  : 4,
    Op.CreateFont        : 5,
    Op.ShowWindow        : 4,
    Op.ShellExec         : 6,
    Op.Execute           : 3,
    Op.GetFileTime       : 3,
    Op.GetDLLVersion     : 4,
    Op.RegisterDll       : 6,
    Op.CreateShortcut    : 6,
    Op.CopyFiles         : 4,
    Op.Reboot            : 1,
    Op.WriteINI          : 5,
    Op.ReadINIStr        : 4,
    Op.DelReg            : 5,
    Op.WriteReg          : 6,
    Op.ReadRegStr        : 5,
    Op.RegEnum           : 5,
    Op.FileClose         : 1,
    Op.FileOpen          : 4,
    Op.FileWrite         : 3,
    Op.FileRead          : 4,
    Op.FileSeek          : 4,
    Op.FindClose         : 1,
    Op.FindNext          : 2,
    Op.FindFirst         : 3,
    Op.WriteUninstaller  : 4,
    Op.SectionSet        : 5,
    Op.InstTypeSet       : 4,
    Op.GetOSInfo         : 6,
    Op.ReservedOpcode    : 2,
    Op.LockWindow        : 1,
    Op.FileWriteW        : 4,
    Op.FileReadW         : 4,
    Op.Log               : 2,
    Op.FindProc          : 2,
    Op.GetFontVersion    : 2,
    Op.GetFontName       : 2,
}


NS_SHELL_STRINGS = {
    0x00: 'DESKTOP',
    0x01: 'INTERNET',
    0x02: 'SMPROGRAMS',
    0x03: 'CONTROLS',
    0x04: 'PRINTERS',
    0x05: 'DOCUMENTS',
    0x06: 'FAVORITES',
    0x07: 'SMSTARTUP',
    0x08: 'RECENT',
    0x09: 'SENDTO',
    0x0A: 'BITBUCKET',
    0x0B: 'STARTMENU',
    0x0D: 'MUSIC',
    0x0E: 'VIDEOS',
    0x10: 'DESKTOP',
    0x11: 'DRIVES',
    0x12: 'NETWORK',
    0x13: 'NETHOOD',
    0x14: 'FONTS',
    0x15: 'TEMPLATES',
    0x16: 'STARTMENU',
    0x17: 'SMPROGRAMS',
    0x18: 'SMSTARTUP',
    0x19: 'DESKTOP',
    0x1A: 'APPDATA',
    0x1B: 'PRINTHOOD',
    0x1C: 'LOCALAPPDATA',
    0x1D: 'ALTSTARTUP',
    0x1E: 'ALTSTARTUP',
    0x1F: 'FAVORITES',
    0x20: 'INTERNET_CACHE',
    0x21: 'COOKIES',
    0x22: 'HISTORY',
    0x23: 'APPDATA',
    0x24: 'WINDIR',
    0x25: 'SYSDIR',
    0x26: 'PROGRAM_FILES',
    0x27: 'PICTURES',
    0x28: 'PROFILE',
    0x29: 'SYSTEMX86',
    0x2A: 'PROGRAM_FILESX86',
    0x2B: 'PROGRAM_FILES_COMMON',
    0x2C: 'PROGRAM_FILES_COMMONX8',
    0x2D: 'TEMPLATES',
    0x2E: 'DOCUMENTS',
    0x2F: 'ADMINTOOLS',
    0x30: 'ADMINTOOLS',
    0x31: 'CONNECTIONS',
    0x35: 'MUSIC',
    0x36: 'PICTURES',
    0x37: 'VIDEOS',
    0x38: 'RESOURCES',
    0x39: 'RESOURCES_LOCALIZED',
    0x3A: 'COMMON_OEM_LINKS',
    0x3B: 'CDBURN_AREA',
    0x3D: 'COMPUTERSNEARME',
}

NS_VARIABLE_STRINGS = (
    "CMDLINE",
    "INSTDIR",
    "OUTDIR",
    "EXEDIR",
    "LANGUAGE",
    "TEMP",
    "PLUGINSDIR",
    "EXEPATH",  # NSIS 2.26+
    "EXEFILE",  # NSIS 2.26+
    "HWNDPARENT",
    "CLICK",    # set from page->clicknext
    "OUTDIR",   # NSIS 2.04+
)


class NSHeaderFlags(enum.IntFlag):
    Uninstall = 1
    Silent = 2
    NoCrc = 4
    ForceCrc = 8
    LongOffset = 16
    ExternalFileSupport = 32
    ExternalFile = 64
    IsStubInstaller = 128


class NSScriptFlags(enum.IntFlag):
    DETAILS_SHOWDETAILS  = 0x0001  # noqa
    DETAILS_NEVERSHOW    = 0x0002  # noqa
    PROGRESS_COLORED     = 0x0004  # noqa
    SILENT               = 0x0008  # noqa
    SILENT_LOG           = 0x0010  # noqa
    AUTO_CLOSE           = 0x0020  # noqa
    DIR_NO_SHOW          = 0x0040  # noqa
    NO_ROOT_DIR          = 0x0080  # noqa
    COMP_ONLY_ON_CUSTOM  = 0x0100  # noqa
    NO_CUSTOM            = 0x0200  # noqa


class LZMAOptions(NamedTuple):
    filter_flag: bool
    dictionary_size: int


class NSBlockHeaderOffset(Struct):
    def __init__(self, reader: StructReader, is64bit: bool):
        if is64bit:
            self.offset = reader.u64()
        else:
            self.offset = reader.u32()
        self.count = reader.u32()


class NSType(enum.IntEnum):
    Nsis2 = 0
    Nsis3 = enum.auto()
    Park1 = enum.auto()  # Park 2.46.1-
    Park2 = enum.auto()  # Park 2.46.2  : GetFontVers
    Park3 = enum.auto()  # Park 2.46.3+ : GetFontName


class NSScriptInstruction(Struct):
    def __init__(self, reader: StructReader):
        self.opcode = reader.u32()
        self.arguments = [reader.u32() for _ in range(6)]


class NSScriptExtendedInstruction(Struct):
    def __init__(self, reader: StructReader):
        self.opcode = reader.u32()
        self.arguments = [reader.u32() for _ in range(8)]


class NSCharCode(enum.IntEnum):
    NONE = 0
    CHAR = enum.auto()
    SKIP = enum.auto()
    SHELL = enum.auto()
    VAR = enum.auto()
    LANG = enum.auto()

    @property
    def special(self):
        return self > NSCharCode.CHAR


@dataclasses.dataclass
class NSItem:
    offset: int
    name: Optional[str] = None
    mtime: Optional[datetime] = None
    is_compressed: bool = True
    is_uninstaller: bool = False
    attributes: Optional[int] = None
    size: Optional[int] = None
    compressed_size: Optional[int] = None
    estimated_size: Optional[int] = None
    dictionary_size: int = 1
    patch_size: int = 0
    prefix: Optional[str] = None

    @property
    def path(self):
        path = self.name
        if self.prefix:
            path = F'{self.prefix}\\{path}'
        return path

    def __str__(self):
        return self.name


class NSHeader(Struct):
    BACKSLASH           = ord('\\')  # noqa
    NS_CMDLINE          = 20         # noqa
    NS_INSTDIR          = 21         # noqa
    NS_OUTDIR           = 22         # noqa
    NS_EXEDIR           = 23         # noqa
    NS_LANGUAGE         = 24         # noqa
    NS_TEMP             = 25         # noqa
    NS_PLUGINSDIR       = 26         # noqa
    NS_EXEPATH          = 27         # noqa NSIS 2.26+
    NS_EXEFILE          = 28         # noqa NSIS 2.26+
    NS_HWNDPARENT_225   = 27         # noqa
    NS_HWNDPARENT_226   = 29         # noqa
    NS_CLICK            = 30         # noqa
    NS_OUTDIR_225       = 29         # noqa NSIS 2.04 - 2.25
    NS_OUTDIR_226       = 31         # noqa NSIS 2.26+

    def _string_args_to_single_arg(self, n: int, m: Optional[int] = None) -> int:
        if self.type >= NSType.Park1:
            return n & 0x7FFF
        else:
            if m is None:
                m = (n >> 8)
            n &= 0x7F
            m &= 0x7F
            return n | (m << 7)

    def _get_char_code(self, char: int) -> NSCharCode:
        if self.type >= NSType.Park1:
            if char < 0x80:
                return NSCharCode.CHAR
            lookup = {
                0xE000: NSCharCode.SKIP,
                0xE001: NSCharCode.VAR,
                0xE002: NSCharCode.SHELL,
                0xE003: NSCharCode.LANG,
            }
        elif self.type is NSType.Nsis3:
            if char > 4:
                return NSCharCode.CHAR
            lookup = {
                0x0002: NSCharCode.SHELL,
                0x0003: NSCharCode.VAR,
                0x0004: NSCharCode.SKIP,
            }
        elif self.type is NSType.Nsis2:
            lookup = {
                0x00FC: NSCharCode.SKIP,
                0x00FD: NSCharCode.VAR,
                0x00FE: NSCharCode.SHELL,
            }
        else:
            raise RuntimeError(F'Unknown NSIS type {self.type}')
        return lookup.get(char, NSCharCode.NONE)

    def _string_code_shell(self, index1: int, index2: Optional[int] = None) -> str:
        if index2 is None:
            index2 = index1 >> 8
            index1 = index1 & 0xFF
        if index1 & 0x80 != 0:
            offset = index1 & 0x3F
            with StreamDetour(self.strings, offset):
                if self.strings.tell() != offset:
                    return '<ERROR>'
                path = self._read_current_string()
                if path.startswith('ProgramFilesDir'):
                    return '$PROGRAMFILES'
                if path.startswith('CommonFilesDir'):
                    return '$COMMONFILES'
                suffix = 32 * (index1 >> 5 & 2)
                return F'$REG{suffix}({path})'
        for index in (index1, index2):
            shell = NS_SHELL_STRINGS.get(index)
            if shell is not None:
                return F'${shell}'
        else:
            return F'<ERROR:SHELL[{index1},{index2}]>'

    def _string_code_variable(self, index: int) -> str:
        varcount = 20 + len(NS_VARIABLE_STRINGS)
        if self._is_nsis200:
            varcount -= 3
        elif self._is_nsis225:
            varcount -= 2
        if index < 20:
            if index >= 10:
                return F'$R{index - 10}'
            return F'$V{index}'
        else:
            if index < varcount:
                if self._is_nsis225 and index >= self.NS_EXEPATH:
                    index += 2
                try:
                    variable = NS_VARIABLE_STRINGS[index - 20]
                except IndexError:
                    pass
                else:
                    return F'${variable}'
            return F'$var{index}'

    def _string_code_language(self, index: int) -> str:
        return F'$LSTR_{index:04X}'

    def __init__(self, reader: StructReader[bytearray], size: int, extended: bool):
        self.is64bit = size >= 4 + 12 * 8 and not any(struct.unpack('8xI' * 8, reader.peek(12 * 8)))
        if self.is64bit:
            xtnsis.log_debug('64bit archive detected')
        bho_size = 12 if self.is64bit else 8
        required = 4 + bho_size * 8
        if size < required:
            raise ValueError(F'Invalid size {size} was specified for NSIS main header, needs to be at least {required}.')
        self.unknown_value = reader.u32()
        self.block_header_offsets = [NSBlockHeaderOffset(reader.read(bho_size), is64bit=self.is64bit) for _ in range(8)]

        self.bh_entries = self.block_header_offsets[2]
        self.bh_strings = self.block_header_offsets[3]
        self.bh_langtbl = self.block_header_offsets[4]

        for k, offset in enumerate(self.block_header_offsets):
            w = 0x10 if self.is64bit else 8
            t = {2: 'entries', 3: 'strings', 4: 'language'}.get(k)
            msg = F'block header offset {k}: 0x{offset.offset:0{w}X}'
            if t is not None:
                msg = F'{msg} ({t})'
            xtnsis.log_debug(msg)

        self.type = NSType.Nsis2

        reader.seekset(self.bh_entries.offset)
        InsnParser = NSScriptExtendedInstruction if extended else NSScriptInstruction
        self.instructions: List[NSScriptInstruction] = [
            InsnParser(reader) for _ in range(self.bh_entries.count)]

        if self.bh_entries.offset > size:
            raise ValueError(
                F'Invalid NSIS header: Size is 0x{size:08X}, but entries block header offset is 0x{self.bh_entries.offset:08X}.')
        if self.bh_strings.offset > size:
            raise ValueError(
                F'Invalid NSIS header: Size is 0x{size:08X}, but strings block header offset is 0x{self.bh_strings.offset:08X}.')
        if self.bh_langtbl.offset > size:
            raise ValueError(
                F'Invalid NSIS header: Size is 0x{size:08X}, but language list header offset is 0x{self.bh_langtbl.offset:08X}.')
        if self.bh_langtbl.offset < self.bh_strings.offset:
            raise ValueError(U'Invalid NSIS header: Language table lies before string table.')
        string_table_size = self.bh_langtbl.offset - self.bh_strings.offset
        if string_table_size < 2:
            raise ValueError(F'The calculated string table size is {string_table_size}, too small to parse.')
        reader.seekset(self.bh_strings.offset)
        self.string_data = strings = reader.read(string_table_size)
        self.unicode = strings[:2] == B'\0\0'
        if strings[-1] != 0 or (self.unicode and strings[-2] != 0):
            raise ValueError(U'The last string table character was unexpectedly nonzero.')
        if self.unicode and string_table_size % 2 != 0:
            raise ValueError(U'Unicode strings detected, but string table length was odd.')

        self.strings = StructReader(strings)
        if self.bh_entries.count > (1 << 25):
            raise ValueError(U'Entries num was out of bounds.')

        self._log_cmd_is_enabled = False
        self._is_nsis225 = False
        self._is_nsis200 = False
        self._bad_cmd = -1

        self._guess_nsis_version()

        items: Dict[(str, int), NSItem] = {}
        for item in self._read_items():
            items.setdefault((item.path, item.offset), item)
        self.items = [items[t] for t in sorted(items.keys())]

    @property
    def nsis_deflate(self):
        return self.type is not NSType.Nsis3

    @property
    def encoding(self):
        return 'utf-16le' if self.unicode else 'latin1'

    @property
    def charsize(self):
        return 2 if self.unicode else 1

    @property
    def _read_chr(self):
        return self.strings.u16 if self.unicode else self.strings.u8

    def _read_current_string(self) -> str:
        string = io.StringIO()
        chars = iter(self._read_chr, 0)
        for letter in chars:
            code = self._get_char_code(letter)
            if code is NSCharCode.CHAR:
                string.write(chr(letter))
                continue
            if code.special:
                try:
                    var1 = next(chars)
                except StopIteration:
                    break
                if var1 == 0:
                    break
                if code is NSCharCode.SKIP:
                    letter = var1
                else:
                    if not self.unicode:
                        try:
                            var2 = next(chars)
                        except StopIteration:
                            break
                        if var2 == 0:
                            break
                        vars = var1, var2
                    else:
                        vars = var1,
                    if code is NSCharCode.SHELL:
                        string.write(self._string_code_shell(*vars))
                        continue
                    else:
                        var = self._string_args_to_single_arg(*vars)
                        if code is NSCharCode.VAR:
                            string.write(self._string_code_variable(var))
                        if code is NSCharCode.LANG:
                            string.write(self._string_code_language(var))
                        continue
            string.write(chr(letter))
        return string.getvalue()

    def _seek_to_string(self, position: int) -> bool:
        pos = position * self.charsize
        return self.strings.seek(pos) == pos

    def _read_string(self, position: int) -> Optional[str]:
        if position < 0:
            return self._string_code_language(-(position + 1))
        if not self._seek_to_string(position):
            return None
        return self._read_current_string()

    def _read_string_raw(self, position: int) -> Optional[str]:
        if not self._seek_to_string(position):
            return None
        if self.unicode:
            return self.strings.read_w_string()
        else:
            return self.strings.read_c_string()

    def _is_var_absolute_path(self, position: int) -> bool:
        var = self._get_var_index(position)
        if var is None:
            return False
        return var in (
            self.NS_INSTDIR,
            self.NS_EXEDIR,
            self.NS_TEMP,
            self.NS_PLUGINSDIR,
        )

    def _is_good_string(self, position: int) -> bool:
        if position == 0:
            return False
        if not self._seek_to_string(position - 1):
            return False
        prefix = self._read_chr()
        return prefix == 0 or prefix == self.BACKSLASH

    def _is_var_str(self, position: int, index: int) -> bool:
        if index > 0x7FFF:
            return False
        var_index = self._get_var_index(position)
        if var_index is None:
            return False
        if self._get_res_finished(position, 0) is None:
            return False
        return var_index == index

    def _get_var_index(self, position: int) -> Optional[int]:
        if not self._seek_to_string(position):
            raise LookupError(F'Invalid string offset 0x{position:08X}')
        try:
            code = self._read_chr()
            if self._get_char_code(code) is not NSCharCode.VAR:
                return None
            arg1 = self._read_chr()
            if arg1 == 0:
                return None
            if self.unicode:
                args = arg1,
            else:
                arg2 = self._read_chr()
                if arg2 == 0:
                    return None
                args = arg1, arg2
            return self._string_args_to_single_arg(*args)
        except EOFError:
            return None

    def _get_res(self, position: int) -> Optional[int]:
        if self.unicode:
            if len(self.strings) - position >= 4:
                return 2
        else:
            if len(self.strings) - position >= 3:
                return 3
        return None

    def _get_res_finished(self, position: int, terminator: int) -> Optional[int]:
        if not self._seek_to_string(position):
            return None
        self.strings.seekrel(3)
        if self.unicode:
            self.strings.seekrel(1)
        if self.strings.remaining_bytes < self.charsize:
            return None
        if self._read_chr() != terminator:
            return None
        return 3 if self.unicode else 4

    def opcode(self, cmd: NSScriptInstruction) -> Op:
        code = cmd.opcode
        if self.type < NSType.Park1:
            if self._log_cmd_is_enabled:
                return Op.FromInt(code)
            if code < Op.SectionSet:
                return Op.FromInt(code)
            if code is Op.SectionSet:
                return Op.Log
            return Op.FromInt(code - 1)
        if code < Op.RegisterDll:
            return Op.FromInt(code)
        if self.type >= NSType.Park2:
            if code == Op.RegisterDll:
                return Op.GetFontVersion
            code -= 1
        if self.type >= NSType.Park3:
            if code == Op.RegisterDll:
                return Op.GetFontName
            code -= 1
        if code >= Op.FileSeek:
            if self.unicode:
                if code == Op.FileSeek:
                    return Op.FileWriteW
                if code == Op.FileSeek + 1:
                    return Op.FileReadW
                code -= 2
            if code >= Op.SectionSet and self._log_cmd_is_enabled:
                if code == Op.SectionSet:
                    return Op.Log
                return Op.FromInt(code - 1)
            if code == Op.FileWriteW:
                return Op.FindProc
        return Op.FromInt(code)

    def _find_bad_cmd(self):
        self._bad_cmd = -1
        for instruction in self.instructions:
            cmd = self.opcode(instruction)
            arg = instruction.arguments
            if cmd is Op.INVALID_OPCODE:
                continue
            if cmd >= self._bad_cmd >= 0:
                continue
            if self.type is NSType.Nsis3:
                if cmd == Op.ReservedOpcode:
                    self._bad_cmd = cmd
                    continue
            else:
                if cmd == Op.ReservedOpcode or cmd == Op.GetOSInfo:
                    self._bad_cmd = cmd
                    continue
            u = max((k for k, a in enumerate(arg, 1) if a), default=0)
            if cmd == Op.FindProc and u == 0:
                self._bad_cmd = cmd
                continue
            if _Op_PARAMETER_COUNT[cmd] < u:
                self._bad_cmd = cmd

    def _guess_nsis_version(self):
        self.strong_nsis = False
        self.strong_park = False
        char_mask = 0x8080 if self.unicode else 0x80
        self.strings.seek(0)
        while not self.strings.eof:
            string = self._read_current_string()
            if string is None:
                continue
            if len(string) < 2:
                continue
            if ord(string[0]) != 3:
                continue
            if ord(string[1]) & char_mask == char_mask:
                self.type = NSType.Nsis3
                self.strong_nsis = True
                break
        if self.unicode:
            if not self.strong_nsis:
                self.type = NSType.Park1
                self.strong_park = True
        elif self.type is NSType.Nsis2:
            for instruction in self.instructions:
                cmd = self.opcode(instruction)
                arg = instruction.arguments
                if cmd is Op.GetDlgItem:
                    if self._is_var_str(arg[1], self.NS_HWNDPARENT_225):
                        self._is_nsis225 = True
                        if arg[0] == self.NS_OUTDIR_225:
                            self._is_nsis200 = True
                            break
                if cmd is Op.AssignVar:
                    if arg[0] == self.NS_OUTDIR_225 and arg[2] == 0 and arg[3] == 0:
                        self._is_nsis225 = self._is_var_str(arg[1], self.NS_OUTDIR)
        got_park_version = False
        mask = 0
        IN = 4 if self.unicode else 2
        if not self.strong_nsis and not self._is_nsis225 and not self._is_nsis200:
            for instruction in self.instructions:
                cmd = instruction.opcode
                arg = instruction.arguments
                alt = arg[3]
                if cmd < Op.WriteUninstaller or cmd > Op.WriteUninstaller + IN:
                    continue
                if arg[4] != 0 or arg[5] != 0 or arg[0] <= 1 or alt <= 1:
                    continue
                if not self._is_good_string(arg[0]) or not self._is_good_string(alt):
                    continue
                index = self._get_var_index(alt)
                if index is None:
                    continue
                additional = self._get_res_finished(alt, self.BACKSLASH)
                if index != self.NS_INSTDIR:
                    continue
                if self._read_string_raw(alt + additional) == self._read_string_raw(arg[0]):
                    inserts = cmd - Op.WriteUninstaller.value
                    mask |= 1 << inserts
            if mask == 1:
                got_park_version = True
            elif mask:
                shift = 0
                nt = self.type
                if self.unicode:
                    shift = 2
                if mask == 1 << (shift + 1):
                    nt = NSType.Park2
                if mask == 1 << (shift + 2):
                    nt = NSType.Park3
                if nt != self.type:
                    got_park_version = True
                    self.type = nt
        self._find_bad_cmd()
        if self._bad_cmd < Op.RegisterDll:
            return
        if self.strong_park and not got_park_version:
            if self._bad_cmd < Op.SectionSet:
                self.type = NSType.Park3
                self._log_cmd_is_enabled = True
                self._find_bad_cmd()
                if self._bad_cmd in range(Op.SectionSet):
                    self.type = NSType.Park2
                    self._log_cmd_is_enabled = False
                    self._find_bad_cmd()
                    if self._bad_cmd in range(Op.SectionSet):
                        self.type = NSType.Park1
                        self._find_bad_cmd()
        if self._bad_cmd >= Op.SectionSet:
            self._log_cmd_is_enabled = not self._log_cmd_is_enabled
            self._find_bad_cmd()
            if self._bad_cmd >= Op.SectionSet and self._log_cmd_is_enabled:
                self._log_cmd_is_enabled = False
                self._find_bad_cmd()

    def _read_items(self) -> List[NSItem]:
        prefixes = ['$INSTDIR']
        out_dir = ''
        out_dir_index = (
            self.NS_OUTDIR_225
        ) if self._is_nsis225 else (
            self.NS_OUTDIR_226
        )
        items: List[NSItem] = []

        for cmd_index, instruction in enumerate(self.instructions):
            def setpath(index: int) -> None:
                item.prefix = None
                item.name = self._read_string(index)
                if not self._is_var_absolute_path(index):
                    item.prefix = prefixes[-1]

            cmd = self.opcode(instruction)
            arg = instruction.arguments

            if cmd is Op.INVALID_OPCODE:
                continue
            elif cmd is Op.CreateDirectory:
                if not arg[1]:
                    continue
                _path = arg[0]
                index = self._get_var_index(_path)
                if index in (out_dir_index, self.NS_OUTDIR):
                    _path += self._get_res(_path)
                path = self._read_string(_path)
                if index == out_dir_index:
                    path = out_dir + path
                elif index == self.NS_OUTDIR:
                    path = prefixes[-1] + path
                prefixes.append(path)
            elif cmd is Op.AssignVar:
                if arg[0] != out_dir_index:
                    continue
                if self._is_var_str(arg[1], self.NS_OUTDIR) and arg[2] == 0 and arg[3] == 0:
                    out_dir = prefixes[-1]
            elif cmd is Op.ExtractFile:
                def epoch(t: int):
                    return (t / 10000000 - 11644473600)
                try:
                    time = datetime.fromtimestamp(epoch((arg[4] << 32) | arg[3]))
                except Exception:
                    time = None
                item = NSItem(arg[2], mtime=time)
                setpath(arg[1])
                items.append(item)
                if not self._is_var_str(arg[1], 10):
                    continue
                cmd_back_offset = 28
                if cmd_index > 1:
                    previous = self.instructions[cmd_index - 1]
                    if self.opcode(previous) is Op.Nop:
                        cmd_back_offset -= 2
                if cmd_index <= cmd_back_offset:
                    continue
                previous = self.instructions[cmd_index - cmd_back_offset]
                if self.opcode(previous) is Op.AssignVar:
                    pa = previous.arguments
                    if pa[0] == 14 and pa[2] == 0 and pa[3] == 0:
                        setpath(pa[1])
            elif cmd is Op.SetFileAttributes:
                if cmd_index > 0:
                    previous = self.instructions[cmd_index - 1]
                    pa = previous.arguments
                    if self.opcode(previous) is Op.ExtractFile and arg[0] == pa[1]:
                        item = items[-1]
                        item.attributes = arg[1]
            elif cmd is Op.WriteUninstaller:
                if arg[4] or arg[5] or arg[0] <= 1 or arg[3] <= 1:
                    continue
                if not self._is_good_string(arg[0]):
                    continue
                if self._bad_cmd in range(Op.WriteUninstaller):
                    continue
                item = NSItem(arg[1])
                setpath(arg[0])
                item.patch_size = arg[2]
                item.is_uninstaller = True
                items.append(item)
        return items

    @property
    def script(self):
        script = io.StringIO()
        name_width = max(len(op.name) for op in Op)
        addr_width = len(F'{len(self.instructions):X}')
        for k, instruction in enumerate(self.instructions):
            if k > 0:
                script.write('\n')
            opcode = self.opcode(instruction)
            script.write(F'0x{k:0{addr_width}X}: {opcode.name:<{name_width}} ')
            for j, arg in enumerate(instruction.arguments[:_Op_PARAMETER_COUNT.get(opcode, 6)]):
                if j > 0:
                    script.write(', ')
                if arg > 20 and self._is_good_string(arg):
                    script.write(repr(self._read_string(arg)))
                elif arg < 0x100:
                    script.write(str(arg))
                elif arg < 0x10000:
                    script.write(F'0x{arg:04X}')
                else:
                    script.write(F'0x{arg:08X}')
        return script.getvalue()


class NSArchive(Struct):
    MAGICS = [
        # https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer
        B'\xEF\xBE\xAD\xDE' B'Null' B'soft' B'Inst',   # v1.6
        B'\xEF\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.3
        B'\xED\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.1
        B'\xEF\xBE\xAD\xDE' B'nsis' B'inst' B'all\0',  # v1.0
    ]

    @dataclasses.dataclass
    class Entry:
        offset: int
        data: bytearray
        size: int
        decompression_error: Optional[Exception] = None

    def __init__(self, reader: StructReader[bytearray]):
        self.flags = NSHeaderFlags(reader.u32())
        self.signature = reader.read(0x10)
        errors = min(sum(1 for a, b in zip(self.signature, sig) if a != b) for sig in self.MAGICS)
        if errors > 3:
            raise ValueError(F'Out of {0x10} bytes, there were {errors} errors in the signature.')

        header_data = None
        header_size = reader.u32()
        # not the same, since the header might be compressed:
        header_data_length = None
        archive_size = reader.u32()
        self.archive_offset = reader.tell()
        body_size = archive_size - self.archive_offset

        xtnsis.log_debug(F'size of headers: {header_size}')
        xtnsis.log_debug(F'size of archive: {archive_size}')

        if body_size < 0:
            raise ValueError('Header indicates that the archive size is less than the header size.')
        if header_size < self.archive_offset:
            raise ValueError(
                F'Header indicates that the header size is {header_size}, '
                F'but at least {self.archive_offset} bytes must be in header.')
        if reader.remaining_bytes < body_size:
            raise ValueError(
                F'Header indicates archive size 0x{archive_size:08X}, '
                F'but only 0x{reader.remaining_bytes:08X} bytes remain.')

        # Header Matching Logic:
        #  X is the header size as given by the first header
        #  T is a value less than 0xE
        #  Y is a value different from 0x80
        # XX XX XX XX __ __ __ __ __ __ __ __  non-solid, uncompressed
        # 00 00 00 00 00 00 00 00 XX XX XX XX  non-solid, uncompressed, extended
        # 5D 00 00 DD DD 00 __ __ __ __ __ __  solid LZMA
        # 00 5D 00 00 DD DD 00 __ __ __ __ __  solid LZMA, empty filter
        # 01 5D 00 00 DD DD 00 __ __ __ __ __  solid LZMA, BCJ filter
        # __ __ __ 80 5D 00 00 DD DD 00 __ __  non-solid LZMA
        # __ __ __ 80 00 5D 00 00 DD DD 00 __  non-solid LZMA, empty filter
        # __ __ __ 80 01 5D 00 00 DD DD 00 __  non-solid LZMA, BCJ filter
        # __ __ __ 80 01 0T __ __ __ __ __ __  non-solid BZip
        # __ __ __ 80 __ __ __ __ __ __ __ __  non-solid deflate
        # 01 0T __ YY __ __ __ __ __ __ __ __  solid BZip
        # __ __ __ YY __ __ __ __ __ __ __ __  solid Deflate

        def lzmacheck(preview):
            if B'\x5D\0\0' not in preview[:4]:
                return False
            filter_flag = preview_bytes[0] <= 1
            reader.seekrel(3 + int(filter_flag))
            self.lzma_options = LZMAOptions(filter_flag, reader.u32())
            return True

        def bzipcheck(p):
            return p[0] == 0x31 and p[1] < 14

        preview_bytes = bytes(reader.peek(16))
        preview_check = preview_bytes.find(header_size.to_bytes(4, 'little'))
        self.solid = True
        self.extended = False

        self.lzma_options: Optional[LZMAOptions] = None
        self.method = NSMethod.Deflate

        self.entries: Dict[int, bytearray] = {}
        self.entry_offset_delta = 4
        self._solid_iter = None

        xtnsis.log_debug('header preview:', lambda: reader.peek(16).hex(' ', 1).upper())

        if preview_check >= 0:
            header_data_length = header_size
            self.method = NSMethod.Copy
            self.solid = False
            if not preview_check:
                header_prefix_size = 0x04
            elif preview_check == 8:
                header_prefix_size = 0x10
                self.extended = True
            else:
                raise ValueError(F'Found header length at unexpected offset {preview_check}; unknown NSIS format.')
            reader.seekrel(header_prefix_size)
            self.entry_offset_delta = header_prefix_size
            header_data = reader.read_exactly(header_data_length)
        elif lzmacheck(preview_bytes):
            self.method = NSMethod.LZMA
        elif preview_bytes[3] == 0x80:
            self.solid = False
            reader.seekrel(4)
            preview_bytes = bytes(reader.peek(4))
            if lzmacheck(preview_bytes):
                self.method = NSMethod.LZMA
            elif bzipcheck(preview_bytes):
                self.method = NSMethod.BZip2
        elif bzipcheck(preview_bytes):
            self.method = NSMethod.BZip2

        dbg_method = self.method.value
        if self.method is NSMethod.LZMA and self.lzma_options.filter_flag:
            dbg_method = F'{dbg_method}/BCJ'
        xtnsis.log_debug(F'compression: {dbg_method}')
        xtnsis.log_debug(F'archive is solid: {self.solid}')

        reader.seekset(self.archive_offset)

        if header_data is None:
            it = self._decompress_items(reader)
            header_entry = next(it)
            if header_entry.decompression_error:
                raise NotImplementedError(
                    U'This archive seems to use an NSIS-specific deflate algorithm which has not been implemented yet. '
                    F'Original error: {exception_to_string(header_entry.decompression_error)}')
            if self.solid:
                self._solid_iter = it
            self.entry_offset_delta += header_entry.size
            header_data = header_entry.data
        else:
            self.entry_offset_delta += len(header_data)

        if not header_data:
            raise ValueError('header data had length zero')

        xtnsis.log_debug(F'read header of length {len(header_data)}')

        self.header_data = header_data
        self.header = NSHeader(header_data, size=header_size, extended=self.extended)
        self.reader = reader

        if self.method is NSMethod.Deflate and self.header.nsis_deflate:
            self.method = NSMethod.NSGzip

    @property
    def script(self):
        return self.header.script

    @property
    def offset_items(self):
        return self.archive_offset + self.entry_offset_delta

    def _extract_item(self, item: NSItem) -> Entry:
        if self.solid:
            while True:
                try:
                    entry = self.entries[item.offset]
                except KeyError:
                    try:
                        entry = next(self._solid_iter)
                    except StopIteration:
                        raise LookupError(F'No data for item {item!s} could not be found.')
                    self.entries[entry.offset - self.entry_offset_delta] = entry
                else:
                    break
        else:
            self.reader.seek(self.offset_items + item.offset)
            dc = self._decompress_items(self.reader)
            entry = next(dc)
        if entry.decompression_error:
            err = exception_to_string(entry.decompression_error)
            msg = F'decompression failed ({err}); lenient mode will extract uncompressed item'
            raise RefineryPartialResult(msg, entry.data)
        else:
            return entry

    class SolidReader(Iterable[Entry]):
        def __init__(self, src: BinaryIO, prefix_length: int):
            self.src = src
            self.pos = 0
            self.prefix_length = prefix_length

        def __iter__(self):
            return self

        def __next__(self):
            offset = self.pos
            mask = (1 << ((self.prefix_length * 8) - 1)) - 1
            size = self.src.read(self.prefix_length)
            if len(size) != self.prefix_length:
                raise StopIteration
            size = int.from_bytes(size, 'little')
            read = size & mask
            data = self.src.read(read)
            if len(data) != read:
                raise EOFError('Unexpected end of stream while decompressing archive entries.')
            self.pos = offset + read + 4
            return NSArchive.Entry(offset, data, size)

    class PartsReader(SolidReader):
        def __init__(self, src: BinaryIO, decompressor: Optional[Type[BinaryIO]], prefix_length: int):
            super().__init__(src, prefix_length)
            self._dc = decompressor

        def __next__(self):
            item = super().__next__()
            is_compressed = bool(item.size & 0x80000000)
            item.size &= 0x7FFFFFFF
            if is_compressed:
                try:
                    dc = self._dc(MemoryFile(item.data))
                    item.data = dc.read()
                except Exception as E:
                    item.decompression_error = E
            return item

    class LZMAFix:
        def __init__(self, src: MemoryFile):
            self._src = src
            self._fix = MemoryFile(bytes(self._src.read(5)) + B'\xFF' * 8)

        def __getattr__(self, key):
            return getattr(self._src, key)

        def read(self, size: int = -1):
            src = self._src
            fix = self._fix
            if not fix.remaining_bytes:
                return src.read(size)
            if size < 0:
                size = fix.remaining_bytes + src.remaining_bytes
            out = bytearray(size)
            temp = fix.read(size)
            m = len(temp)
            out[:m] = temp
            out[m:] = src.read(size - m)
            return out

    def _decompress_items(self, reader: StructReader[bytearray]) -> Iterator[NSArchive.Entry]:
        def NSISLZMAFile(d: StructReader[bytearray]):
            if use_filter := self.lzma_options.filter_flag:
                use_filter = d.u8()
            if use_filter > 1:
                raise ValueError(F'LZMA/BCJ chunk with invalid filter indicator byte 0x{use_filter:X}')
            if not use_filter:
                _filter = None
                _format = None
                _stream = self.LZMAFix(d)
            else:
                _filter = parse_lzma_properties(d.read(5), 1)
                _filter = [dict(id=lzma.FILTER_X86), _filter]
                _format = lzma.FORMAT_RAW
                _stream = d
            return lzma.LZMAFile(_stream, filters=_filter, format=_format)

        decompressor: Type[BinaryIO] = {
            NSMethod.Copy    : None,
            NSMethod.Deflate : DeflateFile,
            NSMethod.NSGzip  : GZipFile,
            NSMethod.LZMA    : NSISLZMAFile,
            NSMethod.BZip2   : BZip2File,
        }[self.method]
        prefix_length = 8 if self.extended else 4
        if self.solid:
            return self.SolidReader(decompressor(reader), prefix_length)
        else:
            return self.PartsReader(reader, decompressor, prefix_length)


class xtnsis(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from NSIS archives.
    """

    @classmethod
    def _find_archive_offset(cls, data: bytearray, before: int = -1, flawmax=2):
        def signatures(*magics):
            for changes in range(flawmax + 1):
                for magic in magics:
                    if not changes:
                        yield 0, magic
                        continue
                    for positions in itertools.permutations(range(len(magic)), r=changes):
                        signature = bytearray(magic)
                        for p in positions:
                            signature[p] = 0x2E
                        yield changes, bytes(signature)
        best_guess = None
        search_space = memoryview(data)
        for flaws, sig in signatures(*NSArchive.MAGICS):
            if flaws > 1:
                search_space = search_space[:0x20_000]
            matches = [m.start() - 4 for m in re.finditer(sig, search_space, flags=re.DOTALL)]
            if before >= 0:
                matches = [match for match in matches if match < before]
            matches.reverse()
            archive = None
            for match in matches:
                if match % 0x200 == 0:
                    archive = match
                    break
            if not archive:
                if matches and not best_guess:
                    best_guess = matches[-1]
            else:
                msg = F'Archive signature was found at offset 0x{archive:X}'
                if flaws > 0:
                    msg = F'{msg}; it has {flaws} imperfections and was likely modified'
                cls.log_info(F'{msg}.')
                return archive
        if best_guess:
            cls.log_info(F'A signature was found at offset 0x{best_guess:08X}; it is not properly aligned.')
            return best_guess
        return None

    def unpack(self, data):
        memory = memoryview(data)
        before = -1
        _error = None
        while True:
            offset = self._find_archive_offset(data, before)
            if offset is None:
                _error = _error or ValueError('Unable to find an NSIS archive marker.')
                raise _error
            try:
                arc = NSArchive(memory[offset:])
            except Exception as e:
                _error = e
                before = offset
            else:
                break

        def info():
            yield F'{arc.header.type.name} archive'
            yield F'compression type {arc.method.value}'
            yield F'mystery value 0x{arc.header.unknown_value:X}'
            yield 'solid archive' if arc.solid else 'fragmented archive'
            yield '64-bit header' if arc.header.is64bit else '32-bit header'
            yield 'unicode' if arc.header.unicode else 'ascii'

        self.log_info(', '.join(info()))

        for item in arc.header.items:
            yield self._pack(item.path, item.mtime, lambda i=item: arc._extract_item(i).data)

        yield self._pack('setup.bin', None, arc.header_data)
        yield self._pack('setup.nsis', None, arc.script.encode(self.codec))

    @classmethod
    def handles(cls, data: bytearray) -> bool:
        return any(magic in data for magic in NSArchive.MAGICS)
