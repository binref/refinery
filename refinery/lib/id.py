"""
This module contains functions to identify certain file formats; some of these functions are used
by units who operate on the same file format to implement the `refinery.units.Unit.handles` method.
The method `refinery.lib.id.get_structured_data_type` is used to determine whether an unknown blob
is a known data format. Units like `refinery.decompress` or `refinery.autoxor` use this as part of
their heuristics to determine that a high quality output has been generated.
"""
from __future__ import annotations

import enum
import re

from typing import Callable, NamedTuple

from refinery.lib.tools import entropy, meminfo
from refinery.lib.types import buf

MimeByExtension = {
    'bin'   : 'application/ocet-stream',
    'exe'   : 'application/exe',
    'sys'   : 'application/exe',
    'dll'   : 'application/exe',
    'elf'   : 'application/x-elf-executable',
    'macho' : 'application/x-mach-binary',
    'class' : 'application/java-byte-code',
    'pdf'   : 'application/pdf',
    'djvu'  : 'image/vnd.djvu',
    'pcap'  : 'application/vnd.tcpdump.pcap',
    'db'    : 'application/x-sqlite3',
    'mdb'   : 'application/x-msaccess',
    'doc'   : 'application/msword',
    'xls'   : 'application/vnd.ms-excel',
    'ppt'   : 'application/vnd.ms-powerpoint',
    'msg'   : 'application/vnd.ms-outlook',
    'msi'   : 'application/x-msi',
    'docx'  : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'pptx'  : 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'xlsx'  : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'txt'   : 'text/plain',
    'json'  : 'application/json',
    'xml'   : 'application/xml',
    'html'  : 'text/html',
    'rtf'   : 'application/rtf',
    'vbe'   : 'text/plain',
    'eml'   : 'message/rfc822',
    'ico'   : 'image/vnd.microsoft.icon',
    'gif'   : 'image/gif',
    'tif'   : 'image/tiff',
    'jpg'   : 'image/jpeg',
    'png'   : 'image/png',
    'bmp'   : 'image/bmp',
    'ogg'   : 'audio/ogg',
    'wav'   : 'audio/wav',
    'avi'   : 'video/x-msvideo',
    'mp3'   : 'audio/mpeg',
    'm3u'   : 'text/plain',
    'mp4'   : 'video/mp4',
    'mpg'   : 'video/mpeg',
    'mid'   : 'audio/midi',
    'mkv'   : 'video/x-matroska',
    'swf'   : 'application/x-shockwave-flash',
    'tar'   : 'application/x-tar',
    '7z'    : 'application/x-7z-compressed',
    'zip'   : 'application/zip',
    'rar'   : 'application/vnd.rar',
    'cab'   : 'application/vnd.ms-cab-compressed',
    'bz'    : 'application/x-bzip',
    'bz2'   : 'application/x-bzip2',
    'gz'    : 'application/gzip',
    'xz'    : 'application/x-xz',
    'zstd'  : 'application/x-zstd',
    'zlib'  : 'application/zlib',
}


class Format:
    __slots__ = 'category', 'extension', 'mime', 'mnemonic', 'details'

    def __hash__(self):
        return hash(tuple(self))

    def __eq__(self, other):
        if not isinstance(other, Format):
            return False
        return all(a == b for a, b in zip(self, other))

    def __iter__(self):
        yield self.category
        yield self.extension
        yield self.mnemonic
        yield self.details
        yield self.mime

    def __init__(
        self,
        category: FormatCategory,
        extension: str | None = None,
        mnemonic: str | None = None,
        details: str | None = None,
        mime: str | None = None,
    ) -> None:
        self.category = category
        self.extension = extension or 'bin'
        self.mnemonic = mnemonic or self.extension.upper()
        self.details = details or self.mnemonic

        if mime is None:
            try:
                mime = MimeByExtension[self.extension]
            except KeyError:
                if category == FormatCategory.Text:
                    mime = 'text/plain'
                else:
                    mime = 'application/ocet-stream'

        self.mime = mime


class FormatCategory(enum.IntEnum):
    Executable = enum.auto()
    Text = enum.auto()
    Document = enum.auto()
    Image = enum.auto()
    Binary = enum.auto()
    Media = enum.auto()
    Archive = enum.auto()
    Compression = enum.auto()
    Serialized = enum.auto()


FC = FormatCategory

PycMagicPattern = re.compile(br'''(?x)
   [\x02\x03]\x99\x99\x00
  |(?:
  | \xca\xfe
  | \x89\x2e
  | \x04\x17
  | \x99\x4e
  | \xfc\xc4
  | \x87\xc6
  | \x65\x34
  | \x31\x61
  | \x2a\xeb
  | \x2d\xed
  |[\x3b\x45\x59\x63\x6d\x77\x81\x8b\x8c\x95\x9f\xa9\xb3\xb7\xc7\xd1\xdb\xe5\xef\xf9]\xf2
  |[\x03\x0a]\xf3
  | \x61\x0a
  |[\xb8\xc2\xcc\xd6\xe0\xea\xf4\xf5\xff]\x0b
  |[\x09\x13\x1d\x1f\x27\x3b\x45\x4f\x58\x62\x6c\x73\x76\x80\x94\x8a\x9e\xb2\xbc\xc6\xd0\xda\xe4\xee\xf8]\x0c
  |[\x02\x0c\x16\x17\x20\x21\x2a-\x2d\x2f-\x33\x3e-\x42\x48\x49\x52-\x55\x5c-\x61\x66-\x6f\x7a-\xa7\xac-\xcb\xde-\xf3]\x0d
  |[\x10-\x18\x1a\x1b\x1d-\x29\x2b\x47]\x0e
  |[\x30\x40\x70\xa0\xc0\xe0\xf0]\x00
  |[\x00\x40\x50\x80\xa0]\x01
  | \x61\x32
  | \x61\x31
  | \x9e\x52
  |[\x20\x2a]\x53
  | \xf3\x03
  | \x7a\x56
  ) \x0D\x0A
''')


class Fmt(Format, enum.Enum):
    """
    An enumeration of all known file formats that can be returned by
     `refinery.lib.id.get_structured_data_type`.
    """

    PE32GUI = (FC.Executable, 'exe', 'PE/32/GUI')
    PE32CUI = (FC.Executable, 'exe', 'PE/32/CUI')
    PE32DLL = (FC.Executable, 'dll', 'PE/32/DLL')
    PE32SYS = (FC.Executable, 'sys', 'PE/32/SYS')
    PE64GUI = (FC.Executable, 'exe', 'PE/64/GUI')
    PE64CUI = (FC.Executable, 'exe', 'PE/64/CUI')
    PE64DLL = (FC.Executable, 'dll', 'PE/64/DLL')
    PE64SYS = (FC.Executable, 'sys', 'PE/64/SYS')

    ELF32LE = (FC.Executable, 'elf', 'ELF/32/LE')
    ELF64LE = (FC.Executable, 'elf', 'ELF/64/LE')
    ELF32BE = (FC.Executable, 'elf', 'ELF/32/BE')
    ELF64BE = (FC.Executable, 'elf', 'ELF/64/BE')

    MACHOuvLE = (FC.Executable, 'macho', 'MachO/Fat/LE')
    MACHOuvBE = (FC.Executable, 'macho', 'MachO/Fat/BE')
    MACHO32LE = (FC.Executable, 'macho', 'MachO/32/LE')
    MACHO64LE = (FC.Executable, 'macho', 'Macho/64/LE')
    MACHO32BE = (FC.Executable, 'macho', 'MachO/32/BE')
    MACHO64BE = (FC.Executable, 'macho', 'Macho/64/BE')

    JAVA = (FC.Executable, 'class', 'JavaClass')
    DEX = (FC.Executable, 'dex', 'Dalvik')
    WASM = (FC.Executable, 'wasm', 'WASM', 'Web Assembly')
    LUAC = (FC.Executable, 'luac', 'LUAC', 'LUA Bytecode')
    PYC = (FC.Executable, 'pyc', 'PYC', 'Python Bytecode')

    PDF = (FC.Document, 'pdf', 'PDF', 'PDF Document')
    CHM = (FC.Document, 'chm', 'CHM', 'Microsoft Windows HtmlHelp Data')
    DJV = (FC.Document, 'djvu')

    PCAP = (FC.Binary, 'pcap', 'PCAP', 'Network Packet Capture')
    PCAPNG = (FC.Binary, 'pcapng', 'PCAP/NG', 'Next-Generation Network Packet Capture')
    SSP = (FC.Binary, 'ssp', 'SmartSniff', 'SmartSniff Packets File')
    SQLITE = (FC.Binary, 'db', 'SQLite', 'SQLite Database')
    DSS = (FC.Binary, 'DS_Store', 'DSS', 'MacOS DS Store')
    A3X = (FC.Binary, 'a3x', 'A3X', 'Compiled AutoIt3')
    IFPS = (FC.Binary, 'ifps', 'IFPS', 'InnerFuse PascalScript')
    PPK = (FC.Binary, 'ppk', 'PuTTY', 'PuTTY Private Key File')
    WIM = (FC.Binary, 'wim', 'WIM', 'Windows Imaging Format')
    EVT = (FC.Binary, 'evt', 'EVT', 'Windows Event Viewer')
    EVTX = (FC.Binary, 'evtx', 'EVTX', 'Windows Event Viewer XML')
    LNK = (FC.Binary, 'lnk', 'LNK', 'Windows Shortcut')
    DMP = (FC.Binary, 'dmp', 'MDMP', 'Mini DuMP Crash Report')

    REG_HIVE = (FC.Binary, 'reg', 'WinReg/Hive', 'Windows Registry Hive File', 'text/plain')
    REG_TEXT = (FC.Binary, 'reg', 'WinReg/Text', 'Windows Registry Script')

    MDB = (FC.Document, 'accdb', 'MDB', 'Microsoft Access Database')
    DOC = (FC.Document, 'doc')
    ONE = (FC.Document, 'one')
    XLS = (FC.Document, 'xls')
    PPT = (FC.Document, 'ppt')
    MSG = (FC.Document, 'msg')
    MSI = (FC.Archive, 'msi')
    CFF = (FC.Binary, 'ole', 'Compound File Format')

    DOCX = (FC.Document, 'docx')
    XLSX = (FC.Document, 'xlsx')
    PPTX = (FC.Document, 'pptx')

    ASCII = (FC.Text, 'txt', 'PlainText', 'Single-Byte, Plain Text Encoding')
    UTF16 = (FC.Text, 'txt', 'UTF16')
    UTF32 = (FC.Text, 'txt', 'UTF32')

    JSON = (FC.Text, 'json')
    XML = (FC.Text, 'xml')
    HTM = (FC.Text, 'html')
    RTF = (FC.Text, 'rtf', 'RTF')
    VBE = (FC.Text, 'vbe', 'VBE', 'Encoded VBScript')
    EML = (FC.Text, 'eml', 'EML', 'Plain-Text EMail Document')

    HIC = (FC.Image, 'heic', 'HEIC', 'High Efficiency Image Container')
    ICO = (FC.Image, r'ico', r'ICO', 'Icon')
    GIF = (FC.Image, r'gif', r'GIF', 'Graphics Interchange Format')
    TIF = (FC.Image, r'tif', r'TIF', 'Tagged Image File Format')
    CIN = (FC.Image, r'cin', r'CIN', 'Kodak Cineon Image')
    NUI = (FC.Image, r'nui', r'NUI', 'Nuru ASCI/ANSI Image or Palette')
    DPX = (FC.Image, r'dpx', r'DPX', 'SMPTE DPX Image')
    BPG = (FC.Image, r'bpg', r'BPG', 'Better Portable Graphics')
    EXR = (FC.Image, r'exr', r'EXR', 'OpenEXR Image')
    JPG = (FC.Image, r'jpg', r'JPG', 'Joint Photographic Experts Group Image')
    JP2 = (FC.Image, r'jp2', r'JP2', 'JPEG 2000')
    QOI = (FC.Image, r'qoi', r'QOI', 'Quite OK Image Format')
    IFF = (FC.Image, r'iff', r'IFF', 'IFF or Amiga Image')
    PNG = (FC.Image, r'png', r'PNG', 'Portable Network Graphics')
    PSD = (FC.Image, r'psd', r'PSD', 'Adobe Photoshop Document')
    BMP = (FC.Image, r'bmp', r'BMP', 'Bitmap')
    FIF = (FC.Image, 'flif', 'FLIF', 'Free Lossless Image Format')
    LEP = (FC.Image, r'lep', r'LEP', 'Lepton Compressed JPEG Image')
    HDR = (FC.Image, r'hdr', r'HDR', 'Radiance High Dynamic Range Image')

    OGG = (FC.Media, 'ogg')
    WAV = (FC.Media, 'wav')
    AVI = (FC.Media, 'avi')
    MP3 = (FC.Media, 'mp3')
    M3U = (FC.Media, 'm3u', 'M3U', 'Multimedia Playlist')
    MP4 = (FC.Media, 'mp4')
    MPG = (FC.Media, 'mpg')
    FLC = (FC.Media, 'flac')
    MID = (FC.Media, 'mid')
    MKV = (FC.Media, 'mkv')
    SWF = (FC.Media, 'swf')
    SIL = (FC.Media, 'sil')

    ACE = (FC.Archive, 'ace')
    ASAR = (FC.Archive, 'asar')
    VHD = (FC.Archive, 'vhd')
    VMDK = (FC.Archive, 'vmdk')
    ISO = (FC.Archive, 'iso')
    ISZ = (FC.Archive, 'isz', 'ISZ', 'Compressed ISO Image')
    DMG = (FC.Archive, 'dmg')
    XAR = (FC.Archive, 'xar', 'XAR', 'eXtensible ARchive Format')
    TAR = (FC.Archive, 'tar')
    OAR = (FC.Archive, 'oar')
    ZIP7 = (FC.Archive, '7z', '7Zip')
    ZIP = (FC.Archive, 'zip')
    RAR = (FC.Archive, 'rar')
    CAB = (FC.Archive, 'cab')
    CPIO = (FC.Archive, 'cpio')
    ZPQ = (FC.Archive, 'zpq')

    S_JAV = (FC.Serialized, 'bin', 'SerializedJava')
    S_DOT = (FC.Serialized, 'bin', 'SerializedDotNet')
    S_PHP = (FC.Serialized, 'bin', 'SerializedPHP')

    APLIB = (FC.Compression, 'ap', 'apLib')
    BZ2 = (FC.Compression, 'bz2', 'BZIP')
    JCALG = (FC.Compression, 'bin', 'jcAlg')
    LZMA = (FC.Compression, 'lzma')
    LZF = (FC.Compression, 'lzf')
    LZH = (FC.Compression, 'lzh')
    LZG = (FC.Compression, 'lzg')
    RNC = (FC.Compression, 'rnc', 'RNC', 'Rob Northern Compression')
    LZIP = (FC.Compression, 'lzip')
    LZO = (FC.Compression, 'lzo')
    LZ4 = (FC.Compression, 'lz4')
    LZW = (FC.Compression, 'lzw')
    LZFSE = (FC.Compression, 'lzfse')
    MSCF = (FC.Compression, 'mscf')
    SZDD = (FC.Compression, 'szdd')
    GZIP = (FC.Compression, 'gz')
    XZ = (FC.Compression, 'xz', 'XZ/LZMA2')
    ZLIB0 = (FC.Compression, 'zlib', 'ZLIB/0')
    ZLIB1 = (FC.Compression, 'zlib', 'ZLIB/1')
    ZLIB2 = (FC.Compression, 'zlib', 'ZLIB/2')
    ZLIB3 = (FC.Compression, 'zlib', 'ZLIB/3')
    ZLIB4 = (FC.Compression, 'zlib', 'ZLIB/4')
    ZLIB5 = (FC.Compression, 'zlib', 'ZLIB/5')
    ZLIB6 = (FC.Compression, 'zlib', 'ZLIB/6')
    ZLIB7 = (FC.Compression, 'zlib', 'ZLIB/7')
    ZSTD = (FC.Compression, 'zstd')


FormatDetails = {format.mnemonic: format for format in Fmt}
StructuralChecks: list[Callable[[buf], Fmt | None]] = []


def _structural_check(fn: Callable[[buf], Fmt | None]):
    StructuralChecks.append(fn)
    return fn


@_structural_check
def get_pe_type(data: buf):
    """
    Get the correct file type extension for a PE file, or None if the input is unlikely to be a
    portable executable in the first place.
    """
    if data[:2] != B'MZ':
        return None
    nt = data[0x3C:0x3E]
    if len(nt) < 2:
        return None
    nt = int.from_bytes(nt, 'little')
    if data[nt:nt + 4] != B'PE\0\0':
        return None
    arch = data[nt + 4:nt + 6]
    if arch == B'\x64\x86':
        dll = Fmt.PE32DLL
        sub = (
            Fmt.PE32SYS,
            Fmt.PE32GUI,
            Fmt.PE32CUI,
        )
    elif arch == B'\x4C\x01':
        dll = Fmt.PE64DLL
        sub = (
            Fmt.PE64SYS,
            Fmt.PE64GUI,
            Fmt.PE64CUI,
        )
    else:
        return None
    if data[nt + 0x16] & 0x20:
        return dll
    subsystem = data[nt + 0x5C] - 1
    if not 0 <= subsystem <= 2:
        return None
    return sub[subsystem]


@_structural_check
def get_elf_type(data: buf):
    """
    Get arch and byte order information of an ELF file or return None if the input is unlikely to be one.
    """
    if not data[:4] == b'\x7FELF':
        return None
    abo = data[4:6]
    if len(data) < 0x40:
        return None
    elif data[6] != 1: # EI_VERSION
        return None
    elif abo == B'\x01\x01':
        return Fmt.ELF32LE
    elif abo == B'\x01\x02':
        return Fmt.ELF32BE
    elif abo == B'\x02\x01':
        return Fmt.ELF64BE
    elif abo == B'\x02\x02':
        return Fmt.ELF64BE


@_structural_check
def get_macho_type(data: buf):
    """
    Get arch and byte order information of a MachO file or return None if the input is unlikely to be one.
    """
    order = 'little'
    magic = int.from_bytes(data[:4], order)
    isfat = False

    if len(data) < 30:
        return None
    elif magic == 0xCE_FAEDFE:
        order = 'big'
        mtype = Fmt.MACHO32BE
    elif magic == 0xCF_FAEDFE:
        order = 'big'
        mtype = Fmt.MACHO64BE
    elif magic == 0xFEEDFACE:
        mtype = Fmt.MACHO32LE
    elif magic == 0xFEEDFACF:
        mtype = Fmt.MACHO64BE
    elif magic == 0xCAFEBABE:
        mtype = Fmt.MACHOuvLE
        isfat = True
    elif magic == 0xBEBAFECA:
        mtype = Fmt.MACHOuvBE
        isfat = True
    else:
        return None
    if isfat:
        cpu = int.from_bytes(data[8:0xC], order)
    else:
        cpu = int.from_bytes(data[4:0x8], order)
    if cpu in (
        0x00000001, # vax
        0x00000002, # ROMP
        0x00000004, # NS32032
        0x00000005, # NS32332
        0x00000006, # mc680x0
        0x00000007, # x32
        0x01000007, # x64
        0x00000008, # mips
        0x00000009, # NS32352
        0x0000000A, # mc98000
        0x0000000B, # hppa
        0x0000000C, # arm32
        0x0100000C, # arm64
        0x0000000D, # mc880000
        0x0000000E, # sparc
        0x0000000F, # i860
        0x00000010, # alpha
        0x00000011, # RS/6000
        0x00000012, # ppc32
        0x01000012, # ppc64
    ):
        return mtype


def get_executable_type(data: buf):
    """
    Determine the type of an executable.
    """
    if t := get_pe_type(data):
        return t
    if t := get_elf_type(data):
        return t
    if t := get_macho_type(data):
        return t


def is_likely_pe(data: buf):
    """
    Tests whether the input data is likely a PE file by checking the first two bytes and the magic
    bytes at the beginning of what should be the NT header.
    """
    return get_pe_type(data) is not None


def slice_offset(haystack: slice, needle: slice):
    """
    Assuming that haystack and needle are used to slice the same buffer, this method determines the
    offset of that needle in the haystack, or `-1` if the haystack would not contain the needle.
    """
    h_start = 0 if haystack.start is None else haystack.start
    h_stop = haystack.stop
    h_step = haystack.step or 1
    n_start = 0 if needle.start is None else needle.start
    n_stop = needle.stop
    n_step = needle.step or 1
    offset = n_start - h_start
    offset, remainder = divmod(offset, h_step)
    single_byte = False
    if h_stop is not None:
        if n_stop is None:
            return -1
        h_length, hr = divmod(h_stop - h_start, h_step)
        n_length, nr = divmod(n_stop - n_start, n_step)
        h_length += bool(hr)
        n_length += bool(nr)
        if n_length == 0:
            return 0
        if n_length + offset > h_length:
            return -1
        if n_length == 1:
            single_byte = True
    if n_step != h_step and not single_byte:
        return -1
    if offset < 0:
        return -1
    if remainder != 0:
        return -1
    return offset


def buffer_offset(
    haystack: buf,
    needle: buf,
    start: int = 0,
    end: int | None = None,
    ncopy: int = 0x100,
    back2front: bool = False,
) -> int:
    """
    Performs a substring search of `needle` in `haystack`. If `haystack` is a `bytes`-like object,
    it uses the standard method. If it is a `memoryview`, the function first checks whether it is
    a view onto a bytes or bytearray object at offset 0: In this case, it can reduce to using the
    underlying object's standard method. Otherwise, it uses a regular expression search. This fails
    when the memoryview is not contiguous: In this case, a bytearray is constructed from the view
    and searched instead.
    """
    if (nc := len(needle)) == 0:
        return 0
    if (hc := len(haystack)) == 0:
        return -1
    if isinstance(haystack, memoryview):
        hs: memoryview = haystack[start:end] # type:ignore
        hi = meminfo(hs)
        if hi and hi.start == 0 and isinstance((obj := hs.obj), (bytes, bytearray)):
            end = len(hs) if end is None else min(len(hs), end)
            return buffer_offset(obj, needle, start, end, ncopy=ncopy, back2front=back2front)
        elif back2front:
            nv = memoryview(needle)
            _s = 0 if end is None else hc - end
            _e = hc - start if start else None
            pos = buffer_offset(haystack[::-1], nv[::-1], _s, _e, ncopy)
            if pos < 0:
                return -1
            return hc - pos - len(nv)
        if isinstance(needle, memoryview):
            if hi and haystack.obj is needle.obj and (ni := meminfo(needle)):
                if (offset := slice_offset(hi, ni)) >= 0:
                    return offset
        if not hs.contiguous:
            haystack = bytearray(haystack)
        else:
            prefix = needle[:ncopy]
            if isinstance(prefix, memoryview):
                prefix = bytes(prefix)
            match_sufficient = True
            suffix = B''
            pattern = re.escape(prefix)
            if rest := nc - len(prefix):
                if rest > ncopy:
                    suffix = needle[-ncopy:]
                    match_sufficient = False
                    rest -= ncopy
                else:
                    suffix = needle[-rest:]
                if isinstance(suffix, memoryview):
                    suffix = bytes(suffix)
            if suffix:
                suffix = re.escape(suffix)
                if rest > 0:
                    suffix = B'.{%d}%s' % (rest, suffix)
                pattern += suffix
            for m in re.finditer(pattern, hs):
                offset = start + m.start()
                if match_sufficient or haystack[offset:offset + nc] == needle:
                    return offset
            else:
                return -1
    if isinstance(needle, memoryview) and not needle.contiguous:
        needle = bytearray(needle)
    find = haystack.rfind if back2front else haystack.find
    return find(needle, start, end)


def buffer_contains(haystack: buf, needle: buf):
    """
    Determines whether `haystack` contains `needle`.
    """
    return buffer_offset(haystack, needle) > 0


def is_likely_pe_dotnet(data: buf):
    """
    Tests whether the input data is likely a .NET PE file by running `refinery.lib.id.is_likely_pe`
    and also checking for the characteristic strings `BSJB`, `#Strings`, and `#Blob`.
    """
    if not is_likely_pe(data):
        return False
    if not buffer_contains(data, b'BSJB'):
        return False
    if not buffer_contains(data, b'#Strings'):
        return False
    if not buffer_contains(data, b'#Blob'):
        return False
    return True


@_structural_check
def get_reg_export_type(data: buf):
    """
    Check whether the input data is a Windows registry file export.
    """
    if data[:4] == b'regf':
        return Fmt.REG_HIVE
    if data[:31] == b'Windows Registry Editor Version':
        return Fmt.REG_TEXT


class TextEncoding(NamedTuple):
    bom: int = 0
    lsb: int = 0
    step: int = 1


def guess_text_encoding(
    data: buf,
    window_size: int = 0x1000,
    ascii_ratio: float = 0.98,
) -> TextEncoding | None:
    """
    Attempts to determine whether the input data is likely printable text. The return value is None
    if the input is unlikely to be text. Otherwise, the return value is a triple of integers: First
    the offset after the byte order mark (`0` in case there is none), then the offset of the first
    low byte of a character (odd for big endian encodings, even for others) and finally the size of
    each encoded character in bytes.
    """
    def ascii_count(v: memoryview):
        count = 0
        ascii = range(0x20, 0x80)
        b = 0xFF
        for b in v:
            count += (b in ascii or b == 9 or b == 10 or b == 13)
        if b == 0 and count > 0:
            # accept a terminating null byte
            count += 1
        return count

    view = memoryview(data)
    size = window_size
    step = 1
    maxbad = 1 - ascii_ratio
    bom = 0
    lsb = 0

    if data[:3] == B'\xEF\xBB\xBF':
        # BOM: UTF8
        bom = 3
    elif data[:4] == B'\xFF\xFE\0\0':
        step = bom = lsb = 4 # UTF-32LE
    elif data[:2] == B'\xFF\xFE':
        step = bom = lsb = 2 # UTF-16LE
    elif data[:2] == B'\xFE\xFF':
        step, bom, lsb = 2, 2, 3
    elif data[:4] == B'\0\0\xFE\xFF':
        step, bom, lsb = 4, 4, 7
    elif any(data[:4] == bom for bom in (
        b'\x2B\x2F\x76\x38',
        b'\x2B\x2F\x76\x39',
        b'\x2B\x2F\x76\x2B',
        b'\x2B\x2F\x76\x2F',
    )):
        # UTF7 BOM
        bom = 4
    elif len(view) % 2 == 0:
        u16le = (win := view[1:size:2]) and ascii_count(win) / len(win) <= maxbad
        u16be = (win := view[0:size:2]) and ascii_count(win) / len(win) <= maxbad
        if u16le:
            if u16be:
                return None
            step, lsb = 2, 0
        elif u16be:
            step, lsb = 2, 1

    win = view[lsb:size:step]

    if step > 1:
        if len(data) % step != 0:
            return None
        if not win or ascii_count(win) / len(win) < ascii_ratio:
            return None

    if len(data) <= bom:
        return None

    if not size:
        return TextEncoding(bom, lsb, step)

    if isinstance(data, (bytes, bytearray)):
        histogram = [data.count(b, bom, size) for b in range(0x100)]
    else:
        histogram = [0] * 256
        for b in view[bom:size]:
            histogram[b] += 1

    presence = memoryview(bytes(1 if v else 0 for v in histogram))

    if sum(presence) > 102:
        # 96 printable ASCII characters plus some slack for control bytes or encoding
        return None
    if sum(presence[0x7F:]) > 5:
        # Allow for some control characters or encoding-specific values
        return None
    if sum(presence[:0x20]) > 5:
        # Tab, CR, LF, Null, plus one byte slack
        return None

    bad = sum(histogram[:0x20]) + sum(histogram[0x7F:]) \
        - histogram[0x0D] \
        - histogram[0x0A] \
        - histogram[0x09]
    if step > 1:
        # disregard zeros for this case
        bad -= histogram[0]
    if bad / sum(histogram) <= maxbad:
        return TextEncoding(bom, lsb, step)


def xml_or_html(view: buf):
    """
    Returns an `refinery.lib.id.Fmt` indicating either XML or HTML, or None if the data does not
    look like either of these formats at all.
    """
    if tag_match := re.search(BR'''(?x)
        ^               # at the very start of the document
        \s{0,10}        # allow for some leading white space
        <               # a tag opens
        ([?!]?          # allow for question or exclamation mark
         [-:\w]{3,64})  # the tag name
        \s{1,20}        # white space after tag name
        (/?>            # the tag may end here, or:
        |[-:\w]{3,32})  # we have an attribute.
    ''', view):
        tag = tag_match[1].lower()
        end = tag_match[2].lower()
        # <?xml...
        if tag == b'?xml':
            return Fmt.XML
        # <HTML>
        # <BODY>
        if tag in (b'html', b'body'):
            return Fmt.HTM
        # <!DOCTYPE html
        if tag == b'!doctype' and end == b'html':
            return Fmt.HTM
        # <project xmlns:xsi=...
        if end.startswith(b'xml'):
            return Fmt.XML
        else:
            return Fmt.HTM
    return None


def ascii_view(
    data: buf,
    window_size: int = 0x1000,
    ascii_ratio: float = 0.98,
):
    """
    If the input data looks like text, get a memoryview of the least significant bytes of each
    encoded letter. Otherwise, return None. Whether or not the data looks like text is determined
    using `refinery.lib.id.guess_text_encoding`; all parameters are forwarded to this function.
    """
    if encoding := guess_text_encoding(data, window_size=window_size, ascii_ratio=ascii_ratio):
        return memoryview(data)[encoding.lsb:len(data):encoding.step]


def is_likely_eml(
    data: buf,
    window_size: int = 0x10000,
):
    """
    Checks the input for common strings that occur as email headers. If at least two are found,
    the function returns True.
    """
    hits = 0
    view = memoryview(data)[:window_size]
    for marker in (
        b'\nReceived:\x20from',
        b'\nSubject:\x20',
        b'\nTo:\x20',
        b'\nFrom:\x20',
        b'\nMessage-ID:\x20',
        b'\nBcc:\x20',
        b'\nContent-Transfer-Encoding:\x20',
        b'\nContent-Type:\x20',
        b'\nReturn-Path:\x20',
    ):
        if not buffer_contains(view, marker):
            continue
        if (hits := hits + 1) >= 2:
            return True
    else:
        return False


def is_likely_vbe(data: buf):
    """
    Checks whether the input contains the known markers used by encoded Visual Basic scripts.
    """
    view = memoryview(data)
    if not buffer_contains(view[:+64], BR'#@~^'):
        return False
    if not buffer_contains(view[-64:], BR'==^#~@'):
        return False
    return True


def is_likely_json(data: buf):
    """
    A fast regular expression based check for whether the input looks like JSON. The expression
    checks whether the input is a sequence of valid JSON tokens: quoted strings, constants,
    integer and floating-point numbers, and control characters. To be explicit, note that this
    function cannot check for correct nesting, regular expressions are insufficient for this.
    """
    _json = RB"""
        \s*((                               # a sequence of the following tokens:
           "([^"\\\r\n]|\\[^\r\n])*"        # a quoted string literal
          | true                            # true
          | false                           # false
          | null                            # null
          | [-+]?([1-9]\d*|0)               # an integer
          | [-+]?\d*\.?\d+([eE][-+]?\d+)?   # a float
          | [\{\}\[\]:,]                    # a structural token
        # | //(.*?)\n                       # do not allow comments (line)
        # | /\*.*?\*/                       # do not allow comments (block)
        )\s*)*?
    """
    _json = RB'(?x)\s*(\{%s\})|(\[%s\])\s*' % (_json, _json)
    return re.fullmatch(_json, data) is not None


@_structural_check
def get_microsoft_format(data: buf):
    """
    Checks for various Microsoft formats. This includes Access Database files and OneNote, but most
    importantly it can distinguish between various compound document formats like MSI, Word, Excel,
    PowerPoint, and Outlook.
    """
    if data[:19] == b'\0\01\0\0Standard ACE DB':
        return Fmt.MDB
    if data[:19] == b'\0\01\0\0Standard Jet DB':
        return Fmt.MDB
    if data[:4] != B'\xD0\xCF\x11\xE0':
        return None
    if data[4:8] != B'\xA1\xB1\x1A\xE1' and any(data[4:12]):
        return None
    if buffer_contains(data, b'\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3'):
        return Fmt.ONE
    for k in range(0x200, 0x10000, 0x200):
        mark = int.from_bytes(data[k:k + 4], 'little')
        if mark == 0x00C1A5EC:
            return Fmt.DOC
        if mark == 0x00100809 and data[k + 4:k + 8] == B'\x00\x06\x05\x00':
            return Fmt.XLS
        if mark == 0xF01D46A0:
            return Fmt.PPT
        if mark == 0xF01E6E00:
            return Fmt.PPT
        if mark == 0x03E8000F:
            return Fmt.PPT
    if buffer_contains(data, b'W\0o\0r\0d\0D\0o\0c\0u\0m\0e\0n\0t\0'):
        # WordDocument
        return Fmt.DOC
    if buffer_contains(data, b'P\0o\0w\0e\0r\0P\0o\0i\0n\0t\0'):
        # PowerPoint
        return Fmt.PPT
    if buffer_contains(data, b'W\0o\0r\0k\0b\0o\0o\0k\0'):
        # Workbook
        return Fmt.XLS
    if buffer_contains(data, b'_\0_\0s\0u\0b\0s\0t\0g\01\0.\00\0_\0'):
        # __substg1._
        return Fmt.MSG
    if buffer_contains(data, b'_\0_\0n\0a\0m\0e\0i\0d\0_\0v\0e\0r\0s\0i\0o\0n\0'):
        # __nameid_version
        return Fmt.MSG
    if buffer_contains(data, b'_\0_\0r\0e\0c\0i\0p\0_\0v\0e\0r\0s\0i\0o\0n\0'):
        # __recip_version
        return Fmt.MSG
    if buffer_contains(data, b'_\0_\0p\0r\0o\0p\0e\0r\0t\0i\0e\0s\0_\0v\0e\0r\0s\0i\0o\0n\0'):
        # __properties_version
        return Fmt.MSG
    if buffer_contains(data, b'B\0o\0o\0k\0'):
        # Book
        return Fmt.XLS
    if re.search(b'Property|ProductCode|UpgradeCode|PackageCode|InstallExecuteSequence|Component|Feature|File|Media', data):
        return Fmt.MSI
    if re.search(B'Msi(?:[A-Z][a-z]{2,30}){2,5}', data):
        return Fmt.MSI
    else:
        return Fmt.CFF


@_structural_check
def get_office_xml_type(data: buf):
    """
    Checks for known XML-based Office document types like DOCX, XLSX, and PPTX.
    """
    if data[:2] != B'PK':
        return None
    if not buffer_contains(data, B'_rels/.rels'):
        return None
    if not buffer_contains(data, B'[Content_Types].xml'):
        return None
    if buffer_contains(data, B'word/document.xml'):
        return Fmt.DOCX
    if buffer_contains(data, B'xl/document.xml'):
        return Fmt.XLSX
    if buffer_contains(data, B'ppt/presentation.xml'):
        return Fmt.PPTX


@_structural_check
def get_compression_type(
    data: buf,
    entropy_minimum: float = 0.7,
    entropy_look_at: int = 0x2000,
):
    """
    This method looks for any of a number of known magic signatures for compression and archive
    formats. If one is find, the method selects a data window from the rest of the buffer and
    computes its entropy. If the entropy exceeds the given threshold, the input is idenfied as
    a known compression format.
    """
    size = len(data)
    view = memoryview(data)
    T = True
    F = False

    if data[:4] == b'\04\0\0\0' and data[0x10:0x18] == B'{"files"':
        return Fmt.ASAR

    for format, entropy_required, offset, signature in (
        (Fmt.APLIB       , T, 0, B'AP32'),                                      # noqa
        (Fmt.ACE         , F, 7, B'**ACE**'),                                   # noqa
        (Fmt.BZ2         , T, 0, B'BZh'),                                       # noqa
        (Fmt.JCALG       , T, 0, B'JC'),                                        # noqa
        (Fmt.LZMA        , T, 0, B'\x5D\0\0\0'),                                # noqa
        (Fmt.LZMA        , T, 0, B'\xFD7zXZ'),                                  # noqa
        (Fmt.RNC         , T, 0, B'RNC\x01'),                                   # noqa
        (Fmt.RNC         , T, 0, B'RNC\x02'),                                   # noqa
        (Fmt.LZF         , T, 0, B'ZV'),                                        # noqa
        (Fmt.LZG         , T, 0, B'LZG'),                                       # noqa
        (Fmt.LZIP        , T, 0, B'LZIP'),                                      # noqa
        (Fmt.LZ4         , T, 0, B'\x04\x22\x4D\x18'),                          # noqa
        (Fmt.LZO         , F, 0, B'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a'),      # noqa
        (Fmt.LZH         , T, 0, B'\x1F\xA0'),                                  # noqa
        (Fmt.LZW         , T, 0, B'\x1F\x9D'),                                  # noqa
        (Fmt.GZIP        , T, 0, B'\x1F\x8B'),                                  # noqa
        (Fmt.XZ          , F, 0, B'\xFD\x37\x7A\x58\x5A\x00'),                  # noqa
        (Fmt.MSCF        , T, 0, B'\x0A\x51\xE5\xC0'),                          # noqa
        (Fmt.RAR         , T, 0, B'Rar!\x1A\x07'),                              # noqa
        (Fmt.XAR         , T, 0, B'xar!'),                                      # noqa
        (Fmt.SZDD        , T, 0, B'SZDD'),                                      # noqa
        (Fmt.ZLIB0       , T, 0, B'\x78\x01'),                                  # noqa
        (Fmt.ZLIB1       , T, 0, B'\x78\x5E'),                                  # noqa
        (Fmt.ZLIB2       , T, 0, B'\x78\x9C'),                                  # noqa
        (Fmt.ZLIB3       , T, 0, B'\x78\xDA'),                                  # noqa
        (Fmt.ZLIB4       , T, 0, B'\x78\x20'),                                  # noqa
        (Fmt.ZLIB5       , T, 0, B'\x78\x7D'),                                  # noqa
        (Fmt.ZLIB6       , T, 0, B'\x78\xBB'),                                  # noqa
        (Fmt.ZLIB7       , T, 0, B'\x78\xF9'),                                  # noqa
        (Fmt.LZFSE       , T, 0, B'bvx2'),                                      # noqa
        (Fmt.ZSTD        , T, 0, B'\x28\xB5\x2F\xFD'),                          # noqa
        (Fmt.ZIP7        , T, 0, B'7z\xBC\xAF\x27\x1C'),                        # noqa
        (Fmt.CAB         , T, 0, B'MSCF'),                                      # noqa
        (Fmt.CHM         , T, 0, B'ITSF'),                                      # noqa
        (Fmt.CPIO        , F, 0, B'070701'),                                    # noqa
        (Fmt.CPIO        , F, 0, B'070702'),                                    # noqa
        (Fmt.CPIO        , F, 0, B'070707'),                                    # noqa
        (Fmt.ZIP         , T, 0, B'PK\x03\x04'),                                # noqa
        (Fmt.ZIP         , T, 0, B'PK\x05\x06'),                                # noqa
        (Fmt.ZIP         , T, 0, B'PK\x07\x08'),                                # noqa
        (Fmt.ISO         , F, 0x8001, B'CD001'),                                # noqa
        (Fmt.ISO         , F, 0x8801, B'CD001'),                                # noqa
        (Fmt.ISO         , F, 0x9001, B'CD001'),                                # noqa
        (Fmt.ISZ         , T, 0, B'IsZ!'),                                      # noqa
        (Fmt.TAR         , F, 257, B'ustar'),                                   # noqa
        (Fmt.TAR         , F, 257, B'ustar'),                                   # noqa
        (Fmt.OAR         , T, 0, B'OAR'),                                       # noqa
        (Fmt.ZPQ         , T, 0, B'7kSt\xA01\x83\xD3\x8C\xB2\x28\xB0\xD3zPQ'),  # noqa
        (Fmt.VMDK        , T, 0, B'KDM'),                                       # noqa
        (Fmt.VMDK        , T, 0, B'# Disk Descripto'),                          # noqa
        (Fmt.VHD         , T, 0, B'conectix'),                                  # noqa
        (Fmt.VHD         , T, 0, B'vhdxfile'),                                  # noqa
        (Fmt.DMG         , T, size - 512, B'koly'),                             # noqa
    ):
        if view[offset:offset + len(signature)] == signature:
            if not entropy_required or len(data) < 0x100:
                return format
            for start in (0x1000, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10):
                if len(view) >= start + entropy_look_at:
                    view = view[start:]
                    break
            else:
                return format
            if entropy(view[:entropy_look_at]) >= entropy_minimum:
                return format


@_structural_check
def get_image_format(data: buf):
    """
    Determine an image format based on known magic signatures or return None if there is no
    match.
    """
    if data[:4] == B'\0\0\x01\0':
        count = int.from_bytes(data[4:6], 'little')
        if not 1 <= count <= 100:
            return None
        w, h, _, r = data[6:10]
        if r != 0:
            return None
        p = int.from_bytes(data[10:12], 'little') # planes
        b = int.from_bytes(data[12:14], 'little') # bit count
        if not any((w == h, p == 1, b in (1, 2, 4, 8, 16, 24, 32, 64, 96, 128, 256))):
            return None
        return Fmt.ICO

    if data[:3] == B'\xFF\xD8\xFF':
        if data[4] in (0xDB, 0xEE, 0xE0):
            return Fmt.JPG
        if data[4] == 0xE1 and data[7:13] == B'\x45\x78\x69\x66\0\0':
            return Fmt.JPG
        return None

    if data[:4] == b'FORM':
        if data[8:12] in (
            B'ILBM',
            B'8SVX',
            B'ACBM',
            B'ANBM',
            B'ANIM',
            B'FAXX',
            B'FTXT',
            B'SMUS',
            B'CMUS',
            B'YUVN',
            B'FANT',
            B'AIFF',
        ):
            return Fmt.IFF
        else:
            return None

    for format, signature in (
        (Fmt.HIC, b'ftypheic'),
        (Fmt.GIF, B'GIF87a'),
        (Fmt.GIF, B'GIF89a'),
        (Fmt.TIF, B'\x49\x49\x2A\x00'),
        (Fmt.TIF, B'\x4D\x4D\x00\x2A'),
        (Fmt.TIF, B'\x49\x49\x2B\x00'),
        (Fmt.TIF, B'\x4D\x4D\x00\x2B'),
        (Fmt.CIN, B'\x80\x2A\x5F\xD7'),
        (Fmt.NUI, B'NURUIMG'),
        (Fmt.NUI, B'NURUPAL'),
        (Fmt.DPX, B'SDPX'),
        (Fmt.DPX, B'XPDS'),
        (Fmt.BPG, B'BPG\xFB'),
        (Fmt.EXR, B'\x76\x2F\x31\x01'),
        (Fmt.JP2, B'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A'),
        (Fmt.JP2, B'\xFF\x4F\xFF\x51'),
        (Fmt.QOI, B'\x71\x6f\x69\x66'),
        (Fmt.PNG, B'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'),
        (Fmt.PSD, B'8BPS'),
        (Fmt.BMP, B'BM'),
        (Fmt.FIF, B'FLIF'),
        (Fmt.LEP, B'\xCF\x84\x01'),
        (Fmt.HDR, B'#?RADIANCE\n'),
    ):
        if data[:len(signature)] == signature:
            return format


@_structural_check
def get_media_format(data: buf):
    """
    Determine a multi-media format based on known magic signatures or return None if there is no
    match.
    """
    if data[:4] == B'RIFF':
        if data[8:12] == b'WAVE':
            return Fmt.WAV
        if data[8:12] == b'AVI ':
            return Fmt.AVI
        return None

    for format, signature in (
        (Fmt.OGG, B'OggS'),
        (Fmt.MP3, B'\xFF\xFB'),
        (Fmt.MP3, B'\xFF\xF3'),
        (Fmt.MP3, B'\xFF\xF2'),
        (Fmt.MP3, B'ID3'),
        (Fmt.M3U, B'#EXTM3U'),
        (Fmt.MPG, B'\0\0\01\xBA'),
        (Fmt.MPG, B'\0\0\01\xB3'),
        (Fmt.FLC, B'fLaC'),
        (Fmt.MID, B'MThd'),
        (Fmt.MKV, B'\x1A\x45\xDF\xA3'),
        (Fmt.SWF, B'CWS'),
        (Fmt.SWF, B'FWS'),
        (Fmt.SIL, B'#!SILK\n'),
    ):
        if data[:len(signature)] == signature:
            return format

    if data[4:12] in (B'ftypisom', B'ftypMSNV'):
        return Fmt.MPG

    if data[4:10] == B'ftypM4':
        return Fmt.MP4

    if len(data) < 0x1000:
        return None

    stop = min(len(data), 0x10000)
    if all(data[i] == 0x47 for i in range(0, stop, 188)):
        if any(data[i - 1] != 0x47 for i in range(0, stop, 188)):
            return Fmt.MPG


@_structural_check
def get_serialization_format(data: buf):
    """
    Checks for known data serialization formats.
    """
    if data[:4] == B'\xAC\xED\x00\x05':
        return Fmt.S_JAV
    if data[:17] == B'\0\01\0\0\0\xFF\xFF\xFF\xFF\x01\0\0\0\0\0\0\0':
        if data[17] in range(18) or data[17] in range(0x14, 0x17):
            return Fmt.S_DOT


@_structural_check
def get_misc_binary_formats(data: buf):
    """
    Checks for various other binary formats that are not covered by other methods in this module.
    """
    if len(data) >= 0x30 and PycMagicPattern.fullmatch(data[:4]):
        if any(data[offset] & 0x7F == 0x63 for offset in (8, 12, 16)):
            return Fmt.PYC

    for format, signature in (
        (Fmt.PDF, B'%PDF-'),
        (Fmt.A3X, B'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D\x41\x55\x33\x21'),
        (Fmt.CHM, B'ITSF'),
        (Fmt.DSS, B'\0\0\0\01Bud1'),
        (Fmt.DJV, B'AT&TFORM'),
        (Fmt.DEX, B'dex\n035\0'),
        (Fmt.IFPS, B'IFPS'),
        (Fmt.JAVA, B'\xCA\xFE\xBA\xBE'),
        (Fmt.WASM, B'\0asm'),
        (Fmt.LUAC, B'\x1BLua'),
        (Fmt.LNK, B'L\0\0\0\01\x14\02\0\0\0\0\0\xC0\0\0\0\0\0\0F'),
        (Fmt.DMP, B'MDMP'),
        (Fmt.PCAP, B'\xD4\xC3\xB2\xA1'),
        (Fmt.PCAP, B'\xA1\xB2\xC3\xD4'),
        (Fmt.PCAP, B'\x4D\x3C\xB2\xA1'),
        (Fmt.PCAP, B'\xA1\xB2\x3C\x4D'),
        (Fmt.PCAPNG, B'\n\r\n\r'),
        (Fmt.SSP, B'SMSNF200'),
        (Fmt.SQLITE, B'SQLite format 3\0'),
        (Fmt.PPK, B'PuTTY-User-Key-File-'),
        (Fmt.WIM, B'MSWIM\0\0\0\xD0\0\0\0\0'),
        (Fmt.EVT, B'LfLe'),
        (Fmt.EVTX, B'ElfFile'),
    ):
        if data[:len(signature)] == signature:
            return format


@_structural_check
def get_text_format(data: buf):
    """
    Implements a heuristic check for whether the input is likely XML data.
    """
    encoding = guess_text_encoding(data)

    if encoding is None:
        return None

    step = encoding.step
    view = memoryview(data)[encoding.lsb:len(data):step]

    if is_likely_vbe(view):
        return Fmt.VBE
    if buffer_contains(view[:200], BR'{\rtf'):
        return Fmt.RTF
    if step == 1 and is_likely_eml(data):
        return Fmt.EML
    if step > 1:
        # The following checks require a contiguous buffer for the regular expression searches.
        view = bytearray(view)
    if format := xml_or_html(view):
        return format
    if is_likely_json(view):
        return Fmt.JSON
    if step == 1:
        return Fmt.ASCII
    if step == 2:
        return Fmt.UTF16
    if step == 4:
        return Fmt.UTF32


def get_structured_data_type(data: buf):
    """
    Attempts to determine whether the input data is just a meaningless blob or whether it has
    structure, i.e. adheres to a known file format. Returns an `refinery.lib.id.Fmt` or `None`.
    """
    for check in StructuralChecks:
        if t := check(data):
            return t


def is_likely_xml(data: buf):
    """
    Checks whether the input data is likely an XML document.
    """
    if view := ascii_view(data, window_size=0):
        return xml_or_html(view) == Fmt.XML
    return False


def is_likely_htm(data: buf):
    """
    Checks whether the input data is likely an HTML document.
    """
    if view := ascii_view(data, window_size=0):
        return xml_or_html(view) == Fmt.HTM
    return False


def is_likely_msi(data: buf):
    """
    Checks whether the input data is likely an MSI.
    """
    return get_microsoft_format(data) == Fmt.MSI


def is_likely_email(data: buf):
    """
    Checks whether the input data is likely a plain-text or Outlook email document.
    """
    if is_likely_eml(data):
        return True
    return get_microsoft_format(data) == Fmt.MSG


def is_likely_doc(data: buf):
    if get_microsoft_format(data) == Fmt.DOC:
        return True
    if get_office_xml_type(data) == Fmt.DOCX:
        return True
    return False
