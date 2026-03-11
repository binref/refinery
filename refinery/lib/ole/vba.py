"""
Parser for VBA macro extraction from OLE and OOXML documents.

Implements MS-OVBA decompression and VBA project/dir stream parsing to extract VBA source code from
Word, Excel, PowerPoint, and related formats. Supports OLE, OpenXML (ZIP), Word 2003 XML, Flat OPC,
and MHTML containers.

Ported from oletools/olevba.py (BSD-licensed) by Philippe Lagadec.
"""
from __future__ import annotations

import base64
import codecs
import enum
import email
import email.feedparser
import math
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib

from io import BytesIO
from typing import Generator, NamedTuple

from refinery.lib.ole.file import MAGIC as OLE_MAGIC, OleFile, STGTY
from refinery.lib.structures import Struct, StructReader

MODULE_EXTENSION = 'bas'
CLASS_EXTENSION = 'cls'
FORM_EXTENSION = 'frm'

NS_W = '{http://schemas.microsoft.com/office/word/2003/wordml}'
TAG_BINDATA = F'{NS_W}binData'
ATTR_NAME = F'{NS_W}name'

NS_XMLPACKAGE = '{http://schemas.microsoft.com/office/2006/xmlPackage}'
TAG_PKGPART = F'{NS_XMLPACKAGE}part'
ATTR_PKG_NAME = F'{NS_XMLPACKAGE}name'
ATTR_PKG_CONTENTTYPE = F'{NS_XMLPACKAGE}contentType'
TAG_PKGBINDATA = F'{NS_XMLPACKAGE}binaryData'
CTYPE_VBAPROJECT = 'application/vnd.ms-office.vbaProject'

MSO_ACTIVEMIME_HEADER = b'ActiveMime'

# MS-OVBA dir stream record IDs (MS-OVBA 2.3.4.2)
_DIR_PROJECTMODULES        = 0x000F  # noqa: E221
_DIR_REFERENCEREGISTERED   = 0x000D  # noqa: E221
_DIR_REFERENCEPROJECT      = 0x000E  # noqa: E221
_DIR_REFERENCENAME         = 0x0016  # noqa: E221
_DIR_REFERENCENAME_UNICODE = 0x003E  # noqa: E221
_DIR_REFERENCECONTROL      = 0x002F  # noqa: E221
_DIR_REFERENCEORIGINAL     = 0x0033  # noqa: E221
_DIR_PROJECTCOMPATVERSION  = 0x004A  # noqa: E221
_DIR_MODULENAME            = 0x0019  # noqa: E221
_DIR_MODULENAMEUNICODE     = 0x0047  # noqa: E221
_DIR_MODULESTREAMNAME      = 0x001A  # noqa: E221
_DIR_MODULEDOCSTRING       = 0x001C  # noqa: E221
_DIR_MODULEHELPCONTEXT     = 0x001E  # noqa: E221
_DIR_MODULEOFFSET          = 0x0031  # noqa: E221
_DIR_MODULECOOKIE          = 0x002C  # noqa: E221
_DIR_MODULETYPE_STD        = 0x0021  # noqa: E221
_DIR_MODULETYPE_CLASS      = 0x0022  # noqa: E221
_DIR_MODULEREADONLY        = 0x0025  # noqa: E221
_DIR_MODULEPRIVATE         = 0x0028  # noqa: E221
_DIR_TERMINATOR            = 0x002B  # noqa: E221

_RE_PRINTABLE_STRING = re.compile(b'[\\t\\r\\n\\x20-\\xFF]{5,}')


class VBAModule(NamedTuple):
    stream_path: str | None
    filename: str | None
    code: str | None


class VBAMacro(NamedTuple):
    subfilename: str
    stream_path: str | None
    filename: str | None
    code: str | None


class VBAFormString(NamedTuple):
    filename: str
    stream_path: str
    value: str


class VBAFormVariable(NamedTuple):
    filename: str
    stream_path: str
    variable: dict[str, object]


_CODEPAGE_OVERRIDES = {
    10000: 'mac-roman',
    10006: 'mac-greek',
    10007: 'mac-cyrillic',
    10029: 'mac-latin2',
    10079: 'mac-iceland',
    10081: 'mac-turkish',
    20127: 'ascii',
    20866: 'koi8-r',
    20932: 'euc-jp',
    21866: 'koi8-u',
    28591: 'iso-8859-1',
    28592: 'iso-8859-2',
    28593: 'iso-8859-3',
    28594: 'iso-8859-4',
    28595: 'iso-8859-5',
    28596: 'iso-8859-6',
    28597: 'iso-8859-7',
    28598: 'iso-8859-8',
    28599: 'iso-8859-9',
    28603: 'iso-8859-13',
    28605: 'iso-8859-15',
    50220: 'iso-2022-jp',
    50225: 'iso-2022-kr',
    51932: 'euc-jp',
    51949: 'euc-kr',
    65000: 'utf-7',
    65001: 'utf-8',
}


def _codepage_to_codec(cp: int) -> str:
    if name := _CODEPAGE_OVERRIDES.get(cp):
        return name
    try:
        return codecs.lookup(F'cp{cp}').name
    except LookupError:
        return 'cp1252'


def _find_vba_projects(
    ole: OleFile,
) -> list[tuple[str, str, str]]:
    """
    Find all VBA project root storages in an OLE file. Returns a list of (vba_root,
    project_path, dir_path) tuples.
    """
    results: list[tuple[str, str, str]] = []
    for storage in ole.listdir(streams=False, storages=True):
        if storage.pop().upper() != 'VBA':
            continue
        vba_root = '/'.join(storage)
        if vba_root:
            vba_root += '/'
        if ole.get_type(project_path := F'{vba_root}PROJECT') != STGTY.STREAM:
            continue
        if ole.get_type(F'{vba_root}VBA/_VBA_PROJECT') != STGTY.STREAM:
            continue
        if ole.get_type(dir_path := F'{vba_root}VBA/dir') != STGTY.STREAM:
            continue
        results.append((vba_root, project_path, dir_path))
    return results


class FileOpenError(Exception):
    """
    Raised when data cannot be recognized as a supported file format.
    """

    def __init__(self, message: str = 'failed to open file'):
        super().__init__(message)


def copytoken_help(
    decompressed_current: int,
    decompressed_chunk_start: int,
) -> tuple[int, int, int, int]:
    """
    Compute bit masks to decode a CopyToken per MS-OVBA 2.4.1.3.19.1. Returns (length_mask,
    offset_mask, bit_count, maximum_length).
    """
    difference = decompressed_current - decompressed_chunk_start
    bit_count = int(math.ceil(math.log(difference, 2)))
    bit_count = max(bit_count, 4)
    length_mask = 0xFFFF >> bit_count
    offset_mask = ~length_mask & 0xFFFF
    maximum_length = (0xFFFF >> bit_count) + 3
    return length_mask, offset_mask, bit_count, maximum_length


def decompress_stream(data: bytes | bytearray | memoryview) -> bytearray:
    """
    Decompress a VBA compressed stream per MS-OVBA section 2.4.1.

    The compressed container starts with a signature byte (0x01), followed by compressed chunks.
    Each chunk has a 2-byte header encoding size, signature (0b011), and a flag indicating whether
    the chunk is compressed or raw.
    """
    view = memoryview(data)

    if len(view) < 1:
        raise ValueError('empty compressed container')

    if view[0] != 0x01:
        raise ValueError(F'invalid signature byte 0x{view[0]:02X}, expected 1')

    decompressed = bytearray()
    pos = 1

    while pos < len(view):
        if pos + 2 > len(view):
            break
        chunk_header = struct.unpack_from('<H', view, pos)[0]
        chunk_size = (chunk_header & 0x0FFF) + 3
        chunk_signature = (chunk_header >> 12) & 0x07
        chunk_flag = (chunk_header >> 15) & 0x01

        if chunk_signature != 0b011:
            raise ValueError('Invalid CompressedChunkSignature in VBA stream')

        if chunk_flag == 1 and chunk_size > 4098:
            raise ValueError(F'CompressedChunkSize {chunk_size} > 4098 but CompressedChunkFlag == 1')
        if chunk_flag == 0 and chunk_size != 4098:
            raise ValueError(F'CompressedChunkSize {chunk_size} != 4098 but CompressedChunkFlag == 0')

        compressed_end = min(len(view), pos + chunk_size)
        compressed_current = pos + 2

        if chunk_flag == 0:
            decompressed.extend(view[compressed_current:compressed_current + 4096])
            compressed_current += 4096
        else:
            decompressed_chunk_start = len(decompressed)
            while compressed_current < compressed_end:
                if compressed_current >= len(view):
                    break
                flag_byte = view[compressed_current]
                compressed_current += 1
                for bit_index in range(8):
                    if compressed_current >= compressed_end:
                        break
                    flag_bit = (flag_byte >> bit_index) & 1
                    if flag_bit == 0:
                        decompressed.append(view[compressed_current])
                        compressed_current += 1
                    else:
                        if compressed_current + 2 > len(view):
                            break
                        copy_token = struct.unpack_from(
                            '<H', view, compressed_current)[0]
                        length_mask, offset_mask, bit_count, _ = (
                            copytoken_help(
                                len(decompressed),
                                decompressed_chunk_start))
                        length = (copy_token & length_mask) + 3
                        temp1 = copy_token & offset_mask
                        temp2 = 16 - bit_count
                        offset = (temp1 >> temp2) + 1
                        copy_source = len(decompressed) - offset
                        for index in range(
                            copy_source, copy_source + length
                        ):
                            decompressed.append(decompressed[index])
                        compressed_current += 2

        pos = compressed_end

    return decompressed


def _is_mso_file(data: bytes | bytearray) -> bool:
    return data[:len(MSO_ACTIVEMIME_HEADER)] == MSO_ACTIVEMIME_HEADER


def _mso_file_extract(data: bytes | bytearray) -> bytes:
    """
    Extract OLE data from an ActiveMime/MSO container by decompressing the embedded zlib stream.
    """
    offsets: list[int] = []
    try:
        offset = struct.unpack_from('<H', data, 0x1E)[0] + 46
        offsets.append(offset)
    except struct.error:
        pass
    offsets.extend([0x32, 0x22A])
    for start in offsets:
        try:
            return zlib.decompress(data[start:])
        except zlib.error:
            pass
    for start in range(len(data)):
        if data[start:start + 1] == b'\x78':
            try:
                return zlib.decompress(data[start:])
            except zlib.error:
                pass
    raise ValueError('unable to decompress data from MSO/ActiveMime file')


class PROJECTSYSKIND(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0001
        reader.u32()  # size
        self.syskind = reader.u32()


class PROJECTCOMPATVERSION(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.compat_version = reader.read_length_prefixed()


class PROJECTLCID(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u32()  # size
        self.lcid = reader.u32()


class PROJECTLCIDINVOKE(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0014
        reader.u32()  # size
        self.lcid_invoke = reader.u32()


class PROJECTCODEPAGE(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0003
        reader.u32()  # size
        self.codepage = reader.u16()
        self.codec: str = _codepage_to_codec(self.codepage)


class PROJECTNAME(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], codec: str):
        reader.u16()  # id 0x0004
        self.name = codecs.decode(reader.read_length_prefixed(), codec, 'replace')


class PROJECTDOCSTRING(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], codec: str):
        reader.u16()  # id 0x0005
        self.docstring = codecs.decode(reader.read_length_prefixed(), codec, 'replace')
        reader.u16()  # reserved 0x0040
        self.docstring_unicode = reader.read_length_prefixed()


class PROJECTHELPFILEPATH(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], codec: str):
        reader.u16()  # id 0x0006
        self.path = codecs.decode(reader.read_length_prefixed(), codec, 'replace')
        reader.u16()  # reserved 0x003D
        self.path_unicode = reader.read_length_prefixed()


class PROJECTHELPCONTEXT(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0007
        reader.u32()  # size
        self.help_context = reader.u32()


class PROJECTLIBFLAGS(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0008
        reader.u32()  # size
        self.lib_flags = reader.u32()


class PROJECTVERSION(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.u16()  # id 0x0009
        reader.u32()  # reserved size
        self.major = reader.u32()
        self.minor = reader.u16()


class PROJECTCONSTANTS(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview], codec: str):
        reader.u16()  # id 0x000C
        self.constants = codecs.decode(reader.read_length_prefixed(), codec, 'replace')
        reader.u16()  # reserved 0x003C
        self.constants_unicode = reader.read_length_prefixed()


class REFERENCENAME(Struct[memoryview]):
    """
    MS-OVBA 2.3.4.2.2.2 — optional name prefix for a reference.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.name = reader.read_length_prefixed()
        reserved = reader.u16()
        self.next_id: int = reserved
        if reserved == _DIR_REFERENCENAME_UNICODE:
            self.name_unicode = reader.read_length_prefixed()
            self.next_id = -1


class REFERENCEORIGINAL(Struct[memoryview]):
    """
    MS-OVBA 2.3.4.2.2.4 — REFERENCEORIGINAL record body.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.libid_original = reader.read_length_prefixed()


class REFERENCECONTROL(Struct[memoryview]):
    """
    MS-OVBA 2.3.4.2.2.3 — REFERENCECONTROL record body.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.size_twiddled = reader.u32()
        self.libid_twiddled = reader.read_length_prefixed()
        self._reserved1 = reader.u32()
        self._reserved2 = reader.u16()
        self._reserved3 = check2 = reader.u16()
        self.ext_name_unicode = None
        self.ext_name = None
        if check2 == _DIR_REFERENCENAME:
            self.ext_name = reader.read_length_prefixed()
            self._reserved3 = ext_reserved = reader.u16()
            if ext_reserved == _DIR_REFERENCENAME_UNICODE:
                self.ext_name_unicode = reader.read_length_prefixed()
                self._reserved3 = reader.u16()  # reserved3
        self.size_extended = reader.u32()
        self.libid_extended = reader.read_length_prefixed()
        self._reserved4 = reader.u32()
        self._reserved5 = reader.u16()
        self.original_typelib = reader.read_guid()
        self.cookie = reader.u32()


class REFERENCEREGISTERED(Struct[memoryview]):
    """
    MS-OVBA 2.3.4.2.2.5 — REFERENCEREGISTERED record body.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.size = reader.u32()
        self.libid = reader.read_length_prefixed()
        self._reserved1 = reader.u32()
        self._reserved2 = reader.u16()


class REFERENCEPROJECT(Struct[memoryview]):
    """
    MS-OVBA 2.3.4.2.2.6 — REFERENCEPROJECT record body.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.size = reader.u32()
        self.abs_path = reader.read_length_prefixed()
        self.rel_path = reader.read_length_prefixed()
        self.major = reader.u32()
        self.minor = reader.u16()


class _VBAProject(Struct[memoryview]):
    """
    Parses the dir stream of a single VBA project inside an OLE file and extracts the VBA source
    code for each module.
    """

    def __init__(
        self,
        reader: StructReader[memoryview],
        ole: OleFile,
        vba_root: str,
        project_path: str,
    ):
        self.ole = ole
        self.vba_root = vba_root
        self.project_path = project_path
        self.module_ext: dict[str, str] = {}

        # PROJECTINFORMATION records
        self.syskind = PROJECTSYSKIND(reader)

        record_id = reader.u16()
        if record_id == _DIR_PROJECTCOMPATVERSION:
            PROJECTCOMPATVERSION(reader)
            record_id = reader.u16()

        # record_id is now the PROJECTLCID id; the struct reads from the size field onward
        self.clsid = PROJECTLCID(reader)
        self.cid_invoke = PROJECTLCIDINVOKE(reader)
        cp = PROJECTCODEPAGE(reader)
        self.codepage = cp.codepage
        self.codec = cp.codec
        self.project_name = PROJECTNAME(reader, self.codec)
        self.project_docstring = PROJECTDOCSTRING(reader, self.codec)
        self.project_file_path = PROJECTHELPFILEPATH(reader, self.codec)
        self.project_help_ctxt = PROJECTHELPCONTEXT(reader)
        self.project_lib_flags = PROJECTLIBFLAGS(reader)
        self.project_version = PROJECTVERSION(reader)
        self.project_constants = PROJECTCONSTANTS(reader, self.codec)

        references: list[
            REFERENCENAME | REFERENCEORIGINAL | REFERENCECONTROL | REFERENCEREGISTERED | REFERENCEPROJECT
        ] = []
        self.references = references
        while (check := reader.u16()) != _DIR_PROJECTMODULES:
            if check == _DIR_REFERENCENAME:
                ref_name = REFERENCENAME(reader)
                references.append(ref_name)
                if ref_name.next_id == -1:
                    continue
                check = ref_name.next_id
            if check == _DIR_REFERENCEORIGINAL:
                ref = REFERENCEORIGINAL(reader)
            elif check == _DIR_REFERENCECONTROL:
                ref = REFERENCECONTROL(reader)
            elif check == _DIR_REFERENCEREGISTERED:
                ref = REFERENCEREGISTERED(reader)
            elif check == _DIR_REFERENCEPROJECT:
                ref = REFERENCEPROJECT(reader)
            else:
                raise ValueError(F'invalid reference record id 0x{check:04X}')
            references.append(ref)

        self._reader = reader

    def parse_project_stream(self) -> None:
        """
        Parse the PROJECT stream to determine module file extensions.
        """
        self.module_ext = {}
        project_data = self.ole.openstream(self.project_path).read()
        for raw_line in re.split(br'\r\n', project_data):
            line = codecs.decode(raw_line, self.codec, 'replace').strip()
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            value = value.lower()
            if name == 'Document':
                value = value.split('/', 1)[0]
                self.module_ext[value] = CLASS_EXTENSION
            elif name == 'Module':
                self.module_ext[value] = MODULE_EXTENSION
            elif name == 'Class':
                self.module_ext[value] = CLASS_EXTENSION
            elif name == 'BaseClass':
                self.module_ext[value] = FORM_EXTENSION

    def parse_modules(self) -> Generator[VBAModule, None, None]:
        """
        Parse MODULE records from the dir stream and yield a VBAModule for each module.
        """
        reader = self._reader
        # PROJECTMODULES record — 0x000F was already consumed
        reader.u32()  # size
        modules_count = reader.u16()
        # ProjectCookieRecord
        reader.u16()  # id
        reader.u32()  # size
        reader.u16()  # cookie

        for _ in range(modules_count):
            result = self._parse_one_module()
            if result is not None:
                yield result

    def _parse_one_module(self) -> VBAModule | None:
        """
        Parse a single MODULE record and return its VBA source code as a VBAModule.
        """
        reader = self._reader
        module_name: str | None = None
        module_name_unicode: str | None = None
        stream_name: str | None = None
        stream_name_unicode: str | None = None
        text_offset: int = 0

        section_id = reader.u16()
        if section_id != _DIR_MODULENAME:
            return None

        module_name = codecs.decode(reader.read_length_prefixed(), self.codec, 'replace')

        section_id = reader.u16()
        while section_id != _DIR_TERMINATOR:
            if section_id == _DIR_MODULENAMEUNICODE:
                module_name_unicode = codecs.decode(reader.read_length_prefixed(), 'utf-16-le', 'replace')
            elif section_id == _DIR_MODULESTREAMNAME:
                stream_name = codecs.decode(reader.read_length_prefixed(), self.codec, 'replace')
                reader.u16()  # reserved 0x0032
                stream_name_unicode = codecs.decode(reader.read_length_prefixed(), 'utf-16-le', 'replace')
            elif section_id == _DIR_MODULEDOCSTRING:
                reader.read_length_prefixed()
                reader.u16()  # reserved 0x0048
                reader.read_length_prefixed()
            elif section_id == _DIR_MODULEOFFSET:
                reader.u32()  # size
                text_offset = reader.u32()
            elif section_id == _DIR_MODULEHELPCONTEXT:
                reader.u32()  # size
                reader.u32()  # help_context
            elif section_id == _DIR_MODULECOOKIE:
                reader.u32()  # size
                reader.u16()  # cookie
            elif section_id in (_DIR_MODULETYPE_STD, _DIR_MODULETYPE_CLASS):
                reader.u32()  # reserved
            elif section_id == _DIR_MODULEREADONLY:
                reader.u32()  # reserved
            elif section_id == _DIR_MODULEPRIVATE:
                reader.u32()  # reserved
            section_id = reader.u16()
        reader.u32()  # terminator reserved

        code_data: bytes | memoryview | None = None
        try_names = (
            stream_name,
            stream_name_unicode,
            module_name,
            module_name_unicode,
        )
        code_path: str | None = None
        for name in try_names:
            if name is None:
                continue
            full_path = F'{self.vba_root}VBA/{name}'
            try:
                code_data = self.ole.openstream(full_path).read()
                code_path = full_path
                break
            except Exception:
                continue

        if code_data is None:
            return None

        code_data = code_data[text_offset:]
        if not code_data:
            return None

        try:
            vba_code_raw = decompress_stream(code_data)
        except Exception:
            return None

        vba_code = vba_code_raw.decode(self.codec, errors='replace')
        ext = self.module_ext.get((module_name or '').lower(), 'vba')
        filename = F'{module_name}.{ext}' if module_name else None

        return VBAModule(code_path, filename, vba_code)


class DocumentFormat(enum.Enum):
    OLE          = 'OLE'          # noqa: E221
    OPENXML      = 'OpenXML'      # noqa: E221
    WORD2003_XML = 'Word2003/XML'
    FLATOPC_XML  = 'FlatOPC/XML'  # noqa: E221
    MHTML        = 'MHTML'        # noqa: E221


class VBAParser:
    """
    Parser for extracting VBA macros from Office documents. Supports OLE (.doc, .xls), OpenXML/ZIP
    (.docm, .xlsm), Word 2003 XML, Flat OPC XML, and MHTML containers.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        if isinstance(data, memoryview):
            data = bytes(data)
        self._data = data
        self._ole: OleFile | None = None
        self._ole_subfiles: list[tuple[str, bytes]] = []
        self._type: DocumentFormat | None = None
        self._vba_projects: list[tuple[str, str, str]] | None = None
        self._vba_forms: list[str] | None = None

        if self._try_ole(data):
            return
        if self._try_zip(data):
            return
        if self._try_word2003xml(data):
            return
        if self._try_flatopc(data):
            return
        if self._try_mhtml(data):
            return

        raise FileOpenError('data is not a supported file type for VBA extraction')

    def _try_ole(self, data: bytes | bytearray) -> bool:
        if data[:8] != OLE_MAGIC:
            return False
        try:
            self._ole = OleFile(data)
            self._type = DocumentFormat.OLE
            return True
        except Exception:
            return False

    def _try_zip(self, data: bytes | bytearray) -> bool:
        if data[:2] != b'PK':
            return False
        try:
            fp = BytesIO(data)
            if not zipfile.is_zipfile(fp):
                return False
            fp.seek(0)
            with zipfile.ZipFile(fp) as zf:
                for name in zf.namelist():
                    with zf.open(name) as fh:
                        magic = fh.read(8)
                    if magic[:8] == OLE_MAGIC:
                        with zf.open(name) as fh:
                            ole_data = fh.read()
                        self._ole_subfiles.append((name, ole_data))
            if self._ole_subfiles:
                self._type = DocumentFormat.OPENXML
                return True
        except Exception:
            pass
        return False

    def _try_word2003xml(self, data: bytes | bytearray) -> bool:
        ns = b'http://schemas.microsoft.com/office/word/2003/wordml'
        if ns not in data:
            return False
        try:
            et = ET.fromstring(data)
            found = False
            for bindata in et.iter(TAG_BINDATA):
                fname = bindata.get(ATTR_NAME, 'noname.mso')
                mso_data = base64.b64decode(bindata.text or '')
                if _is_mso_file(mso_data):
                    try:
                        ole_data = _mso_file_extract(mso_data)
                        self._ole_subfiles.append((fname, ole_data))
                        found = True
                    except Exception:
                        pass
            if found:
                self._type = DocumentFormat.WORD2003_XML
                return True
        except Exception:
            pass
        return False

    def _try_flatopc(self, data: bytes | bytearray) -> bool:
        ns = b'http://schemas.microsoft.com/office/2006/xmlPackage'
        if ns not in data:
            return False
        try:
            et = ET.fromstring(data)
            found = False
            for pkgpart in et.iter(TAG_PKGPART):
                content_type = pkgpart.get(ATTR_PKG_CONTENTTYPE, 'unknown')
                if content_type != CTYPE_VBAPROJECT:
                    continue
                for bindata in pkgpart.iterfind(TAG_PKGBINDATA):
                    try:
                        ole_data = base64.b64decode(bindata.text or '')
                        fname = pkgpart.get(ATTR_PKG_NAME, 'unknown')
                        self._ole_subfiles.append((fname, ole_data))
                        found = True
                    except Exception:
                        pass
            if found:
                self._type = DocumentFormat.FLATOPC_XML
                return True
        except Exception:
            pass
        return False

    def _try_mhtml(self, data: bytes | bytearray) -> bool:
        data_lower = data.lower()
        if b'mime' not in data_lower:
            return False
        if b'version' not in data_lower:
            return False
        if b'multipart' not in data_lower:
            return False
        mime_pos = data_lower.find(b'mime')
        vers_pos = data_lower.find(b'version')
        if abs(vers_pos - mime_pos) >= 20:
            return False

        try:
            stripped = data.lstrip(b'\r\n\t ')
            mime_offset = stripped.find(b'MIME')
            content_offset = stripped.find(b'Content')
            if -1 < mime_offset <= content_offset:
                stripped = stripped[mime_offset:]
            elif content_offset > -1:
                stripped = stripped[content_offset:]

            old_header_re = getattr(email.feedparser, 'headerRE')
            loose_re = re.compile(r'^(From |[\041-\071\073-\176]{1,}:?|[\t ])')
            setattr(email.feedparser, 'headerRE', loose_re)
            try:
                mhtml = email.message_from_bytes(stripped)
            finally:
                setattr(email.feedparser, 'headerRE', old_header_re)

            found = False
            for part in mhtml.walk():
                part_data = part.get_payload(decode=True)
                if not isinstance(part_data, bytes):
                    continue
                if _is_mso_file(part_data):
                    try:
                        ole_data = _mso_file_extract(part_data)
                        fname = part.get_filename('editdata.mso')
                        self._ole_subfiles.append((fname, ole_data))
                        found = True
                    except Exception:
                        pass
                elif part_data[:8] == OLE_MAGIC:
                    fname = part.get_filename('embedded.ole')
                    self._ole_subfiles.append((fname, part_data))
                    found = True
            if found:
                self._type = DocumentFormat.MHTML
                return True
        except Exception:
            pass
        return False

    def _find_vba_forms(
        self,
        ole: OleFile,
    ) -> list[str]:
        """
        Find form storages containing 'f' and 'o' streams.
        """
        results: list[str] = []
        for storage in ole.listdir(streams=False, storages=True):
            prefix = '/'.join(storage)
            o_stream = F'{prefix}/o'
            f_stream = F'{prefix}/f'
            if (ole.exists(o_stream)
                    and ole.get_type(o_stream) == STGTY.STREAM
                    and ole.exists(f_stream)
                    and ole.get_type(f_stream) == STGTY.STREAM):
                results.append(prefix)
        return results

    def _extract_vba(
        self,
        ole: OleFile,
        vba_root: str,
        project_path: str,
        dir_path: str,
    ) -> Generator[VBAModule, None, None]:
        """
        Extract VBA macros from one VBA project inside an OLE file.
        """
        dir_data = decompress_stream(ole.openstream(dir_path).read())
        project = _VBAProject.Parse(
            memoryview(dir_data), ole, vba_root, project_path)
        project.parse_project_stream()
        yield from project.parse_modules()

    def extract_macros(self) -> Generator[VBAMacro, None, None]:
        """
        Extract and decompress VBA macro source code from the file. Yields a VBAMacro for each
        VBA module found.
        """
        if self._ole is not None:
            yield from self._extract_macros_from_ole('', self._ole)
        for subfile_name, ole_data in self._ole_subfiles:
            try:
                sub_ole = OleFile(ole_data)
            except Exception:
                continue
            yield from self._extract_macros_from_ole(subfile_name, sub_ole)

    def _extract_macros_from_ole(
        self,
        subfilename: str,
        ole: OleFile,
    ) -> Generator[VBAMacro, None, None]:
        """
        Extract macros from a single OLE file object.
        """
        projects = _find_vba_projects(ole)
        for vba_root, project_path, dir_path in projects:
            try:
                for module in self._extract_vba(ole, vba_root, project_path, dir_path):
                    yield VBAMacro(
                        subfilename,
                        module.stream_path,
                        module.filename,
                        module.code,
                    )
            except Exception:
                continue

    def extract_all_macros(self) -> list[VBAMacro]:
        """
        Extract all VBA macros and return them as a list of VBAMacro entries.
        """
        return list(self.extract_macros())

    def extract_form_strings(self) -> Generator[VBAFormString, None, None]:
        """
        Extract printable strings from VBA form object streams. Yields a VBAFormString for each
        string found in form 'o' streams.
        """
        if self._ole is not None:
            yield from self._extract_form_strings_from_ole('', self._ole)
        for subfile_name, ole_data in self._ole_subfiles:
            try:
                sub_ole = OleFile(ole_data)
            except Exception:
                continue
            yield from self._extract_form_strings_from_ole(subfile_name, sub_ole)

    def _extract_form_strings_from_ole(
        self,
        filename: str,
        ole: OleFile,
    ) -> Generator[VBAFormString, None, None]:
        forms = self._find_vba_forms(ole)
        for form_storage in forms:
            o_stream = F'{form_storage}/o'
            try:
                form_data = ole.openstream(o_stream).read()
            except Exception:
                continue
            for m in _RE_PRINTABLE_STRING.finditer(form_data):
                found_str = m.group().decode('utf8', errors='replace')
                if found_str != 'Tahoma':
                    yield VBAFormString(filename, o_stream, found_str)

    def extract_form_strings_extended(self) -> Generator[VBAFormVariable, None, None]:
        """
        Extract extended form variable data using OLE form parsing. Yields a VBAFormVariable for
        each form control variable found.
        """
        if self._ole is not None:
            yield from self._extract_form_strings_extended_from_ole('', self._ole)
        for subfile_name, ole_data in self._ole_subfiles:
            try:
                sub_ole = OleFile(ole_data)
            except Exception:
                continue
            yield from self._extract_form_strings_extended_from_ole(subfile_name, sub_ole)

    def _extract_form_strings_extended_from_ole(
        self,
        filename: str,
        ole: OleFile,
    ) -> Generator[VBAFormVariable, None, None]:
        from refinery.lib.ole.forms import (
            extract_OleFormVariables,
            OleFormParsingError,
        )
        forms = self._find_vba_forms(ole)
        for form_storage in forms:
            try:
                for variable in extract_OleFormVariables(
                    ole, form_storage
                ):
                    yield VBAFormVariable(filename, form_storage, variable)
            except OleFormParsingError:
                raise
            except Exception:
                continue
