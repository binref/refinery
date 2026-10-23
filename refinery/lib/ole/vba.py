"""
Parser for VBA macro extraction from OLE and OOXML documents.

Implements MS-OVBA decompression and the parsing of the dir stream of a VBA project. VBA projects
are stored in compound files: the input itself, a part of an OpenXML (ZIP) document, a Word 2003
XML or Flat OPC document, an MHTML file, or the VBA storage of a Microsoft Access database. The
function `vba_containers` lists the compound files of an input, `vba_compound_files` opens them and
lists the VBA projects inside each, and every `VBAProject` lists its modules as `VBAModule` objects.
The forms of a compound file are listed by `vba_form_storages`.
"""
from __future__ import annotations

import base64
import codecs
import email
import email.feedparser
import enum
import math
import re
import struct
import zipfile
import zlib

from typing import Callable, Iterator, NamedTuple

from defusedxml.ElementTree import fromstring

from refinery.lib.access import AccessDatabase, is_access_database
from refinery.lib.id import buffer_contains
from refinery.lib.ole.file import MAGIC as OLE_MAGIC
from refinery.lib.ole.file import STGTY, OleFile, OleFileLike
from refinery.lib.structures import MemoryFile, Struct, StructReader
from refinery.lib.types import buf

_NAMESPACE_WORD2003 = 'http://schemas.microsoft.com/office/word/2003/wordml'
_NAMESPACE_FLATOPC = 'http://schemas.microsoft.com/office/2006/xmlPackage'

NS_W = F'{{{_NAMESPACE_WORD2003}}}'
TAG_BINDATA = F'{NS_W}binData'
ATTR_NAME = F'{NS_W}name'

NS_XMLPACKAGE = F'{{{_NAMESPACE_FLATOPC}}}'
TAG_PKGPART = F'{NS_XMLPACKAGE}part'
ATTR_PKG_NAME = F'{NS_XMLPACKAGE}name'
ATTR_PKG_CONTENTTYPE = F'{NS_XMLPACKAGE}contentType'
TAG_PKGBINDATA = F'{NS_XMLPACKAGE}binaryData'
CTYPE_VBAPROJECT = 'application/vnd.ms-office.vbaProject'

MSO_ACTIVEMIME_HEADER = b'ActiveMime'

_RE_PRINTABLE_STRING = re.compile(b'[\\t\\r\\n\\x20-\\xFF]{5,}')

Reporter = Callable[[str, Exception], None]
"""
A function that receives the location of a part of the input that cannot be read, and the error
that occurred while reading it.
"""


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


def _find_vba_projects(ole: OleFileLike) -> list[str]:
    """
    The storages of all VBA projects in the given compound file. Each storage is given as a path
    prefix, which is empty for the root storage and otherwise ends with a forward slash.
    """
    storages: list[str] = []
    for storage, entry in ole.walk(streams=False, storages=True):
        if storage[-1].upper() != 'VBA' or ole.find('/'.join(storage)) is not entry:
            continue
        vba_root = '/'.join(storage[:-1])
        if vba_root:
            vba_root += '/'
        if ole.get_type(F'{vba_root}PROJECT') != STGTY.STREAM:
            continue
        if ole.get_type(F'{vba_root}VBA/_VBA_PROJECT') != STGTY.STREAM:
            continue
        if ole.get_type(_dir_path(vba_root)) != STGTY.STREAM:
            continue
        storages.append(vba_root)
    return storages


def _dir_path(storage: str) -> str:
    return F'{storage}VBA/dir'


def vba_form_storages(ole: OleFileLike) -> list[str]:
    """
    The paths of all form storages in the given compound file, i.e. storages that hold a stream
    named `f` and a stream named `o`. The storage of a frame inside a form is a form storage below
    the storage of the form.
    """
    forms: list[str] = []
    for storage, entry in ole.walk(streams=False, storages=True):
        prefix = '/'.join(storage)
        if ole.find(prefix) is not entry:
            continue
        if (
            ole.get_type(F'{prefix}/o') == STGTY.STREAM
            and ole.get_type(F'{prefix}/f') == STGTY.STREAM
        ):
            forms.append(prefix)
    return forms


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
    if difference < 2:
        bit_count = 4
    else:
        bit_count = max(int(math.ceil(math.log(difference, 2))), 4)
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


def _is_mso_file(data: buf) -> bool:
    return data[:len(MSO_ACTIVEMIME_HEADER)] == MSO_ACTIVEMIME_HEADER


def _mso_file_extract(data: buf) -> bytes:
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


def _is_mhtml(data: buf) -> bool:
    if (mime := re.search(B'(?i)mime', data)) is None:
        return False
    if (version := re.search(B'(?i)version', data)) is None:
        return False
    if re.search(B'(?i)multipart', data) is None:
        return False
    return abs(version.start() - mime.start()) < 20


def is_vba_container(data: buf) -> bool:
    """
    A quick check whether the given data looks like one of the containers that `vba_containers`
    reads: a compound file, a Microsoft Access database, an OpenXML document, a Word 2003 XML or
    Flat OPC document, or an MHTML file.
    """
    view = memoryview(data)
    if view[:8] == OLE_MAGIC or is_access_database(view):
        return True
    if view[:2] == B'PK':
        return buffer_contains(view, B'[Content_Types].xml')
    if buffer_contains(view, _NAMESPACE_WORD2003.encode()):
        return True
    if buffer_contains(view, _NAMESPACE_FLATOPC.encode()):
        return True
    return _is_mhtml(view)


class VBAContainer(NamedTuple):
    """
    A compound file of an input, which may hold VBA projects. The part is the name under which the
    input stores the compound file, or `None` when the compound file is the input itself. The part
    of a zip member has forward slashes in place of backslashes on every platform. The
    compound file is read only when `open` is called, which raises the error of the read when the
    part cannot be read or is no compound file.
    """
    part: str | None
    open: Callable[[], OleFileLike]


def _ole_containers(data: memoryview) -> list[VBAContainer]:
    if data[:8] != OLE_MAGIC:
        return []
    return [VBAContainer(None, lambda: OleFile(data))]


def _zip_containers(data: memoryview) -> list[VBAContainer]:
    if data[:2] != B'PK':
        return []
    try:
        archive = zipfile.ZipFile(MemoryFile(data, bytes))
    except Exception:
        return []
    containers: list[VBAContainer] = []
    for info in archive.infolist():
        try:
            with archive.open(info) as part:
                is_ole = part.read(8) == OLE_MAGIC
        except Exception:
            is_ole = True
        if is_ole:
            name = info.filename.replace('\\', '/')
            containers.append(VBAContainer(name, lambda info=info: OleFile(archive.read(info))))
    return containers


def _word2003_containers(data: memoryview) -> list[VBAContainer]:
    if not buffer_contains(data, _NAMESPACE_WORD2003.encode()):
        return []
    try:
        document = fromstring(bytes(data))
    except Exception:
        return []

    def extract(text: str, decoded: bytes | None):
        if decoded is None:
            decoded = base64.b64decode(text)
        return OleFile(_mso_file_extract(decoded))

    containers: list[VBAContainer] = []
    for bindata in document.iter(TAG_BINDATA):
        text = bindata.text or ''
        try:
            decoded = base64.b64decode(text)
        except Exception:
            decoded = None
        else:
            if not _is_mso_file(decoded):
                continue
        name = bindata.get(ATTR_NAME, 'noname.mso')
        containers.append(VBAContainer(name, lambda text=text, decoded=decoded: extract(text, decoded)))
    return containers


def _flatopc_containers(data: memoryview) -> list[VBAContainer]:
    if not buffer_contains(data, _NAMESPACE_FLATOPC.encode()):
        return []
    try:
        document = fromstring(bytes(data))
    except Exception:
        return []
    containers: list[VBAContainer] = []
    for package_part in document.iter(TAG_PKGPART):
        if package_part.get(ATTR_PKG_CONTENTTYPE, 'unknown') != CTYPE_VBAPROJECT:
            continue
        name = package_part.get(ATTR_PKG_NAME, 'unknown')
        for bindata in package_part.iterfind(TAG_PKGBINDATA):
            text = bindata.text or ''
            containers.append(VBAContainer(name, lambda text=text: OleFile(base64.b64decode(text))))
    return containers


def _mhtml_containers(data: memoryview) -> list[VBAContainer]:
    if not _is_mhtml(data):
        return []
    try:
        stripped = bytes(data).lstrip(b'\r\n\t ')
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
        containers: list[VBAContainer] = []
        for part in mhtml.walk():
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                continue
            if _is_mso_file(payload):
                name = part.get_filename('editdata.mso')
                containers.append(VBAContainer(name, lambda payload=payload: OleFile(_mso_file_extract(payload))))
            elif payload[:8] == OLE_MAGIC:
                name = part.get_filename('embedded.ole')
                containers.append(VBAContainer(name, lambda payload=payload: OleFile(payload)))
    except Exception:
        return []
    return containers


def _access_containers(data: memoryview) -> list[VBAContainer]:
    if not is_access_database(data):
        return []
    if (ole := AccessDatabase(bytes(data)).open_vba()) is None:
        return []
    return [VBAContainer(None, lambda: ole)]


def vba_containers(data: buf) -> list[VBAContainer]:
    """
    The compound files of the given input that may hold VBA projects, in the order in which the
    input stores them. The input is a compound file, an OpenXML document or any other zip archive,
    a Word 2003 XML or Flat OPC document, an MHTML file, or a Microsoft Access database. The parts
    of these containers are found without reading them in full; a part that cannot be read is
    listed, so that the error of opening it can be reported. Raises `FileOpenError` when the input
    is none of these containers or has no part that may be a compound file. The error of reading
    the VBA storage of an Access database is raised.
    """
    view = memoryview(data)
    for find_containers in (
        _ole_containers,
        _access_containers,
        _zip_containers,
        _word2003_containers,
        _flatopc_containers,
        _mhtml_containers,
    ):
        if containers := find_containers(view):
            return containers
    raise FileOpenError('data is not a supported file type for VBA extraction')


def _open_containers(
    containers: list[VBAContainer],
    report: Reporter,
) -> Iterator[tuple[str | None, OleFileLike]]:
    """
    Opens the given containers one at a time and lists each part name with its compound file. A
    part that cannot be opened is passed to the given function with the error and skipped. When the
    input itself cannot be opened, the error is raised.
    """
    for container in containers:
        try:
            ole = container.open()
        except Exception as error:
            if container.part is None:
                raise
            report(container.part, error)
            continue
        yield container.part, ole


def _location(part: str | None, path: str) -> str:
    if part is None:
        return path
    return F'{part}/{path}'


class DirRecord(enum.IntEnum):
    """
    The ids of the records of a dir stream that are read for their content or that have a body of
    fixed size (MS-OVBA 2.3.4.2).
    """
    PROJECTSYSKIND = 0x0001
    PROJECTLCID = 0x0002
    PROJECTCODEPAGE = 0x0003
    PROJECTNAME = 0x0004
    PROJECTHELPCONTEXT = 0x0007
    PROJECTLIBFLAGS = 0x0008
    PROJECTVERSION = 0x0009
    PROJECTMODULES = 0x000F
    PROJECTCOOKIE = 0x0013
    PROJECTLCIDINVOKE = 0x0014
    MODULENAME = 0x0019
    MODULESTREAMNAME = 0x001A
    MODULEHELPCONTEXT = 0x001E
    MODULETYPEPROCEDURAL = 0x0021
    MODULETYPEDOCUMENT = 0x0022
    MODULEREADONLY = 0x0025
    MODULEPRIVATE = 0x0028
    MODULETERMINATOR = 0x002B
    MODULECOOKIE = 0x002C
    MODULEOFFSET = 0x0031
    MODULESTREAMNAMEUNICODE = 0x0032
    MODULENAMEUNICODE = 0x0047
    PROJECTCOMPATVERSION = 0x004A


_FIXED_BODY_SIZES: dict[int, int] = {
    DirRecord.PROJECTSYSKIND       : 4,
    DirRecord.PROJECTLCID          : 4,
    DirRecord.PROJECTCODEPAGE      : 2,
    DirRecord.PROJECTHELPCONTEXT   : 4,
    DirRecord.PROJECTLIBFLAGS      : 4,
    DirRecord.PROJECTVERSION       : 6,
    DirRecord.PROJECTMODULES       : 2,
    DirRecord.PROJECTCOOKIE        : 2,
    DirRecord.PROJECTLCIDINVOKE    : 4,
    DirRecord.MODULEHELPCONTEXT    : 4,
    DirRecord.MODULETYPEPROCEDURAL : 0,
    DirRecord.MODULETYPEDOCUMENT   : 0,
    DirRecord.MODULEREADONLY       : 0,
    DirRecord.MODULEPRIVATE        : 0,
    DirRecord.MODULETERMINATOR     : 0,
    DirRecord.MODULECOOKIE         : 2,
    DirRecord.MODULEOFFSET         : 4,
    DirRecord.PROJECTCOMPATVERSION : 4,
}


class _DirStreamRecord(Struct[memoryview]):
    """
    A record of a dir stream: a 16-bit id, a 32-bit size, and a body. The body has the given size,
    unless the record is listed in `_FIXED_BODY_SIZES`; for these, the 32-bit field is a reserved
    value or the size of a body whose size is fixed anyway.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.id = reader.u16()
        size = reader.u32()
        self.body = reader.read_exactly(_FIXED_BODY_SIZES.get(self.id, size))

    @property
    def value(self) -> int:
        return int.from_bytes(self.body, 'little')


class VBAModuleRecord(Struct[memoryview]):
    """
    The MODULE record of a dir stream (MS-OVBA 2.3.4.2.3.2): the name of a module, the name of its
    stream, both also in UTF-16 if present, and the offset of the compressed source code in the
    stream. The record begins with the name of the module and ends with a terminator; records
    between them that are not listed here are skipped.
    """
    def __init__(self, reader: StructReader[memoryview], codec: str):
        if (record := _DirStreamRecord(reader)).id != DirRecord.MODULENAME:
            raise ValueError(F'Expected a module record, found a record with id 0x{record.id:04X}.')
        self.name = codecs.decode(record.body, codec, 'replace')
        self.name_unicode: str | None = None
        self.stream_name: str | None = None
        self.stream_name_unicode: str | None = None
        self.text_offset: int | None = None
        while (record := _DirStreamRecord(reader)).id != DirRecord.MODULETERMINATOR:
            if record.id == DirRecord.MODULENAMEUNICODE:
                self.name_unicode = codecs.decode(record.body, 'utf-16le', 'replace')
            elif record.id == DirRecord.MODULESTREAMNAME:
                self.stream_name = codecs.decode(record.body, codec, 'replace')
            elif record.id == DirRecord.MODULESTREAMNAMEUNICODE:
                self.stream_name_unicode = codecs.decode(record.body, 'utf-16le', 'replace')
            elif record.id == DirRecord.MODULEOFFSET:
                self.text_offset = record.value

    @property
    def stream_names(self) -> list[str]:
        """
        The names under which the stream of the module may be stored, in the order in which they
        are tried: the names of the stream, then the names of the module.
        """
        names = (self.stream_name, self.stream_name_unicode, self.name, self.name_unicode)
        return list(dict.fromkeys(name for name in names if name is not None))


class VBADirectory(Struct[memoryview]):
    """
    The decompressed dir stream of a VBA project (MS-OVBA 2.3.4.2): the system kind, the code page
    and the name of the project as stored, and the number of its modules. The stream is a sequence
    of records; the records in front of the list of modules, which include the references, are read
    in any order. Every record is read with its exact length, so that a record which runs past the
    end of the stream raises `refinery.lib.structures.EOF`. The module records that follow are read
    by `module_records`, one at a time.
    """
    def __init__(self, reader: StructReader[memoryview]):
        information: dict[int, memoryview] = {}
        while (record := _DirStreamRecord(reader)).id != DirRecord.PROJECTMODULES:
            information[record.id] = record.body
        self.module_count = record.value
        self._module_data = reader.read()

        def field(record: DirRecord) -> memoryview:
            try:
                return information[record]
            except KeyError:
                raise ValueError(F'The dir stream has no {record.name} record.') from None

        self.syskind = int.from_bytes(field(DirRecord.PROJECTSYSKIND), 'little')
        self.codepage = int.from_bytes(field(DirRecord.PROJECTCODEPAGE), 'little')
        self.codec = _codepage_to_codec(self.codepage)
        self.name = codecs.decode(field(DirRecord.PROJECTNAME), self.codec, 'replace')

    @property
    def is_64bit(self) -> bool:
        return self.syskind == 3

    def module_records(self) -> Iterator[VBAModuleRecord]:
        """
        The module records of the stream, in their order, preceded by the project cookie record if
        there is one. A record that cannot be read raises its error after the records in front of
        it have been listed.
        """
        reader = StructReader(self._module_data)
        if reader.u16(peek=True) == DirRecord.PROJECTCOOKIE:
            _DirStreamRecord(reader)
        for _ in range(self.module_count):
            yield VBAModuleRecord(reader, self.codec)


class VBAProject:
    """
    A VBA project in a compound file of the input. The part is the name under which the input
    stores the compound file, or `None` when the compound file is the input itself. The storage is
    the path prefix of the project inside the compound file, which is empty for the root storage
    and otherwise ends with a forward slash.
    """
    def __init__(
        self,
        part: str | None,
        ole: OleFileLike,
        storage: str,
        directory: VBADirectory,
    ):
        self.part = part
        self.ole = ole
        self.storage = storage
        self.directory = directory

    @property
    def dir_path(self) -> str:
        return _dir_path(self.storage)

    def modules(self) -> Iterator[VBAModule]:
        """
        The modules of the project, in the order of the dir stream. A module record that cannot be
        read raises its error after the modules in front of it have been listed.
        """
        for record in self.directory.module_records():
            yield VBAModule(self, record)

    @property
    def name(self) -> str:
        return self.directory.name

    @property
    def codec(self) -> str:
        return self.directory.codec

    @property
    def is_64bit(self) -> bool:
        return self.directory.is_64bit

    def location(self, path: str) -> str:
        """
        The location of the stream with the given path in the compound file of this project: the
        path, preceded by the part when there is one.
        """
        return _location(self.part, path)


class VBAModule:
    """
    A module of a `VBAProject`. The name of the module is the first name in the `stream_names` of
    its record under which the project holds a stream, or the first of these names when there is
    no such stream. The path and the location refer to the stream with that name.
    """
    def __init__(self, project: VBAProject, record: VBAModuleRecord):
        self.project = project
        self.record = record
        code = F'{project.storage}VBA/'
        names = record.stream_names
        stored = [name for name in names if project.ole.get_type(F'{code}{name}') == STGTY.STREAM]
        self.name = (stored or names)[0]
        self.path = F'{code}{self.name}'
        self.location = project.location(self.path)

    def read(self) -> memoryview:
        """
        The content of the module stream.
        """
        return self.project.ole.openstream(self.path).read()

    def source(self) -> str:
        """
        The decompressed source code of the module.
        """
        if (offset := self.record.text_offset) is None:
            raise ValueError('The module record has no offset of the source code.')
        if offset >= len(data := self.read()):
            raise ValueError(F'The source code offset {offset} lies outside the stream of {len(data)} bytes.')
        return decompress_stream(data[offset:]).decode(self.project.codec, 'replace')


class VBACompoundFile:
    """
    A compound file of the input and the VBA projects inside it whose dir stream can be read. The
    part is the name under which the input stores the compound file, or `None` when the compound
    file is the input itself.
    """
    def __init__(self, part: str | None, ole: OleFileLike, projects: list[VBAProject]):
        self.part = part
        self.ole = ole
        self.projects = projects

    def location(self, path: str) -> str:
        """
        The location of the stream or storage with the given path in this compound file: the path,
        preceded by the part when there is one.
        """
        return _location(self.part, path)


def vba_compound_files(data: buf, report: Reporter) -> Iterator[VBACompoundFile]:
    """
    The compound files of the given input that `vba_containers` lists, read one at a time, each with
    its VBA projects. An input that is no supported container has no compound files. A part that
    cannot be opened as a compound file, and a project whose dir stream cannot be read or parsed,
    are passed to the given function with their location and the error; the others are listed.
    When the input itself is a compound file or an Access database that cannot be read, the error
    is raised.
    """
    try:
        containers = vba_containers(data)
    except FileOpenError:
        return
    for part, ole in _open_containers(containers, report):
        projects: list[VBAProject] = []
        for storage in _find_vba_projects(ole):
            path = _dir_path(storage)
            try:
                directory = VBADirectory.Parse(memoryview(decompress_stream(ole.openstream(path).read())))
            except Exception as error:
                report(_location(part, path), error)
                continue
            projects.append(VBAProject(part, ole, storage, directory))
        yield VBACompoundFile(part, ole, projects)


def vba_projects(data: buf, report: Reporter) -> Iterator[VBAProject]:
    """
    The VBA projects of the compound files that `vba_compound_files` lists, in their order.
    """
    for compound_file in vba_compound_files(data, report):
        yield from compound_file.projects


def vba_form_strings(ole: OleFileLike, storage: str) -> list[bytes]:
    """
    The runs of at least five printable bytes in the `o` stream of the form storage with the given
    path, as stored, except the name of the default font Tahoma.
    """
    data = ole.openstream(F'{storage}/o').read()
    strings = (match.group() for match in _RE_PRINTABLE_STRING.finditer(data))
    return [string for string in strings if string != B'Tahoma']
