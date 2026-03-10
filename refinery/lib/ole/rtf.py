"""
Port of oletools rtfobj.py and oleobj.py for RTF embedded object extraction. Parses RTF documents
and extracts OLE 1.0 objects and OLE Package streams without requiring oletools as a dependency.
"""
from __future__ import annotations

import enum
import re

from dataclasses import dataclass, field

from refinery.lib.structures import EOF, Struct, StructReader

KNOWN_CLSIDS: dict[str, str] = {
    '00000300-0000-0000-C000-000000000046': 'StdOleLink (CVE-2017-0199, CVE-2017-8570, CVE-2017-8759, CVE-2018-8174)',
    '00000303-0000-0000-C000-000000000046': 'File Moniker (CVE-2017-0199, CVE-2017-8570)',
    '00000309-0000-0000-C000-000000000046': 'Composite Moniker (CVE-2017-8570)',
    '00020C01-0000-0000-C000-000000000046': 'OLE Package Object',
    '00021700-0000-0000-C000-000000000046': 'Microsoft Equation 2.0 (CVE-2017-11882, CVE-2018-0802)',
    '00022601-0000-0000-C000-000000000046': 'OLE Package Object',
    '0002CE02-0000-0000-C000-000000000046': 'Microsoft Equation 3.0 (CVE-2017-11882, CVE-2018-0802)',
    '0003000B-0000-0000-C000-000000000046': 'Microsoft Equation (CVE-2017-11882, CVE-2018-0802)',
    '0003000C-0000-0000-C000-000000000046': 'OLE Package Object',
    '0003000E-0000-0000-C000-000000000046': 'OLE Package Object',
    '0004A6B0-0000-0000-C000-000000000046': 'Microsoft Equation 2.0 (CVE-2017-11882, CVE-2018-0802)',
    '3050F4D8-98B5-11CF-BB82-00AA00BDCE0B': 'HTML Application (CVE-2017-0199)',
    '79EAC9E0-BAF9-11CE-8C82-00AA004BA90B': 'URL Moniker (CVE-2017-0199, CVE-2017-8570, CVE-2018-8174)',
    'D27CDB6E-AE6D-11CF-96B8-444553540000': 'Shockwave Flash Object',
    'ECABB0C7-7F19-11D2-978E-0000F8757E2A': 'SOAP Moniker (CVE-2017-8759)',
    'F20DA720-C02F-11CE-927B-0800095AE340': 'OLE Package Object',
    'F4754C9B-64F5-4B40-8AF4-679732AC0607': 'Microsoft Word Document (Word.Document.12)',
}

DESTINATION_CONTROL_WORDS: frozenset[bytes] = frozenset((
    b"aftncn",
    b"aftnsep",
    b"aftnsepc",
    b"annotation",
    b"atnauthor",
    b"atndate",
    b"atnid",
    b"atnparent",
    b"atnref",
    b"atrfend",
    b"atrfstart",
    b"author",
    b"background",
    b"bkmkend",
    b"bkmkstart",
    b"blipuid",
    b"buptim",
    b"category",
    b"colorschememapping",
    b"colortbl",
    b"comment",
    b"company",
    b"creatim",
    b"datafield",
    b"datastore",
    b"defchp",
    b"defpap",
    b"do",
    b"doccomm",
    b"docvar",
    b"dptxbxtext",
    b"ebcend",
    b"ebcstart",
    b"factoidname",
    b"falt",
    b"fchars",
    b"ffdeftext",
    b"ffentrymcr",
    b"ffexitmcr",
    b"ffformat",
    b"ffhelptext",
    b"ffl",
    b"ffname",
    b"ffstattext",
    b"field",
    b"file",
    b"filetbl",
    b"fldinst",
    b"fldrslt",
    b"fldtype",
    b"fontemb",
    b"fonttbl",
    b"footer",
    b"footerf",
    b"footerl",
    b"footerr",
    b"footnote",
    b"formfield",
    b"ftncn",
    b"ftnsep",
    b"ftnsepc",
    b"g",
    b"generator",
    b"gridtbl",
    b"header",
    b"headerf",
    b"headerl",
    b"headerr",
    b"hl",
    b"hlfr",
    b"hlinkbase",
    b"hlloc",
    b"hlsrc",
    b"hsv",
    b"info",
    b"keywords",
    b"latentstyles",
    b"lchars",
    b"levelnumbers",
    b"leveltext",
    b"lfolevel",
    b"linkval",
    b"list",
    b"listlevel",
    b"listname",
    b"listoverride",
    b"listoverridetable",
    b"listpicture",
    b"liststylename",
    b"listtable",
    b"listtext",
    b"lsdlockedexcept",
    b"macc",
    b"maccPr",
    b"mailmerge",
    b"malnScr",
    b"manager",
    b"margPr",
    b"mbar",
    b"mbarPr",
    b"mbaseJc",
    b"mbegChr",
    b"mborderBox",
    b"mborderBoxPr",
    b"mbox",
    b"mboxPr",
    b"mchr",
    b"mcount",
    b"mctrlPr",
    b"md",
    b"mdeg",
    b"mdegHide",
    b"mden",
    b"mdiff",
    b"mdPr",
    b"me",
    b"mendChr",
    b"meqArr",
    b"meqArrPr",
    b"mf",
    b"mfName",
    b"mfPr",
    b"mfunc",
    b"mfuncPr",
    b"mgroupChr",
    b"mgroupChrPr",
    b"mgrow",
    b"mhideBot",
    b"mhideLeft",
    b"mhideRight",
    b"mhideTop",
    b"mlim",
    b"mlimLoc",
    b"mlimLow",
    b"mlimLowPr",
    b"mlimUpp",
    b"mlimUppPr",
    b"mm",
    b"mmaddfieldname",
    b"mmathPict",
    b"mmaxDist",
    b"mmc",
    b"mmcJc",
    b"mmconnectstr",
    b"mmconnectstrdata",
    b"mmcPr",
    b"mmcs",
    b"mmdatasource",
    b"mmheadersource",
    b"mmmailsubject",
    b"mmodso",
    b"mmodsofilter",
    b"mmodsofldmpdata",
    b"mmodsomappedname",
    b"mmodsoname",
    b"mmodsorecipdata",
    b"mmodsosort",
    b"mmodsosrc",
    b"mmodsotable",
    b"mmodsoudl",
    b"mmodsoudldata",
    b"mmodsouniquetag",
    b"mmPr",
    b"mmquery",
    b"mmr",
    b"mnary",
    b"mnaryPr",
    b"mnoBreak",
    b"mnum",
    b"mobjDist",
    b"moMath",
    b"moMathPara",
    b"moMathParaPr",
    b"mopEmu",
    b"mphant",
    b"mphantPr",
    b"mplcHide",
    b"mpos",
    b"mr",
    b"mrad",
    b"mradPr",
    b"mrPr",
    b"msepChr",
    b"mshow",
    b"mshp",
    b"msPre",
    b"msPrePr",
    b"msSub",
    b"msSubPr",
    b"msSubSup",
    b"msSubSupPr",
    b"msSup",
    b"msSupPr",
    b"mstrikeBLTR",
    b"mstrikeH",
    b"mstrikeTLBR",
    b"mstrikeV",
    b"msub",
    b"msubHide",
    b"msup",
    b"msupHide",
    b"mtransp",
    b"mtype",
    b"mvertJc",
    b"mvfmf",
    b"mvfml",
    b"mvtof",
    b"mvtol",
    b"mzeroAsc",
    b"mzeroDesc",
    b"mzeroWid",
    b"nesttableprops",
    b"nonesttables",
    b"objalias",
    b"objclass",
    b"objdata",
    b"object",
    b"objname",
    b"objsect",
    b"oldcprops",
    b"oldpprops",
    b"oldsprops",
    b"oldtprops",
    b"oleclsid",
    b"operator",
    b"panose",
    b"password",
    b"passwordhash",
    b"pgp",
    b"pgptbl",
    b"picprop",
    b"pict",
    b"pn",
    b"pnseclvl",
    b"pntext",
    b"pntxta",
    b"pntxtb",
    b"printim",
    b"propname",
    b"protend",
    b"protstart",
    b"protusertbl",
    b"result",
    b"revtbl",
    b"revtim",
    b"rxe",
    b"shp",
    b"shpgrp",
    b"shpinst",
    b"shppict",
    b"shprslt",
    b"shptxt",
    b"sn",
    b"sp",
    b"staticval",
    b"stylesheet",
    b"subject",
    b"sv",
    b"svb",
    b"tc",
    b"template",
    b"themedata",
    b"title",
    b"txe",
    b"ud",
    b"upr",
    b"userprops",
    b"wgrffmtfilter",
    b"windowcaption",
    b"writereservation",
    b"writereservhash",
    b"xe",
    b"xform",
    b"xmlattrname",
    b"xmlattrvalue",
    b"xmlclose",
    b"xmlname",
    b"xmlnstbl",
    b"xmlopen",
    b"margSz",
    b"pnaiu",
    b"pnaiud",
))

_BACKSLASH = ord('\\')
_BRACE_OPEN = ord('{')
_BRACE_CLOSE = ord('}')
_SPACE = ord(' ')

_RE_CONTROL_WORD = re.compile(
    b'\\\\([a-zA-Z]{1,250})'
    b'(?:(-?\\d+)(?=[^0-9])|(?=[^a-zA-Z0-9])|$)'
)
_RE_CONTROL_SYMBOL = re.compile(b'\\\\[^a-zA-Z]')
_RE_TEXT = re.compile(b'[^{}\\\\]+')
_RE_NON_HEX = re.compile(b'[^a-fA-F0-9]')


class TYPE(enum.IntEnum):
    LINKED = 0x01
    EMBEDDED = 0x02


class OleObject(Struct[memoryview]):
    """
    Represents an OLE 1.0 Object parsed from binary data according to MS-OLEDS 2.2 OLE1.0 Format
    Structures.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.ole_version = reader.u32()
        format_id = reader.u32()
        try:
            self.format_id: TYPE | None = TYPE(format_id)
        except Exception:
            raise ValueError(F'Unknown OLE format ID {format_id:#x}.')
        self.class_name = reader.read_length_prefixed()[:-1]
        self.topic_name = reader.read_length_prefixed()[:-1]
        self.item_name = reader.read_length_prefixed()[:-1]
        if self.format_id == TYPE.EMBEDDED:
            self.data_size: int | None = reader.u32()
            self.data: memoryview = reader.read(self.data_size)
            self.extra_data: memoryview = reader.read()
        else:
            self.data_size = None
            self.data = memoryview(B'')
            self.extra_data = memoryview(B'')


class OleNativeStream(Struct):
    """
    Parses an OLE Package / OLE Native Stream structure to extract the embedded filename, paths,
    and payload data.
    """

    def __init__(self, reader: StructReader, package: bool = False):
        if not package:
            reader.u32()
        reader.u16()
        self.filename = reader.read_c_string('latin1')
        self.src_path = reader.read_c_string('latin1')
        reader.u32()
        reader.u32()
        self.temp_path = reader.read_c_string('latin1')
        try:
            self.actual_size = reader.u32()
            self.data: bytes | None = reader.read(self.actual_size)
            self.is_link = False
        except (EOF, IndexError):
            self.is_link = True
            self.actual_size = 0
            self.data = None


@dataclass
class RtfObject:
    """
    Represents an object embedded in an RTF document, with parsed OLE metadata when available.
    """
    start: int = 0
    end: int = 0
    hexdata: bytes = b''
    rawdata: bytes = b''
    is_ole: bool = False
    oledata: bytes | None = None
    oledata_size: int | None = None
    format_id: TYPE | None = None
    class_name: bytes | None = None
    is_package: bool = False
    olepkgdata: bytes | None = None
    filename: str | None = None
    src_path: str | None = None
    temp_path: str | None = None
    clsid: str | None = None
    clsid_desc: str | None = None


@dataclass
class _Destination:
    """
    Internal tracking state for an RTF destination (a named group that accumulates data).
    """
    cword: bytes | None = None
    data: bytearray = field(default_factory=bytearray)
    start: int = 0
    end: int = 0
    group_level: int = 0


class RtfParser:
    """
    Generic RTF parser implementing a state machine that tracks groups, destinations, control
    words, control symbols, binary data, and text. Designed to handle malformed RTF as MS Word
    does.
    """
    def __init__(self, data: bytes | bytearray | memoryview):
        self.data: bytes | bytearray | memoryview = data
        self.index: int = 0
        self.group_level: int = 0
        self.current_destination = document_destination = _Destination()
        self.destinations: list[_Destination] = [document_destination]
        n = len(data)
        while self.index < n:
            byte = data[self.index]
            if byte == _BRACE_OPEN:
                self._open_group()
                self.index += 1
                continue
            if byte == _BRACE_CLOSE:
                self._close_group()
                self.index += 1
                continue
            if byte == _BACKSLASH:
                m = _RE_CONTROL_WORD.match(data, self.index)
                if m:
                    cword = m.group(1)
                    param = m.group(2)
                    self._control_word(m, cword, param)
                    self.index += len(m.group())
                    if cword == b'bin':
                        self._bin(param)
                    continue
                m = _RE_CONTROL_SYMBOL.match(data, self.index)
                if m:
                    self.control_symbol(m)
                    self.index += len(m.group())
                    continue
            m = _RE_TEXT.match(data, self.index)
            if m:
                self._text(m)
                self.index += len(m.group())
                continue
            self.index += 1
        self._end_of_file()

    def _open_group(self) -> None:
        self.group_level += 1
        self.open_group()

    def open_group(self) -> None:
        pass

    def _close_group(self) -> None:
        self.close_group()
        if self.group_level == self.current_destination.group_level:
            self._close_destination()
        self.group_level -= 1

    def close_group(self) -> None:
        pass

    def _open_destination(
        self, matchobject: re.Match, cword: bytes
    ) -> None:
        if self.current_destination.group_level == self.group_level:
            self._close_destination()
        dest = _Destination(cword)
        dest.group_level = self.group_level
        dest.start = self.index + len(matchobject.group())
        self.destinations.append(dest)
        self.current_destination = dest
        self.open_destination(dest)

    def open_destination(self, destination: _Destination) -> None:
        pass

    def _close_destination(self) -> None:
        self.current_destination.end = self.index
        self.close_destination(self.current_destination)
        if self.destinations:
            self.destinations.pop()
        if self.destinations:
            self.current_destination = self.destinations[-1]

    def close_destination(self, destination: _Destination) -> None:
        pass

    def _control_word(
        self,
        matchobject: re.Match,
        cword: bytes,
        param: bytes | None,
    ) -> None:
        if cword in DESTINATION_CONTROL_WORDS:
            self._open_destination(matchobject, cword)
        self.control_word(matchobject, cword, param)

    def control_word(
        self,
        matchobject: re.Match,
        cword: bytes,
        param: bytes | None,
    ) -> None:
        pass

    def control_symbol(self, matchobject: re.Match) -> None:
        pass

    def _text(self, matchobject: re.Match) -> None:
        text = matchobject.group()
        self.current_destination.data += text
        self.text(matchobject, text)

    def text(
        self, matchobject: re.Match, text: bytes
    ) -> None:
        pass

    def _bin(self, param: bytes | None) -> None:
        if param is None:
            binlen = 0
        else:
            binlen = int(param)
        if binlen < 0:
            binlen = 0
        index = self.index
        try:
            if self.data[index] == _SPACE:
                index += 1
        except IndexError:
            pass
        bindata = bytes(self.data[index:(index := index + binlen)])
        self.index = index
        self.bin_data(bindata)

    def bin_data(self, bindata: bytes) -> None:
        pass

    def _end_of_file(self) -> None:
        while self.group_level > 0:
            self._close_group()
        self.end_of_file()

    def end_of_file(self) -> None:
        pass


def _extract_clsid(oledata: bytes) -> tuple[str | None, str | None]:
    """
    Attempt to read the root entry CLSID from OLE2 data using refinery's internal OLE parser.
    Returns (clsid, description) or (None, None).
    """
    from refinery.lib.ole.file import OleFile, is_ole_file
    try:
        if not is_ole_file(oledata):
            return None, None
        ole = OleFile(oledata)
        raw_clsid = ole.getclsid('/')
        if not raw_clsid:
            return None, None
        desc = KNOWN_CLSIDS.get(raw_clsid.upper())
        return raw_clsid, desc
    except Exception:
        return None, None


class RtfObjParser(RtfParser):
    """
    Specialized RTF parser that extracts embedded OLE objects from RTF documents. After calling
    parse(), the extracted objects are available in the `objects` list.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self.objects: list[RtfObject] = []
        super().__init__(data)

    def open_destination(self, destination: _Destination) -> None:
        pass

    def close_destination(self, destination: _Destination) -> None:
        if destination.cword != b'objdata':
            return
        rtfobj = RtfObject()
        self.objects.append(rtfobj)
        rtfobj.start = destination.start
        rtfobj.end = destination.end
        hexdata = destination.data.translate(None, b' \t\r\n\f\v')
        hexdata = _RE_NON_HEX.sub(b'', hexdata)
        if len(hexdata) & 1:
            hexdata = hexdata[:-1]
        rtfobj.hexdata = hexdata
        try:
            object_data = bytes.fromhex(hexdata.decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            return
        rtfobj.rawdata = object_data
        try:
            obj = OleObject.Parse(memoryview(object_data))
            rtfobj.format_id = obj.format_id
            rtfobj.class_name = obj.class_name
            rtfobj.oledata_size = obj.data_size
            rtfobj.oledata = obj.data
            rtfobj.is_ole = True
            if obj.class_name and bytes(obj.class_name).lower() == b'package':
                try:
                    opkg = OleNativeStream.Parse(obj.data, package=True)
                    rtfobj.filename = opkg.filename
                    rtfobj.src_path = opkg.src_path
                    rtfobj.temp_path = opkg.temp_path
                    rtfobj.olepkgdata = opkg.data
                    rtfobj.is_package = True
                except Exception:
                    pass
            elif obj.data:
                clsid, clsid_desc = _extract_clsid(obj.data)
                if clsid is not None:
                    rtfobj.clsid = clsid
                    rtfobj.clsid_desc = clsid_desc
        except Exception:
            pass

    def bin_data(self, bindata: bytes) -> None:
        if self.current_destination.cword == b'objdata':
            import binascii
            self.current_destination.data.extend(binascii.hexlify(bindata))

    def control_symbol(self, matchobject: re.Match) -> None:
        symbol = matchobject.group()[1:2]
        if symbol != b"'":
            return
        # MS Word hex escape: \'hh
        # Read two bytes following the escape (any characters, not
        # just hex) and advance the index by 2.
        self.index += 2
        if self.current_destination.cword == b'objdata':
            # Emulate the MS Word RTF parser bug: if the number of
            # hex digits accumulated so far is odd, the last digit
            # is silently dropped before the \' escape is processed.
            self.current_destination.data = bytearray(_RE_NON_HEX.sub(b'', self.current_destination.data))
            if len(self.current_destination.data) & 1:
                del self.current_destination.data[-1:]
