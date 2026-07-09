from __future__ import annotations

import re

from enum import Enum
from pathlib import Path

from refinery.lib import xml
from refinery.lib.dt import isodate
from refinery.units.formats import JSONTableUnit, Unit
from refinery.units.formats.office.xtdoc import xtdoc


class _Prop(str, Enum):
    app = 'app.xml'
    core = 'core.xml'
    custom = 'custom.xml'


class _Kind(str, Enum):
    access = 'access'
    ole = 'ole'
    ooxml = 'ooxml'
    opendocument = 'opendocument'
    pdf = 'pdf'
    rtf = 'rtf'


def _interpret(value: str | dict):
    if isinstance(value, dict):
        return {k: _interpret(v) for k, v in value.items()}
    if value.isdigit():
        return int(value)
    casefold = value.lower()
    if casefold == 'false':
        return False
    if casefold == 'true':
        return True
    return isodate(value) or value


class docmeta(JSONTableUnit):
    """
    Extract metadata from documents. This covers legacy OLE2 Office documents (Word, Excel, and
    PowerPoint), the modern OOXML formats (DOCX, XLSX, and PPTX), OpenDocument files (ODT, ODS, and
    ODP), PDF documents, and RTF documents. For OOXML files, this includes custom document
    properties; for Microsoft Access databases, this includes the database engine, timestamps, and
    the user profile paths leaked by the compiled VBA project and by the import/export
    specifications.
    """
    @Unit.Requires('pymupdf', 1)
    def _mupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        return pymupdf

    @classmethod
    def _classify(cls, data) -> _Kind | None:
        from refinery.lib.access import is_access_database
        from refinery.lib.id import Fmt, buffer_contains, get_microsoft_format, get_office_xml_type
        if is_access_database(data):
            return _Kind.access
        if data[:5] == B'%PDF-':
            return _Kind.pdf
        if re.match(BR'\s{0,500}\{\\rtf', memoryview(data)[:505]):
            return _Kind.rtf
        if data[:2] == B'PK':
            if get_office_xml_type(data) in (Fmt.DOCX, Fmt.XLSX, Fmt.PPTX):
                return _Kind.ooxml
            if buffer_contains(data, B'vnd.oasis.opendocument'):
                return _Kind.opendocument
            return None
        if get_microsoft_format(data) in (Fmt.DOC, Fmt.XLS, Fmt.PPT, Fmt.CFF):
            return _Kind.ole
        return None

    @classmethod
    def handles(cls, data) -> bool | None:
        return cls._classify(data) is not None

    def json(self, data: bytearray):
        kind = self._classify(data)
        if kind is None:
            return None
        dispatch = {
            _Kind.access       : self._json_access,
            _Kind.ole          : self._json_ole,
            _Kind.ooxml        : self._json_ooxml,
            _Kind.opendocument : self._json_opendocument,
            _Kind.pdf          : self._json_pdf,
            _Kind.rtf          : self._json_rtf,
        }
        return dispatch[kind](data)

    def _json_access(self, data: bytearray):
        from refinery.lib.access import AccessDatabase
        return AccessDatabase(data).metadata()

    def _json_ole(self, data: bytearray):
        from refinery.lib.ole.file import OleFile
        with OleFile(data) as ole:
            meta = ole.get_metadata().dump()
        for noise in ('codepage', 'codepage_doc', 'thumbnail'):
            meta.pop(noise, None)
        return meta or None

    def _json_rtf(self, data: bytearray):
        from refinery.lib.ole.rtf import RtfInfoParser
        return RtfInfoParser(data).info or None

    def _json_pdf(self, data: bytearray):
        from refinery.lib.dt import pdfdate
        from refinery.lib.tools import NoLogging
        with NoLogging():
            document = self._mupdf.open(stream=data, filetype='pdf')
            meta = document.metadata
        if not meta:
            return None
        result = {}
        for key, value in meta.items():
            if not value:
                continue
            if key.endswith('Date') and (parsed := pdfdate(value)) is not None:
                value = parsed
            result[key] = value
        return result or None

    def _json_opendocument(self, data: bytearray):
        from refinery.units.formats.archive.xtzip import xtzip
        meta = data | xtzip('meta.xml') | bytearray
        if not meta or (dom := xml.parse(meta)) is None:
            return None
        while dom.tag.rpartition(':')[2].lower() != 'document-meta':
            if not dom.children:
                return None
            dom = dom.children[0]
        contents = {}
        for wrapper in dom:
            if wrapper.tag.rpartition(':')[2].lower() != 'meta':
                continue
            for node in wrapper:
                _, _, name = node.tag.partition(':')
                if content := node.content:
                    contents[name or node.tag] = _interpret(content.strip())
                elif node.attributes:
                    for key, value in node.attributes.items():
                        _, _, subname = key.partition(':')
                        contents[subname or key] = _interpret(value)
        return {'meta': contents} if contents else None

    def _json_ooxml(self, data: bytearray):
        props = data | xtdoc('docProps/*.xml', exact=True, path=b'path') | {'path': bytearray}
        result = {}

        for path, page in props.items():
            name = Path(path).name
            if (dom := xml.parse(page)) is None:
                self.log_info(F'failed to parse as XML: {path}')
                continue
            try:
                prop = _Prop(name)
            except ValueError:
                self.log_info(F'skipped unknown property: {name}')
                continue

            result[prop.name] = contents = {}

            if prop == _Prop.custom:
                while dom.tag.lower() != 'properties':
                    dom = dom.children[0]
                for node in dom:
                    assert node.tag.lower() == 'property'
                    assert len(node.children) == 1
                    content = node.children[0].content
                    if content is None:
                        continue
                    contents[node.attributes['name']] = content.strip()
            elif prop == _Prop.app:
                while dom.tag.lower() != 'properties':
                    dom = dom.children[0]
                for node in dom:
                    if not (content := node.content):
                        continue
                    contents[node.tag] = content
            elif prop == _Prop.core:
                while dom.tag.lower() != 'cp:coreproperties':
                    dom = dom.children[0]
                for node in dom:
                    t, _, name = node.tag.partition(':')
                    if not name:
                        continue
                    if not (content := node.content):
                        continue
                    contents[name] = content
            for name, value in contents.items():
                contents[name] = _interpret(value)

        return result
