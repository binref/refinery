#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from collections import OrderedDict
from io import StringIO
from typing import Callable, Dict, TYPE_CHECKING

from defusedxml.ElementTree import XML

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

from refinery.lib.frame import Chunk
from refinery.lib.structures import MemoryFile, StructReader
from refinery.units.formats import Unit
from refinery.units.formats.archive.xtzip import xtzip


class doctxt(Unit):
    """
    Extract text from Word Documents
    """

    @Unit.Requires('olefile', 'formats', 'office')
    def _olefile():
        import olefile
        return olefile

    def process(self, data: bytearray):
        extractors: Dict[str, Callable[[bytearray], str]] = OrderedDict(
            doc=self._extract_ole,
            docx=self._extract_docx,
            odt=self._extract_odt,
        )
        if data.startswith(B'PK'):
            self.log_debug('document contains zip file signature, likely a odt or docx file')
            extractors.move_to_end('doc')
            if 'opendocument' in str(data | xtzip('mimetype')):
                self.log_debug('odt signature detected')
                extractors.move_to_end('odt', last=False)
        for filetype, extractor in extractors.items():
            self.log_debug(F'trying to extract as {filetype}')
            try:
                result = extractor(data)
            except ImportError:
                raise
            except Exception as error:
                self.log_info(F'failed extractring as {filetype}: {error!s}')
            else:
                return result.encode(self.codec)
        raise ValueError('All extractors failed, the input data is not recognized as any known document format.')

    def _extract_docx(self, data: Chunk) -> str:
        NAMESPACE = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
        PARAGRAPH = F'{NAMESPACE}p'
        TEXT = F'{NAMESPACE}t'
        chunk = data | xtzip('word/document.xml') | bytearray
        if not chunk:
            raise ValueError('No document.xml file found.')
        root: Element = XML(chunk)
        with StringIO() as output:
            for index, paragraph in enumerate(root.iter(PARAGRAPH)):
                if index > 0:
                    output.write('\n')
                for node in paragraph.iter(TEXT):
                    if node.text:
                        output.write(node.text)
            return output.getvalue()

    def _extract_odt(self, data: bytes):
        def _extract_text(node: Element):
            NAMESPACE = '{urn:oasis:names:tc:opendocument:xmlns:text:1.0}'
            PARAGRAPH = F'{NAMESPACE}p'
            SPAN = F'{NAMESPACE}span'
            SPACE = F'{NAMESPACE}s'
            with StringIO() as res:
                for element in node:
                    tag = element.tag
                    text = element.text or ''
                    tail = element.tail or ''
                    if tag in [PARAGRAPH, SPAN]:
                        res.write(text)
                    elif tag == SPACE:
                        res.write(' ')
                    else:
                        self.log_debug(F'unknown tag: {tag}')
                    res.write(_extract_text(element))
                    res.write(tail)
                    if tag == PARAGRAPH:
                        res.write('\n')
                return res.getvalue()

        NAMESPACE = '{urn:oasis:names:tc:opendocument:xmlns:office:1.0}'
        BODY = F'{NAMESPACE}body'
        TEXT = F'{NAMESPACE}text'
        for part in xtzip().unpack(data):
            if part.path != 'content.xml':
                continue
            xml_content: bytes = part.get_data()
            root: Element = XML(xml_content)
            body: Element = root.find(BODY)
            text: Element = body.find(TEXT)
            return _extract_text(text)
        else:
            raise ValueError('found no text')

    def _extract_ole(self, data: bytearray) -> str:
        stream = MemoryFile(data)
        with self._olefile.OleFileIO(stream) as ole:
            doc = ole.openstream('WordDocument').read()
            with StructReader(doc) as reader:
                table_name = F'{(doc[11]>>1)&1}Table'
                reader.seek(0x1A2)
                offset = reader.u32()
                length = reader.u32()
            with StructReader(ole.openstream(table_name).read()) as reader:
                reader.seek(offset)
                table = reader.read(length)
            piece_table = self._load_piece_table(table)
            return self._get_text(doc, piece_table)

    def _load_piece_table(self, table: bytes) -> bytes:
        with StructReader(table) as reader:
            while not reader.eof:
                entry_type = reader.read_byte()
                if entry_type == 1:
                    reader.seekrel(reader.read_byte())
                    continue
                if entry_type == 2:
                    length = reader.u32()
                    return reader.read(length)
                raise NotImplementedError(F'Unsupported table entry type value 0x{entry_type:X}.')

    def _get_text(self, doc: bytes, piece_table: bytes) -> str:
        piece_count: int = 1 + (len(piece_table) - 4) // 12
        with StringIO() as text:
            with StructReader(piece_table) as reader:
                character_positions = [reader.u32() for _ in range(piece_count)]
                for i in range(piece_count - 1):
                    cp_start = character_positions[i]
                    cp_end = character_positions[i + 1]
                    fc_value = reader.read_struct('xxLxx', unwrap=True)
                    is_ansi = bool((fc_value >> 30) & 1)
                    fc = fc_value & 0xBFFFFFFF
                    cb = cp_end - cp_start
                    if is_ansi:
                        encoding = 'cp1252'
                        fc = fc // 2
                    else:
                        encoding = 'utf16'
                        cb *= 2
                    raw = doc[fc : fc + cb]
                    text.write(raw.decode(encoding).replace('\r', '\n'))
            return text.getvalue()
