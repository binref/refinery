#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
from typing import List
from xml.etree import ElementTree

from refinery.lib.frame import Chunk
from refinery.lib.structures import MemoryFile
from refinery.units.formats import Unit
from refinery.units.formats.archive.xtzip import xtzip


class doctxt(Unit):
    """
    Extract text from Word Documents
    """

    @Unit.Requires("olefile", optional=False)
    def _olefile():
        import olefile
        return olefile

    def process(self, data):
        """try to extract as OLE format (97-2003)"""
        errors = {}
        with MemoryFile(data) as stream:
            try:
                return self._extract_ole(stream)
            except OSError as e:
                errors["doc"] = f"can't extract as OLE: {e}"

        """ try to extract as ODT format """
        try:
            return self._extract_odt(data)
        except Exception as e:
            errors["odt"] = f"can't extract as ODT: {e}"

        """ try to extract as DOCX format (2007, 2013, 2016, 2019) """
        try:
            return self._extract_docx(data)
        except Exception as e:
            errors["docx"] = f"can't extract as DOCX: {e}"

        self.log_warn(f"failed to extract text: {errors.values()}")

    def _extract_ole(self, stream: MemoryFile) -> bytes:
        with self._olefile.OleFileIO(stream) as ole:
            s: self._olefile.OleFileIO = ole.openstream("WordDocument")
            doc: bytes = s.read()
            fib: bytes = doc[:1472]
            table: bytes = self._load_table(ole, fib)
            piece_table: bytes = self._load_piece_table(table)
            text: str = self._get_text(doc, piece_table)
            return text.encode("utf-8")

    def _extract_docx(self, data: Chunk) -> bytes:
        NAMESPACE: str = (
            "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        )
        PARAGRAPH: str = f"{NAMESPACE}p"
        TEXT: str = f"{NAMESPACE}t"

        for part in xtzip().unpack(data):
            if part.path != "word/document.xml":
                continue
            xml_content: bytes = part.get_data()
            root: ElementTree.Element = ElementTree.fromstring(xml_content)
            paragraphs: List[str] = []
            for paragraph in root.iter(PARAGRAPH):
                texts: List[str] = []
                for node in paragraph.iter(TEXT):
                    if node.text:
                        texts.append(node.text)
                if texts:
                    paragraphs.append("".join(texts))
            if not paragraphs:
                raise ValueError("found no text")
            return "\n\n".join(paragraphs).encode("utf-8")

    def _extract_odt(self, data: bytes):
        def _extract_text(node: ElementTree.Element):
            NAMESPACE2: str = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
            PARAGRAPH: str = f"{NAMESPACE2}p"
            SPAN: str = f"{NAMESPACE2}span"
            SPACE: str = f"{NAMESPACE2}s"
            res: str = ""
            for element in node.findall("*"):
                tag: str = element.tag
                text: str = element.text
                if tag in [PARAGRAPH, SPAN]:
                    if text:
                        res += text
                elif tag == SPACE:
                    res += " "
                res += _extract_text(element)

                if tag == PARAGRAPH:
                    res += "\n\n"
            return res

        NAMESPACE: str = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"
        BODY: str = f"{NAMESPACE}body"
        TEXT: str = f"{NAMESPACE}text"
        res = None
        for part in xtzip().unpack(data):
            if part.path != "content.xml":
                continue
            xml_content: bytes = part.get_data()
            root: ElementTree.Element = ElementTree.fromstring(xml_content)

            body: ElementTree.Element = root.find(BODY)
            text: ElementTree.Element = body.find(TEXT)
            res: str = _extract_text(text).encode("utf-8")
        if not res:
            raise ValueError("found no text")
        return res

    def _get_unit32(self, data: bytes, offset: int) -> int:
        return struct.unpack("<I", data[offset : offset + 4])[0]

    def _table_stream_name(self, fib: bytes) -> str:
        bit = (fib[0xB] >> 1) & 1
        return f"{bit}Table"

    def _load_table(self, ole, fib: bytes) -> bytes:
        offset: int = self._get_unit32(fib, 0x1A2)
        length: int = self._get_unit32(fib, 0x1A6)
        table_name: str = self._table_stream_name(fib)

        s: self._olefile.OleStream = ole.openstream(table_name)
        s.seek(offset)
        table: bytes = s.read(length)
        return table

    def _load_piece_table(self, table: bytes) -> bytes:
        i = 0
        while i < len(table):
            entry_type: int = table[i]
            if entry_type == 1:
                i += 2 + table[i + 1]
            elif entry_type == 2:
                piece_table_length: int = self._get_unit32(table, i + 1)
                piece_table: bytes = table[i + 5 : i + 5 + piece_table_length]
                return piece_table
            else:
                return

    def _get_text(self, doc: bytes, piece_table: bytes) -> str:
        piece_count: int = (len(piece_table) - 4) // 12
        character_positions: List[int] = []
        for i in range(piece_count + 1):
            character_positions.append(self._get_unit32(piece_table, i * 4))

        text: str = ""
        for i in range(piece_count):
            cp_start: int = character_positions[i]
            cp_end: int = character_positions[i + 1]
            desc_offset: int = (piece_count + 1) * 4 + i * 8
            descriptor: bytes = piece_table[desc_offset : desc_offset + 8]
            fc_value: int = self._get_unit32(descriptor, 2)
            is_ansi: bool = (fc_value & 0x40000000) == 0x40000000
            fc: int = fc_value & 0xBFFFFFFF
            cb: int = cp_end - cp_start
            if is_ansi:
                fc = fc // 2
                encoding: str = "cp1252"
            else:
                encoding: str = "utf16"
                cb *= 2
            raw: bytes = doc[fc : fc + cb]
            if is_ansi:
                raw = raw.replace(b"\r", b"\n")
            else:
                raw = raw.replace(b"\x00\r", b"\x00\n")
            text += raw.decode(encoding)
        return text
