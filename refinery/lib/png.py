"""
Shared PNG parsing library. Provides structure definitions and constants for parsing
Portable Network Graphics (PNG) files, used by both the format extractor unit and the
PNG carver.
"""
from __future__ import annotations

import enum
import zlib

from refinery.lib.structures import Struct, StructReader

PNG_SIGNATURE = b'\x89PNG\r\n\x1A\n'


class PngChunkType(bytes, enum.Enum):
    IHDR = b'IHDR'
    PLTE = b'PLTE'
    IDAT = b'IDAT'
    IEND = b'IEND'
    bKGD = b'bKGD'
    cHRM = b'cHRM'
    cICP = b'cICP'
    dSIG = b'dSIG'
    eXIf = b'eXIf'
    gAMA = b'gAMA'
    hIST = b'hIST'
    iCCP = b'iCCP'
    iTXt = b'iTXt'
    pHYs = b'pHYs'
    sBIT = b'sBIT'
    sPLT = b'sPLT'
    sRGB = b'sRGB'
    sTER = b'sTER'
    tEXt = b'tEXt'
    tIME = b'tIME'
    tRNS = b'tRNS'
    zTXt = b'zTXt'


PNG_CHUNK_TYPES = frozenset(t.value for t in PngChunkType)


class PngChunk(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.offset = reader.tell()
        self.size = reader.u32()
        self.type_tag = bytes(reader.read_exactly(4))
        try:
            self.type = PngChunkType(self.type_tag)
        except ValueError:
            self.type = None
        self.data = reader.read_exactly(self.size)
        self.crc = reader.u32()

    @property
    def valid(self) -> bool:
        cs = zlib.crc32(self.type_tag)
        cs = zlib.crc32(self.data, cs)
        return cs & 0xFFFFFFFF == self.crc

    @property
    def type_name(self) -> str:
        if isinstance(self.type, PngChunkType):
            return self.type.name
        return self.type_tag.decode('ascii', errors='replace')


class PngIHDR(Struct):
    def __init__(self, reader: StructReader):
        reader.bigendian = True
        self.width = reader.u32()
        self.height = reader.u32()
        self.bit_depth = reader.u8()
        self.color_type = reader.u8()
        self.compression = reader.u8()
        self.filter = reader.u8()
        self.interlace = reader.u8()


class Png(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        signature = reader.read_exactly(8)
        if bytes(signature) != PNG_SIGNATURE:
            raise ValueError('Invalid PNG signature.')
        self.ihdr: PngIHDR | None = None
        self.chunks: list[PngChunk] = []
        self.text_chunks: list[PngChunk] = []
        self.meta_chunks: list[PngChunk] = []
        while not reader.eof:
            chunk = PngChunk(reader)
            self.chunks.append(chunk)
            if chunk.type == PngChunkType.IHDR:
                if self.ihdr is not None:
                    raise ValueError('Duplicate IHDR chunk in PNG file.')
                self.ihdr = PngIHDR.Parse(chunk.data)
            elif chunk.type in (PngChunkType.tEXt, PngChunkType.zTXt, PngChunkType.iTXt):
                self.text_chunks.append(chunk)
            elif isinstance(chunk.type, PngChunkType) and chunk.type not in (
                PngChunkType.IHDR,
                PngChunkType.PLTE,
                PngChunkType.IDAT,
                PngChunkType.IEND,
            ):
                self.meta_chunks.append(chunk)
            if chunk.type == PngChunkType.IEND:
                break
