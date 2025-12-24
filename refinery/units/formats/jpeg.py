from __future__ import annotations

import enum
import re

from refinery.lib import json
from refinery.lib.id import Fmt, get_image_format
from refinery.lib.structures import Struct, StructReader, struct_to_json
from refinery.units.formats import PathExtractorUnit, UnpackResult


class JpegMarker(int, enum.Enum):

    StartOfImage = 0xD8
    EndOfImage = 0xD9
    StartOfScan = 0xDA
    DCTBaseline = 0xC0
    DCTProgressive = 0xC2
    DefineQuantizationTable = 0xDB
    DefineHuffmanTable = 0xC4
    DefineRestartInterval = 0xDD
    Comment = 0xFE

    RST0 = 0xD0
    RST1 = 0xD1
    RST2 = 0xD2
    RST3 = 0xD3
    RST4 = 0xD4
    RST5 = 0xD5
    RST6 = 0xD6
    RST7 = 0xD7

    App00 = 0xE0
    App01 = 0xE1
    App02 = 0xE2
    App03 = 0xE3
    App04 = 0xE4
    App05 = 0xE5
    App06 = 0xE6
    App07 = 0xE7
    App08 = 0xE8
    App09 = 0xE9
    App10 = 0xEA
    App11 = 0xEB
    App12 = 0xEC
    App13 = 0xED
    App14 = 0xEE
    App15 = 0xEF

    SOI = StartOfImage
    EOI = EndOfImage
    SOS = StartOfScan
    DQT = DefineQuantizationTable
    DHT = DefineHuffmanTable
    DRI = DefineRestartInterval
    COM = Comment
    SOF0 = DCTBaseline
    SOF2 = DCTProgressive


class JpegSOFComponent(Struct):
    def __init__(self, reader: StructReader):
        self.id = reader.u8()
        hv = reader.u8()
        self.hs = hv >> 4
        self.vs = hv & 15
        self.qt = reader.u8()


class JpegSOF(Struct):
    def __init__(self, reader: StructReader):
        self.precision = reader.u8()
        self.height = reader.u16()
        self.width = reader.u16()
        self.components = [JpegSOFComponent(reader) for _ in range(reader.u8())]


class JpegStream(Struct):
    def __init__(self, reader: StructReader):
        self.offset = reader.tell()
        if (h := reader.u8()) != 0xFF:
            raise ValueError(F'Invalid magic byte {h:#04x} at start of stream.')
        self.type = t = JpegMarker(reader.u8())
        if t in range(0xD0, 0xDA):
            self.size = 0
            self.data = b''
            self.scan = b''
        else:
            self.size = reader.u16() - 2
            if self.size < 0:
                raise ValueError(F'Invalid size {self.size}.')
            self.data = reader.read_exactly(self.size)
            if t == JpegMarker.StartOfScan:
                eos = re.search(br'\xFF(?!\0)', reader.peek())
                if eos is None:
                    raise ValueError('Could not find end of stream data.')
                self.scan = reader.read(eos.start())
            else:
                self.scan = b''


class Jpeg(Struct):
    def __init__(self, reader: StructReader):
        self.streams: list[JpegStream] = []
        self.sof = None
        self.scandata: list[memoryview] = []
        self.scans: list[JpegStream] = []
        self.comments: list[JpegStream] = []
        self.meta: list[JpegStream] = []

        reader.bigendian = True

        while not reader.eof:
            stream = JpegStream(reader)
            self.streams.append(stream)
            if stream.type in (JpegMarker.SOF0, JpegMarker.SOF2):
                if self.sof is not None:
                    raise ValueError('Duplicate SOF Stream in File.')
                self.sof = JpegSOF.Parse(stream.data)
            elif stream.type == JpegMarker.StartOfScan:
                self.scans.append(stream)
            elif stream.type == JpegMarker.Comment:
                self.comments.append(stream)
            elif stream.type in range(JpegMarker.App00, JpegMarker.App15 + 1):
                self.meta.append(stream)


class jpeg(PathExtractorUnit):
    """
    Extract the raw segments from a JPG image.
    """
    def unpack(self, data):
        jpg = Jpeg.Parse(data)
        for k, stream in enumerate(jpg.streams):
            yield UnpackResult(F'streams/{k}.{stream.type.name}', stream.__buffer__(0))
        for k, comment in enumerate(jpg.comments):
            yield UnpackResult(F'comments/{k}', comment.data)
        for k, scan in enumerate(jpg.scans):
            yield UnpackResult(F'scans/{k}', scan.scan)
        for k, meta in enumerate(jpg.meta):
            extension = {
                JpegMarker.App00: '.jfif',
                JpegMarker.App01: '.exif',
                JpegMarker.App02: '.iccp',
            }.get((t := meta.type), '')
            yield UnpackResult(F'meta/{k}.{t.name.lower()}{extension}', meta.data)
        if sof := jpg.sof:
            yield UnpackResult('meta/dimensions.json', json.dumps(struct_to_json(sof)))

    @classmethod
    def handles(cls, data) -> bool:
        return get_image_format(data) == Fmt.JPG
