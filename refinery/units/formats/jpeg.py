from __future__ import annotations

import enum
import re

from refinery.lib import json
from refinery.lib.id import Fmt, get_image_format
from refinery.lib.structures import EOF, Struct, StructReader, struct_to_json
from refinery.units.formats import PathExtractorUnit, UnpackResult


class JpegMarker(int, enum.Enum):
    """
    The markers that the JPEG standard defines.
    """
    StartOfImage = 0xD8
    EndOfImage = 0xD9
    StartOfScan = 0xDA
    DCTBaseline = 0xC0
    DCTExtendedSequential = 0xC1
    DCTProgressive = 0xC2
    Lossless = 0xC3
    DifferentialDCTSequential = 0xC5
    DifferentialDCTProgressive = 0xC6
    DifferentialLossless = 0xC7
    Extension = 0xC8
    ArithmeticDCTExtendedSequential = 0xC9
    ArithmeticDCTProgressive = 0xCA
    ArithmeticLossless = 0xCB
    ArithmeticDifferentialDCTSequential = 0xCD
    ArithmeticDifferentialDCTProgressive = 0xCE
    ArithmeticDifferentialLossless = 0xCF
    DefineQuantizationTable = 0xDB
    DefineHuffmanTable = 0xC4
    DefineArithmeticConditioning = 0xCC
    DefineRestartInterval = 0xDD
    DefineNumberOfLines = 0xDC
    DefineHierarchicalProgression = 0xDE
    ExpandReferenceComponents = 0xDF
    Comment = 0xFE
    Temporary = 0x01

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

    Ext00 = 0xF0
    Ext01 = 0xF1
    Ext02 = 0xF2
    Ext03 = 0xF3
    Ext04 = 0xF4
    Ext05 = 0xF5
    Ext06 = 0xF6
    Ext07 = 0xF7
    Ext08 = 0xF8
    Ext09 = 0xF9
    Ext10 = 0xFA
    Ext11 = 0xFB
    Ext12 = 0xFC
    Ext13 = 0xFD

    SOI = StartOfImage
    EOI = EndOfImage
    SOS = StartOfScan
    DQT = DefineQuantizationTable
    DHT = DefineHuffmanTable
    DAC = DefineArithmeticConditioning
    DRI = DefineRestartInterval
    DNL = DefineNumberOfLines
    DHP = DefineHierarchicalProgression
    EXP = ExpandReferenceComponents
    COM = Comment
    TEM = Temporary
    SOF0 = DCTBaseline
    SOF1 = DCTExtendedSequential
    SOF2 = DCTProgressive
    SOF3 = Lossless

    @property
    def is_standalone(self) -> bool:
        """
        Whether the marker stands alone, i.e. it is not followed by a segment.
        """
        return self == JpegMarker.TEM or self in range(0xD0, 0xDA)

    @property
    def is_frame(self) -> bool:
        """
        Whether the marker starts a frame header, which gives the dimensions of the image.
        """
        return self in range(0xC0, 0xD0) and self not in (
            JpegMarker.DHT,
            JpegMarker.Extension,
            JpegMarker.DAC,
        )


class JpegSOFComponent(Struct):
    def __init__(self, reader: StructReader):
        self.id = reader.u8()
        hv = reader.u8()
        self.hs = hv >> 4
        self.vs = hv & 15
        self.qt = reader.u8()


class JpegSOF(Struct):
    def __init__(self, reader: StructReader):
        reader.bigendian = True
        self.precision = reader.u8()
        self.height = reader.u16()
        self.width = reader.u16()
        self.components = [JpegSOFComponent(reader) for _ in range(reader.u8())]


_MARKER = re.compile(br'(?<!\xFF)\xFF+(?=[^\x00\xFF])')
_END_OF_SCAN = re.compile(br'(?<!\xFF)\xFF+(?=[^\x00\xD0-\xD7\xFF])')


class JpegStream(Struct):
    """
    A marker with the fill bytes in front of it and the segment that follows it. The segment of a
    scan is followed by its entropy-coded data, which runs across restart markers up to the next
    marker of any other kind or to the end of the data. A segment that the end of the data cuts
    holds the bytes that are there.
    """
    def __init__(self, reader: StructReader):
        self.offset = reader.tell()
        if (h := reader.u8()) != 0xFF:
            raise ValueError(F'Invalid magic byte {h:#04x} at start of stream.')
        while (marker := reader.u8()) == 0xFF:
            pass
        self.type = t = JpegMarker(marker)
        if t.is_standalone:
            self.size = 0
            self.data = b''
            self.scan = b''
        else:
            self.size = reader.u16() - 2
            if self.size < 0:
                raise ValueError(F'Invalid size {self.size}.')
            self.data = reader.read(self.size)
            if t == JpegMarker.StartOfScan:
                end = _END_OF_SCAN.search(reader.peek())
                self.scan = reader.read(None if end is None else end.start())
            else:
                self.scan = b''

    @property
    def truncated(self) -> bool:
        """
        Whether the end of the data cuts the segment.
        """
        return len(self.data) < self.size


class Jpeg(Struct):
    """
    A JPEG image, which begins with its start-of-image marker and ends with its end-of-image marker
    or with the end of the data; the data that follows the end-of-image marker is not part of the
    structure. The junk of the image is the data in front of a marker that is not fill bytes, and
    the rest of the data when it ends inside a marker or inside the length of a segment.
    """
    def __init__(self, reader: StructReader):
        self.streams: list[JpegStream] = []
        self.junk: list[memoryview] = []
        self.sof = None
        self.scandata: list[memoryview] = []
        self.scans: list[JpegStream] = []
        self.comments: list[JpegStream] = []
        self.meta: list[JpegStream] = []

        reader.bigendian = True

        if reader.peek(2) != B'\xFF\xD8':
            raise ValueError('The data does not begin with a start-of-image marker.')

        while not reader.eof:
            start = reader.tell()
            marker = _MARKER.search(reader.peek())
            if marker is None or marker.start() > 0:
                self.junk.append(reader.read(None if marker is None else marker.start()))
                continue
            try:
                stream = JpegStream(reader)
            except EOF:
                reader.seekset(start)
                self.junk.append(reader.read())
                break
            self.streams.append(stream)
            if (t := stream.type).is_frame:
                if self.sof is not None:
                    raise ValueError('Duplicate SOF Stream in File.')
                if not stream.truncated:
                    self.sof = JpegSOF.Parse(stream.data)
            elif t == JpegMarker.StartOfScan:
                self.scans.append(stream)
            elif t == JpegMarker.Comment:
                self.comments.append(stream)
            elif t in range(JpegMarker.App00, JpegMarker.App15 + 1):
                self.meta.append(stream)
            elif t == JpegMarker.EndOfImage:
                break

    @property
    def truncated(self) -> bool:
        """
        Whether the data ends before the end-of-image marker.
        """
        return self.streams[-1].type != JpegMarker.EndOfImage


class jpeg(PathExtractorUnit):
    """
    Extract the raw segments from a JPG image. Parses JFIF/EXIF markers to recover embedded
    thumbnails, metadata, and comment segments. Data appended after the end of the image, such as
    a hidden payload, is extracted as the overlay. Data between the segments that belongs to none
    of them is extracted as junk. A truncated image, such as one carved from a larger file, gives
    everything up to the cut, and a segment that the cut divides gives the part in front of it.
    """
    def unpack(self, data):
        view = memoryview(data)
        jpg = Jpeg.Parse(view)
        if jpg.junk:
            self.log_warn('the image contains data that belongs to none of its segments')
        if jpg.truncated:
            self.log_warn('the data ends before the end of the image')
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
        for k, junk in enumerate(jpg.junk):
            yield UnpackResult(F'junk/{k}', junk)
        if overlay := view[len(jpg):]:
            yield UnpackResult('overlay', overlay)

    @classmethod
    def handles(cls, data) -> bool:
        return get_image_format(data) == Fmt.JPG
