from __future__ import annotations

import codecs
import enum
import lzma
import struct
import zlib

from refinery.lib.id import Fmt, get_media_format
from refinery.lib.structures import Struct, StructReader, StructReaderBits
from refinery.units.formats import PathExtractorUnit, UnpackResult


class SWFCompression(bytes, enum.Enum):
    NONE = b'FWS'
    ZLIB = b'CWS'
    LZMA = b'ZWS'


class SWFTagType(int, enum.Enum):
    End                 = 0   # noqa
    DefineBits          = 6   # noqa
    JPEGTables          = 8   # noqa
    DefineFont          = 10  # noqa
    DoAction            = 12  # noqa
    DefineSound         = 14  # noqa
    DefineBitsLossless  = 20  # noqa
    DefineBitsJPEG2     = 21  # noqa
    DefineBitsJPEG3     = 35  # noqa
    DefineBitsLossless2 = 36  # noqa
    DefineFont2         = 48  # noqa
    DoInitAction        = 59  # noqa
    DefineVideoStream   = 60  # noqa
    VideoFrame          = 61  # noqa
    DoABC               = 72  # noqa
    DefineFont3         = 75  # noqa
    SymbolClass         = 76  # noqa
    DoABC2              = 82  # noqa
    DefineBinaryData    = 87  # noqa
    DefineBitsJPEG4     = 90  # noqa
    DefineFont4         = 91  # noqa


class SWFSoundCodec(int, enum.Enum):
    UncompressedNE = 0   # noqa
    ADPCM          = 1   # noqa
    MP3            = 2   # noqa
    UncompressedLE = 3   # noqa
    Nellymoser16k  = 4   # noqa
    Nellymoser8k   = 5   # noqa
    Nellymoser     = 6   # noqa
    Speex          = 11  # noqa


_SOUND_EXTENSIONS = {
    SWFSoundCodec.UncompressedNE : 'wav',
    SWFSoundCodec.ADPCM          : 'wav',
    SWFSoundCodec.MP3            : 'mp3',
    SWFSoundCodec.UncompressedLE : 'wav',
    SWFSoundCodec.Nellymoser16k  : 'pcm',
    SWFSoundCodec.Nellymoser8k   : 'pcm',
    SWFSoundCodec.Nellymoser     : 'pcm',
    SWFSoundCodec.Speex          : 'spx',
}


def sound_extension(codec: int) -> str:
    try:
        return _SOUND_EXTENSIONS[SWFSoundCodec(codec)]
    except (ValueError, KeyError):
        return 'bin'


class SWFHeader(Struct):
    def __init__(self, reader: StructReader):
        sig = bytes(reader.read_exactly(3))
        try:
            self.compression = SWFCompression(sig)
        except ValueError:
            raise ValueError(F'Invalid SWF signature: {sig!r}')
        self.version = reader.u8()
        self.file_length = reader.u32()


class SWFRect(Struct):
    def __init__(self, reader: StructReaderBits):
        reader.bigendian = True
        nbits = reader.read_integer(5)
        self.xmin = reader.read_integer(nbits, signed=True)
        self.xmax = reader.read_integer(nbits, signed=True)
        self.ymin = reader.read_integer(nbits, signed=True)
        self.ymax = reader.read_integer(nbits, signed=True)
        reader.byte_align()
        reader.bigendian = False


class SWFTag(Struct):
    def __init__(self, reader: StructReader):
        tag_code_and_length = reader.u16()
        type_code = tag_code_and_length >> 6
        length = tag_code_and_length & 0x3F
        if length == 0x3F:
            length = reader.u32()
        try:
            self.type = SWFTagType(type_code)
        except ValueError:
            self.type = type_code
        self.length = length
        self.data = reader.read_exactly(length)


class SWF(Struct):
    def __init__(self, reader: StructReader):
        self.header = SWFHeader(reader)
        rest = reader.read()
        if self.header.compression == SWFCompression.ZLIB:
            rest = zlib.decompress(rest)
        elif self.header.compression == SWFCompression.LZMA:
            compressed_length = int.from_bytes(bytes(rest[:4]), 'little')
            lzma_props = bytes(rest[4:9])
            lzma_data = bytes(rest[9:4 + compressed_length])
            uncompressed_size = self.header.file_length - 8
            header = lzma_props + struct.pack('<Q', uncompressed_size)
            rest = lzma.decompress(header + lzma_data, format=lzma.FORMAT_ALONE)
        body = StructReaderBits(memoryview(bytearray(rest)))
        self.rect = SWFRect(body)
        body.bigendian = False
        self.frame_rate = body.u16()
        self.frame_count = body.u16()
        self.tags: list[SWFTag] = []
        while not body.eof:
            tag = SWFTag(body)
            self.tags.append(tag)
            if isinstance(tag.type, SWFTagType) and tag.type == SWFTagType.End:
                break


def _png_chunk(chunk_type: bytes, data: bytes | bytearray) -> bytearray:
    chunk = bytearray()
    chunk.extend(struct.pack('>I', len(data)))
    chunk.extend(chunk_type)
    chunk.extend(data)
    crc = zlib.crc32(chunk_type)
    crc = zlib.crc32(data, crc)
    chunk.extend(struct.pack('>I', crc & 0xFFFFFFFF))
    return chunk


def reconstruct_jpeg(
    data: bytes | bytearray | memoryview,
    jpeg_tables: bytes | bytearray | memoryview | None = None,
) -> bytearray:
    view = memoryview(data)
    out = bytearray()
    if jpeg_tables is not None:
        tables = memoryview(jpeg_tables)
        tables_body = bytes(tables)
        if tables_body[:2] == b'\xFF\xD8':
            tables_body = tables_body[2:]
        if tables_body[-2:] == b'\xFF\xD9':
            tables_body = tables_body[:-2]
        image_body = bytes(view)
        if image_body[:2] == b'\xFF\xD8':
            image_body = image_body[2:]
        out.extend(b'\xFF\xD8')
        out.extend(tables_body)
        out.extend(image_body)
    else:
        out.extend(bytes(view))
    result = bytearray()
    k = 0
    length = len(out)
    while k < length:
        if k + 3 < length and out[k] == 0xFF and out[k + 1] == 0xD9:
            if out[k + 2] == 0xFF and out[k + 3] == 0xD8:
                k += 4
                continue
        result.append(out[k])
        k += 1
    if result[:2] != b'\xFF\xD8':
        result[0:0] = b'\xFF\xD8'
    if result[-2:] != b'\xFF\xD9':
        result.extend(b'\xFF\xD9')
    return result


def reconstruct_png(
    width: int,
    height: int,
    has_alpha: bool,
    format_code: int,
    color_table_size: int,
    zlib_data: bytes | bytearray | memoryview,
) -> bytearray:
    raw = zlib.decompress(bytes(zlib_data))
    png = bytearray(b'\x89PNG\r\n\x1A\n')
    if format_code == 3:
        bit_depth = 8
        if has_alpha:
            color_type = 3
        else:
            color_type = 3
        ihdr = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
        png.extend(_png_chunk(b'IHDR', ihdr))
        entry_size = 4 if has_alpha else 3
        table_bytes = color_table_size * entry_size
        palette_data = raw[:table_bytes]
        pixel_data = raw[table_bytes:]
        plte = bytearray()
        trns = bytearray()
        for i in range(color_table_size):
            offset = i * entry_size
            if has_alpha:
                plte.extend(palette_data[offset + 1:offset + 4])
                trns.append(palette_data[offset])
            else:
                plte.extend(palette_data[offset:offset + 3])
        png.extend(_png_chunk(b'PLTE', bytes(plte)))
        if has_alpha:
            png.extend(_png_chunk(b'tRNS', bytes(trns)))
        rows = bytearray()
        stride = width
        for y in range(height):
            rows.append(0)
            row_start = y * stride
            rows.extend(pixel_data[row_start:row_start + stride])
        idat = zlib.compress(bytes(rows))
        png.extend(_png_chunk(b'IDAT', idat))
    elif format_code == 4:
        bit_depth = 8
        color_type = 2
        ihdr = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
        png.extend(_png_chunk(b'IHDR', ihdr))
        rows = bytearray()
        stride = width * 2
        for y in range(height):
            rows.append(0)
            for x in range(width):
                offset = y * stride + x * 2
                pixel = int.from_bytes(raw[offset:offset + 2], 'little')
                r = ((pixel >> 10) & 0x1F) * 255 // 31
                g = ((pixel >> 5) & 0x1F) * 255 // 31
                b = (pixel & 0x1F) * 255 // 31
                rows.extend((r, g, b))
        idat = zlib.compress(bytes(rows))
        png.extend(_png_chunk(b'IDAT', idat))
    elif format_code == 5:
        if has_alpha:
            bit_depth = 8
            color_type = 6
            ihdr = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
            png.extend(_png_chunk(b'IHDR', ihdr))
            rows = bytearray()
            stride = width * 4
            for y in range(height):
                rows.append(0)
                for x in range(width):
                    offset = y * stride + x * 4
                    a = raw[offset]
                    r = raw[offset + 1]
                    g = raw[offset + 2]
                    b = raw[offset + 3]
                    if a > 0 and a < 255:
                        r = min(r * 255 // a, 255)
                        g = min(g * 255 // a, 255)
                        b = min(b * 255 // a, 255)
                    rows.extend((r, g, b, a))
            idat = zlib.compress(bytes(rows))
            png.extend(_png_chunk(b'IDAT', idat))
        else:
            bit_depth = 8
            color_type = 2
            ihdr = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 0, 0, 0)
            png.extend(_png_chunk(b'IHDR', ihdr))
            rows = bytearray()
            stride = width * 4
            for y in range(height):
                rows.append(0)
                for x in range(width):
                    offset = y * stride + x * 4
                    rows.extend(raw[offset + 1:offset + 4])
            idat = zlib.compress(bytes(rows))
            png.extend(_png_chunk(b'IDAT', idat))
    else:
        raise ValueError(F'Unknown lossless bitmap format code: {format_code}')
    png.extend(_png_chunk(b'IEND', b''))
    return png


class swf(PathExtractorUnit):
    """
    Extract content from Shockwave Flash (SWF) files; multimedia data and ActionScript bytecode.
    """

    @classmethod
    def handles(cls, data) -> bool | None:
        return get_media_format(data) == Fmt.SWF

    def unpack(self, data):
        parsed = SWF.Parse(data)
        jpeg_tables: bytes | bytearray | memoryview | None = None
        symbol_names: dict[int, str] = {}
        counters: dict[str, int] = {}

        for tag in parsed.tags:
            if tag.type == SWFTagType.JPEGTables:
                if len(tag.data) > 0:
                    jpeg_tables = tag.data
            elif tag.type == SWFTagType.SymbolClass:
                reader = StructReader(memoryview(tag.data))
                count = reader.u16()
                for _ in range(count):
                    char_id = reader.u16()
                    name = reader.read_c_string()
                    try:
                        name = codecs.decode(name, 'utf-8')
                    except Exception:
                        name = codecs.decode(name, 'latin-1')
                    if name:
                        symbol_names[char_id] = name

        def _unique(base_path: str) -> str:
            count = counters.get(base_path, 0)
            counters[base_path] = count + 1
            if count == 0:
                return base_path
            return F'{base_path}.{count}'

        def _name(char_id: int, fallback: str) -> str:
            name = symbol_names.get(char_id)
            if name is not None:
                name = name.replace('\\', '/').rsplit('/', 1)[-1]
                name = name.replace('\0', '')
                if name:
                    return name
            return fallback

        for tag in parsed.tags:
            tt = tag.type
            td = memoryview(tag.data)

            if tt == SWFTagType.DefineBits:
                reader = StructReader(td)
                char_id = reader.u16()
                image_data = reader.read()
                name = _name(char_id, F'{char_id}')
                path = _unique(F'images/{name}.jpg')
                yield UnpackResult(path, reconstruct_jpeg(image_data, jpeg_tables))

            elif tt == SWFTagType.DefineBitsJPEG2:
                reader = StructReader(td)
                char_id = reader.u16()
                image_data = bytes(reader.read())
                name = _name(char_id, F'{char_id}')
                if image_data[:8] == b'\x89PNG\r\n\x1A\n':
                    ext = 'png'
                    payload = image_data
                elif image_data[:6] in (b'GIF87a', b'GIF89a'):
                    ext = 'gif'
                    payload = image_data
                else:
                    ext = 'jpg'
                    payload = reconstruct_jpeg(image_data)
                path = _unique(F'images/{name}.{ext}')
                yield UnpackResult(path, payload)

            elif tt == SWFTagType.DefineBitsJPEG3:
                reader = StructReader(td)
                char_id = reader.u16()
                alpha_offset = reader.u32()
                image_data = reader.read_exactly(alpha_offset)
                name = _name(char_id, F'{char_id}')
                path = _unique(F'images/{name}.jpg')
                yield UnpackResult(path, reconstruct_jpeg(image_data))

            elif tt == SWFTagType.DefineBitsJPEG4:
                reader = StructReader(td)
                char_id = reader.u16()
                alpha_offset = reader.u32()
                reader.u16()
                image_data = reader.read_exactly(alpha_offset)
                name = _name(char_id, F'{char_id}')
                path = _unique(F'images/{name}.jpg')
                yield UnpackResult(path, reconstruct_jpeg(image_data))

            elif tt == SWFTagType.DefineBitsLossless:
                reader = StructReader(td)
                char_id = reader.u16()
                fmt = reader.u8()
                w = reader.u16()
                h = reader.u16()
                if fmt == 3:
                    color_table_size = reader.u8() + 1
                else:
                    color_table_size = 0
                zdata = reader.read()
                name = _name(char_id, F'{char_id}')
                path = _unique(F'images/{name}.png')
                yield UnpackResult(path, reconstruct_png(
                    w, h, False, fmt, color_table_size, zdata))

            elif tt == SWFTagType.DefineBitsLossless2:
                reader = StructReader(td)
                char_id = reader.u16()
                fmt = reader.u8()
                w = reader.u16()
                h = reader.u16()
                if fmt == 3:
                    color_table_size = reader.u8() + 1
                else:
                    color_table_size = 0
                zdata = reader.read()
                name = _name(char_id, F'{char_id}')
                path = _unique(F'images/{name}.png')
                yield UnpackResult(path, reconstruct_png(
                    w, h, True, fmt, color_table_size, zdata))

            elif tt == SWFTagType.DefineSound:
                reader = StructReader(td)
                char_id = reader.u16()
                flags = reader.u8()
                codec_id = (flags >> 4) & 0xF
                reader.u32()
                sound_data = bytes(reader.read())
                ext = sound_extension(codec_id)
                name = _name(char_id, F'{char_id}')
                path = _unique(F'sounds/{name}.{ext}')
                yield UnpackResult(path, sound_data)

            elif tt == SWFTagType.VideoFrame:
                reader = StructReader(td)
                stream_id = reader.u16()
                frame_num = reader.u16()
                video_data = bytes(reader.read())
                path = _unique(F'video/{stream_id}/{frame_num}.bin')
                yield UnpackResult(path, video_data)

            elif tt == SWFTagType.DoAction:
                path = _unique('scripts/doaction.as')
                yield UnpackResult(path, bytes(td))

            elif tt == SWFTagType.DoInitAction:
                reader = StructReader(td)
                sprite_id = reader.u16()
                bytecode = bytes(reader.read())
                path = _unique(F'scripts/initaction_{sprite_id}.as')
                yield UnpackResult(path, bytecode)

            elif tt == SWFTagType.DoABC:
                path = _unique('scripts/abc.abc')
                yield UnpackResult(path, bytes(td))

            elif tt == SWFTagType.DoABC2:
                reader = StructReader(td)
                reader.u32()
                abc_name = reader.read_c_string()
                try:
                    abc_name = codecs.decode(abc_name, 'utf-8')
                except Exception:
                    abc_name = codecs.decode(abc_name, 'latin-1')
                if not abc_name:
                    abc_name = 'abc'
                abc_data = bytes(reader.read())
                path = _unique(F'scripts/{abc_name}.abc')
                yield UnpackResult(path, abc_data)

            elif tt == SWFTagType.DefineBinaryData:
                reader = StructReader(td)
                tag_id = reader.u16()
                reader.u32()
                binary_data = bytes(reader.read())
                name = _name(tag_id, F'{tag_id}')
                path = _unique(F'binary/{name}.bin')
                yield UnpackResult(path, binary_data)

            elif tt in (
                SWFTagType.DefineFont,
                SWFTagType.DefineFont2,
                SWFTagType.DefineFont3,
                SWFTagType.DefineFont4,
            ):
                reader = StructReader(td)
                char_id = reader.u16()
                path = _unique(F'fonts/{char_id}.font')
                yield UnpackResult(path, bytes(td))
