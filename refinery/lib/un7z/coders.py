"""
Decompression and filter chain for 7z archives.

Maps 7z codec IDs to decompressor implementations and handles
chaining multiple coders (filters + compressors) together.
"""
from __future__ import annotations

import bz2
import hashlib
import lzma
import zlib

from functools import partial
from typing import TYPE_CHECKING

from refinery.lib.decompression import parse_lzma_properties
from refinery.lib.un7z.bcj2 import decode_bcj2

if TYPE_CHECKING:
    from refinery.lib.types import buf
    from refinery.lib.un7z.headers import Folder

from refinery.lib.un7z.headers import (
    SzCorruptArchive,
    SzPasswordRequired,
    SzUnsupportedMethod,
)

CODEC_COPY         = b'\x00'              # noqa
CODEC_DELTA        = b'\x03'              # noqa
CODEC_LZMA2        = b'\x21'              # noqa
CODEC_LZMA         = b'\x03\x01\x01'      # noqa
CODEC_PPMD         = b'\x03\x04\x01'      # noqa
CODEC_BCJ_X86      = b'\x03\x03\x01\x03'  # noqa
CODEC_BCJ2         = b'\x03\x03\x01\x1B'  # noqa
CODEC_PPC          = b'\x03\x03\x02\x05'  # noqa
CODEC_IA64         = b'\x03\x03\x04\x01'  # noqa
CODEC_ARM          = b'\x03\x03\x05\x01'  # noqa
CODEC_ARMT         = b'\x03\x03\x07\x01'  # noqa
CODEC_ARM64        = b'\x0a'              # noqa
CODEC_RISCV        = b'\x0b'              # noqa
CODEC_SPARC        = b'\x03\x03\x08\x05'  # noqa
CODEC_DEFLATE      = b'\x04\x01\x08'      # noqa
CODEC_DEFLATE64    = b'\x04\x01\x09'      # noqa
CODEC_BZIP2        = b'\x04\x02\x02'      # noqa
CODEC_AES256SHA256 = b'\x06\xF1\x07\x01'  # noqa


def _decompress_lzma_generic(
    data: bytes | bytearray | memoryview,
    props: bytes,
    unpack_size: int,
    version: int,
) -> bytes:
    view = memoryview(data)
    filters = parse_lzma_properties(memoryview(props), version=version)
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filters])
    return dec.decompress(view, max_length=unpack_size)


def _decompress_ppmd(data: bytes | bytearray | memoryview, props: bytes, unpack_size: int) -> bytes:
    from refinery.lib.shared.pyppmd import pyppmd
    if len(props) < 5:
        raise SzCorruptArchive('PPMd properties too short.')
    order = props[0]
    mem_size = int.from_bytes(props[1:5], 'little')
    dec = pyppmd.Ppmd7Decoder(order, mem_size)
    return dec.decode(bytes(data), unpack_size)


def _decompress_deflate(data: bytes | bytearray | memoryview, props: bytes, unpack_size: int) -> bytes:
    dec = zlib.decompressobj(-15)
    return dec.decompress(data, max_length=unpack_size)


def _decompress_deflate64(data: bytes | bytearray | memoryview, props: bytes, unpack_size: int) -> bytearray:
    from refinery.lib.seven.deflate import Deflate
    from refinery.lib.structures import StructReader
    u = bytearray()
    deflate = Deflate(u, StructReader(memoryview(data)), df64=True)
    deflate.decode()
    return u


def _decompress_bzip2(data: bytes | bytearray | memoryview, props: bytes, unpack_size: int) -> bytes:
    return bz2.decompress(data)


def _decompress_copy(data: bytes | bytearray | memoryview, props: bytes, unpack_size: int) -> bytes | bytearray | memoryview:
    return data


def _filter_delta(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    distance = 1
    if props:
        distance = props[0] + 1
    state = bytearray(distance)
    output = bytearray(len(data))
    j = 0
    for i in range(len(data)):
        b = (data[i] + state[j]) & 0xFF
        state[j] = b
        output[i] = b
        j += 1
        if j == distance:
            j = 0
    return output


def _filter_bcj_x86(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    size = len(buf)
    if size < 5:
        return buf
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    prev_mask = 0
    prev_pos = ip - 5
    pos = 0
    limit = size - 5
    _M32 = 0xFFFFFFFF
    while pos <= limit:
        b = buf[pos]
        if b != 0xE8 and b != 0xE9:
            pos += 1
            continue
        offset = ip + pos - prev_pos
        prev_pos = ip + pos
        if offset > 5:
            prev_mask = 0
        else:
            for _ in range(offset):
                prev_mask &= 0x77
                prev_mask <<= 1
        if buf[pos + 4] not in (0x00, 0xFF) or (prev_mask >> 1) not in _BCJ_ALLOWED_MASKS:
            pos += 1
            prev_mask |= 1
            if buf[pos + 3] in (0x00, 0xFF):
                prev_mask |= 0x10
            continue
        src = buf[pos + 1] | (buf[pos + 2] << 8) | (buf[pos + 3] << 16) | (buf[pos + 4] << 24)
        distance = ip + pos + 5
        idx = _BCJ_MASK_TO_BIT_NUMBER[prev_mask >> 1]
        while True:
            dest = (src - distance) & _M32
            if prev_mask == 0:
                break
            b_check = (dest >> (24 - idx * 8)) & 0xFF
            if b_check != 0x00 and b_check != 0xFF:
                break
            src = dest ^ ((1 << (32 - idx * 8)) - 1) & _M32
        buf[pos + 1] = dest & 0xFF
        buf[pos + 2] = (dest >> 8) & 0xFF
        buf[pos + 3] = (dest >> 16) & 0xFF
        buf[pos + 4] = [0x00, 0xFF][(dest >> 24) & 1]
        pos += 5
        prev_mask = 0
    return buf


_BCJ_ALLOWED_MASKS = {0, 1, 2, 4, 8, 9, 10, 12}
_BCJ_MASK_TO_BIT_NUMBER = [0, 1, 2, 2, 3, 3, 3, 3]


def _filter_arm(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    pos = 0
    while pos + 3 < len(buf):
        if buf[pos + 3] == 0xEB:
            val = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)
            val <<= 2
            target = (val - (ip + pos + 8)) & 0x03FFFFFF
            target >>= 2
            buf[pos + 0] = target & 0xFF
            buf[pos + 1] = (target >> 8) & 0xFF
            buf[pos + 2] = (target >> 16) & 0xFF
        pos += 4
    return buf


def _filter_armt(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    pos = 0
    while pos + 3 < len(buf):
        b1 = buf[pos + 1]
        if (b1 & 0xF8) == 0xF0 and (buf[pos + 3] & 0xF8) == 0xF8:
            val = ((b1 & 0x07) << 19) | (buf[pos + 0] << 11) | ((buf[pos + 3] & 0x07) << 8) | buf[pos + 2]
            cur = (ip + pos + 4) >> 1
            target = (val - cur) & 0x003FFFFF
            buf[pos + 0] = (target >> 11) & 0xFF
            buf[pos + 1] = 0xF0 | ((target >> 19) & 0x07)
            buf[pos + 2] = target & 0xFF
            buf[pos + 3] = 0xF8 | ((target >> 8) & 0x07)
            pos += 4
        else:
            pos += 2
    return buf


def _filter_ppc(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    pos = 0
    while pos + 3 < len(buf):
        if buf[pos] == 0x48 and (buf[pos + 3] & 0x03) == 0x01:
            val = (
                ((buf[pos + 0] & 0x03) << 24)
                | (buf[pos + 1] << 16)
                | (buf[pos + 2] << 8)
                | (buf[pos + 3] & 0xFC)
            )
            target = (val - (ip + pos)) & 0x03FFFFFF
            buf[pos + 0] = 0x48 | ((target >> 24) & 0x03)
            buf[pos + 1] = (target >> 16) & 0xFF
            buf[pos + 2] = (target >> 8) & 0xFF
            buf[pos + 3] = (target & 0xFC) | 0x01
        pos += 4
    return buf


def _filter_ia64(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    pos = 0
    while pos + 15 < len(buf):
        tmpl = buf[pos] & 0x1F
        mask = _IA64_BRANCH_TABLE.get(tmpl, 0)
        if mask:
            for bit_pos in range(3):
                if not (mask & (1 << bit_pos)):
                    continue
                bit_offset = bit_pos * 41 + 5
                byte_start = bit_offset >> 3
                bit_start = bit_offset & 7
                raw = 0
                for k in range(6):
                    raw |= buf[pos + byte_start + k] << (8 * k)
                inst = (raw >> bit_start) & 0x1FFFFFFFFFF
                if ((inst >> 37) & 0x0F) == 5 and ((inst >> 9) & 0x07) == 0:
                    src = ((inst >> 13) & 0x0FFFFF) | (((inst >> 36) & 1) << 20)
                    src = (src << 4) & 0xFFFFFFFF
                    src = (src - (ip + pos)) & 0xFFFFFFFF
                    src >>= 4
                    inst &= ~(0x1FFFFF << 13)
                    inst |= (src & 0x0FFFFF) << 13
                    inst |= ((src >> 20) & 1) << 36
                    raw &= ~(0x1FFFFFFFFFF << bit_start)
                    raw |= inst << bit_start
                    for k in range(6):
                        buf[pos + byte_start + k] = (raw >> (8 * k)) & 0xFF
        pos += 16
    return buf


_IA64_BRANCH_TABLE = {
    0x10: 4, 0x11: 4, 0x12: 6, 0x13: 6,
    0x16: 7, 0x17: 7, 0x18: 4, 0x19: 4,
    0x1C: 4, 0x1D: 4,
}


def _filter_sparc(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    pos = 0
    while pos + 3 < len(buf):
        b0 = buf[pos]
        b1 = buf[pos + 1]
        if (b0 == 0x40 and (b1 & 0xC0) == 0) or (b0 == 0x7F and b1 >= 0xC0):
            val = (b0 << 24) | (b1 << 16) | (buf[pos + 2] << 8) | buf[pos + 3]
            val = (val << 2) & 0xFFFFFFFF
            val = (val - (ip + pos)) & 0xFFFFFFFF
            val &= 0x01FFFFFF
            val = (val - (1 << 24)) & 0xFFFFFFFF
            val ^= 0xFF000000
            val >>= 2
            val |= 0x40000000
            buf[pos + 0] = (val >> 24) & 0xFF
            buf[pos + 1] = (val >> 16) & 0xFF
            buf[pos + 2] = (val >> 8) & 0xFF
            buf[pos + 3] = val & 0xFF
        pos += 4
    return buf


def _filter_arm64(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    M32 = 0xFFFFFFFF
    pos = 0
    size = len(buf) & ~3
    flag = 1 << 20
    mask = (1 << 24) - (flag << 1)
    while pos < size:
        v = int.from_bytes(buf[pos:pos + 4], 'little')
        pos += 4
        pc = ip + pos
        if ((v - 0x94000000) & 0xFC000000) == 0:
            c = pc >> 2
            v = (v - c) & M32
            v &= 0x03FFFFFF
            v |= 0x94000000
            buf[pos - 4:pos] = v.to_bytes(4, 'little')
            continue
        if ((v - 0x90000000) & 0x9F000000) == 0:
            t = v + flag
            if t & mask:
                continue
            z = (v & 0xFFFFFFE0) | (v >> 26)
            c = (pc >> (12 - 3)) & (M32 ^ 7)
            z = (z - c) & M32
            v = 0x90000000 | (v & 0x1F)
            v |= z << 26
            v |= (((z & ((flag << 1) - 1)) - flag) & 0x00FFFFE0)
            v &= M32
            buf[pos - 4:pos] = v.to_bytes(4, 'little')
    return buf


def _filter_riscv(data: bytes | bytearray | memoryview, props: bytes) -> bytearray:
    buf = bytearray(data)
    ip = 0
    if props and len(props) >= 4:
        ip = int.from_bytes(props[:4], 'little')
    M32 = 0xFFFFFFFF
    size = len(buf) & ~1
    if size <= 6:
        return buf
    limit = size - 6
    pos = 0
    while pos < limit:
        b = buf[pos]
        a = ((b ^ 0x10) + 1) & 0xFF
        if a & 0x77:
            b2 = buf[pos + 2]
            a2 = ((b2 ^ 0x10) + 1) & 0xFF
            pos += 4
            if a2 & 0x77:
                continue
            pos -= 2
            if pos >= limit:
                break
            a = a2
            b = b2
        pc = ip + pos
        if (a & 8) == 0:
            a = (((buf[pos] | (buf[pos + 1] << 8)) ^ 0x10) + 1) & 0xFFFF
            a = (a - (0x100 - 0x7F)) & 0xFFFF
            if a & 0xD80:
                pos += 4
                continue
            a_old = (a + (0xEF - 0x7F)) & 0xFFF
            v = (buf[pos + 3] << 1) | (buf[pos + 2] << 9) | ((a & 0xF000) << 5)
            v = (v - pc) & M32
            a = a_old
            a |= (v << 11) & (1 << 31)
            a |= (v << 20) & (0x3FF << 21)
            a |= (v << 9) & (1 << 20)
            a |= v & (0xFF << 12)
            a &= M32
            buf[pos + 0] = a & 0xFF
            buf[pos + 1] = (a >> 8) & 0xFF
            buf[pos + 2] = (a >> 16) & 0xFF
            buf[pos + 3] = (a >> 24) & 0xFF
            pos += 4
        else:
            v = (((buf[pos] | (buf[pos + 1] << 8)) ^ 0x10) + 1) & 0xFFFF
            a = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16) | (buf[pos + 3] << 24)
            if (v & 0xE80) == 0:
                r = a >> 27
                check = ((v - (3 << 12) - (2 << 7) - 8) << 18) & M32
                if check < (r & 0x1D):
                    b32 = (buf[pos + 4] << 24) | (buf[pos + 5] << 16) | (buf[pos + 6] << 8) | buf[pos + 7]
                    b32 = (b32 - pc) & M32
                    v2 = a >> 12
                    inst = (r << 7) + 0x17
                    inst = (inst + ((b32 + 0x800) & 0xFFFFF000)) & M32
                    fup = v2 | ((b32 << 20) & M32)
                    fup &= M32
                    buf[pos + 0] = inst & 0xFF
                    buf[pos + 1] = (inst >> 8) & 0xFF
                    buf[pos + 2] = (inst >> 16) & 0xFF
                    buf[pos + 3] = (inst >> 24) & 0xFF
                    buf[pos + 4] = fup & 0xFF
                    buf[pos + 5] = (fup >> 8) & 0xFF
                    buf[pos + 6] = (fup >> 16) & 0xFF
                    buf[pos + 7] = (fup >> 24) & 0xFF
                    pos += 8
                else:
                    pos += 4
            else:
                b32 = buf[pos + 4] | (buf[pos + 5] << 8) | (buf[pos + 6] << 16) | (buf[pos + 7] << 24)
                check = (((b32 - 3) ^ (v << 8)) & 0xF8003) == 0
                if not check:
                    pos += 6
                else:
                    fup = (a & 0xFFFFF000) | ((b32 >> 20) & 0xFFF)
                    inst = ((b32 << 12) & M32) | (0x17 + (2 << 7))
                    inst &= M32
                    buf[pos + 0] = inst & 0xFF
                    buf[pos + 1] = (inst >> 8) & 0xFF
                    buf[pos + 2] = (inst >> 16) & 0xFF
                    buf[pos + 3] = (inst >> 24) & 0xFF
                    buf[pos + 4] = fup & 0xFF
                    buf[pos + 5] = (fup >> 8) & 0xFF
                    buf[pos + 6] = (fup >> 16) & 0xFF
                    buf[pos + 7] = (fup >> 24) & 0xFF
                    pos += 8
    return buf


def _decrypt_aes256sha256(
    data: bytes | bytearray | memoryview,
    props: bytes,
    password: str | bytes,
) -> bytes:
    if len(props) < 2:
        raise SzCorruptArchive('AES-256-SHA-256 properties too short.')
    first_byte = props[0]
    num_cycles_power = first_byte & 0x3F
    salt_size = ((first_byte >> 7) & 1) + (props[1] >> 4)
    iv_size = ((first_byte >> 6) & 1) + (props[1] & 0x0F)
    prop_data = props[2:]
    salt = bytes(prop_data[:salt_size])
    iv = bytes(prop_data[salt_size:salt_size + iv_size])
    iv = iv + b'\x00' * (16 - len(iv))
    if isinstance(password, str):
        password = password.encode('utf-16-le')
    elif isinstance(password, (bytes, bytearray, memoryview)):
        password = bytes(password).decode('utf-8').encode('utf-16-le')
    key_material = salt + password
    num_rounds = 1 << num_cycles_power
    h = hashlib.sha256()
    for i in range(num_rounds):
        h.update(key_material)
        h.update(i.to_bytes(8, 'little'))
    key = h.digest()
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


SIMPLE_DECOMPRESSORS = {
    CODEC_COPY      : _decompress_copy,
    CODEC_LZMA      : partial(_decompress_lzma_generic, version=1),
    CODEC_LZMA2     : partial(_decompress_lzma_generic, version=2),
    CODEC_DEFLATE   : _decompress_deflate,
    CODEC_DEFLATE64 : _decompress_deflate64,
    CODEC_BZIP2     : _decompress_bzip2,
    CODEC_PPMD      : _decompress_ppmd,
}

SIMPLE_FILTERS = {
    CODEC_BCJ_X86 : _filter_bcj_x86,
    CODEC_ARM     : _filter_arm,
    CODEC_ARMT    : _filter_armt,
    CODEC_ARM64   : _filter_arm64,
    CODEC_RISCV   : _filter_riscv,
    CODEC_PPC     : _filter_ppc,
    CODEC_IA64    : _filter_ia64,
    CODEC_SPARC   : _filter_sparc,
    CODEC_DELTA   : _filter_delta,
}


def decompress_folder(
    folder: Folder,
    packed_streams: list[memoryview],
    password: str | bytes | None = None,
) -> buf:
    """
    Decode the main output stream of the folder. The list `packed_streams` holds the packed streams
    of the folder in the order of the archive, which is the order of `Folder.packed_indices`.
    """
    return _FolderDecoder(folder, packed_streams, password).out_stream(folder.main_out_stream)


class _FolderDecoder:
    """
    Decodes the output streams of one folder by following its bonds back to its packed streams.
    Every output stream is decoded at most once, so that coders bound in a cycle cannot loop.
    """
    def __init__(
        self,
        folder: Folder,
        packed_streams: list[memoryview],
        password: str | bytes | None,
    ):
        self.folder = folder
        self.packed_streams = packed_streams
        self.password = password
        self.decoded: set[int] = set()

    def out_stream(self, out_index: int) -> buf:
        if out_index in self.decoded:
            raise SzCorruptArchive(F'Output stream {out_index} is read more than once.')
        self.decoded.add(out_index)
        folder = self.folder
        coder_index = folder.coder_of_out_stream(out_index)
        coder = folder.coders[coder_index]
        cid = coder.codec_id
        size = folder.unpack_sizes[out_index]
        output: buf
        if coder.num_out_streams != 1:
            raise SzUnsupportedMethod(F'Codec {cid.hex()} has {coder.num_out_streams} output streams.')
        if cid == CODEC_BCJ2:
            main, call, jump, rc = self.in_streams(coder_index, 4)
            output = decode_bcj2(main, call, jump, rc, size)
        elif cid == CODEC_AES256SHA256:
            if (password := self.password) is None:
                raise SzPasswordRequired('Password required for AES-encrypted archive.')
            data, = self.in_streams(coder_index, 1)
            output = _decrypt_aes256sha256(data, coder.properties, password)
        elif decompress := SIMPLE_DECOMPRESSORS.get(cid):
            data, = self.in_streams(coder_index, 1)
            output = decompress(data, coder.properties, size)
        elif apply_filter := SIMPLE_FILTERS.get(cid):
            data, = self.in_streams(coder_index, 1)
            output = apply_filter(data, coder.properties)
        else:
            raise SzUnsupportedMethod(F'Unsupported codec: {cid.hex()}')
        if len(output) > size:
            output = memoryview(output)[:size]
        return output

    def in_streams(self, coder_index: int, count: int) -> list[buf]:
        in_streams = self.folder.in_streams_of(coder_index)
        if len(in_streams) != count:
            raise SzCorruptArchive(F'Coder {coder_index} has {len(in_streams)} input streams, expected {count}.')
        return [self.in_stream(in_index) for in_index in in_streams]

    def in_stream(self, in_index: int) -> buf:
        if (out_index := self.folder.bound_out_stream(in_index)) is not None:
            return self.out_stream(out_index)
        return self.packed_streams[self.folder.packed_stream(in_index)]
