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
    from refinery.lib.un7z.headers import BindPair, Folder

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
    CODEC_PPC     : _filter_ppc,
    CODEC_IA64    : _filter_ia64,
    CODEC_SPARC   : _filter_sparc,
    CODEC_DELTA   : _filter_delta,
}


def decompress_folder(
    folder: Folder,
    packed_streams: list[memoryview],
    unpack_size: int,
    password: str | bytes | None = None,
) -> bytes | bytearray:
    if _is_bcj2_folder(folder):
        return _decompress_bcj2_folder(folder, packed_streams, unpack_size, password)
    return _decompress_simple_folder(folder, packed_streams, unpack_size, password)


def _is_bcj2_folder(folder: Folder) -> bool:
    for coder in folder.coders:
        if coder.codec_id == CODEC_BCJ2:
            return True
    return False


def _resolve_coder_chain(folder: Folder) -> list[int]:
    bound_out = {bp.out_index for bp in folder.bind_pairs}
    main_out = -1
    for i in range(folder.total_out_streams):
        if i not in bound_out:
            main_out = i
            break
    chain: list[int] = []
    current_out = main_out
    while True:
        coder_idx = _out_stream_to_coder(folder, current_out)
        chain.append(coder_idx)
        coder = folder.coders[coder_idx]
        if coder.num_in_streams != 1:
            break
        in_stream = _coder_first_stream(folder, coder_idx, output=False)
        bp = _find_bind_pair(folder, in_stream, by_input=True)
        if bp is None:
            break
        current_out = bp.out_index
    chain.reverse()
    return chain


def _out_stream_to_coder(folder: Folder, out_stream: int) -> int:
    idx = 0
    for i, coder in enumerate(folder.coders):
        if out_stream < idx + coder.num_out_streams:
            return i
        idx += coder.num_out_streams
    raise SzCorruptArchive(F'Out stream {out_stream} not found.')


def _coder_first_stream(folder: Folder, coder_idx: int, *, output: bool) -> int:
    idx = 0
    attr = 'num_out_streams' if output else 'num_in_streams'
    for i, coder in enumerate(folder.coders):
        if i == coder_idx:
            return idx
        idx += getattr(coder, attr)
    raise SzCorruptArchive(F'Coder {coder_idx} not found.')


def _find_bind_pair(folder: Folder, stream: int, *, by_input: bool) -> BindPair | None:
    attr = 'in_index' if by_input else 'out_index'
    for bp in folder.bind_pairs:
        if getattr(bp, attr) == stream:
            return bp
    return None


def _get_packed_stream_for_coder(folder: Folder, coder_idx: int) -> int:
    in_stream = _coder_first_stream(folder, coder_idx, output=False)
    bound_in = {bp.in_index for bp in folder.bind_pairs}
    pack_idx = 0
    for s in range(folder.total_in_streams):
        if s not in bound_in:
            if s == in_stream:
                return pack_idx
            pack_idx += 1
    return 0


def _decompress_simple_folder(
    folder: Folder,
    packed_streams: list[memoryview],
    unpack_size: int,
    password: str | bytes | None = None,
) -> bytes | bytearray:
    chain = _resolve_coder_chain(folder)
    pack_idx = _get_packed_stream_for_coder(folder, chain[0])
    current_data: bytes | bytearray | memoryview = packed_streams[pack_idx]
    for coder_idx in chain:
        coder = folder.coders[coder_idx]
        cid = coder.codec_id
        out_idx = _coder_first_stream(folder, coder_idx, output=True)
        coder_unpack_size = folder.unpack_sizes[out_idx] if out_idx < len(folder.unpack_sizes) else unpack_size
        if cid == CODEC_AES256SHA256:
            if password is None:
                raise SzPasswordRequired('Password required for AES-encrypted archive.')
            current_data = _decrypt_aes256sha256(current_data, coder.properties, password)
        elif cid in SIMPLE_DECOMPRESSORS:
            current_data = SIMPLE_DECOMPRESSORS[cid](current_data, coder.properties, coder_unpack_size)
        elif cid in SIMPLE_FILTERS:
            current_data = SIMPLE_FILTERS[cid](current_data, coder.properties)
        else:
            raise SzUnsupportedMethod(F'Unsupported codec: {cid.hex()}')
    if len(current_data) > unpack_size:
        current_data = current_data[:unpack_size]
    return current_data


def _resolve_stream(
    folder: Folder,
    global_in: int,
    packed_streams: list[memoryview],
    password: str | bytes | None,
) -> bytes | bytearray | memoryview:
    bp = _find_bind_pair(folder, global_in, by_input=True)
    if bp is None:
        bound_in = {bp2.in_index for bp2 in folder.bind_pairs}
        pack_idx = 0
        for s in range(folder.total_in_streams):
            if s not in bound_in:
                if s == global_in:
                    return packed_streams[pack_idx]
                pack_idx += 1
        return b''
    source_coder_idx = _out_stream_to_coder(folder, bp.out_index)
    source_coder = folder.coders[source_coder_idx]
    source_in = _coder_first_stream(folder, source_coder_idx, output=False)
    source_data = _resolve_stream(folder, source_in, packed_streams, password)
    out_idx = _coder_first_stream(folder, source_coder_idx, output=True)
    unpack = folder.unpack_sizes[out_idx] if out_idx < len(folder.unpack_sizes) else len(source_data)
    cid = source_coder.codec_id
    if cid == CODEC_AES256SHA256:
        if password is None:
            raise SzPasswordRequired('Password required.')
        source_data = _decrypt_aes256sha256(source_data, source_coder.properties, password)
    if cid in SIMPLE_DECOMPRESSORS:
        source_data = SIMPLE_DECOMPRESSORS[cid](source_data, source_coder.properties, unpack)
    elif cid in SIMPLE_FILTERS:
        source_data = SIMPLE_FILTERS[cid](source_data, source_coder.properties)
    return source_data


def _decompress_bcj2_folder(
    folder: Folder,
    packed_streams: list[memoryview],
    unpack_size: int,
    password: str | bytes | None = None,
) -> bytes | bytearray:
    bcj2_coder_idx = -1
    for i, coder in enumerate(folder.coders):
        if coder.codec_id == CODEC_BCJ2:
            bcj2_coder_idx = i
            break
    if bcj2_coder_idx < 0:
        raise SzCorruptArchive('BCJ2 coder not found in folder.')
    bcj2_coder = folder.coders[bcj2_coder_idx]
    bcj2_first_in = _coder_first_stream(folder, bcj2_coder_idx, output=False)
    bcj2_in_streams: list[bytes | bytearray | memoryview] = []
    for s in range(bcj2_coder.num_in_streams):
        global_in = bcj2_first_in + s
        bcj2_in_streams.append(_resolve_stream(folder, global_in, packed_streams, password))
    if len(bcj2_in_streams) < 4:
        raise SzCorruptArchive(F'BCJ2 requires 4 input streams, got {len(bcj2_in_streams)}.')
    result = decode_bcj2(
        bcj2_in_streams[0],
        bcj2_in_streams[1],
        bcj2_in_streams[2],
        bcj2_in_streams[3],
        unpack_size,
    )
    bcj2_out = _coder_first_stream(folder, bcj2_coder_idx, output=True)
    bp = _find_bind_pair(folder, bcj2_out, by_input=False)
    if bp is not None:
        post_coder_idx = _out_stream_to_coder(folder, bp.in_index)
        post_coder = folder.coders[post_coder_idx]
        if post_coder.codec_id in SIMPLE_FILTERS:
            result = SIMPLE_FILTERS[post_coder.codec_id](result, post_coder.properties)
    return result[:unpack_size]
