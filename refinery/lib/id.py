"""
This module contains functions to identify certain file formats; these functions are used by units
who operate on the same file format to implement the `refinery.units.Unit.handles` method.
"""
from __future__ import annotations

import re

from typing import Callable

_STRUCTURAL_CHECKS: list[Callable[[bytearray], str | None]] = []


def _structural_check(fn: Callable[[bytearray], str | None]):
    _STRUCTURAL_CHECKS.append(fn)
    return fn


@_structural_check
def get_pe_type(data: bytearray):
    """
    Get the correct file type extension for a PE file, or None if the input is unlikely to be a
    portable executable in the first place.
    """
    if data[:2] != B'MZ':
        return None
    ntoffset = data[0x3C:0x3E]
    if len(ntoffset) < 2:
        return None
    ntoffset = int.from_bytes(ntoffset, 'little')
    if data[ntoffset:ntoffset + 2] != B'PE':
        return None
    if data[ntoffset + 0x16] & 0x20:
        return 'DLL'
    else:
        return 'EXE'


def is_likely_pe(data: bytearray):
    """
    Tests whether the input data is likely a PE file by checking the first two bytes and the magic
    bytes at the beginning of what should be the NT header.
    """
    return get_pe_type(data) is not None


def is_likely_pe_dotnet(data: bytearray):
    """
    Tests whether the input data is likely a .NET PE file by running `refinery.lib.id.is_likely_pe`
    and also checking for the characteristic strings `BSJB`, `#Strings`, and `#Blob`.
    """
    if not is_likely_pe(data):
        return False
    if data.find(b'BSJB') < 0:
        return False
    if data.find(b'#Strings') < 0:
        return False
    if data.find(b'#Blob') < 0:
        return False
    return True


@_structural_check
def get_reg_export_type(data: bytearray):
    """
    Check whether the input data is a Windows registry file export.
    """
    if data[:4] == B'regf':
        return 'REG'
    if data[:31] == b'Windows Registry Editor Version':
        return 'REG'
    return None


def guess_text_encoding(
    data: bytearray,
    window_size: int = 0x2000,
    ascii_ratio: float = 0.98,
) -> int:
    """
    Attempts to determine whether the input data is likely printable text. The return value is zero
    if the input is unlikely to be text. Otherwise, the return value is the likely width of an
    encoded character. Currently supported return values are only `1` and `2`, where `2` indicates
    a big or little endian UTF-16 encoding.
    """
    view = memoryview(data)
    size = window_size
    step = 1
    maxbad = 1 - ascii_ratio
    offset = 0

    if data.startswith(B'\xEF\xBB\xBF'):
        # BOM: UTF8
        offset = 3
    elif data.startswith(B'\xFF\xFE'):
        # BOM: UTF-16LE
        if len(data) % 2 == 0:
            return 0
        if not (win := view[2:size:1]) or sum(win) / len(win) > maxbad:
            return 0
        step = offset = 2
    elif data.startswith(B'\xFE\xFF'):
        # BOM: UTF-16BE
        if len(data) % 2 == 0:
            return 0
        if not (win := view[3:size:1]) or sum(win) / len(win) > maxbad:
            return 0
        step = offset = 2
    elif len(view) % 2 == 0:
        u16le = (win := view[1:size:2]) and sum(win) / len(win) <= maxbad
        u16be = (win := view[0:size:2]) and sum(win) / len(win) <= maxbad
        if u16le or u16be:
            step = 2

    if len(data) <= offset:
        return step

    histogram = [data.count(b, offset, size) for b in range(0x100)]
    presence = memoryview(bytes(1 if v else 0 for v in histogram))

    if sum(presence) > 102:
        # 96 printable ASCII characters plus some slack for control bytes or encoding
        return 0
    if sum(presence[0x7F:]) > 5:
        # Allow for some control characters or encoding-specific values
        return 0
    if sum(presence[:0x20]) > 5:
        # Tab, CR, LF, Null, plus one byte slack
        return 0

    bad = sum(histogram[:0x20]) + sum(histogram[0x7F:]) \
        - histogram[0x0D] \
        - histogram[0x0A] \
        - histogram[0x09]
    if step == 2:
        bad -= histogram[0] // 2
    if bad / sum(histogram) > maxbad:
        return 0

    while True:
        try:
            win = view[offset:size:step]
            bad = sum(m.end() - m.start()
                for m in re.finditer(BR'[^\t\n\r\x20-\x7E]+', win))
        except TypeError:
            pass
        else:
            if bad and bad / len(win) > maxbad:
                return 0
        if size >= len(view):
            return step
        size <<= 1


@_structural_check
def _is_txt(data: bytearray):
    if guess_text_encoding(data) > 0:
        return 'TXT'


@_structural_check
def get_compression_type(
    data: bytearray,
    entropy_minimum: float = 0.7,
    entropy_look_at: int = 0x2000,
):
    """
    This method looks for any of a number of known magic signatures for compression and archive
    formats. If one is find, the method selects a data window from the rest of the buffer and
    computes its entropy. If the entropy exceeds the given threshold, the input is idenfied as
    a known compression format.
    """
    for name, signature in (
        ('apLib'       , B'AP32'),                                      # noqa
        ('Bzip2'       , B'BZh'),                                       # noqa
        ('jcAlg'       , B'JC'),                                        # noqa
        ('LZMA'        , B'\x5D\0\0\0'),                                # noqa
        ('LZMA'        , B'\xFD7zXZ'),                                  # noqa
        ('LZF'         , B'ZV'),                                        # noqa
        ('LZG'         , B'LZG'),                                       # noqa
        ('LZIP'        , B'LZIP'),                                      # noqa
        ('LZO'         , B'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a'),      # noqa
        ('LZW'         , B'\x1F\x9D'),                                  # noqa
        ('MSCF'        , B'\x0A\x51\xE5\xC0'),                          # noqa
        ('SZDD'        , B'SZDD'),                                      # noqa
        ('GZIP'        , B'\x1F\x8B'),                                  # noqa
        ('ZLIB(L)'     , B'\x78\x01'),                                  # noqa
        ('ZLIB(M)'     , B'\x78\x9C'),                                  # noqa
        ('ZLIB(H)'     , B'\x78\xDA'),                                  # noqa
        ('ZSTD'        , B'\x28\xB5\x2F\xFD'),                          # noqa
        ('7Zip'        , B'7z\xBC\xAF\x27\x1C'),                        # noqa
        ('CAB'         , B'MSCF'),                                      # noqa
        ('CHM'         , B'ITSF'),                                      # noqa
        ('CPIO'        , B'070701'),                                    # noqa
        ('ZIP'         , B'PK\03\04'),                                  # noqa
        ('ZPQ'         , B'7kSt\xA01\x83\xD3\x8C\xB2\x28\xB0\xD3zPQ'),  # noqa
    ):
        if data.startswith(signature):
            from refinery.lib.tools import entropy
            view = memoryview(data)
            for start in (0x1000, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10):
                if len(view) >= start + entropy_look_at:
                    view = view[start:]
                    break
            if entropy(view[:entropy_look_at]) >= entropy_minimum:
                return name


def is_structured_data(data: bytearray):
    """
    Attempts to determine whether the input data is just a meaningless blob or whether it has
    structure, i.e. adheres to a known file format.
    """
    for check in _STRUCTURAL_CHECKS:
        if t := check(data):
            return t
