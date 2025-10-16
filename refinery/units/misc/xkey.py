from __future__ import annotations

import enum

from collections import Counter
from itertools import product
from typing import Generator, NamedTuple

from Cryptodome.Util.strxor import strxor

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


def _generate_cribs(cribs: bytes | tuple[bytes | tuple[bytes, ...], ...]) -> Generator[bytes]:
    if isinstance(cribs, tuple):
        for p in product(*[(c if isinstance(c, tuple) else (c,)) for c in cribs]):
            yield B''.join(p)
    else:
        yield cribs


def _cyclic_base(data: bytes, min_repeat: int = 2):
    if len(data) < min_repeat:
        return None
    repeat = 0
    length = 1
    n = len(data)
    for k in range(1, n):
        if data[k] == data[repeat]:
            repeat = (repeat + 1) % length
        else:
            m = k + 1
            if m * min_repeat > n:
                return None
            else:
                repeat = 0
                length = m
    return data[:length]


def _S(options: bytes):
    return tuple(bytes((b,)) for b in options)


class xkey(Unit):
    """
    The unit expects encrypted input which was encrypted byte-wise with a polyalphabetic key. For
    both bit-wise and byte-wise addition, it can attempt do determine this key by three methods:

    1. Known plaintext cribs: The unit contains a library of file signatures that are expected to
       occur at specific offsets. It uses these to attempt a known-plaintext attack against the
       input. If a key is found that is at most half the size of such a crib, it is returned.
    2. Known alphabets: For each given key length, the input is split into slices that would have
       been encrypted with a single byte for keys of that length. Each such slice undergoes a
       character frequency analysis. If the histogram indicates that an alphabet of a small size
       was used (i.e. base64), then the unit attempts to determine the key based on this.
    3. Known high frequency glyph: Works if the plaintext contains one letter that occurs with
       very high frequency, i.e. zero padding in PE or ELF files, and the space character in text.
       Based on this assumption, the unit computes the most likely key. This method will work best
       on uncompressed files that were encrypted with a short key.

    When no option is set, the unit uses all the above methods by default. When at least one of
    the methods is selected, it will attempt only selected methods. When a custom plaintext is given,
    the other methods are disabled by default.
    """

    _CRIBS: dict[range, dict[str, bytes | tuple[bytes | tuple[bytes, ...], ...]]] = {
        range(0, 64, 4): {
            'ZIP'           : (B'PK\x03\x04', (B'\x14\x00', B'\x0A\x00'), (B'\x08\x00', B'\x00\x00')),
            'RAR'           : (B'Rar!\x1A\x07', (B'\x01\x00', B'\x00')),
            'ZPAQ'          : (B'\x37\x6B\x53\x74\xA0\x31\x83\xD3\x8C\xB2\x28\xB0\xD3\x7A\x50\x51'),
            'ZSTD'          : (B'\x28\xB5\x2F\xFD'),
            'ZZip'          : (B'7z\xBC\xAF\x27\x1C', (B'\x00\x02', B'\x00\x03', B'\x00\x04')),
            'APLib'         : (B'AP32\x18\0\0\0'),
            'BZip'          : (B'BZh'),
            'LNK'           : (B'L\0\0\0\01\x14\02\0\0\0\0\0\xC0\0\0\0\0\0\0F', (B'', B'\x9B')),
            'DDS'           : (B'\x00\x00\x00\x01Bud1'),
            'ELF'           : (B'\x7FELF'),
            'JavaClass'     : (B'\xCA\xFE\xBA\xBE'),
            'LZIP'          : (B'LZIP'),
            'SZDD'          : (B'SZDD\x88\xF0\x27\x33'),
            'LZMA'          : (B'\x5D\x00\x00\x00'),
            'LZMA/XZ'       : (B'\xFD7zXZ'),
            'LZO'           : (B'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a'),
            'MachO/BE'      : (B'\xCA\xFE\xBA\xBE'),
            'MachO/LE'      : (B'\xBE\xBA\xFE\xCA'),
            'MSCF'          : (B'\x0A\x51\xE5\xC0'),
            'OleDocument'   : (B'\xD0\xCF\x11\xE0', (B'', B'\xA1\xB1\x1A\xE1'), (B'', B'\0\0\0\0\0\0\0\0')),
            'PdfDocument'   : (B'%PDF-', _S(B'12'), (B'.'), _S(B'0123456789'), _S(B'\r\n')),
            'SQLite'        : (B'SQLite format 3\0'),
            'GIF'           : (B'GIF87a', B'GIF89a'),
            'PNG'           : (B'\x89PNG\r\n\x1A\n'),
            'DEX'           : (B'dex\n035\0'),
            'JPG'           : (B'\xFF\xD8\xFF', _S(B'\xE0\xE1\xEE'), (B'\x00\x10\x4A\x46\x49\x46\x00\x01', B'')),
            'OneNote'       : (B'\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3'),
            'A3xScript'     : (B'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7DAU3!EA0', _S(B'56')),
            'RTFDocument'   : (B'{\\rtf1', (B'\\adeflang', B'\\ansi', B'')),
            'CallToPop'     : (B'\xE8\0\0\0\0', (
                               B'\x41\x58', B'\x41\x59', B'\x41\x5A', B'\x41\x5B',
                                   B'\x58',     B'\x59',     B'\x5A',     B'\x5B',   # noqa
                                   B'\x5C',     B'\x5D',     B'\x5E',     B'\x5F',   # noqa
                               )),
            'Cert'          : (B'-----BEGIN CERTIFICATE-----'),
            'PrivateKey'    : (B'-----BEGIN PRIVATE KEY-----'),
            'PrivateKeyDSA' : (B'-----BEGIN DSA PRIVATE KEY-----'),
            'PrivateKeyRSA' : (B'-----BEGIN RSA PRIVATE KEY-----'),
            'PrivateKeySSH' : (B'-----BEGIN OPENSSH PRIVATE KEY-----'),
            'PEM'           : (B'-----BEGIN '),
            'PuTTY-Key'     : (B'PuTTY-User-Key-File-', (B'2:', B'3:')),
            'MsAccess'      : (B'\0\01\0\0Standard ', (B'ACE', B'Jet'), B' DB'),
        },
        range(0x10, 0x11): {
            'ASAR'          : (B'{"files":{"'),
        },
        range(0x10): {
            'DocTypeLower'  : (B'<!doctype\x20', (B'', B'html')),
            'DocTypeUpper'  : (B'<!DOCTYPE\x20', (B'', B'HTML')),
            'HTMLLower'     : (B'<html>'),
            'HTMLUpper'     : (B'<HTML>'),
            'XML'           : (B'<?xml version="'),
            'Ace'           : (B'**ACE**'),
        },
        range(0x36, 0x41): {
            'PEStub': (
                B'\0\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'
                B'This program cannot be run in DOS mode.\r'
            ),
            'PEDelphiStub': (
                B'\0\xBA\x10\x00\x0E\x1F\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x90\x90'
                B'This program must be run under Win', (B'32', B'64'), B'\x0D\x0A'
            ),
        },
        range(0x48, 0x60): {
            'PEStubMsg'      : (B'This program cannot be run in DOS mode.\r'),
            'PEDelphiStubMsg': (B'This program must be run under Win', (B'32', B'64'), B'\x0D\x0A'),
        },
        range(0xD0, 0xD1): {
            'Tar'           : (B'\x00' * 0x30 + B'ustar', (B'\x20\x20\x00', B'\x00\x30\x30')),
        },
    }

    _ENC_ALPHABETS = [
        B'0123456789,',
        B'0123456789;',
        B'0123456789ABCDEF',
        B'0123456789abcdef',
        B'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
        B'abcdefghijklmnopqrstuvwxyz234567',
        B'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
        B'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_',
    ]

    _WSH_ALPHABET = bytes(set(range(0x20, 0x80)) - {0x3C, 0x3E} | {0x09})

    class _rt(enum.IntEnum):
        crib = 0
        alph = 1
        freq = 2

    class _result(NamedTuple):
        key: bytes
        how: xkey._rt
        xor: bool | None = None
        score: float = 0.0

    def __init__(
        self,
        range: Param[slice, Arg.Bounds(help=(
            'range of length values to try in Python slice syntax, the default is {default}.'
        ))] = slice(1, 32),
        plaintext: Param[buf, Arg.Binary('-p', help=(
            'Provide a buffer of known plaintext. Without a search position, this can slow '
            'down the key search significantly.'
        ))] = B'',
        searchpos: Param[slice, Arg.Bounds('-s', metavar='S:E', help=(
            'Only used when a known plaintext buffer is provided; In this case it narrows the '
            'search range for the offset of that data to between S and E.'
        ))] = slice(0, None),
        alph: Param[bool, Arg.Switch('-a',
            help='Enable search for keys via known encoder alphabets.')] = False,
        crib: Param[bool, Arg.Switch('-c',
            help='Enable search for keys via known plaintext cribs.')] = False,
        freq: Param[bool, Arg.Switch('-f',
            help='Enable search for keys via frequency analysis.')] = False,
    ):
        if not any((alph, crib, freq)) and not plaintext:
            alph = crib = freq = True
        super().__init__(
            range=range,
            plaintext=plaintext,
            searchpos=searchpos,
            alph=alph,
            crib=crib,
            freq=freq,
        )

    def process(self, data: bytearray):
        for result in self._attack(data):
            out = result.key
            if how := result.how:
                out = self.labelled(out, method=how)
            return out

    def _attack(self, data: bytearray):
        bounds: slice = self.args.range
        view = memoryview(data)
        length = len(view)

        if length <= 1:
            return

        if length >= 0x100:
            view = view[:-4]

        start = bounds.start or 1
        stop = min(bounds.stop or length, length)

        if (step := bounds.step) is None:
            step = 1
        elif bounds.start is None:
            start *= step

        self.log_debug(
            F'received input range [{bounds.start}:{bounds.stop}:{bounds.step}], '
            F'using [{start}:{stop}:{step}]')

        criblist: list[tuple[range, dict[str, bytes | tuple[bytes | tuple[bytes, ...], ...]]]] = []

        if p := self.args.plaintext:
            pos: slice = self.args.searchpos
            end = len(data) - len(p) if pos.stop is None else pos.stop
            criblist.append((range(pos.start or 0, end + 1), {'Plaintext': (p,)}))
        if self.args.crib:
            for r, byname in self._CRIBS.items():
                compiled = {
                    name: tuple(_generate_cribs(cribs))
                    for name, cribs in byname.items()
                }
                criblist.append((r, compiled))

        if self.args.alph:
            alphabets: dict[int, list[bytes]] | None = {}
            for alphabet in self._ENC_ALPHABETS:
                for suffix in (B'', B'\x20', B'\x0A', B'\x20\x0A'):
                    a = alphabet + suffix
                    alphabets.setdefault(len(a), []).append(a)
            alphabets[len(self._WSH_ALPHABET)] = [self._WSH_ALPHABET]
        else:
            alphabets = None

        for xor in (True, False):
            if key := self._process_crib(view, xor, criblist):
                yield self._result(key, self._rt.crib, xor)

        hist = {}
        freq = []

        for xor in (True, False):
            result = self._process_freq(view, (start, stop, step), alphabets, xor, hist)
            if result is None or not result.key:
                continue
            if result.how == self._rt.freq:
                freq.append(result)
                continue
            yield result

        yield from freq

    def _process_crib(
        self,
        view: memoryview,
        xor: bool,
        criblist: list[tuple[range, dict[str, list[bytes]]]]
    ):
        for offsets, cribs_by_type in criblist:
            for name, cribs in cribs_by_type.items():
                for crib in cribs:
                    cn = len(crib)
                    for offset in offsets:
                        test = view[offset:offset + cn]
                        if len(test) != cn:
                            continue
                        key = strxor(test, crib) if xor else bytes(
                            a - b & 0xFF for a, b in zip(test, crib))
                        if key := _cyclic_base(key):
                            self.log_info(F'found key via crib {name}:', crib, clip=True)
                            shift = -offset % len(key)
                            return key[shift:] + key[:shift]

    def _process_freq(
        self,
        view: memoryview,
        bounds: tuple[int, int, int],
        alphabets: dict[int, list[bytes]] | None,
        xor: bool,
        hist: dict[int, tuple[list[bytes], list[Counter]]],
    ):
        n = len(view)
        start, stop, step = bounds
        score = 0
        guess = None
        first = not hist

        for keylen in range(start, stop + 1, step):
            try:
                cached = hist[keylen]
            except KeyError:
                patches = [view[j::keylen] for j in range(keylen)]
                histograms = [Counter(p) for p in patches]
                hist[keylen] = patches, histograms
            else:
                patches, histograms = cached

            if alphabets is not None:
                hlc = Counter(len(h) for h in histograms)
                base, coverage = hlc.most_common(1)[0]

                if coverage * 2 > keylen and base in alphabets:
                    self.log_debug(F'solving for potential plaintext alphabet of size 0x{base:02X} at {keylen}')
                    keys: dict[bytes, bytes] = {}
                    for alphabet in alphabets[base]:
                        key = bytearray(keylen)
                        for k, patch in enumerate(patches):
                            keybyte = set(range(0x100))
                            for c in patch:
                                keybyte &= (
                                    {c ^ p & 0xFF for p in alphabet}
                                ) if xor else (
                                    {c - p & 0xFF for p in alphabet}
                                )
                                if len(keybyte) == 1:
                                    key[k] = next(iter(keybyte))
                                    break
                            else:
                                key = None
                                break
                        if key is not None:
                            keys[alphabet] = key
                    if len(keys) == 1:
                        self.log_debug(F'discovered plaintext alphabet of size 0x{base:02X} at {keylen}')
                        alphabet, key = keys.popitem()
                        return self._result(bytes(key), self._rt.alph, xor)

            if not first or not self.args.freq:
                continue

            _guess = [h.most_common(1)[0] for h in histograms]
            _score = sum(letter_count for _, letter_count in _guess) / n
            # This scaling accounts for the smaller probability of larger keys. No proper statistical analysis has been
            # conducted to derive it; there might be plenty of room for improvement here.
            _score = _score * ((n - keylen) / (n - 1)) ** keylen

            logmsg = F'[{{}}] score {_score * 100:05.2f}% for key length {keylen}'
            if _score > score:
                self.log_info(logmsg.format('+'))
                score = _score
                guess = bytes(value for value, _ in _guess)
            else:
                self.log_debug(logmsg.format(' '))

        if guess is not None:
            return self._result(guess, self._rt.freq, score=score * 100)
