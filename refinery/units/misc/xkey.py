#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from itertools import product
from collections import Counter
from refinery import Unit, Arg

try:
    from Crypto.Util.strxor import strxor
except ImportError:
    def strxor(a, b): return bytes(x ^ y for x, y in zip(a, b))


def _generate_cribs(cribs: bytes | tuple[bytes | tuple[bytes, ...], ...]):
    if isinstance(cribs, bytes):
        yield cribs
        return
    for p in product(*[[c] if isinstance(c, bytes) else c for c in cribs]):
        yield B''.join(p)


def _cyclic_base(string: bytes):
    n = len(string)
    for p in range(1, n // 2 + 1):
        q = n // p + 1
        k = string[:p]
        t = q * k
        if t.startswith(string):
            return k
    return None


def _S(options: bytes):
    return tuple(bytes((b,)) for b in options)


class xkey(Unit):
    """
    The unit expects encrypted input which was encrypted byte-wise with a polyalphabetic key. It
    attempts do determine this key by three methods:

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
            'OleDocument'   : (B'\xD0\xCF\x11\xE0'),
            'PdfDocument'   : (B'%PDF-', _S(B'12'), (B'.'), _S(B'0123456789'), _S(B'\r\n')),
            'SQLite'        : (B'SQLite format 3\0'),
            'GIF'           : (B'GIF87a', B'GIF89a'),
            'PNG'           : (B'\x89PNG\r\n\x1A\n'),
            'DEX'           : (B'dex\n035\0'),
            'JPG'           : (B'\xFF\xD8\xFF', _S(B'\xE0\xE1\xEE'), (B'\x00\x10\x4A\x46\x49\x46\x00\x01', B'')),
            'OneNote'       : (B'\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3'),
            'A3xScript'     : (B'\xA3\x48\x4B\xBE\x98\x6C\x4A\xA9\x99\x4C\x53\x0A\x86\xD6\x48\x7D'),
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
        range(0x40): {
            'DocTypeLower'  : (B'<!doctype'),
            'DocTypeUpper'  : (B'<!DOCTYPE'),
            'HTMLLower'     : (B'<html>'),
            'HTMLUpper'     : (B'<HTML>'),
            'XML'           : (B'<?xml version="'),
            'Ace'           : (B'**ACE**'),
        },
        range(0x40, 0x60): {
            'PEDelphiStub'  : (B'This program cannot be run in DOS mode.'),
            'PEStub'        : (B'This program must be run under Win', (B'32', B'64')),
        },
        range(0xD0, 0xD1): {
            'Tar'           : (B'\x00' * 0x30 + B'ustar', (B'\x20\x20\x00', B'\x00\x30\x30')),
        },
        range(0x200): {
            'EmailReceived' : (B'\nReceived:\x20from'),
            'EmailSubject'  : (B'\nSubject:\x20'),
            'EmailFrom'     : (B'\nFrom:\x20'),
            'EmailTo'       : (B'\nTo:\x20'),
            'PESectionData' : (B'.data\0\0\0'),
            'PESectionText' : (B'.text\0\0\0'),
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

    def __init__(
        self,
        range: Arg.Bounds(help='range of length values to try in Python slice syntax, the default is {default}.') = slice(1, 32),
        no_alph: Arg.Switch('-na', '--no-alph', help='disables search for keys via known encoder alphabets') = False,
        no_crib: Arg.Switch('-nc', '--no-crib', help='disables search for keys via known plaintext cribs') = False,
    ):
        super().__init__(range=range, no_alph=no_alph, no_crib=no_crib)

    def process(self, data: bytearray):
        score = 0
        guess = None
        bounds: slice = self.args.range
        view = memoryview(data)

        n = len(view)

        if n <= 1:
            return view
        if n >= 0x100:
            view = view[:-4]

        start = bounds.start or 1
        stop = min(bounds.stop or n, n)

        if bounds.step is not None:
            step = bounds.step
            if bounds.start is None:
                start *= step
        else:
            step = 1

        self.log_debug(F'received input range [{bounds.start}:{bounds.stop}:{bounds.step}], using [{start}:{stop}:{step}]')

        if not self.args.no_crib:
            for offsets, cribs_by_type in self._CRIBS.items():
                for name, cribs in cribs_by_type.items():
                    cribs = _generate_cribs(cribs)
                    for offset, crib in product(offsets, cribs):
                        if len(crib) < start:
                            continue
                        if len(crib) > stop:
                            continue
                        if (len(crib) - start) % step != 0:
                            continue
                        test = view[offset:offset + len(crib)]
                        if len(test) != len(crib):
                            continue
                        key = _cyclic_base(strxor(test, crib))
                        if key is not None:
                            self.log_info(F'found key via crib for {name}:', crib)
                            shift = -offset % len(key)
                            return key[shift:] + key[:shift]

        if not self.args.no_alph:
            alphabets: dict[int, list[bytes]] = {}
            for alphabet in self._ENC_ALPHABETS:
                for suffix in (B'', B'\x20', B'\x0A', B'\x20\x0A'):
                    a = alphabet + suffix
                    alphabets.setdefault(len(a), []).append(a)

            alphabets[len(self._WSH_ALPHABET)] = self._WSH_ALPHABET

        for keylen in range(start, stop + 1, step):
            patches = [view[j::keylen] for j in range(keylen)]
            histograms = [Counter(p) for p in patches]

            if not self.args.no_alph:
                hlc = Counter(len(h) for h in histograms)
                base, coverage = hlc.most_common(1)[0]

                if coverage * 2 > keylen and base in alphabets:
                    self.log_info(F'detected potential plaintext alphabet of size 0x{base:02X} at {keylen}')
                    keys: dict[bytes, bytes] = {}
                    for alphabet in alphabets[base]:
                        key = bytearray(keylen)
                        for k, patch in enumerate(patches):
                            keybyte = set(range(0x100))
                            for x in patch:
                                keybyte &= {y ^ x for y in alphabet}
                                if len(keybyte) == 1:
                                    key[k] = next(iter(keybyte))
                                    break
                            else:
                                key = None
                                break
                        if key is not None:
                            keys[alphabet] = key
                    if len(keys) == 1:
                        alphabet, key = keys.popitem()
                        return key

            _guess = [h.most_common(1)[0] for h in histograms]
            _score = sum(letter_count for _, letter_count in _guess) / n
            # This scaling accounts for the smaller probability of larger keys. No proper statistical analysis has been
            # conducted to derive it; there might be plenty of room for improvement here.
            _score = _score * ((n - keylen) / (n - 1)) ** keylen

            logmsg = F'got score {_score * 100:5.2f}% for length {keylen}'
            if _score > score:
                self.log_info(logmsg)
                score = _score
                guess = bytearray(value for value, _ in _guess)
            else:
                self.log_debug(logmsg)

        return guess
