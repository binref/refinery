#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------------------------\
# This code was ported directly from unzpaq.cpp; it is not very Pythonic and has inherited a   |
# somewhat convoluted structure from the source. Cleaning it up seems to be largely pointless  |
# given the archaic nature of the file format.                                                 |
# ---------------------------------------------------------------------------------------------/
from __future__ import annotations
from typing import Optional, Dict, List, TYPE_CHECKING
from types import CodeType

if TYPE_CHECKING:
    from hashlib import _Hash

from array import array
from datetime import datetime
from enum import IntEnum
from math import log, exp
from dataclasses import dataclass, field

import hashlib
import itertools
import re
import io

from refinery.units.formats.archive import ArchiveUnit, Arg
from refinery.lib.structures import MemoryFile, StructReader


_TCU32 = 'I'
_TCI32 = 'i'
_TCU16 = 'H'
_TCI16 = 'h'


class _HaltExecution(Exception):
    pass


def _i32(x: int):
    return -(~(x - 1) & 0xFFFFFFFF) if x & 0x80000000 else x


def _resize(a: array, c: int, b: int = 0):
    c *= (1 << b)
    del a[c:]
    a.extend(itertools.repeat(0, c - len(a)))


def _memzap(a: array, offset: int, n: int):
    a[offset:offset + n] = itertools.repeat(0, n)


class CompType(IntEnum):
    NONE  = 0 # noqa
    CONS  = 1 # noqa
    CM    = 2 # noqa
    ICM   = 3 # noqa
    MATCH = 4 # noqa
    AVG   = 5 # noqa
    MIX2  = 6 # noqa
    MIX   = 7 # noqa
    ISSE  = 8 # noqa
    SSE   = 9 # noqa


CompSize = [0, 2, 3, 2, 3, 4, 6, 6, 3, 5]
CompSize.extend(itertools.repeat(0, 256 - len(CompSize)))


class ZPAQL:

    output: Optional[MemoryFile]
    header: bytearray # hsize[2] hh hm ph pm n COMP (guard) HCOMP (guard)
    cend: int
    hbegin: int
    hend: int

    m: bytearray
    h: array
    r: array

    a: int
    b: int
    c: int
    d: int
    f: int
    pc: int

    sha1: Optional[_Hash]

    _cpu_defs: Dict[int, str]
    _cpu_spec: Dict[int, CodeType]

    def __init__(self):
        self.h = array(_TCU32)
        self.r = array(_TCU32)
        self.m = bytearray()
        self.sha1 = None
        self.output = None
        self.header = bytearray()
        self.clear()

        self._cpu_spec = {}
        self._cpu_defs = {
            0x01: 'a = a + 1 & 0xFFFFFFFF',
            0x02: 'a = a - 1 & 0xFFFFFFFF',
            0x03: 'a = ~a & 0xFFFFFFFF',
            0x04: 'a = 0',
            0x07: 'a = r[{} % len(r)]',
            0x08: 'b, a = a, b',
            0x09: 'b = b + 1 & 0xFFFFFFFF',
            0x0A: 'b = b - 1 & 0xFFFFFFFF',
            0x0B: 'b = ~b & 0xFFFFFFFF',
            0x0C: 'b = 0',
            0x0F: 'b = r[{} % len(r)]',
            0x10: 'c, a = a, c',
            0x11: 'c = c + 1 & 0xFFFFFFFF',
            0x12: 'c = c - 1 & 0xFFFFFFFF',
            0x13: 'c = ~c & 0xFFFFFFFF',
            0x14: 'c = 0',
            0x17: 'c = r[{} % len(r)]',
            0x18: 'd, a = a, d',
            0x19: 'd = d + 1 & 0xFFFFFFFF',
            0x1A: 'd = d - 1 & 0xFFFFFFFF',
            0x1B: 'd = ~d & 0xFFFFFFFF',
            0x1C: 'd = 0',
            0x1F: 'd = r[{} % len(r)]',
            0x20: 'm[b % len(m)], a = a, m[b % len(m)]',
            0x21: 'm[b % len(m)] += 1',
            0x22: 'm[b % len(m)] -= 1',
            0x23: 'm[b % len(m)] = ~m[b % len(m)] & 0xFF',
            0x24: 'm[b % len(m)] = 0',
            0x27: 'pc += ((header[pc] + 128) & 255) - 127 if f else 1',
            0x28: 'm[c % len(m)], a = a, m[c % len(m)]',
            0x29: 'm[c % len(m)] += 1',
            0x2A: 'm[c % len(m)] -= 1',
            0x2B: 'm[c % len(m)] = ~m[c % len(m)] & 0xFF',
            0x2C: 'm[c % len(m)] = 0 & 0xFF',
            0x2F: 'pc += 1 if f else ((header[pc] + 128) & 255) - 127',
            0x30: 'h[d % len(h)], a = a, h[d % len(h)]',
            0x31: 'h[d % len(h)] += 1',
            0x32: 'h[d % len(h)] -= 1',
            0x33: 'h[d % len(h)] = ~h[d % len(h)]',
            0x34: 'h[d % len(h)] = 0',
            0x37: 'r[{} % len(r)] = a',
            0x38: 'raise halt(pc)',
            0x39: 'out(a & 255)',
            0x3B: 'a = ((a + m[b % len(m)] + 512) * 773) & 0xFFFFFFFF',
            0x3C: 'h[d % len(h)] = (h[d % len(h)] + a + 512) * 773 & 0xFFFFFFFF',
            0x3F: 'pc += ((header[pc] + 128) & 255) - 127',
            0x40: '',
            0x41: 'a = b',
            0x42: 'a = c',
            0x43: 'a = d',
            0x44: 'a = m[b % len(m)]',
            0x45: 'a = m[c % len(m)]',
            0x46: 'a = h[d % len(h)]',
            0x47: 'a = {}',
            0x48: 'b = a',
            0x49: '',
            0x4A: 'b = c',
            0x4B: 'b = d',
            0x4C: 'b = m[b % len(m)]',
            0x4D: 'b = m[c % len(m)]',
            0x4E: 'b = h[d % len(h)]',
            0x4F: 'b = {}',
            0x50: 'c = a',
            0x51: 'c = b',
            0x52: '',
            0x53: 'c = d',
            0x54: 'c = m[b % len(m)]',
            0x55: 'c = m[c % len(m)]',
            0x56: 'c = h[d % len(h)]',
            0x57: 'c = {}',
            0x58: 'd = a',
            0x59: 'd = b',
            0x5A: 'd = c',
            0x5B: '',
            0x5C: 'd = m[b % len(m)]',
            0x5D: 'd = m[c % len(m)]',
            0x5E: 'd = h[d % len(h)]',
            0x5F: 'd = {}',
            0x60: 'm[b % len(m)] = a & 0xFF',
            0x61: 'm[b % len(m)] = b & 0xFF',
            0x62: 'm[b % len(m)] = c & 0xFF',
            0x63: 'm[b % len(m)] = d & 0xFF',
            0x64: '',
            0x65: 'm[b % len(m)] = m[c % len(m)]',
            0x66: 'm[b % len(m)] = h[d % len(h)] & 0xFF',
            0x67: 'm[b % len(m)] = {}',
            0x68: 'm[c % len(m)] = a & 0xFF',
            0x69: 'm[c % len(m)] = b & 0xFF',
            0x6A: 'm[c % len(m)] = c & 0xFF',
            0x6B: 'm[c % len(m)] = d & 0xFF',
            0x6C: 'm[c % len(m)] = m[b % len(m)]',
            0x6D: '',
            0x6E: 'm[c % len(m)] = h[d % len(h)] & 0xFF',
            0x6F: 'm[c % len(m)] = {}',
            0x70: 'h[d % len(h)] = a',
            0x71: 'h[d % len(h)] = b',
            0x72: 'h[d % len(h)] = c',
            0x73: 'h[d % len(h)] = d',
            0x74: 'h[d % len(h)] = m[b % len(m)]',
            0x75: 'h[d % len(h)] = m[c % len(m)]',
            0x76: '',
            0x77: 'h[d % len(h)] = {}',
            0x80: 'a = a + a & 0xFFFFFFFF',
            0x81: 'a = a + b & 0xFFFFFFFF',
            0x82: 'a = a + c & 0xFFFFFFFF',
            0x83: 'a = a + d & 0xFFFFFFFF',
            0x84: 'a = a + m[b % len(m)] & 0xFFFFFFFF',
            0x85: 'a = a + m[c % len(m)] & 0xFFFFFFFF',
            0x86: 'a = a + h[d % len(h)] & 0xFFFFFFFF',
            0x87: 'a = a + {} & 0xFFFFFFFF',
            0x88: 'a = 0',
            0x89: 'a = a - b & 0xFFFFFFFF',
            0x8A: 'a = a - c & 0xFFFFFFFF',
            0x8B: 'a = a - d & 0xFFFFFFFF',
            0x8C: 'a = a - m[b % len(m)] & 0xFFFFFFFF',
            0x8D: 'a = a - m[c % len(m)] & 0xFFFFFFFF',
            0x8E: 'a = a - h[d % len(h)] & 0xFFFFFFFF',
            0x8F: 'a = a - {} & 0xFFFFFFFF',
            0x90: 'a = a * a & 0xFFFFFFFF',
            0x91: 'a = a * b & 0xFFFFFFFF',
            0x92: 'a = a * c & 0xFFFFFFFF',
            0x93: 'a = a * d & 0xFFFFFFFF',
            0x94: 'a = a * m[b % len(m)] & 0xFFFFFFFF',
            0x95: 'a = a * m[c % len(m)] & 0xFFFFFFFF',
            0x96: 'a = a * h[d % len(h)] & 0xFFFFFFFF',
            0x97: 'a = a * {} & 0xFFFFFFFF',
            0x98: 'a = a//a if a else 0',
            0x99: 'a = a//b if b else 0',
            0x9A: 'a = a//c if c else 0',
            0x9B: 'a = a//d if d else 0',
            0x9C: 't = m[b % len(m)]\na = a//t if t else 0',
            0x9D: 't = m[c % len(m)]\na = a//t if t else 0',
            0x9E: 't = h[d % len(h)]\na = a//t if t else 0',
            0x9F: 't = {}           \na = a//t if t else 0',
            0xA0: 'a = a % a if a else 0',
            0xA1: 'a = a % b if b else 0',
            0xA2: 'a = a % c if c else 0',
            0xA3: 'a = a % d if d else 0',
            0xA4: 't = m[b % len(m)]\na = a % t if t else 0',
            0xA5: 't = m[c % len(m)]\na = a % t if t else 0',
            0xA6: 't = h[d % len(h)]\na = a % t if t else 0',
            0xA7: 't = {}           \na = a % t if t else 0',
            0xA8: 'a &= a',
            0xA9: 'a &= b',
            0xAA: 'a &= c',
            0xAB: 'a &= d',
            0xAC: 'a &= m[b % len(m)]',
            0xAD: 'a &= m[c % len(m)]',
            0xAE: 'a &= h[d % len(h)]',
            0xAF: 'a &= {}',
            0xB0: 'a &= ~a',
            0xB1: 'a &= ~b',
            0xB2: 'a &= ~c',
            0xB3: 'a &= ~d',
            0xB4: 'a &= ~m[b % len(m)]',
            0xB5: 'a &= ~m[c % len(m)]',
            0xB6: 'a &= ~h[d % len(h)]',
            0xB7: 'a &= ~{}',
            0xB8: 'a |= a',
            0xB9: 'a |= b',
            0xBA: 'a |= c',
            0xBB: 'a |= d',
            0xBC: 'a |= m[b % len(m)]',
            0xBD: 'a |= m[c % len(m)]',
            0xBE: 'a |= h[d % len(h)]',
            0xBF: 'a |= {}',
            0xC0: 'a ^= a',
            0xC1: 'a ^= b',
            0xC2: 'a ^= c',
            0xC3: 'a ^= d',
            0xC4: 'a ^= m[b % len(m)]',
            0xC5: 'a ^= m[c % len(m)]',
            0xC6: 'a ^= h[d % len(h)]',
            0xC7: 'a ^= {}',
            0xC8: 'a = (a << (a & 31)) & 0xFFFFFFFF',
            0xC9: 'a = (a << (b & 31)) & 0xFFFFFFFF',
            0xCA: 'a = (a << (c & 31)) & 0xFFFFFFFF',
            0xCB: 'a = (a << (d & 31)) & 0xFFFFFFFF',
            0xCC: 'a = (a << (m[b % len(m)] & 31)) & 0xFFFFFFFF',
            0xCD: 'a = (a << (m[c % len(m)] & 31)) & 0xFFFFFFFF',
            0xCE: 'a = (a << (h[d % len(h)] & 31)) & 0xFFFFFFFF',
            0xCF: 'a = (a << ({} & 31)) & 0xFFFFFFFF',
            0xD0: 'a >>= (a & 31)',
            0xD1: 'a >>= (b & 31)',
            0xD2: 'a >>= (c & 31)',
            0xD3: 'a >>= (d & 31)',
            0xD4: 'a >>= (m[b % len(m)] & 31)',
            0xD5: 'a >>= (m[c % len(m)] & 31)',
            0xD6: 'a >>= (h[d % len(h)] & 31)',
            0xD7: 'a >>= ({} & 31)',
            0xD8: 'f = (a == a)',
            0xD9: 'f = (a == b)',
            0xDA: 'f = (a == c)',
            0xDB: 'f = (a == d)',
            0xDC: 'f = (a == m[b % len(m)])',
            0xDD: 'f = (a == m[c % len(m)])',
            0xDE: 'f = (a == h[d % len(h)])',
            0xDF: 'f = (a == {})',
            0xE0: 'f = (a < a)',
            0xE1: 'f = (a < b)',
            0xE2: 'f = (a < c)',
            0xE3: 'f = (a < d)',
            0xE4: 'f = (a < m[b % len(m)])',
            0xE5: 'f = (a < m[c % len(m)])',
            0xE6: 'f = (a < h[d % len(h)])',
            0xE7: 'f = (a < {})',
            0xE8: 'f = (a > a)',
            0xE9: 'f = (a > b)',
            0xEA: 'f = (a > c)',
            0xEB: 'f = (a > d)',
            0xEC: 'f = (a > m[b % len(m)])',
            0xED: 'f = (a > m[c % len(m)])',
            0xEE: 'f = (a > h[d % len(h)])',
            0xEF: 'f = (a > {})',
            0xFF: (
                'pc = hbegin + header[pc] + 256 * header[pc + 1]\n'
                'if pc >= hend: raise RuntimeError'
            )
        }

    def inith(self):
        self.init(self.header[2], self.header[3])

    def initp(self):
        self.init(self.header[4], self.header[5])

    def run(self, input: int):
        assert self.cend > 6
        assert self.hbegin >= self.cend + 128
        assert self.hend >= self.hbegin
        assert self.hend < len(self.header) - 130
        assert len(self.m) > 0
        assert len(self.h) > 0
        assert self.header[0] + 256 * self.header[1] == self.cend + self.hend - self.hbegin - 2
        self.pc = self.hbegin
        self.a = input
        self.execute_loop()

    def read(self, in2: StructReader) -> int:
        hsize = in2.u16()
        self.header = bytearray(hsize + 300)
        cend = hbegin = hend = 0
        self.header[cend] = hsize & 255
        cend += 1
        self.header[cend] = hsize >> 8
        cend += 1
        while cend < 7:
            self.header[cend] = in2.u8()
            cend += 1
        n = self.header[cend - 1]
        for _ in range(n):
            type = in2.u8()
            self.header[cend] = type
            cend += 1
            size = CompSize[type]
            for _ in range(1, size):
                self.header[cend] = in2.u8()
                cend += 1
        end_byte = in2.u8()
        self.header[cend] = end_byte
        cend += 1
        if end_byte != 0:
            raise ValueError('missing COMP END')
        hbegin = hend = cend + 128
        if hend > hsize + 129:
            raise ValueError('missing HCOMP')
        while hend < hsize + 129:
            assert hend < len(self.header) - 8
            op = in2.u8()
            self.header[hend] = op
            hend += 1
        end_byte = in2.u8()
        self.header[hend] = end_byte
        hend += 1
        self.cend = cend
        self.hend = hend
        self.hbegin = hbegin
        if end_byte != 0:
            raise ValueError('missing HCOMP END')
        assert cend >= 7 and cend < len(self.header)
        assert hbegin == cend + 128 and hbegin < len(self.header)
        assert hend > hbegin and hend < len(self.header)
        assert hsize == self.header[0] + 256 * self.header[1]
        assert hsize == cend - 2 + hend - hbegin
        return cend + hend - hbegin

    def clear(self):
        self.cend = 0
        self.hbegin = 0
        self.hend = 0
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.f = 0
        self.pc = 0
        self.header.clear()
        self.m.clear()
        del self.h[:]
        del self.r[:]

    def outc(self, c: int):
        c &= 0xFF
        if self.output is not None:
            self.output.write_byte(c)
        if self.sha1 is not None:
            self.sha1.update(bytes((c,)))

    def init(self, hbits: int, mbits: int):
        assert len(self.header) > 0
        assert self.cend >= 7
        assert self.hbegin >= self.cend + 128
        assert self.hend >= self.hbegin
        assert self.hend < len(self.header) - 130
        assert self.header[0] + 256 * self.header[1] == self.cend - 2 + self.hend - self.hbegin
        mlen = 1 << mbits
        hlen = 1 << hbits
        rlen = 0x100
        del self.m[mlen:]
        self.m.extend(itertools.repeat(0, mlen - len(self.m)))
        del self.h[hlen:]
        self.h.extend(itertools.repeat(0, hlen - len(self.h)))
        del self.r[rlen:]
        self.r.extend(itertools.repeat(0, rlen - len(self.r)))
        _resize(self.r, 256)
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.f = 0
        self.pc = 0

    def execute_loop(self):

        def out(c: int):
            c &= 0xFF
            if self.output is not None:
                self.output.write_byte(c)
            if self.sha1 is not None:
                self.sha1.update(bytes((c,)))

        cpu = dict(self.__dict__)
        cpu.update(out=out, halt=_HaltExecution)

        while True:
            pc = cpu['pc']
            try:
                code = self._cpu_spec[pc]
            except KeyError:
                with io.StringIO() as writer:
                    start = pc
                    done = False
                    xtzpaq.log_info(F'precompiling block B{start:08X}')
                    while not done:
                        opcode = self.header[pc]
                        try:
                            line = self._cpu_defs[opcode]
                        except KeyError:
                            raise RuntimeError(F'invalid opcode: 0x{opcode:02X}')
                        pc += 1
                        if '{}' in line:
                            line = line.format(self.header[pc])
                            pc += 1
                        if 'pc' in line:
                            done = True
                            writer.write(F'pc = {pc}\n')
                        writer.write(F'{line}\n')
                    code = writer.getvalue()
                self._cpu_spec[start] = code = compile(
                    code, F'<BB:{start:08X}>', 'exec', optimize=2)
            try:
                exec(code, {}, cpu)
            except _HaltExecution:
                break
            except Exception as E:
                raise E

        self.__dict__.update((k, cpu[k]) for k in self.__dict__.keys() & cpu.keys())


class Component:
    def __init__(self):
        self.init()

    def init(self):
        self.limit = 0
        self.cxt = 0
        self.a = 0
        self.b = 0
        self.c = 0
        self.ht = bytearray()
        self.cm = array(_TCU32)
        self.a16 = array(_TCU32)


class StateTable:
    _N = 64
    ns: bytearray

    def next(self, state: int, y: int):
        assert 0 <= state <= 256
        assert 0 <= y <= 3
        return self.ns[state * 4 + y]

    def cminit(self, state: int):
        assert 0 <= state <= 256
        ns = self.ns
        a = (ns[state * 4 + 3] * 2 + 1) << 22
        b = ns[state * 4 + 2] + ns[state * 4 + 3] + 1
        return a // b

    def num_states(self, n0: int, n1: int):
        bound = (20, 48, 15, 8, 6, 5)
        if n0 < n1:
            return self.num_states(n1, n0)
        if n0 < 0 or n1 < 0 or n1 >= len(bound) or n0 > bound[n1]:
            return 0
        return 1 + int(n1 > 0 and n0 + n1 <= 17)

    def discount(self, n0: int):
        return (n0 >= 1) + (n0 >= 2) + (n0 >= 3) + (n0 >= 4) + (n0 >= 5) + (n0 >= 7) + (n0 >= 8)

    def next_state(self, n0: int, n1: int, y: int):
        if n0 < n1:
            n1, n0 = self.next_state(n1, n0, 1 - y)
            return n0, n1
        if y:
            n1 += 1
            n0 = self.discount(n0)
        else:
            n0 += 1
            n1 = self.discount(n1)
        while not self.num_states(n0, n1):
            if n1 < 2:
                n0 = n0 - 1
            else:
                n0 = (n0 * (n1 - 1) + (n1 // 2)) // n1
                n1 = n1 - 1
        return n0, n1

    def __init__(self):
        N = 50
        t = [[bytearray(N) for _ in range(N)] for _ in range(2)]
        state = 0
        for i in range(N):
            for n1 in range(i + 1):
                n0 = i - n1
                n = self.num_states(n0, n1)
                assert 0 <= n <= 2
                if not n:
                    continue
                t[0][n0][n1] = state
                t[1][n0][n1] = state + n - 1
                state += n
        self.ns = bytearray(1024)
        for n0 in range(N):
            for n1 in range(N):
                for y in range(self.num_states(n0, n1)):
                    assert 0 <= y <= 1
                    s = t[y][n0][n1]
                    assert 0 <= s <= 256
                    s0, s1 = self.next_state(n0, n1, 0)
                    assert 0 <= s0 <= N and 0 <= s1 <= N
                    self.ns[s * 4 + 0] = t[0][s0][s1]
                    s0, s1 = self.next_state(n0, n1, 1)
                    assert 0 <= s0 <= N and 0 <= s1 <= N
                    self.ns[s * 4 + 1] = t[1][s0][s1]
                    self.ns[s * 4 + 2] = n0
                    self.ns[s * 4 + 3] = n1


class Predictor:

    c8: int
    hmap4: int
    p: array
    h: array
    z: ZPAQL

    comp: List[Component]

    dt2k: array
    dt: array
    squasht: array
    stretcht: array
    st: StateTable

    def __init__(self, z: ZPAQL):
        self.c8 = 1
        self.hmap4 = 1
        self.z = z
        self.st = StateTable()
        self.dt2k = array(_TCI32)
        self.dt = array(_TCI32)
        self.squasht = array(_TCU16)
        self.stretcht = array(_TCI16)
        self.p = array(_TCI32)
        self.h = array(_TCU32)
        self.comp = []
        for _ in range(0x100):
            self.p.append(0)
            self.h.append(0)
            self.comp.append(Component())
        self.p = array(_TCI32)
        self.h = array(_TCU32)
        _resize(self.p, 256)
        _resize(self.h, 256)
        self.dt2k.append(0)
        for i in range(1, 0x100):
            self.dt2k.append(2048 // i)
        for i in range(1024):
            self.dt.append(((1 << 17) // (i * 2 + 3)) * 2)
        for i in range(32768):
            _k = 100000
            _l = log((i + 0.5) / (32767.5 - i)) * 64 + 0.5
            self.stretcht.append(int(_l + _k) - _k)
        for i in range(4096):
            _e = exp((i - 2048) * (-1.0 / 64)) + 1
            self.squasht.append(int(32768.0 / _e))
        sqsum = 0
        stsum = 0
        for v in reversed(self.stretcht):
            stsum = stsum * 3 + v & 0xFFFFFFFF
        for v in reversed(self.squasht):
            sqsum = sqsum * 3 + v & 0xFFFFFFFF
        if stsum != 3887533746:
            raise RuntimeError(F'checksum failure for stretch {stsum}')
        if sqsum != 2278286169:
            raise RuntimeError(F'checksum failure for squash {sqsum}')

    def init(self):
        self.z.inith()
        for i in range(0x100):
            self.h[i] = 0
            self.p[i] = 0
            self.comp[i].init()
        n = self.z.header[6]
        cp = memoryview(self.z.header)[7:self.z.cend]
        for i in range(n):
            assert cp
            cr = self.comp[i]
            ct = CompType(cp[0])
            if ct is CompType.CONS:
                self.p[i] = (cp[1] - 128) * 4
            elif ct is CompType.CM:
                if cp[1] > 32:
                    raise ValueError('max size for CM is 32')
                _resize(cr.cm, 1, cp[1])
                cr.limit = cp[2] * 4
                for j in range(len(cr.cm)):
                    cr.cm[j] = 0x80000000
            elif ct is CompType.ICM:
                if cp[1] > 26:
                    raise ValueError('max size for ICM is 26')
                cr.limit = 1023
                _resize(cr.cm, 256)
                _resize(cr.ht, 64, cp[1])
                for j in range(256):
                    cr.cm[j] = self.st.cminit(j)
            elif ct is CompType.MATCH:
                if cp[1] > 32 or cp[2] > 32:
                    raise ValueError('max size for MATCH is 32/32')
                _resize(cr.cm, 1, cp[1])
                _resize(cr.ht, 1, cp[2])
                cr.ht[0] = 1
            elif ct is CompType.AVG:
                if cp[1] >= i:
                    raise ValueError('AVG j >= i')
                if cp[2] >= i:
                    raise ValueError('AVG k >= i')
            elif ct is CompType.MIX2:
                if cp[1] > 32:
                    raise ValueError('max size for MIX2 is 32')
                if cp[3] >= i:
                    raise ValueError('MIX2 k >= i')
                if cp[2] >= i:
                    raise ValueError('MIX2 j >= i')
                cr.c = 1 << cp[1]  # size (number of contexts)
                _resize(cr.a16, 1, cp[1])
                for j in range(len(cr.a16)):
                    cr.a16[j] = 32768
            elif ct is CompType.MIX:
                if cp[1] > 32:
                    raise ValueError('max size for MIX is 32')
                if cp[2] >= i:
                    raise ValueError('MIX j >= i')
                if cp[3] < 1 or cp[3] > i - cp[2]:
                    raise ValueError('MIX m not in 1..i-j')
                m = cp[3] # number of inputs
                assert m >= 1
                cr.c = 1 << cp[1]  # size (number of contexts)
                _resize(cr.cm, m, cp[1])
                for j in range(len(cr.cm)):
                    cr.cm[j] = 65536 // m
            elif ct is CompType.ISSE:
                if cp[1] > 32:
                    raise ValueError('max size for ISSE is 32')
                if cp[2] >= i:
                    raise ValueError('ISSE j >= i')
                _resize(cr.ht, 64, cp[1])
                _resize(cr.cm, 512)
                for j in range(256):
                    clamped = self.clamp512k(self.stretch(self.st.cminit(j) >> 8) * 1024)
                    cr.cm[j * 2 + 0] = 1 << 15
                    cr.cm[j * 2 + 1] = clamped
            elif ct is CompType.SSE:
                if cp[1] > 32:
                    raise ValueError('max size for SSE is 32')
                if cp[2] >= i:
                    raise ValueError('SSE j >= i')
                if cp[3] > cp[4] * 4:
                    raise ValueError('SSE start > limit*4')
                _resize(cr.cm, 32, cp[1])
                cr.limit = cp[4] * 4
                for j in range(len(cr.cm)):
                    cr.cm[j] = self.squash((j & 31) * 64 - 992) << 17 | cp[3]
            else:
                raise ValueError('unknown component type')
            cs = CompSize[cp[0]]
            cp = cp[cs:]

    def predict(self):
        assert 0 < self.c8 < 256
        n = self.z.header[6]
        assert 0 < n < 256
        cp = memoryview(self.z.header)[7:]
        assert self.z.header[6] == n
        p = self.p
        h = self.h
        for i in range(n):
            cr = self.comp[i]
            ct = CompType(cp[0])
            if ct is CompType.CONS:
                pass
            elif ct is CompType.CM:
                cr.cxt = self.h[i] ^ self.hmap4
                p[i] = self.stretch(cr.cm[cr.cxt] >> 17)
            elif ct is CompType.ICM:
                assert self.hmap4 & 15 > 0
                if self.c8 == 1 or (self.c8 & 0xF0) == 16:
                    cr.c = self.find(cr.ht, cp[1] + 2, h[i] + 16 * self.c8)
                cr.cxt = cr.ht[cr.c + (self.hmap4 & 15)]
                p[i] = self.stretch(cr.cm[cr.cxt] >> 8)
            elif ct is CompType.MATCH:
                assert len(cr.cm) == 1 << cp[1]
                assert len(cr.ht) == 1 << cp[2]
                assert cr.a <= 255
                assert cr.c in {0, 1}
                assert cr.cxt < 8
                assert cr.limit < len(cr.ht)
                if cr.a == 0:
                    p[i] = 0
                else:
                    cr.c = (cr.ht[cr.limit - cr.b] >> (7 - cr.cxt)) & 1
                    p[i] = self.stretch(self.dt2k[cr.a] * (cr.c * -2 + 1) & 32767)
            elif ct is CompType.AVG:
                p[i] = (p[cp[1]] * cp[3] + p[cp[2]] * (256 - cp[3])) >> 8
            elif ct is CompType.MIX2:
                cr.cxt = (h[i] + (self.c8 & cp[5])) & (cr.c - 1)
                assert cr.cxt < len(cr.a16)
                w = cr.a16[cr.cxt]
                assert 0 <= w < 65536
                p[i] = (w * p[cp[2]] + (65536 - w) * p[cp[3]]) >> 16
                assert -2048 <= p[i] < 2048
            elif ct is CompType.MIX:
                m = cp[3]
                assert 1 <= m <= i
                cr.cxt = h[i] + (self.c8 & cp[5])
                cr.cxt = (cr.cxt & (cr.c - 1)) * m
                assert cr.cxt <= len(cr.cm) - m
                w = cr.cxt
                p[i] = 0
                for j in range(m):
                    p[i] += (_i32(cr.cm[w + j]) >> 8) * p[cp[2] + j]
                p[i] = self.clamp2k(p[i] >> 8)
            elif ct is CompType.ISSE:
                if self.c8 == 1 or (self.c8 & 0xF0) == 16:
                    cr.c = self.find(cr.ht, cp[1] + 2, h[i] + 16 * self.c8)
                cr.cxt = cr.ht[cr.c + (self.hmap4 & 15)]
                wt0 = _i32(cr.cm[cr.cxt * 2 + 0])
                wt1 = _i32(cr.cm[cr.cxt * 2 + 1])
                p[i] = self.clamp2k((wt0 * p[cp[2]] + wt1 * 64) >> 16)
            elif ct is CompType.SSE:
                cr.cxt = (h[i] + self.c8) * 32
                pq = min(max(0, p[cp[2]] + 992), 1983)
                wt = pq & 63
                pq >>= 6
                assert 0 <= pq <= 30
                cr.cxt += pq
                p[i] = self.stretch((
                    (cr.cm[cr.cxt + 0] >> 10) * (64 - wt) + (cr.cm[cr.cxt + 1] >> 10) * wt) >> 13)
                cr.cxt += wt >> 5
            else:
                raise ValueError('component predict not implemented')
            cs = CompSize[cp[0]]
            cp = cp[cs:]
        assert CompType(cp[0]) is CompType.NONE
        return self.squash(p[n - 1])

    def update(self, y: int):
        assert y in (0, 1)
        assert 0 < self.c8 < 256
        assert 0 < self.hmap4 < 512
        cp = memoryview(self.z.header)[7:]
        n = self.z.header[6]
        h = self.h
        p = self.p
        assert 0 < n < 256
        for i in range(n):
            cr = self.comp[i]
            ct = CompType(cp[0])
            if ct is CompType.CONS:
                pass
            elif ct is CompType.CM:
                self.train(cr, y)
            elif ct is CompType.ICM:
                k = cr.c + (self.hmap4 & 15)
                cr.ht[k] = self.st.next(cr.ht[k], y)
                pn = cr.cm[cr.cxt]
                pn += (y * 32767 - (pn >> 8)) >> 2
                cr.cm[cr.cxt] = pn
            elif ct is CompType.MATCH:
                assert cr.a <= 255
                assert cr.c in (0, 1)
                assert cr.cxt < 8
                assert len(cr.cm) == 1 << cp[1]
                assert len(cr.ht) == 1 << cp[2]
                assert cr.limit < len(cr.ht)
                if cr.c != y:
                    cr.a = 0  # mismatch?
                cr.ht[cr.limit] = (cr.ht[cr.limit] << 1) + y & 0xFF
                cr.cxt += 1
                if cr.cxt == 8:
                    cr.cxt = 0
                    cr.limit += 1
                    cr.limit &= (1 << cp[2]) - 1
                    hi = h[i] % len(cr.cm)
                    if cr.a != 0:
                        cr.a += int(cr.a < 255)
                    else:  # look for a match
                        cr.b = cr.limit - cr.cm[hi]
                        if cr.b & (len(cr.ht) - 1):
                            while cr.a < 255 and cr.ht[cr.limit - cr.a - 1] == cr.ht[cr.limit - cr.a - cr.b - 1]:
                                cr.a += 1
                    cr.cm[hi] = cr.limit
            elif ct is CompType.AVG:
                pass
            elif ct is CompType.MIX2:
                assert len(cr.a16) == cr.c
                assert cr.cxt < cr.c
                err = (y * 32767 - self.squash(p[i])) * cp[4] >> 5
                w = cr.a16[cr.cxt]
                w += (err * (p[cp[2]] - p[cp[3]]) + (1 << 12)) >> 13
                cr.a16[cr.cxt] = min(max(w, 0), 65535)
            elif ct is CompType.MIX:
                m = cp[3]
                assert m > 0 and m <= i
                assert len(cr.cm) == m * cr.c
                assert cr.cxt + m <= len(cr.cm)
                err = (y * 32767 - self.squash(p[i])) * cp[4] >> 4
                w = cr.cxt
                for j in range(m):
                    cr.cm[w + j] = self.clamp512k(_i32(cr.cm[w + j]) + ((err * p[cp[2] + j] + (1 << 12)) >> 13))
            elif ct is CompType.ISSE:
                assert cr.cxt == cr.ht[cr.c + (self.hmap4 & 15)]
                err = y * 32767 - self.squash(p[i])
                w = cr.cxt * 2
                cr.cm[w + 0] = self.clamp512k(_i32(cr.cm[w + 0]) + ((err * p[cp[2]] + (1 << 12)) >> 13))
                cr.cm[w + 1] = self.clamp512k(_i32(cr.cm[w + 1]) + ((err + 16) >> 5))
                cr.ht[cr.c + (self.hmap4 & 15)] = self.st.next(cr.cxt, y)
            elif ct is CompType.SSE:
                self.train(cr, y)
            else:
                raise RuntimeError
            cs = CompSize[cp[0]]
            cp = cp[cs:]

        assert CompType(cp[0]) is CompType.NONE

        self.c8 *= 2
        self.c8 += y
        if self.c8 >= 256:
            self.z.run(self.c8 - 256)
            self.hmap4 = 1
            self.c8 = 1
            self.h[:n] = self.z.h[:n]
        elif 16 <= self.c8 < 32:
            self.hmap4 = ((self.hmap4 & 15) << 5) | (y << 4) | 1
        else:
            self.hmap4 = (self.hmap4 & 0x1f0) | (((self.hmap4 & 15) * 2 + y) & 15)

    def is_modeled(self):
        return self.z.header[6] != 0

    def train(self, cr: Component, y: int):
        assert 0 <= y <= 1
        cxt = cr.cxt % len(cr.cm)
        pn = cr.cm[cxt]
        count = pn & 0x3FF
        error = y * 32767 - (pn >> 17)
        pn += (error * self.dt[count] & -1024) + (count < cr.limit)
        pn &= 0xFFFFFFFF
        cr.cm[cxt] = pn

    def squash(self, x: int):
        assert -2048 <= x <= 2047
        return self.squasht[x + 2048]

    def stretch(self, x: int):
        assert 0 <= x <= 32767
        return self.stretcht[x]

    def clamp2k(self, x: int):
        return min(max(x, -2048), 2047)

    def clamp512k(self, x: int):
        return min(max(x, -(1 << 19)), (1 << 19) - 1) & 0xFFFFFFFF

    def find(self, ht: array, sizebits: int, cxt: int):
        assert len(ht) == 16 << sizebits
        chk = cxt >> sizebits & 255
        h0 = (cxt * 16) & (len(ht) - 16)
        if ht[h0] == chk:
            return h0
        h1 = h0 ^ 16
        if ht[h1] == chk:
            return h1
        h2 = h0 ^ 32
        if ht[h2] == chk:
            return h2
        if ht[h0 + 1] <= ht[h1 + 1] and ht[h0 + 1] <= ht[h2 + 1]:
            _memzap(ht, h0, 16)
            ht[h0] = chk
            return h0
        elif ht[h1 + 1] < ht[h2 + 1]:
            _memzap(ht, h1, 16)
            ht[h1] = chk
            return h1
        else:
            _memzap(ht, h2, 16)
            ht[h2] = chk
            return h2


class Decoder:
    src: Optional[StructReader]

    low: int
    high: int
    curr: int
    pr: Predictor

    def __init__(self, z: ZPAQL):
        self.src = None
        self.pr = Predictor(z)
        self._set_values(1, 0xFFFFFFFF, 0)

    def _set_values(self, low, high, curr):
        self.low = low
        self.high = high
        self.curr = curr

    def init(self):
        self.pr.init()
        if self.pr.is_modeled():
            self._set_values(1, 0xFFFFFFFF, 0)
        else:
            self._set_values(0, 0x00000000, 0)

    def decode(self, p: int) -> int:
        assert 0 <= p < 65536
        assert 0 < self.low < self.high
        if self.curr < self.low or self.high < self.curr:
            raise RuntimeError('archive corrupted')
        mid = self.low + (((self.high - self.low) * p) >> 16) & 0xFFFFFFFF
        assert self.low <= mid <= self.high
        rv = self.curr <= mid
        if rv:
            self.high = mid
        else:
            self.low = mid + 1 & 0xFFFFFFFF
        while (self.high ^ self.low) < 0x1000000:
            self.high <<= 8
            self.high |= 0xFF
            self.high &= 0xFFFFFFFF
            self.low = (self.low << 8) & 0xFFFFFFFF
            if self.low == 0:
                self.low = 1
            self.curr <<= 8
            self.curr |= self.src.read_byte()
            self.curr &= 0xFFFFFFFF
        return int(rv)

    def decompress(self) -> Optional[int]:
        pr = self.pr
        if pr.is_modeled():
            if self.curr == 0:
                with self.src.be:
                    self.curr = self.src.u32()
            if self.decode(0):
                if self.curr:
                    raise ValueError('decoding end of input')
                return None
            else:
                c = 1
                while c < 256:
                    p = pr.predict() * 2 + 1
                    c *= 2
                    c += self.decode(p)
                    pr.update(c & 1)
                return c - 256
        else:
            if self.curr == 0:
                with self.src.be:
                    self.curr = self.src.u32()
            if self.curr == 0:
                return None
            assert self.curr > 0
            self.curr -= 1
            if self.src.eof:
                return None
            return self.src.read_byte()


class PostProcessor:
    state: int
    hsize: int
    ph: int
    pm: int
    z: ZPAQL

    def __init__(self):
        self.z = ZPAQL()
        self.init(0, 0)

    def init(self, h: int, m: int):
        self.state = 0
        self.hsize = 0
        self.ph = h
        self.pm = m
        self.z.clear()

    def set_output(self, writer: MemoryFile):
        self.z.output = writer

    def set_hasher(self, hasher: _Hash):
        self.z.sha1 = hasher

    def write(self, c: Optional[int]):
        assert c is None or c in range(256)
        z = self.z
        s = self.state
        if c is None:
            if s == 5:
                c = -1
            elif s != 1:
                raise ValueError('Unexpected EOS')
        elif s == 0:
            if c is None:
                raise ValueError('Unexpected EOS')
            self.state = s = c + 1
            if s > 2:
                raise RuntimeError('unknown post processing type')
            if s == 1:
                z.clear()
        elif s == 1:
            z.outc(c)
        elif s == 2:
            self.hsize = c
            self.state = 3
        elif s == 3:
            self.hsize += c * 256
            if self.hsize < 1:
                raise RuntimeError('Empty PCOMP')
            _resize(z.header, self.hsize + 300)
            z.cend = 8
            z.hbegin = z.hend = z.cend + 128
            z.header[4] = self.ph
            z.header[5] = self.pm
            self.state = 4
        elif s == 4:
            assert z.hend < len(z.header)
            z.header[z.hend] = c
            z.hend += 1
            if z.hend - z.hbegin == self.hsize:
                self.hsize = z.cend - 2 + z.hend - z.hbegin
                z.header[0] = self.hsize & 255
                z.header[1] = self.hsize >> 8
                z.initp()
                self.state = 5
        elif s == 5:
            z.run(c)
        return self.state


class Decompressor:
    z: ZPAQL
    dec: Decoder
    pp: PostProcessor

    class State(IntEnum):
        BLOCK = 0
        FILENAME = 1
        COMMENT = 2
        DATA = 3
        SEGEND = 4

    state: State
    first_seg: bool

    def __init__(self):
        self.z = z = ZPAQL()
        self.dec = Decoder(z)
        self.pp = PostProcessor()
        self.state = Decompressor.State.BLOCK
        self.first_seg = True

    def set_input(self, data) -> StructReader:
        self.dec.src = ip = StructReader(data)
        return ip

    def set_output(self, op: MemoryFile):
        self.pp.set_output(op)

    def set_hasher(self, sha1: _Hash):
        self.pp.set_hasher(sha1)

    def read_block(self) -> bool:
        if self.state is not Decompressor.State.BLOCK:
            raise RuntimeError('invalid state')
        h1 = 0x3D49B113
        h2 = 0x29EB7F93
        h3 = 0x2614BE13
        h4 = 0x3828EB13
        ip = self.dec.src
        while not ip.eof:
            c = ip.read_byte()
            h1 = h1 * 12 + c & 0xFFFFFFFF
            h2 = h2 * 20 + c & 0xFFFFFFFF
            h3 = h3 * 28 + c & 0xFFFFFFFF
            h4 = h4 * 44 + c & 0xFFFFFFFF
            if h1 == 0xB16B88F1 and h2 == 0xFF5376F1 and h3 == 0x72AC5BF1 and h4 == 0x2F909AF1:
                break
        if ip.eof:
            return False
        c = ip.read_byte()
        z = self.z
        if c not in (1, 2):
            raise RuntimeError('unsupported ZPAQ level')
        if ip.read_byte() != 1:
            raise RuntimeError('unsupported ZPAQ type')
        z.read(ip)
        if c == 1 and len(z.header) > 6 and z.header[6] == 0:
            raise RuntimeError('ZPAQ level 1 requires at least 1 component')
        self.state = Decompressor.State.FILENAME
        self.first_seg = True
        return True

    def read_filename(self) -> Optional[str]:
        if self.state is not Decompressor.State.FILENAME:
            raise RuntimeError('invalid state')
        ip = self.dec.src
        c = ip.read_byte()
        if c == 1:
            self.state = Decompressor.State.COMMENT
            return ip.read_c_string('utf8')
        elif c == 0xFF:
            self.state = Decompressor.State.BLOCK
            return None
        else:
            raise RuntimeError('missing segment or end of block')

    def read_comment(self, op: Optional[MemoryFile] = None) -> Optional[str]:
        if self.state is Decompressor.State.BLOCK:
            return None
        if self.state is not Decompressor.State.COMMENT:
            raise RuntimeError('invalid state')
        ip = self.dec.src
        comment = ip.read_c_string('utf8')
        if ip.read_byte() != 0:
            raise RuntimeError('missing reserved byte')
        self.state = Decompressor.State.DATA
        return comment

    def decompress_data(self):
        if self.state is not Decompressor.State.DATA:
            raise RuntimeError('invalid state')
        z = self.z
        dec = self.dec
        pp = self.pp
        if self.first_seg:
            dec.init()
            assert len(z.header) > 5
            pp.init(z.header[4], z.header[5])
            self.first_seg = False
        while pp.state & 3 != 1:
            pp.write(dec.decompress())
        while True:
            c = dec.decompress()
            pp.write(c)
            if c is None:
                self.state = Decompressor.State.SEGEND
                return

    def read_segment_end(self) -> Optional[bytes]:
        if self.state is not Decompressor.State.SEGEND:
            raise RuntimeError('invalid state')
        dec = self.dec
        src = dec.src
        c = src.read_byte()
        if c == 254:
            checksum = None
        elif c == 253:
            checksum = src.read(20)
        else:
            raise RuntimeError('missing end of segment marker')
        self.state = Decompressor.State.FILENAME
        return checksum


class xtzpaq(ArchiveUnit):
    """
    Extract files from a ZPAQ archive.
    """

    _MAGIC = B'\x37\x6B\x53\x74\xA0\x31\x83\xD3\x8C\xB2\x28\xB0\xD3\x7A\x50\x51'

    def __init__(
        self, *paths,
        index: Arg.Switch('-i', help='Archive is an index (no d-blocks).') = False,
        **more
    ):
        for _code, _size in {
            _TCU32: 4,
            _TCI32: 4,
            _TCU16: 2,
            _TCI16: 2,
        }.items():
            _item_size = array(_code).itemsize
            if _item_size == _size:
                continue
            raise RuntimeError(
                F'Expected array type "{_code}" to have entries of size {_size}, but the API '
                F'reports a size of {_item_size}.')

        super().__init__(*paths, index=index, **more)

    @classmethod
    def handles(cls, data: bytearray) -> Optional[bool]:
        return cls._MAGIC in data

    def unpack(self, archive: bytearray):
        def mkdate(date) -> datetime:
            date = int(date)
            year = date // 1000000 // 10000
            month = date // 100000000 % 100
            day = date // 1000000 % 100
            hour = date // 10000 % 100
            minute = date // 100 % 100
            second = date % 100
            return datetime(year, month, day, hour, minute, second, 0)

        @dataclass
        class DT:
            date: int = 0
            attr: int = 0
            name: str = ""
            frag: List[int] = field(default_factory=list)

            @property
            def dt(self) -> Optional[datetime]:
                if self.date > 0:
                    return mkdate(self.date)

        # TODO: implement password-protected archives
        # key = self.args.pwd
        index = self.args.index
        bsize: Dict[int, int] = {}  # frag ID -> d block compressed size
        dt: Dict[str, DT] = {}      # filename -> date, attr, frags
        frag: List[bytes] = []      # ID -> hash[20] size[4] data
        csize = 0                   # expected offset of next non d block
        streaming = False
        journaling = False

        done = False
        dc = Decompressor()
        src = dc.set_input(archive)

        while not done and dc.read_block():
            while not done:
                filename = dc.read_filename()
                if filename is None:
                    break
                self.log_info('reading file', filename)
                comment = dc.read_comment()
                jsize = 0
                if len(comment) >= 4 and comment[-4:] == "jDC\x01":
                    num = re.search('^\\d+', comment)
                    if not num:
                        raise RuntimeError('missing size in comment')
                    jsize = int(num[0])
                    if streaming:
                        raise RuntimeError('journaling block after streaming one')
                    journaling = True
                    self.log_info('archive type is journaling')
                else:
                    if journaling:
                        raise RuntimeError('streaming block after journaling one')
                    if index:
                        raise RuntimeError('streaming block in index')
                    streaming = True
                    self.log_info('archive type is streaming')

                # Test journaling filename. The format must be
                # jDC[YYYYMMDDHHMMSS][t][NNNNNNNNNN]
                # where YYYYMMDDHHMMSS is the date, t is the type {c,d,h,i}, and
                # NNNNNNNNNN is the 10 digit first fragment ID for types c,d,h.
                # They must be in ascending lexicographical order.

                frag_id = 0
                block_type = None

                if journaling:
                    if len(filename) != 28:
                        raise RuntimeError('filename size not 28')
                    if filename[:3] != 'jDC':
                        raise RuntimeError('filename not jDC')
                    block_type = filename[17]
                    if block_type not in 'cdhi':
                        raise RuntimeError('type not c,d,h,i')
                    try:
                        mkdate(filename[3:17])
                    except Exception as E:
                        raise RuntimeError('invalid date') from E
                    frag_id = int(filename[18:28])
                    if not 1 <= frag_id <= 4294967295:
                        raise RuntimeError('fragment ID out of range')

                seg = MemoryFile(size_limit=jsize)
                dc.set_output(seg)
                sha1 = hashlib.sha1()
                dc.set_hasher(sha1)
                dc.decompress_data()

                if journaling and len(seg) != jsize:
                    raise RuntimeError('incomplete output')

                checksum = dc.read_segment_end()
                if checksum is None:
                    self.log_debug('no checksum')
                elif checksum != sha1.digest():
                    raise RuntimeError('SHA1 mismatch')

                # check csize at first non-d block
                if csize and block_type in 'chi':
                    if csize != offset:
                        raise RuntimeError(F'csize={csize} does not point to offset={offset}')
                    csize = 0

                # get csize from c block
                seglen = len(seg)
                seg = StructReader(seg.getbuffer())
                if block_type == 'c':
                    if seglen < 8:
                        raise RuntimeError("c block too small")
                    csize = seg.u64()
                    offset = src.tell() + 1
                    self.log_debug(F'csize={csize} at offset={offset}')
                    if csize >> 63:
                        self.log_warn('incomplete transaction at end of archive')
                        done = True
                    elif index and csize != 0:
                        raise RuntimeError('nonzero csize in index')
                    # Set csize to expected offset of first non d block
                    # assuming 1 more byte for unread end of block marker.
                    csize += offset

                if block_type == 'd':
                    if index:
                        raise RuntimeError('d block in index')
                    bsize[frag_id] = src.tell() + 1 - offset  # compressed size
                    self.log_debug(F' {bsize[frag_id]} -> {len(seg)}')
                    # Test frag size list at end. The format is f[id..id+n-1] fid n
                    # where fid may be id or 0. sizes must sum to the rest of block.
                    if seglen < 8:
                        raise RuntimeError('d block too small')
                    seg.seekset(-8)
                    fid = seg.u32() or frag_id
                    n = seg.u32()
                    if fid != frag_id:
                        raise RuntimeError('missing ID')
                    if n > (seglen - 8) // 4:
                        raise RuntimeError('frag list too big')
                    fragsum = 0  # computed sum of frag sizes
                    seg.seekset(-4 * (n + 2))
                    for _ in range(n):
                        fragsum += seg.u32()
                    if fragsum + n * 4 + 8 != seglen:
                        raise RuntimeError('bad frag size list')
                    # Save frag hashes and sizes. For output, save data too.
                    seg.seekset(fragsum)
                    data = memoryview(seg.getbuffer())
                    assert seg.remaining_bytes == n * 4 + 8
                    for i in range(n):
                        while len(frag) <= frag_id + i:
                            frag.append(B'')
                        if frag[frag_id + i]:
                            raise RuntimeError('duplicate frag ID')
                        f = seg.u32()
                        h = hashlib.sha1(data[:f]).digest()
                        frag[frag_id + i] = h + f.to_bytes(4, 'little') + data[:f]
                        data = data[f:]

                    assert len(data) == n * 4 + 8
                    assert seg.remaining_bytes == 8

                # Test and save h block. Format is: bsize (sha1[20] size)...
                # where bsize is the compressed size of the d block with the same id,
                # and each size corresonds to a fragment in that block. The list
                # must match the list in the d block if present.

                if block_type == 'h':
                    if seglen % 24 != 4:
                        raise RuntimeError('bad h block size')
                    b = seg.u32()
                    self.log_debug(F'[{frag_id}..{frag_id + seglen // 24}[ {b}')
                    fragsum = 0 # uncompressed size of all frags
                    for i in range(seglen // 24):
                        fd = seg.read(24)
                        if index:
                            while len(frag) <= frag_id + i:
                                frag.append(B'')
                            if frag[frag_id + i]:
                                raise RuntimeError('data in index')
                            frag[frag_id + i] = fd
                        elif frag_id + i >= len(frag) or len(frag[frag_id + i]) < 24:
                            raise RuntimeError('no matching d block')
                        elif frag[frag_id + i][:24] != fd:
                            raise RuntimeError('frag size or hash mismatch')
                        fragsum += int.from_bytes(fd[20:24], 'little')

                # Test i blocks and save files to extract. Format is:
                #   date filename 0 na attr[0..na) ni ptr[0..ni)   (to update)
                #   0    filename                                  (to delete)
                # Date is 64 bits in YYYYMMDDHHMMSS format.

                if block_type == 'i':
                    while not seg.eof:
                        f = DT(seg.u64())
                        f.name = seg.read_c_string('utf8')
                        if f.date > 0:
                            na = seg.u32()
                            if na > 65535:
                                raise ValueError('attr size > 65535')
                            f.attr = seg.read_integer(na * 8)
                            ni = seg.u32()
                            for i in range(ni):
                                a = seg.u32()
                                f.frag.append(a)
                                if index:
                                    continue
                                elif not 1 <= a < len(frag):
                                    raise RuntimeError('frag ID out of range')
                                elif not frag[a]:
                                    raise LookupError('missing frag data')
                        dt[f.name] = f

                if streaming:
                    yield self._pack(filename, None, seg.getvalue())

            offset = src.tell()

        self.log_debug(F'{offset} bytes of archive tested')

        if not journaling:
            return

        for name, f in dt.items():
            if not f.date:
                continue
            size = sum(
                int.from_bytes(frag[fp][20:24], 'little')
                for fp in f.frag
                if 0 < fp < len(frag) and len(frag[fp]) >= 24
            )
            out = MemoryFile()
            for fp in f.frag:
                if fp < len(frag):
                    out.write(memoryview(frag[fp])[24:])
            if len(out) != size:
                self.log_warn('invalid size during unpacking')
            yield self._pack(name, f.dt, out.getvalue())
