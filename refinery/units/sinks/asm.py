#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
from string import ascii_letters, digits
from enum import Enum

from .. import arg, Unit

__all__ = ['asm']


class box:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class ARCH(Enum):
    x16 = CS_ARCH_X86, CS_MODE_16
    x32 = CS_ARCH_X86, CS_MODE_32
    x64 = CS_ARCH_X86, CS_MODE_64
    arm = CS_ARCH_ARM, CS_MODE_ARM

    def __str__(self):
        return self.name


class asm(Unit):
    """
    Disassembles the input data using the capstone disassembly library.
    """

    def __init__(
        self,
        mode  : arg.option(choices=ARCH, help='select one of the following architectures: {choices}; the default is {default}.') = ARCH.x32,
        addr  : arg.switch('-a', help='hide addresses of instruction') = True,
        bytes : arg.switch('-b', help='hide instruction bytes next to disassembly') = True,
        str   : arg.switch('-s', help='disassemble over detected strings') = True,
        zeros : arg.switch('-z', help='disassemble zero byte patches') = True,
        width : arg.number('-w', bound=(3, None), help='number of data bytes to put in one row, {default} by default') = 15
    ):
        mode = arg.as_option(mode, ARCH)
        self.superinit(super(), **vars())

    def _printable(self, b):
        return 0x20 <= b <= 0x7E and b not in B' \t\v\r\n'

    def _strings(self, data):
        if not self.args.str:
            return
        for match in re.finditer(BR'([ -~]{5,})\x00?|((?:[ -~]\x00){5,})(?:\x00\x00)?', data):
            string = match[0]
            try:
                string = string.decode('UTF16-LE') if not string.end \
                    else string.decode('UTF8')
            except Exception:
                continue
            alpha = len([x for x in string if x in digits or x in ascii_letters])
            if 2 * alpha > len(string):
                yield box(start=match.start(), end=match.end(), data=string)
                self.log_info(F'detected string at {match.start():08X}:', string)

    def _format(self, addr=0, data=B'', code='', arg='', comment=''):
        data_str = ''.join('%c' % X if self._printable(X) else '.' for X in data)
        data_hex = ' '.join('%02X' % X for X in data)
        if comment: comment = '    ; ' + comment
        return {
            'addr': addr,
            'str': data_str,
            'hex': data_hex,
            'code': code,
            'arg': arg,
            'comment': comment
        }

    def _bytepatch(self, data, addr, end):
        return self._format(addr, data[addr:end], 'db', ','.join('%02X' % b for b in data[addr:end]))

    def _nullsize(self, data, offset, max):
        length = 0
        try:
            while not data[offset + length] and length < max:
                length += 1
        except IndexError:
            pass
        return length

    def _disassemble(self, data):
        capstone = Cs(*self.args.mode.value)
        strz = self._strings(data)
        string = next(strz, None)
        cursor, done = 0, 0
        while done < len(data):
            cursor = max(cursor, done)
            patchsize = self._nullsize(data, cursor, self.args.width)
            if patchsize > 2:
                yield self._format(done, data[done:done + patchsize], 'db', ','.join('0' * patchsize))
                done += patchsize
                continue
            if cursor >= len(data):
                yield self._bytepatch(data, done, len(data))
                done = cursor
            if string and cursor >= string.end:
                yield self._bytepatch(data, done, string.start)
                yield self._format(string.start, data[string.start:string.end], 'db', string.data)
                done = string.end
                continue
            try:
                ins = next(capstone.disasm(
                    data[cursor:cursor + 15], cursor, count=1))
                end = ins.address + ins.size
                if self.args.str and string:
                    if end > string.start and string.end > cursor:
                        cursor = string.end
                        continue
            except StopIteration:
                cursor += 1
                continue
            else:
                yield self._format(ins.address, ins.bytes, ins.mnemonic, ins.op_str)
                done = end

    def process(self, data):
        disassembly = list(self._disassemble(data))
        for key in ['hex', 'str', 'code', 'arg']:
            m = max(len(r[key]) for r in disassembly)
            for r in disassembly:
                r[key] = r[key].ljust(m)
        line_format = '{code} {arg}{comment}'
        if self.args.bytes:
            line_format = '{hex}  {str}  ' + line_format
        if self.args.addr:
            line_format = '0x{addr:08X}:  ' + line_format
        return '\n'.join(line_format.format(**r) for r in disassembly).encode(self.codec)
