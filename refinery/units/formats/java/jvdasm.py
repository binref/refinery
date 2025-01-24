#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java disassembler. The main logic is implemented int `refinery.lib.java.JvOpCode`.
"""
import re
import io

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.java import JvClassFile, JvCode, opc


def _parse_descriptor(descriptor: str):
    def parse_type_list(args: str):
        while args:
            suffix = ''
            while args.startswith('['):
                args = args[1:]
                suffix += '[]'
            code, args = args[0], args[1:]
            if code == 'L':
                spec, _, args = args.partition(';')
                spec = spec.replace('/', '.')
            else:
                spec = {
                    'Z': 'boolean',
                    'B': 'byte',
                    'S': 'short',
                    'I': 'int',
                    'J': 'long',
                    'F': 'float',
                    'D': 'double',
                    'C': 'char',
                    'V': 'void',
                }[code]
            yield spec + suffix

    args, retval = re.match(R'^\((.*?)\)(.*?)$', descriptor).groups()
    retval, = parse_type_list(retval)
    return retval, tuple(parse_type_list(args))


class jvdasm(PathExtractorUnit):
    """
    Disassembles the JVM bytecode instructions of methods of classes defined in Java class
    files. The unit is implemented as a path extractor and each path name corresponds to the
    name of one method defined in the class file.
    """
    _OPC_STRLEN = max(len(op.name) for op in opc)

    def _hex(self, bytestring, sep=''):
        return sep.join(F'{x:02x}' for x in bytestring)

    def unpack(self, data):
        jc = JvClassFile(data)
        tt = '  '
        opcw = self._OPC_STRLEN
        for method in jc.methods:
            for attribute in method.attributes:
                if attribute.name == 'Code': break
            else:
                self.log_warn(F'no code found for method: {method.name}')
                continue
            code: JvCode = attribute.parse(JvCode)
            with io.StringIO() as display:
                rv, args = _parse_descriptor(method.descriptor)
                args = ', '.join(args)
                print(F'{rv} {jc.this!s}::{method!s}({args})', file=display)
                for op in code.disassembly:
                    olen = len(op.raw)
                    if op.table is None:
                        args = ', '.join(repr(a) for a in op.arguments)
                    else:
                        ow = 4 if op.code is opc.tableswitch else 8
                        olen = olen - (len(op.table) - 1) * ow
                        args = F'defaultjmp => {op.table[None]:#010x}'
                        jmps = []
                        for k, (key, jmp) in enumerate(op.table.items()):
                            if key is None:
                                continue
                            raw = self._hex(op.raw[olen + k * ow: olen + k * ow + ow], ' ')
                            jmps.append(F'{tt}{raw!s:<{opcw + 15}} {key:#010x} => {jmp:#010x}')
                        args = '\n'.join((args, *jmps))
                    opch = self._hex(op.raw[:olen], ' ')
                    if len(opch) > 14:
                        opch += F'\n{tt}{tt:<15}'
                    print(F'{tt}{opch:<15}{op.code!r:<{opcw}} {args}', file=display)
                name = method.name
                if name.startswith('<'):
                    this = jc.this.value.split('/')
                    this = this[-1]
                    name = F'{this}${name[1:-1]}'
                yield UnpackResult(F'{name}.jd', display.getvalue().encode(self.codec))
