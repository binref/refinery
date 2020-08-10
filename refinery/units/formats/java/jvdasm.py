#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java disassembler. The main logic is implemented int `refinery.lib.java.JvOpCode`.
"""
import re
import io

from .. import PathExtractorUnit, UnpackResult
from ....lib.java import JvClassFile, JvCode, opc


class jvdasm(PathExtractorUnit):
    """
    Disassembles the JVM bytecode instructions of methods of classes defined in Java class
    files. The unit is implemented as a `refinery.units.formats.PathExtractorUnit` and each
    path name corresponds to the name of one method defined in the class file.
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
                args, retval = re.match(R'^\((.*?)\)(.*?)$', method.descriptor).groups()
                print(F'{jc.this!s}::{method!s}{method.descriptor}', file=display)
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
                            jmps.append(F'{tt}{raw!s:<{opcw+15}} {key:#010x} => {jmp:#010x}')
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
