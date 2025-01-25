#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java disassembler. The main logic is implemented int `refinery.lib.java.JvOpCode`.
"""
import re
import io
import collections

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.java import JvClassFile, JvClassMember, JvCode, opc


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
        def _name(method: JvClassMember):
            name = method.name
            if name == '<init>':
                _, _, name = str(jc.this).rpartition('/')
            elif m := re.fullmatch('<(.*?)>', name):
                name = F'.{m[0]}'
            return name

        def _path(method: JvClassMember):
            return F'{jc.this!s}/{_name(method)}'

        jc = JvClassFile(data)
        tab = '  '
        namespace = '.'.join(str(jc.this).split('/'))
        opcw = self._OPC_STRLEN
        path_counter = collections.defaultdict(int)
        path_index = collections.defaultdict(int)

        for method in jc.methods:
            path_counter[_path(method)] += 1
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
                print(F'{rv} {namespace}::{_name(method)}({args})', file=display)
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
                            jmps.append(F'{tab}{raw!s:<{opcw + 15}} {key:#010x} => {jmp:#010x}')
                        args = '\n'.join((args, *jmps))
                    opch = self._hex(op.raw[:olen], ' ')
                    if len(opch) > 14:
                        opch += F'\n{tab}{tab:<15}'
                    print(F'{tab}{opch:<15}{op.code!r:<{opcw}} {args}', file=display)
                path = _path(method)
                if path_counter[path] > 1:
                    k = path_index[path]
                    path_index[path] = k + 1
                    path = F'{path}[{k}]'
                yield UnpackResult(path, display.getvalue().encode(self.codec))

    @classmethod
    def handles(self, data):
        return data[:4] == B'\xCA\xFE\xBA\xBE'
