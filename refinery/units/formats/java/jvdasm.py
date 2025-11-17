"""
Java disassembler. The main logic is implemented int `refinery.lib.java.JvOpCode`.
"""
from __future__ import annotations

import collections
import io
import re

from refinery.lib.java import (
    JvBaseType,
    JvClassFile,
    JvClassMember,
    JvClassProperty,
    JvCode,
    JvString,
    JvTypePath,
    opc,
)
from refinery.lib.types import Param
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult


def _parse_descriptor(
    descriptor: str,
    color_reset: str,
    color_space: str,
    color_types: str,
    color_array: str,
):
    def parse_type_list(args: str):
        while args:
            suffix = ''
            while args.startswith('['):
                args = args[1:]
                suffix += '[]'
            code, args = args[0], args[1:]
            if code == 'L':
                spec, _, args = args.partition(';')
                *ns, t = spec.split('/')
                ns = '.'.join([F'{color_space}{part}{color_reset}' for part in ns])
                spec = F'{ns}.{color_types}{t}{color_reset}'
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
                spec = F'{color_types}{spec}{color_reset}'
            yield F'{spec}{color_array}{suffix}{color_reset}'

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

    def __init__(
        self, *paths,
        gray: Param[bool, Arg.Switch('-g', help='Disable colored output.')] = False,
        **keywords
    ):
        super().__init__(*paths, gray=gray, **keywords)

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
        try:
            if self.args.gray or not self.isatty():
                raise ImportError
            import colorama
        except ImportError:
            class _FG():
                def __getattr__(self, _):
                    return ''
            FG = _FG()
            RS = ''
        else:
            FG = colorama.Fore
            RS = colorama.Style.RESET_ALL
        finally:
            c_none = RS
            c_space = FG.LIGHTCYAN_EX
            c_types = FG.LIGHTCYAN_EX
            c_member = FG.LIGHTYELLOW_EX
            c_kwd = FG.LIGHTYELLOW_EX
            c_const = FG.LIGHTRED_EX
            c_string = FG.LIGHTRED_EX
            c_address = FG.LIGHTBLACK_EX
            c_label = RS

        def _color(arg, offset):
            if isinstance(arg, (str, JvString)):
                color = c_string
            elif isinstance(arg, (JvClassProperty, JvTypePath)):
                ns, dd, prop = str(arg).partition('::')
                if not dd:
                    return repr(arg)
                ns = ns.split('.')
                ns = '.'.join(F'{c_space}{p}{c_none}' for p in ns)
                return F'{ns}{dd}{c_member}{prop}{c_none}'
            elif isinstance(arg, int) and arg + offset in labels:
                return F'{c_label}0x{arg + offset:08X}{c_none}'
            elif isinstance(arg, (bool, int, float)):
                color = c_const
            elif isinstance(arg, JvBaseType):
                color = c_kwd
            else:
                return repr(arg)
            return F'{color}{arg!r}{c_none}'

        jc = JvClassFile.Parse(data)
        tab = ' '
        namespace = '.'.join(str(jc.this).split('/'))
        opcw = self._OPC_STRLEN
        path_counter = collections.defaultdict(int)
        path_index = collections.defaultdict(int)

        for method in jc.methods:
            path_counter[_path(method)] += 1
        for method in jc.methods:
            for attribute in method.attributes:
                if attribute.name == 'Code':
                    break
            else:
                self.log_warn(F'no code found for method: {method.name}')
                continue
            code: JvCode = attribute.parse(JvCode)
            with io.StringIO() as display:
                rv, args = _parse_descriptor(method.descriptor, c_none, c_space, c_types, c_kwd)
                args = ', '.join(args)
                print(
                    F'{c_types}{rv}{c_none} {c_space}{namespace}{c_none}'
                    F'::{c_member}{_name(method)}{c_none}({args})', file=display)
                offset = 0
                labels = set()
                addresses = set()

                for op in code.disassembly:
                    addresses.add(offset)
                    if op.table:
                        labels.update(offset + jmp for jmp in op.table.values())
                    elif op.code in (opc.goto, opc.goto_w):
                        labels.update(offset + arg for arg in op.arguments if isinstance(arg, int))
                    offset += len(op.raw)

                offset = 0
                labels = labels & addresses

                for op in code.disassembly:
                    if offset in labels:
                        label = F'{c_label}{offset:08X}{c_none}:'
                    else:
                        label = F'{c_address}{offset:08X}{c_none}:'
                    addr = offset
                    olen = len(op.raw)
                    offset += olen
                    if op.table is None:
                        args = ', '.join(_color(a, addr) for a in op.arguments)
                    else:
                        ow = 4 if op.code is opc.tableswitch else 8
                        olen = olen - (len(op.table) - 1) * ow
                        args = F'___default => {c_label}{op.table[None] + addr:#010x}{c_none}'
                        jmps = []
                        for k, (key, jmp) in enumerate(op.table.items()):
                            if key is None:
                                continue
                            raw = self._hex(op.raw[olen + k * ow: olen + k * ow + ow], ' ')
                            jmps.append(
                                F'{label}{tab}'
                                F'{raw!s:<{opcw + 15}} '
                                F'{c_const}{key:#010x}{c_none} => '
                                F'{c_label}{jmp + addr:#010x}{c_none}')
                        args = '\n'.join((args, *jmps))
                    opch = self._hex(op.raw[:olen], ' ')
                    if len(opch) > 14:
                        opch += F'\n{label}{tab}{tab:<15}'
                    print(
                        F'{label}{tab}'
                        F'{opch:<15}'
                        F'{c_kwd}{op.code!r:<{opcw}}{c_none} {args}', file=display)
                path = _path(method)
                if path_counter[path] > 1:
                    k = path_index[path]
                    path_index[path] = k + 1
                    path = F'{path}[{k}]'
                yield UnpackResult(path, display.getvalue().encode(self.codec))

    @classmethod
    def handles(cls, data):
        return data.startswith(B'\xCA\xFE\xBA\xBE')
