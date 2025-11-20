from __future__ import annotations

import marshal
import sys

from types import CodeType

from refinery.lib import json
from refinery.lib.py import SYS_PYTHON, Marshal, code_header, version2tuple
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class pym(Unit):
    """
    Converts Python-Marshaled code objects to the PYC (Python Bytecode) format. If it is an
    older Python version, you can use the `refinery.pyc` unit to then decompile the code, but
    for more recent versions a separate Python decompiler will be required.
    """
    def __init__(
        self,
        version: Param[str | None, Arg.String('-V', metavar='V',
            help='Optionally select the (known) Python version.')] = None,
        system: Param[bool, Arg.Switch('-s',
            help='Try to use the built-in marshal.loads before using the parser.')] = False,
        redump: Param[bool, Arg.Switch('-r',
            help='Load marshaled code objects before re-dumping them.')] = False,
    ):
        super().__init__(
            version=version,
            system=system,
            redump=redump,
        )

    def reverse(self, data):
        return marshal.dumps(data)

    def process(self, data):
        def toblob(data):
            if isinstance(data, (bytes, bytearray)):
                self.log_info('unmarshalled a byte string, returning as is')
                return data
            if isinstance(data, str):
                self.log_info(F'unmarshalled a string object, encoding as {self.codec}')
                return data.encode(self.codec)
            if isinstance(data, CodeType):
                self.log_info('unmarshalled a code object, converting to pyc')
                pyc = code_header()
                pyc.extend(marshal.dumps(data))
                return pyc
            if isinstance(data, int):
                self.log_info('unmarshalled an integer, returning big endian encoding')
                q, r = divmod(data.bit_length(), 8)
                q += int(bool(r))
                return data.to_bytes(q, 'big')
            if isinstance(data, dict):
                return json.dumps(data, pretty=False, tojson=json.bytes_as_string)
            raise NotImplementedError(
                F'No serialization implemented for object of type {data.__class__.__name__}')

        if version := self.args.version:
            version = version2tuple(version)

        if version and version != SYS_PYTHON or not self.args.system:
            out = None
        else:
            try:
                out = marshal.loads(data)
            except Exception as error:
                self.log_info(F'the marshal.loads method failed: {error!s}')
                out = None
            else:
                v = sys.version_info
                self.log_info(F'unmarshaled using the {v.major}.{v.minor}.{v.micro} built-in marshal.loads')

        if out is None:
            dumpcode = not self.args.redump
            memory = memoryview(data)
            unpacker = Marshal(memory, version=version, dumpcode=dumpcode)
            out = unpacker.object()

        if isinstance(out, (list, tuple, set, frozenset)):
            self.log_info('object is a collection, converting each item individually')
            for item in out:
                yield toblob(item)
        else:
            yield toblob(out)
