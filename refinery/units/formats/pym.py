#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.json import BytesAsStringEncoder

import marshal


class pym(Unit):
    """
    Converts Python-Marshaled code objects to the PYC (Python Bytecode) format. If it is an
    older Python version, you can use the `refinery.pyc` unit to then decompile the code, but
    for more recent versions a separate Python decompiler will be required.

    WARNING: This unit will invoke the `marshal.loads` function, which may be unsafe. Please
    refer to the official Python documentation for more details.
    """

    def reverse(self, data):
        return marshal.dumps(data)

    def process(self, data):
        data = marshal.loads(data)
        code = (lambda: 0).__code__.__class__

        def toblob(data):
            if isinstance(data, (bytes, bytearray)):
                self.log_info(U'unmarshalled a byte string, returning as is')
                return data
            if isinstance(data, str):
                self.log_info(F'unmarshalled a string object, encoding as {self.codec}')
                return data.encode(self.codec)
            if isinstance(data, code):
                self.log_info(U'unmarshalled a code object, converting to pyc')
                import importlib
                return importlib._bootstrap_external._code_to_timestamp_pyc(data)
            if isinstance(data, int):
                self.log_info(U'unmarshalled an integer, returning big endian encoding')
                q, r = divmod(data.bit_length(), 8)
                q += int(bool(r))
                return data.to_bytes(q, 'big')
            if isinstance(data, dict):
                with BytesAsStringEncoder as encoder:
                    return encoder.dumps(data).encode(self.codec)
            raise NotImplementedError(
                F'No serialization implemented for object of type {data.__class__.__name__}')

        if isinstance(data, list):
            self.log_info('object is a list, converting each item individually')
            for item in data:
                yield toblob(item)
        else:
            yield toblob(data)
