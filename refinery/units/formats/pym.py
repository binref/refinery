#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import overload, get_origin, get_args, Type, TypeVar
from types import CodeType

from refinery.units import Unit
from refinery.lib.json import BytesAsStringEncoder
from refinery.lib.structures import StructReader

import importlib.util
import marshal
import enum
import sys
import inspect

_T = TypeVar('_T')
_MAX_MARSHAL_STACK_DEPTH = 2000


class _MC(enum.IntEnum):
    ASCII                = b'a'[0] # noqa
    ASCII_INTERNED       = b'A'[0] # noqa
    BINARY_COMPLEX       = b'y'[0] # noqa
    BINARY_FLOAT         = b'g'[0] # noqa
    CODE                 = b'c'[0] # noqa
    CODE_OLD             = b'C'[0] # noqa
    COMPLEX              = b'x'[0] # noqa
    DICT                 = b'{'[0] # noqa
    ELLIPSIS             = b'.'[0] # noqa
    FALSE                = b'F'[0] # noqa
    FLOAT                = b'f'[0] # noqa
    FROZENSET            = b'>'[0] # noqa
    INT                  = b'i'[0] # noqa
    INT64                = b'I'[0] # noqa
    INTERNED             = b't'[0] # noqa
    LIST                 = b'['[0] # noqa
    LONG                 = b'l'[0] # noqa
    NONE                 = b'N'[0] # noqa
    NULL                 = b'0'[0] # noqa
    REF                  = b'r'[0] # noqa
    SET                  = b'<'[0] # noqa
    SHORT_ASCII          = b'z'[0] # noqa
    SHORT_ASCII_INTERNED = b'Z'[0] # noqa
    SLICE                = b':'[0] # noqa
    SMALL_TUPLE          = b')'[0] # noqa
    STOPITER             = b'S'[0] # noqa
    STRING               = b's'[0] # noqa
    STRINGREF            = b'R'[0] # noqa
    TRUE                 = b'T'[0] # noqa
    TUPLE                = b'('[0] # noqa
    UNICODE              = b'u'[0] # noqa
    UNKNOWN              = b'?'[0] # noqa


class _CK(enum.IntFlag):
    """
    Python variable kind flags.
    """
    ArgPos = 0b0000_0010 # noqa 
    ArgKw  = 0b0000_0100 # noqa 
    ArgVar = 0b0000_1000 # noqa 
    Arg    = 0b0000_1110 # noqa
    Hidden = 0b0001_0000 # noqa
    Local  = 0b0010_0000 # noqa
    Cell   = 0b0100_0000 # noqa
    Free   = 0b1000_0000 # noqa


class _PY(tuple, enum.Enum):
    V_1_00 = (1,  0) # noqa
    V_1_03 = (1,  3) # noqa
    V_1_05 = (1,  5) # noqa
    V_2_01 = (2,  1) # noqa
    V_2_03 = (2,  3) # noqa switch to 32bit
    V_3_00 = (3,  0) # noqa
    V_3_08 = (3,  8) # noqa
    V_3_10 = (3, 10) # noqa
    V_3_11 = (3, 11) # noqa

    def header(self):
        def tobytes(m: int):
            return m.to_bytes(2, 'little') + B'\r\n'
        nulls = b'\0\0\0\0'
        magic = {
            _PY.V_1_00: tobytes(39170),
            _PY.V_1_03: tobytes(11913),
            _PY.V_1_05: tobytes(20121),
            _PY.V_2_01: tobytes(60202),
            _PY.V_2_03: tobytes(62211), # 2.7
            _PY.V_3_00: tobytes(3000),  # 3.0
            _PY.V_3_08: tobytes(3413),  # 3.8
            _PY.V_3_10: tobytes(3438),  # 3.10
            _PY.V_3_11: importlib.util.MAGIC_NUMBER,
        }[self] + nulls
        # Sadly, we cannot determine this exactly:
        # 1.0 - 3.2 [magic][timestamp]        4 bytes
        # 3.3 - 3.6 [magic][timestamp][size]  8 bytes
        # 3.7 - now [magic][flags][misc]     12 bytes
        # All changes happen between 3.0 and 3.8, which we cannot distinguish based on the
        # layout of marshaled code objects. We will have to guess to minimize the damage:
        if self >= _PY.V_3_00:
            magic += nulls
        if self >= _PY.V_3_08:
            magic += nulls
        c = B'C' if self == _PY.V_1_00 else B'c'
        return magic + c


class Null(Exception):
    """
    Raised when the unmarshal C implementation would return a null pointer.
    """
    pass


class UnknownTypeCode(ValueError):
    """
    Raised when an unknown type code is encountered during unmarshal.
    """
    def __init__(self, code):
        self.code = code
        super().__init__(F'Unknown marshal type code 0x{code:02X}.')


class Marshal(StructReader[memoryview]):
    """
    A specialization of the `refinery.lib.structures.StructReader` to read marshaled objects.
    """

    def __init__(self, data, load_code=False):
        super().__init__(memoryview(data))
        self.refs = []
        self.version = (1, 0)
        self._depth = 0
        self._load_code = load_code

    @overload
    def object(self, typecheck: Type[_T]) -> _T:
        ...

    @overload
    def object(self) -> object:
        ...

    def object(self, typecheck=None):
        """
        Read a marshaled object from the stream. The implementation attempts to be cross-version
        compatible.
        """
        depth = self._depth
        if depth > _MAX_MARSHAL_STACK_DEPTH:
            raise RuntimeError(
                F'The marshal stack depth limit of {_MAX_MARSHAL_STACK_DEPTH} was exceeded.')
        self._depth = depth + 1
        try:
            o: object = self._load_object()
        except Null:
            raise
        else:
            if args := get_args(typecheck):
                typecheck = tuple(get_origin(t) or t for t in args)
            if typecheck and not isinstance(o, typecheck):
                if isinstance(typecheck, tuple):
                    expected = F'one of {", ".join(t.__name__ for t in typecheck)}'
                else:
                    expected = typecheck.__name__
                raise TypeError(
                    F'Unmarshelled object of type {o.__class__.__name__}, '
                    F'expected {expected}.')
            else:
                return o
        finally:
            self._depth = depth

    def _load_object(self):
        code = self.read_integer(7)
        flag = self.read_integer(1)
        store_reference = bool(flag)

        try:
            code = _MC(code)
        except Exception:
            raise UnknownTypeCode(code)

        def read_sequence(sequence_type):
            def _sequence():
                for _ in range(self.read_integer(prefix_size)):
                    yield self.object()
            nonlocal store_reference
            if store_reference:
                index = len(self.refs)
                self.refs.append(None)
            rv = sequence_type(_sequence())
            if store_reference:
                self.refs[index] = rv
                store_reference = False
            return rv

        prefix_size = 32
        string_interned = False
        string_codec = 'utf8'

        if code == _MC.CODE_OLD:
            code = _MC.CODE

        if code == _MC.SMALL_TUPLE:
            code = _MC.TUPLE
            prefix_size = 8

        if code == _MC.ASCII_INTERNED:
            code = _MC.ASCII
            string_interned = True
        if code == _MC.SHORT_ASCII_INTERNED:
            code = _MC.SHORT_ASCII
            string_interned = True
        if code == _MC.SHORT_ASCII:
            code = _MC.ASCII
            prefix_size = 8
        if code == _MC.INTERNED:
            code = _MC.UNICODE
            string_interned = True
        if code == _MC.ASCII:
            code = _MC.UNICODE
            string_codec = 'latin1'

        if code == _MC.NULL:
            raise Null
        elif code == _MC.NONE:
            return None
        elif code == _MC.STOPITER:
            return StopIteration
        elif code == _MC.ELLIPSIS:
            return (...)
        elif code == _MC.FALSE:
            return False
        elif code == _MC.TRUE:
            return True
        elif code == _MC.INT:
            rv = self.i32()
        elif code == _MC.INT64:
            rv = self.i64()
        elif code == _MC.LONG:
            rv = self.i32()
        elif code == _MC.FLOAT:
            rv = float(self.read_length_prefixed_ascii(8))
        elif code == _MC.BINARY_FLOAT:
            rv = self.f64()
        elif code == _MC.COMPLEX:
            im = float(self.read_length_prefixed_ascii(8))
            re = float(self.read_length_prefixed_ascii(8))
            rv = complex(re, im)
        elif code == _MC.BINARY_COMPLEX:
            im = self.f64()
            re = self.f64()
            rv = complex(re, im)
        elif code == _MC.STRING:
            rv = bytes(self.read_length_prefixed(32))
        elif code == _MC.UNICODE:
            rv = self.read_length_prefixed(prefix_size, string_codec)
            if string_interned:
                rv = sys.intern(rv)
        elif code == _MC.TUPLE:
            return read_sequence(tuple)
        elif code == _MC.LIST:
            return read_sequence(list)
        elif code == _MC.DICT:
            rv = {}
            if store_reference:
                self.refs.append(rv)
            while True:
                try:
                    key = self.object()
                    val = self.object()
                except Null:
                    break
                else:
                    rv[key] = val
            return rv
        elif code == _MC.SET:
            return read_sequence(set)
        elif code == _MC.FROZENSET:
            return read_sequence(frozenset)
        elif code == _MC.REF:
            try:
                index = self.u32()
                return self.refs[index]
            except IndexError as IE:
                raise ValueError('Invalid reference during unmarshal.') from IE
        elif code == _MC.SLICE:
            if store_reference:
                index = len(self.refs)
                self.refs.append(None)
            rv = slice(self.object(), self.object(), self.object())
            if store_reference:
                self.refs[index] = rv
            return rv
        elif code == _MC.CODE:
            if store_reference:
                index = len(self.refs)
                self.refs.append(None)
            try:
                signature = inspect.signature(CodeType)
            except ValueError:
                import re
                docs = re.sub(r'[\s\[\]]', '', CodeType.__doc__)
                spec = re.search(r'(?i)code\w*\((\w+(?:,\w+)*)\)', docs)
                params = spec.group(1).split(',') if spec else []
            else:
                params = list(signature.parameters)

            arguments = {}
            start = self.tell()

            for version in _PY:
                if version < self.version:
                    continue
                self.seekset(start)
                intval = self.u32 if version >= _PY.V_2_03 else self.u16
                arguments.clear()
                arguments.update(
                    name='',
                    qualname='',
                    filename='',
                    argcount=0,
                    posonlyargcount=0,
                    kwonlyargcount=0,
                    nlocals=0,
                    flags=0,
                    stacksize=1000,
                    firstlineno=1,
                    linetable=B'',
                    exceptiontable=B'',
                    constants=(),
                    names=(),
                    varnames=(),
                    freevars=(),
                    cellvars=(),
                )
                MAX_ARGS = 0x100
                MAX_VARS = 0x10000
                try:
                    if _PY.V_1_03 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(argcount=n)
                    if _PY.V_3_08 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(posonlyargcount=n)
                    if _PY.V_3_00 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(kwonlyargcount=n)
                    if _PY.V_1_03 <= version < _PY.V_3_11:
                        if (n := intval()) > MAX_VARS:
                            raise ValueError
                        arguments.update(nlocals=n)
                    if _PY.V_1_05 <= version:
                        arguments.update(stacksize=intval())
                    if _PY.V_1_03 <= version:
                        arguments.update(flags=intval())
                    if _PY.V_1_00 <= version:
                        codestring = self.object(bytes)
                        arguments.update(codestring=codestring)
                        arguments.update(constants=self.object(tuple))
                        arguments.update(names=self.object(tuple))
                    if _PY.V_1_03 <= version < _PY.V_3_11:
                        arguments.update(varnames=self.object(tuple))
                    if _PY.V_2_01 <= version < _PY.V_3_11:
                        arguments.update(freevars=self.object(tuple))
                        arguments.update(cellvars=self.object(tuple))
                    if _PY.V_3_11 <= version:
                        co_localsplusnames = self.object(tuple)
                        co_localspluskinds = self.object(bytes)
                        co_freevars = []
                        co_cellvars = []
                        co_varnames = []
                        co_nlocals = 0
                        for name, k in zip(co_localsplusnames, co_localspluskinds):
                            kind = _CK(k)
                            if kind & _CK.Free:
                                co_freevars.append(name)
                                continue
                            if kind & _CK.Cell:
                                co_cellvars.append(name)
                                continue
                            if kind & _CK.Local:
                                co_varnames.append(name)
                                co_nlocals += 1
                                continue
                            raise TypeError(
                                F'Read unexpected unexpected variable kind {kind!r} while unmarshaling code.')
                        arguments.update(freevars=tuple(co_freevars))
                        arguments.update(cellvars=tuple(co_cellvars))
                        arguments.update(varnames=tuple(co_varnames))
                        arguments.update(nlocals=co_nlocals)
                    if _PY.V_1_00 <= version:
                        arguments.update(filename=self.object(str))
                        arguments.update(name=self.object(str))
                    if _PY.V_3_11 <= version:
                        arguments.update(qualname=self.object(str))
                    if _PY.V_1_05 <= version:
                        arguments.update(firstlineno=intval())
                    if _PY.V_1_05 <= version < _PY.V_3_10:
                        lnotab = self.object(bytes)
                        if len(lnotab) % 2 != 0:
                            raise ValueError
                        arguments.update(linetable=lnotab)
                    if _PY.V_3_10 <= version:
                        arguments.update(linetable=self.object(bytes))
                    if _PY.V_3_11 <= version:
                        arguments.update(exceptiontable=self.object(bytes))
                    if start == 1 and not self.eof:
                        raise ValueError
                except Exception:
                    continue
                else:
                    if version < self.version:
                        continue
                    self.version = version
                    break
            else:
                raise RuntimeError('Failed to parse code object.')
            if not self._load_code:
                rv = None
            else:
                try:
                    rv = CodeType(*[arguments[p] for p in params])
                except Exception:
                    rv = None
            if rv is None:
                size = self.tell() - start
                self.seekset(start)
                rv = B'%s%s' % (self.version.header(), self.read(size))
            if store_reference:
                self.refs[index] = rv
            return rv
        else:
            raise UnknownTypeCode(code.value)

        if store_reference:
            self.refs.append(rv)

        return rv


class pym(Unit):
    """
    Converts Python-Marshaled code objects to the PYC (Python Bytecode) format. If it is an
    older Python version, you can use the `refinery.pyc` unit to then decompile the code, but
    for more recent versions a separate Python decompiler will be required.
    """
    def reverse(self, data):
        return marshal.dumps(data)

    def process(self, data):
        def toblob(data):
            if isinstance(data, (bytes, bytearray)):
                self.log_info(U'unmarshalled a byte string, returning as is')
                return data
            if isinstance(data, str):
                self.log_info(F'unmarshalled a string object, encoding as {self.codec}')
                return data.encode(self.codec)
            if isinstance(data, CodeType):
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

        try:
            out = marshal.loads(data)
        except Exception:
            out = Marshal(memoryview(data)).object()

        if isinstance(out, (list, tuple, set, frozenset)):
            self.log_info('object is a collection, converting each item individually')
            for item in out:
                yield toblob(item)
        else:
            yield toblob(out)
