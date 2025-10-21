from __future__ import annotations

import enum
import importlib.util
import inspect
import io
import re
import sys

from types import CodeType
from typing import Generator, NamedTuple, TypeVar, get_args, get_origin, overload

from refinery.lib.shared import decompyle3, uncompyle6, xdis
from refinery.lib.structures import MemoryFile, StructReader
from refinery.lib.tools import NoLogging, normalize_word_separators
from refinery.lib.types import buf

_T = TypeVar('_T')

_MAX_MARSHAL_STACK_DEPTH = 2000

SYS_PYTHON = (
    sys.version_info.major,
    sys.version_info.minor,
    sys.version_info.micro,
)


class PyVer(NamedTuple):
    major: int
    minor: int
    micro: int

    def __str__(self):
        return F'{self.major}.{self.minor}.{self.micro}'


def version2tuple(v: str) -> PyVer:
    """
    Convert a version string of the form `3.12` or `3.12.0-final` to the tuple `(3,12,0)`.
    """
    if m := re.match(r'^(\d)\.(\d+)(?:\.(\d+))?', v):
        major = int(m[1])
        minor = int(m[2])
        micro = m[3] and int(m[3]) or 0
        return PyVer(major, minor, micro)
    else:
        raise ValueError(v)


class Code(NamedTuple):
    version: tuple[int]
    timestamp: int
    magic: int
    container: CodeType
    is_pypi: bool
    code_objects: dict


def extract_code_from_buffer(buffer: buf, file_name: str | None = None) -> Generator[Code]:
    code_objects = {}
    file_name = file_name or '<unknown>'
    load = xdis.load.load_module_from_file_object
    with NoLogging(NoLogging.Mode.STD_ERR):
        version, timestamp, magic_int, codes, is_pypy, _, _ = load(MemoryFile(buffer), file_name, code_objects)
    if not isinstance(codes, list):
        codes = [codes]
    for code in codes:
        yield Code(version, timestamp, magic_int, code, is_pypy, code_objects)


def disassemble_code(code: CodeType, version: str | float | tuple[int, ...] | None = None):
    if version is None:
        opc = None
    else:
        if isinstance(version, float):
            version = str(version)
        if isinstance(version, tuple):
            version = xdis.version_info.version_tuple_to_str(version)
        opc = xdis.op_imports.op_imports[version]
    return xdis.std.Bytecode(code, opc=opc)


def decompile_buffer(buffer: Code | buf, file_name: str | None = None) -> buf:
    errors = ''
    python = ''

    if not isinstance(buffer, Code):
        codes = list(extract_code_from_buffer(buffer, file_name))
    else:
        codes = [buffer]

    def _engines():
        nonlocal errors
        try:
            dc = decompyle3.main.decompile
        except ImportError:
            errors += '# The decompiler decompyle3 is not installed.\n'
        else:
            yield 'decompyle3', dc
        try:
            dc = uncompyle6.main.decompile
        except ImportError:
            errors += '# The decompiler decompyle3 is not installed.\n'
        else:
            yield 'uncompyle6', dc

    engines = dict(_engines())

    if not engines:
        errors += '# (all missing, install one of the above to enable decompilation)'

    for code in codes:
        for name, decompile in engines.items():
            with io.StringIO(newline='') as output, NoLogging(NoLogging.Mode.ALL):
                try:
                    decompile(
                        co=code.container,
                        bytecode_version=code.version,
                        out=output,
                        timestamp=code.timestamp,
                        code_objects=code.code_objects,
                        is_pypy=code.is_pypi,
                        magic_int=code.magic,
                    )
                except Exception as E:
                    errors += '\n'.join(F'# {line}' for line in (
                        F'Error while decompiling with {name}:', *str(E).splitlines(True)))
                    errors += '\n'
                else:
                    python = output.getvalue()
                    break
    if python:
        # removes leading comments
        python = python.splitlines(True)
        python.reverse()
        while python[-1].strip().startswith('#'):
            python.pop()
        python.reverse()
        python = ''.join(python)
        return python.encode('utf8')
    if not isinstance(buffer, Code):
        embedded = max(re.findall(B'[\\s!-~]+', buffer), key=len)
        if len(buffer) - len(embedded) < 0x20:
            return embedded
    disassembly = MemoryFile()
    with io.TextIOWrapper(disassembly, 'utf8', newline='\n') as output:
        output.write(errors)
        output.write('# Generating Disassembly:\n\n')
        for code in codes:
            instructions = list(disassemble_code(code.container, code.version))
            width_offset = max(len(str(i.offset)) for i in instructions)
            for i in instructions:
                opname = normalize_word_separators(i.opname, '.').lower()
                offset = F'{i.offset:0{width_offset}d}'
                output.write(F'# {offset:>5} {opname:<25} {i.argrepr}\n')
        output.write('\n')
    return disassembly.getvalue()


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


class PV(PyVer, enum.Enum):
    V_1_00 = (1,  0, 0) # noqa
    V_1_03 = (1,  3, 0) # noqa
    V_1_05 = (1,  5, 0) # noqa
    V_2_01 = (2,  1, 0) # noqa
    V_2_03 = (2,  3, 0) # noqa switch to 32bit
    V_3_00 = (3,  0, 0) # noqa
    V_3_08 = (3,  8, 0) # noqa
    V_3_10 = (3, 10, 0) # noqa
    V_3_11 = (3, 11, 0) # noqa


def code_header(version: tuple[int, int, int] | str | None = None) -> bytearray:
    """
    Produce a code object header for the given version.
    """
    if version is None:
        vt = SYS_PYTHON
        magic = bytearray(importlib.util.MAGIC_NUMBER)
    else:
        if isinstance(version, str):
            vs = version
            vt = version2tuple(version)
        else:
            major, minor, micro = version
            vs = F'{major}.{minor}.{micro}'
            vt = version
        magic = bytearray(xdis.magics.by_version[vs])

    nulls = b'\0\0\0\0'
    magic.extend(nulls)
    # 1.0 - 3.2 [magic][timestamp]        4 bytes
    # 3.3 - 3.6 [magic][timestamp][size]  8 bytes
    # 3.7 - now [magic][flags][misc]     12 bytes
    if vt >= (3, 3):
        magic.extend(nulls)
    if vt >= (3, 7):
        magic.extend(nulls)
    return magic


class Null(RuntimeError):
    """
    Raised when the unmarshal C implementation would return a null pointer.
    """


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

    def __init__(
        self,
        data,
        dumpcode: bool = False,
        version: tuple[int, int, int] | tuple[int, int] | int | str | None = None
    ):
        super().__init__(memoryview(data))

        if version is not None:
            if isinstance(version, str):
                version = version2tuple(version)
            if isinstance(version, int):
                version = (version, 0, 0)
            if len(version) == 2:
                major, minor, *_ = version
                version = (major, minor, 0)

        self.refs = []
        self.version = version

        _py_versions: list[PyVer] = []

        for v in xdis.magics.by_version:
            try:
                _py_versions.append(version2tuple(v))
            except Exception:
                continue

        self._py_versions = _py_versions = sorted(set(_py_versions))

        self._min_version = _py_versions[+0]
        self._max_version = _py_versions[~0]
        self._depth = 0
        self._dumpcode = dumpcode
        self.strings: list[str] = []
        self.buffers: list[bytes] = []
        self._store_strings = True

    def _quicksave(self):
        return (
            self.tell(),
            len(self.buffers),
            len(self.strings),
            len(self.refs),
        )

    def _quickload(self, *args):
        pos, bsc, usc, rc = args
        self.buffers[bsc:] = ()
        self.strings[usc:] = ()
        self.refs[rc:] = ()
        self.seekset(pos)

    @overload
    def object(self, typecheck: type[_T], store_strings: bool = True) -> _T:
        ...

    @overload
    def object(self, *, store_strings: bool = True) -> object:
        ...

    def object(self, typecheck=None, store_strings=True):
        """
        Read a marshaled object from the stream. The implementation attempts to be cross-version
        compatible.
        """
        depth = self._depth
        store = self._store_strings
        if depth > _MAX_MARSHAL_STACK_DEPTH:
            raise RuntimeError(
                F'The marshal stack depth limit of {_MAX_MARSHAL_STACK_DEPTH} was exceeded.')
        self._depth = depth + 1
        self._store_strings = store_strings
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
                    F'Unmarshelled object of type {o.__class__!r}, '
                    F'expected {expected}.')
            else:
                return o
        finally:
            self._depth = depth
            self._store_strings = store

    def _load_object(self):
        head = self.u8()
        code = head & 0x7F
        flag = head & 0x80
        store_reference = bool(flag)
        index = None

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
                self.refs[index] = rv
                store_reference = False
            else:
                rv = sequence_type(_sequence())
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
            rv = 0
            for _ in range(self.u32()):
                digit = self.u16()
                if digit >> 15:
                    raise ValueError('Python LONG digit has MSB set.')
                rv <<= 15
                rv |= digit
        elif code == _MC.FLOAT:
            rv = float(self.read_length_prefixed_ascii(8))
        elif code == _MC.BINARY_FLOAT:
            rv = self.f64()
        elif code == _MC.COMPLEX:
            im = float(self.read_length_prefixed_ascii(8))
            rl = float(self.read_length_prefixed_ascii(8))
            rv = complex(rl, im)
        elif code == _MC.BINARY_COMPLEX:
            im = self.f64()
            rl = self.f64()
            rv = complex(rl, im)
        elif code == _MC.STRING:
            rv = bytes(self.read_length_prefixed(32))
            if self._store_strings:
                self.buffers.append(rv)
        elif code == _MC.UNICODE:
            rv = self.read_length_prefixed(prefix_size, string_codec)
            if self._store_strings:
                self.strings.append(rv)
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
                self.refs[index] = rv
            else:
                rv = slice(self.object(), self.object(), self.object())
            return rv
        elif code == _MC.CODE:

            if store_reference:
                index = len(self.refs)
                self.refs.append(None)
            try:
                signature = inspect.signature(CodeType)
            except ValueError:
                if docs := CodeType.__doc__:
                    docs = re.sub(r'[\s\[\]]', '', docs)
                    spec = re.search(r'(?i)code\w*\((\w+(?:,\w+)*)\)', docs)
                    params = spec.group(1).split(',') if spec else []
                else:
                    raise
            else:
                params = list(signature.parameters)

            arguments = {}
            start, *qs = self._quicksave()

            versions = [v] if (v := self.version) else PV

            for version in versions:
                if version < self._min_version:
                    continue
                self._quickload(start, *qs)
                intval = self.u32 if version >= PV.V_2_03 else self.u16
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
                    if PV.V_1_03 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(argcount=n)
                    if PV.V_3_08 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(posonlyargcount=n)
                    if PV.V_3_00 <= version:
                        if (n := intval()) > MAX_ARGS:
                            raise ValueError
                        arguments.update(kwonlyargcount=n)
                    if PV.V_1_03 <= version < PV.V_3_11:
                        if (n := intval()) > MAX_VARS:
                            raise ValueError
                        arguments.update(nlocals=n)
                    if PV.V_1_05 <= version:
                        arguments.update(stacksize=intval())
                    if PV.V_1_03 <= version:
                        arguments.update(flags=intval())
                    if PV.V_1_00 <= version:
                        codestring = self.object(bytes, store_strings=False)
                        arguments.update(codestring=codestring)
                        arguments.update(constants=self.object(tuple))
                        arguments.update(names=self.object(tuple))
                    if PV.V_1_03 <= version < PV.V_3_11:
                        arguments.update(varnames=self.object(tuple))
                    if PV.V_2_01 <= version < PV.V_3_11:
                        arguments.update(freevars=self.object(tuple))
                        arguments.update(cellvars=self.object(tuple))
                    if PV.V_3_11 <= version:
                        co_localsplusnames = self.object(tuple, store_strings=False)
                        co_localspluskinds = self.object(bytes, store_strings=False)
                        co_freevars = []
                        co_cellvars = []
                        co_varnames = []
                        co_nlocals = 0
                        for name, version_index in zip(co_localsplusnames, co_localspluskinds):
                            kind = _CK(version_index)
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
                    if PV.V_1_00 <= version:
                        arguments.update(filename=self.object(str))
                        arguments.update(name=self.object(str))
                    if PV.V_3_11 <= version:
                        arguments.update(qualname=self.object(str))
                    if PV.V_1_05 <= version:
                        arguments.update(firstlineno=intval())
                    if PV.V_1_05 <= version < PV.V_3_10:
                        lnotab = self.object(bytes, store_strings=False)
                        if len(lnotab) % 2 != 0:
                            raise ValueError
                        arguments.update(linetable=lnotab)
                    if PV.V_3_10 <= version:
                        arguments.update(linetable=self.object(bytes, store_strings=False))
                    if PV.V_3_11 <= version:
                        arguments.update(exceptiontable=self.object(bytes, store_strings=False))
                    if start == 1 and not self.eof:
                        raise ValueError
                except Exception:
                    continue
                else:
                    if version < self._min_version:
                        continue
                    self._min_version = version
                    break
            else:
                raise RuntimeError('Failed to parse code object.')

            try:
                code_object = CodeType(*[arguments[p] for p in params])
            except Exception:
                code_object = None
            else:
                new_max = self._min_version
                old_max = self._max_version
                for v in self._py_versions:
                    if v < new_max:
                        continue
                    if v > old_max:
                        break
                    try:
                        for _ in disassemble_code(code_object, str(v)):
                            pass
                    except Exception:
                        break
                    else:
                        new_max = v
                self._max_version = new_max

            if not self._dumpcode:
                rv = code_object or arguments
            else:
                ch = code_header(self._max_version)
                size = self.tell() - start
                self.seekset(start)
                rv = B'%s%c%s' % (ch, head, self.read(size))
            if store_reference:
                assert index is not None
                self.refs[index] = rv
            return rv
        else:
            raise UnknownTypeCode(code.value)

        if store_reference:
            self.refs.append(rv)

        return rv
