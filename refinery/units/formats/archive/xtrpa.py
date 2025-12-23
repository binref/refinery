from __future__ import annotations

import codecs
import pickle
import pickletools
import zlib

from refinery.lib.structures import MemoryFile, Struct, StructReader
from refinery.units.formats.archive import PathExtractorUnit, UnpackResult

_SAFE_PICKLE_OPCODES = {
    'ADDITEMS',          # Add items to set
    'APPEND',            # Append to list
    'BINBYTES',          # Bytes (4‑byte length)
    'BINBYTES8',         # Bytes (8‑byte length)
    'BINFLOAT',          # Float (binary)
    'BINGET',            # Memo get (1‑byte)
    'BININT',            # Int (4‑byte)
    'BININT1',           # Int (1‑byte)
    'BININT2',           # Int (2‑byte)
    'BINPUT',            # Memo put (1‑byte)
    'BINSTRING',         # Bytes string (4‑byte, proto ≤1)
    'BINUNICODE',        # Unicode (4‑byte length)
    'BINUNICODE8',       # Unicode (8‑byte length)
    'BYTEARRAY8',        # Bytearray (8‑byte length)
    'DICT',              # Build dict
    'DUP',               # Duplicate top
    'EMPTY_DICT',        # New dict
    'EMPTY_LIST',        # New list
    'EMPTY_SET',         # New set
    'EMPTY_TUPLE',       # New tuple
    'FLOAT',             # Float (ASCII)
    'FRAME',             # Frame boundary
    'FROZENSET',         # Build frozenset
    'GET',               # Memo get (ASCII)
    'INT',               # Int (ASCII)
    'LIST',              # Build list
    'LONG_BINGET',       # Memo get (4‑byte)
    'LONG_BINPUT',       # Memo put (4‑byte)
    'LONG',              # Long (ASCII)
    'LONG1',             # Long (1‑byte length)
    'LONG4',             # Long (4‑byte length)
    'MARK',              # Mark stack
    'MEMOIZE',           # Memoize top
    'NEWFALSE',          # False
    'NEWTRUE',           # True
    'NONE',              # None
    'POP_MARK',          # Pop to MARK
    'POP',               # Pop top
    'PROTO',             # Protocol version
    'PUT',               # Memo put (ASCII)
    'SETITEM',           # Dict setitem
    'SETITEMS',          # Dict setitems
    'SHORT_BINBYTES',    # Bytes (1‑byte length)
    'SHORT_BINSTRING',   # Bytes string (1‑byte, proto ≤1)
    'SHORT_BINUNICODE',  # Unicode (1‑byte length)
    'STOP',              # End pickle
    'STRING',            # String (ASCII, proto ≤1)
    'TUPLE',             # Build tuple
    'TUPLE1',            # 1‑tuple
    'TUPLE2',            # 2‑tuple
    'TUPLE3',            # 3‑tuple
    'UNICODE',           # Unicode (newline‑term)
}

assert _SAFE_PICKLE_OPCODES <= {opc.name for opc in pickletools.opcodes}


class RPA(Struct):
    Signature = b"RPA-"

    def __init__(self, reader: StructReader[memoryview]):
        if reader.peek(2) == B'\x78\x9c':
            pos = 0
            key = 0
            ver = (1, 0)
        elif reader.peek(4) == self.Signature:
            meta = codecs.decode(reader.readline(), 'ascii').split()
            meta = iter(meta)
            version_info = next(meta)
            if len(version_info) > 0x100:
                raise ValueError('Invalid version info.')
            try:
                rpa, sep, vs = version_info.partition('-')
                ver = tuple(map(int, vs.split('.')))
            except Exception:
                raise ValueError('Invalid version info.')
            if rpa != 'RPA' or sep != '-':
                raise RuntimeError
            if len(ver) != 2:
                raise ValueError(F'Version {vs} had an unexpected format.')
            pos = int(next(meta), 16)
            key = 0
            if ver >= (3, 2):
                _ = next(meta)
            for sk in meta:
                key ^= int(sk, 16)
        else:
            raise ValueError('Unknown header.')

        self.version = ver
        reader.seek(pos)

        _index = reader.peek()
        _index = zlib.decompress(_index)

        for opc, _, _ in pickletools.genops(_index):
            if opc.name not in _SAFE_PICKLE_OPCODES:
                raise ValueError(F'Insecure pickle opcode {opc.name} not permitted.')

        index: dict[
            str, list[tuple[int, int] | tuple[int, int, str | bytes]]
        ] = pickle.loads(_index, encoding='latin1')

        if not isinstance(index, dict):
            raise ValueError(F'Index data was not a dictionary but a {index.__class__.__name__}.')

        files: dict[str, memoryview | bytearray] = {}
        self.files = files

        for path, entries in index.items():
            if len(entries) == 1:
                offset, length, *_p = entries[0]
                if not _p or not _p[0]:
                    offset ^= key
                    length ^= key
                    reader.seek(offset)
                    files[path] = reader.read_exactly(length)
                    continue
            out = MemoryFile()
            for entry in entries:
                offset, length, *_p = entry
                offset ^= key
                length ^= key
                reader.seek(offset)
                if len(_p) == 0:
                    prefix = _p[0]
                    if isinstance(prefix, str):
                        prefix = prefix.encode('latin1')
                    out.write(prefix)
                out.write(reader.read_exactly(length))
            files[path] = out.getvalue()


class xtrpa(PathExtractorUnit):
    """
    Extract files and metadata from RenPy Archives.
    """
    def unpack(self, data):
        rpa = RPA.Parse(memoryview(data))
        for path, data in rpa.files.items():
            yield UnpackResult(path, data)

    @classmethod
    def handles(cls, data):
        if data[:4] == RPA.Signature:
            return True
        if data[:2] != B'\x78\x9c':
            return False
