from __future__ import annotations

import collections
import itertools
import re

from refinery.lib import json
from refinery.lib.dotnet.header import DotNetHeader, NetMetaDataTables
from refinery.lib.structures import StructReader
from refinery.lib.types import buf
from refinery.units import Unit
from refinery.units.formats.pe.dotnet import CodePath


class dnarrays(Unit):
    """
    Extracts arrays of strings or integers that are encoded in the .NET binary as IL opcodes.
    The data is exported as JSON.
    """
    @staticmethod
    def _read_int(reader: StructReader):
        value = reader.read_byte() - 0x16
        if value < 0:
            raise ValueError
        elif value <= 8:
            return value
        elif value == 9:
            return reader.read_byte()
        elif value == 10:
            return reader.u32()
        else:
            raise ValueError

    @staticmethod
    def _read_str(reader: StructReader, header: DotNetHeader):
        if reader.read_byte() != 0x72:
            raise ValueError
        token: int = reader.read_integer(24)
        value: str = header.meta.Streams.US[token]
        if reader.read_byte() != 0x70:
            raise ValueError
        return value

    _STACK_ARRAY_PATTERN_STR = re.compile(
        BR'''(?x)
        (?: [\x16-\x1E]|\x1F.|\x20.{4} ) # load array length
        (?:  \x8D...\x01               ) # newarr System.String
        (?:
        (?:  \x25                      ) # dup
        (?: [\x16-\x1E]|\x1F.|\x20.{4} ) # load integer index
        (?:  \x72...\x70               ) # load the string
        (?:  \xA2                      ) # stelem.ref
        ){4,}
        ''', flags=re.DOTALL)

    def _str_arrays(self, data: buf, header: DotNetHeader, tables: NetMetaDataTables):
        for match in self._STACK_ARRAY_PATTERN_STR.finditer(data):
            reader = StructReader(match[0])
            result: list[str] = []
            size = self._read_int(reader)
            if reader.read_byte() != 0x8D:
                raise RuntimeError
            stt = reader.read_integer(24)
            if reader.read_byte() != 0x01:
                raise RuntimeError
            if stt < 1 or tables.TypeRef[stt - 1].TypeName != 'String':
                continue
            self.log_info(F'str array pattern at 0x{match.start():X}, size {size}')
            for k in range(size):
                if reader.read_byte() != 0x25:
                    raise RuntimeError
                if self._read_int(reader) != k:
                    break
                result.append(self._read_str(reader, header))
                if reader.read_byte() != 0xA2:
                    raise RuntimeError
            else:
                yield match.start(), result

    _STACK_ARRAY_PATTERN_INT = re.compile(
        BR'''(?x)
        (    \x12.|\xFE\x0D..          ) # load array variable
        (?: [\x16-\x1E]|\x1F.|\x20.{4} ) # push integer value
        (?:  \x52                      ) # store value into array
        (?:
        (?:  \1                        ) # load same array variable
        (?: [\x16-\x1E]|\x1F.|\x20.{4} ) # load integer index
        (?:  \x58                      ) # add; compute offset
        (?: [\x16-\x1E]|\x1F.|\x20.{4} ) # push integer value
        (?:  \x52                      ) # store value into array
        ){4,}
        ''', flags=re.DOTALL)

    def _int_arrays(self, data: buf, header: DotNetHeader, tables: NetMetaDataTables):
        for match in self._STACK_ARRAY_PATTERN_INT.finditer(data):
            self.log_info(F'int array pattern at 0x{match.start():X}')
            reader = StructReader(match[0])
            result: list[int] = []
            opc, = reader.peek(1)
            skip = {0x12: 2, 0xFE: 4}[opc]
            reader.seekrel(skip)
            for index in itertools.count(1):
                result.append(self._read_int(reader))
                assert reader.read_byte() == 0x52
                if reader.eof:
                    yield match.start(), result
                    break
                reader.seekrel(skip)
                if self._read_int(reader) != index:
                    self.log_info('index inconsistency; aborting')
                    break
                assert reader.read_byte() == 0x58

    def process(self, data):
        header = DotNetHeader(data)
        tables = header.meta.Streams.Tables
        cp = CodePath(header)

        arrays = dict(itertools.chain(
            self._int_arrays(data, header, tables),
            self._str_arrays(data, header, tables),
        ))
        result = collections.defaultdict(list)
        for offset in sorted(arrays):
            result[cp.method_spec(offset)].append(arrays[offset])

        result = {m: {F'v{k}': v for k, v in enumerate(t, 1)} for m, t in result.items()}
        return json.dumps(result)

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
