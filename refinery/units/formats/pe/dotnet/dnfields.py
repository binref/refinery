#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import fnmatch
import struct

from .... import arg, Unit
from .....lib.dotnet.header import DotNetHeader


class dnfields(Unit):
    """
    This unit can extract data from constant field variables in classes of .NET
    executables. Since the .NET header stores only the offset and not the size of
    constant fields, heuristics are used to search for opcode sequences that load
    the data and additional heuristics are used to guess the size of the data
    type.
    """
    _SIZEMAP = {
        '^s?byte|char$'  : 1,
        '^[us]?int.?16$' : 2,
        '^[us]?int.?32$' : 4,
        '^[us]?int.?64$' : 8,
    }

    def __init__(self, fields: arg(help='Any sequence of wildcard patterns') = ['*']):
        pass

    def _guess_field_info(self, tables, data, t):
        pattern = (
            BR'(\x20....|\x1F.)'                # ldc.i4  count
            BR'\x8D(...)([\x01\x02])'           # newarr  col|row
            BR'\x25'                            # dup
            BR'\xD0\x%02x\x%02x\x%02x\x04' % (  # ldtoken t
                (t >> 0x00) & 0xFF,
                (t >> 0x08) & 0xFF,
                (t >> 0x10) & 0xFF
            )
        )
        for match in re.finditer(pattern, data, flags=re.DOTALL):
            count, j, r = match.groups()
            count, j, r = struct.unpack('=LLB', B'%s%s\0%s' % (count[1:].ljust(4, B'\0'), j, r))
            element = tables[r][j - 1]
            for pattern, size in self._SIZEMAP.items():
                if re.match(pattern, element.TypeName, flags=re.IGNORECASE):
                    return element.TypeName, count, size

    def process(self, data) -> dict(path='The name of the field that was extracted.'):
        header = DotNetHeader(data, parse_resources=False)
        tables = header.meta.Streams.Tables
        iwidth = len(str(len(tables.FieldRVA)))

        for pattern in self.args.fields:
            for k, rv in enumerate(tables.FieldRVA):
                index = rv.Field.Index
                field = tables.Field[index - 1]
                if not fnmatch.fnmatch(field.Name, pattern):
                    continue
                guess = self._guess_field_info(tables, data, index)
                if guess is None:
                    self.log_debug(lambda: F'field {k:0{iwidth}d}: {field.Name} unable to guess type information')
                    continue
                typename, count, size = guess
                totalsize = count * size
                self.log_info(lambda: F'field {k:0{iwidth}d}: {field.Name} of type {typename}, count: {count}')
                offset = header.pe.get_offset_from_rva(rv.RVA)
                yield dict(
                    data=data[offset:offset + totalsize],
                    path=field.Name
                )
