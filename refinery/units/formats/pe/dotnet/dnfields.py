#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import struct

from typing import NamedTuple, Optional

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.dotnet.header import DotNetHeader


class FieldInfo(NamedTuple):
    type: str
    count: int
    size: int
    name: Optional[str]


class dnfields(PathExtractorUnit):
    """
    This unit can extract data from constant field variables in classes of .NET
    executables. Since the .NET header stores only the offset and not the size of
    constant fields, heuristics are used to search for opcode sequences that load
    the data and additional heuristics are used to guess the size of the data
    type.
    """
    _SIZEMAP = {
        '^s?byte$'       : 1,
        '^s?char$'       : 2,
        '^[us]?int.?16$' : 2,
        '^[us]?int.?32$' : 4,
        '^[us]?int.?64$' : 8,
    }

    def __init__(
        self, *paths,
        regex=False,
        list=False,
        path=b'name',
        join_path=False,
        drop_path=False,
    ):
        super().__init__(*paths, list=list, join_path=join_path, drop_path=drop_path, regex=regex, path=path)

    def _guess_field_info(self, tables, data, t) -> FieldInfo:
        pattern = (
            BR'(\x20....|\x1F.)'                # ldc.i4  count
            BR'\x8D(...)([\x01\x02])'           # newarr  col|row
            BR'\x25'                            # dup
            BR'\xD0\x%02x\x%02x\x%02x\x04'      # ldtoken t
            BR'(?:.{0,12}'                      # ...
            BR'\x80(...)\x04)?' % (             # stsfld variable
                (t >> 0x00) & 0xFF,
                (t >> 0x08) & 0xFF,
                (t >> 0x10) & 0xFF
            )
        )
        for match in re.finditer(pattern, data, flags=re.DOTALL):
            count, j, r, name = match.groups()
            count, j, r = struct.unpack('<LLB', B'%s%s\0%s' % (count[1:].ljust(4, B'\0'), j, r))
            if name:
                try:
                    name = struct.unpack('<L', B'%s\0' % name)
                    name = name[0]
                    name = tables[4][name - 1].Name
                except Exception as E:
                    self.log_info(F'attempt to parse field name failed: {E!s}')
                    name = None
            element = tables[r][j - 1]
            for pattern, size in self._SIZEMAP.items():
                if re.match(pattern, element.TypeName, flags=re.IGNORECASE):
                    return FieldInfo(element.TypeName, count, size, name)

    def unpack(self, data):
        header = DotNetHeader(data, parse_resources=False)
        tables = header.meta.Streams.Tables
        fields = tables.FieldRVA
        if not fields:
            return
        iwidth = len(str(len(fields)))
        rwidth = max(len(F'{field.RVA:X}') for field in fields)
        rwidth = max(rwidth, 4)
        remaining_field_indices = set(range(len(tables.Field)))

        for k, rv in enumerate(fields):
            index = rv.Field.Index
            field = tables.Field[index - 1]
            remaining_field_indices.discard(index - 1)
            fname = field.Name
            ftype = None
            if len(field.Signature) == 2:
                # Crude signature parser for non-array case. Reference:
                # https://www.codeproject.com/Articles/42649/NET-File-Format-Signatures-Under-the-Hood-Part-1
                # https://www.codeproject.com/Articles/42655/NET-file-format-Signatures-under-the-hood-Part-2
                guess = {
                    0x03: FieldInfo('Char',   1, 1, None),  # noqa
                    0x04: FieldInfo('SByte',  1, 1, None),  # noqa
                    0x05: FieldInfo('Byte',   1, 1, None),  # noqa
                    0x06: FieldInfo('Int16',  1, 2, None),  # noqa
                    0x07: FieldInfo('UInt16', 1, 2, None),  # noqa
                    0x08: FieldInfo('Int32',  1, 4, None),  # noqa
                    0x09: FieldInfo('UInt32', 1, 4, None),  # noqa
                    0x0A: FieldInfo('Int64',  1, 8, None),  # noqa
                    0x0B: FieldInfo('UInt64', 1, 8, None),  # noqa
                    0x0C: FieldInfo('Single', 1, 4, None),  # noqa
                    0x0D: FieldInfo('Double', 1, 8, None),  # noqa
                }.get(field.Signature[1], None)
            else:
                guess = self._guess_field_info(tables, data, index)
            if guess is None:
                self.log_debug(lambda: F'field {k:0{iwidth}d} name {field.Signature}: unable to guess type information')
                continue
            totalsize = guess.count * guess.size
            if guess.name is not None:
                fname = guess.name
            if not fname.isprintable():
                fname = F'F{rv.RVA:0{rwidth}X}'
            ftype = guess.type
            if guess.count > 1:
                ftype += F'[{guess.count}]'
            self.log_info(lambda: F'field {k:0{iwidth}d} at RVA 0x{rv.RVA:04X} of type {guess.type}, count: {guess.count}, name: {fname}')
            offset = header.pe.get_offset_from_rva(rv.RVA)
            yield UnpackResult(fname, lambda t=offset, s=totalsize: data[t:t + s], type=ftype)

        for index in remaining_field_indices:
            field = tables.Field[index]
            name = field.Name
            if field.Flags.HasFieldRVA:
                self.log_warn(F'field {name} has RVA flag set, but no RVA was found')
            token = index.to_bytes(3, 'little')
            values = set()
            for match in re.finditer((
                BR'\x72(?P<token>...)\x70'          # ldstr
                BR'(?:\x6F(?P<function>...)\x0A)?'  # call GetBytes
                BR'\x80%s\x04'                      # stsfld
            ) % re.escape(token), data, re.DOTALL):
                md = match.groupdict()
                fn_token = md.get('function')
                fn_index = fn_token and int.from_bytes(fn_token, 'little') or None
                if fn_index is not None:
                    fn_name = tables.MemberRef[fn_index].Name
                    if fn_name != 'GetBytes':
                        self.log_warn(F'skipping string assignment passing through call to {fn_name}')
                        continue
                k = int.from_bytes(md['token'], 'little')
                values.add(header.meta.Streams.US[k].encode(self.codec))
            if not values:
                continue
            if len(values) == 1:
                yield UnpackResult(name, next(iter(values)), type='string')
