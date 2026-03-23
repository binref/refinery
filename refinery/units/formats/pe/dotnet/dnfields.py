from __future__ import annotations

import functools
import re
import struct

from collections import Counter
from typing import NamedTuple

from refinery.lib.dotnet import integer_from_ldc
from refinery.lib.dotnet.header import DotNetHeader
from refinery.lib.dotnet.signatures import FieldSig, SzArrayTypeSig, parse_signature
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.formats.pe.dotnet import CodePath


class FieldInfo(NamedTuple):
    type: str
    elements: int
    size: int
    offset: int


class dnfields(PathExtractorUnit):
    """
    Extract data from constant field variables in classes of .NET executables.

    Since the .NET header stores only the offset and not the size of constant fields, heuristics
    are used to search for opcode sequences that load the data and additional heuristics are used
    to guess the size of the data type.
    """
    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)

    def unpack(self, data):
        header = DotNetHeader(data, parse_resources=False)
        tables = header.meta.Streams.Tables
        fields = tables.FieldRVA
        cpaths = CodePath(header)

        if not fields:
            return

        icache: dict[bytes, FieldInfo] = {}
        memory = memoryview(data)

        @functools.lru_cache(maxsize=None)
        def _memory_matches(pattern: bytes):
            return list(re.finditer(pattern, memory, flags=re.DOTALL))

        def _guess_field_info(t: int, signature: bytes, field_name: str | None = None, sizemap: dict = {
            '^s?byte$'       : 1,
            '^s?char$'       : 2,
            '^[us]?int.?16$' : 2,
            '^[us]?int.?32$' : 4,
            '^[us]?int.?64$' : 8,
        }) -> tuple[str | None, FieldInfo | None]:
            try:
                info = icache[signature]
            except KeyError:
                info = None
            else:
                if field_name is not None:
                    return field_name, info
            pattern = (
                BR'(\x20....|\x1F.|[\x17-\x1E])'    # ldc.i4  count
                BR'\x8D(...)([\x01\x02])'           # newarr  col|row
                BR'\x25'                            # dup
                BR'\xD0\x%02x\x%02x\x%02x\x04'      # ldtoken t
                BR'(?:.{0,12}?'                     # ...
                BR'\x80(...)\x04)?' % (             # stsfld variable
                    (t >> 0x00) & 0xFF,
                    (t >> 0x08) & 0xFF,
                    (t >> 0x10) & 0xFF
                )
            )
            for match in _memory_matches(pattern):
                if info is None:
                    count, j, r, name = match.groups()
                    count = integer_from_ldc(count)
                    j, r = struct.unpack('<LB', B'%s\0%s' % (j, r))
                    r = int(r)
                    j = int(j)
                    typename = tables[r][j - 1].TypeName
                else:
                    count = 0
                    name = match.group(4)
                    typename = info.type
                for pattern, size in sizemap.items():
                    if not re.match(pattern, typename, flags=re.IGNORECASE):
                        continue
                    if name is not None:
                        try:
                            name = struct.unpack('<L', B'%s\0' % name)
                            name = int(name[0])
                            name = tables.Field[name - 1].Name
                        except Exception as E:
                            self.log_info(F'attempt to parse field name failed: {E!s}')
                            name = None
                    if name is None:
                        name = field_name
                    if info is None:
                        info = FieldInfo(typename, count, size, match.start())
                    icache[signature] = info
                    return name, info
            return None, None

        def _guess_array_info(
            t: int,
            signature: bytes,
            element_name: str,
            element_size: int,
            field_name: str | None = None,
        ) -> tuple[str | None, FieldInfo | None]:
            try:
                info = icache[signature]
            except KeyError:
                info = None
            else:
                if field_name is not None:
                    return field_name, info
            pattern = (
                BR'(\x20....|\x1F.|[\x17-\x1E])'     # ldc.i4  count
                BR'\x8D...[\x01\x02]'                # newarr  col|row
                BR'\x25'                             # dup
                BR'\xD0\x%02x\x%02x\x%02x\x04'       # ldtoken t
                BR'(?:.{0,12}?'                      # ...
                BR'\x80(...)\x04)?' % (              # stsfld variable
                    (t >> 0x00) & 0xFF,
                    (t >> 0x08) & 0xFF,
                    (t >> 0x10) & 0xFF
                )
            )
            for match in _memory_matches(pattern):
                count_bytes, name = match.groups()
                count = integer_from_ldc(count_bytes)
                if name is not None:
                    try:
                        nc = struct.unpack('<L', B'%s\0' % name)
                        nc = int(nc[0])
                        name = tables.Field[nc - 1].Name
                    except Exception as E:
                        self.log_info(
                            F'attempt to parse field name failed: {E!s}')
                        name = None
                if name is None:
                    name = field_name
                if info is None:
                    info = FieldInfo(
                        element_name, count, element_size, match.start())
                icache[signature] = info
                return name, info
            return None, None

        iwidth = len(str(len(fields)))
        rwidth = max(len(F'{field.RVA:X}') for field in fields)
        rwidth = max(rwidth, 4)
        remaining_field_indices = set(range(len(tables.Field)))

        unpack = []
        name_count = Counter(tables[rv.Field].Name for rv in fields)
        name_width = len(str(len(fields)))

        for k, rv in enumerate(fields):
            _index = rv.Field.Index
            field = tables.Field[_index - 1]
            remaining_field_indices.discard(_index - 1)
            if not field.Flags.HasFieldRVA:
                continue
            fname = field.Name
            type = None
            signature = bytes(field.Signature)
            offset = header.pe.rva_to_offset(rv.RVA)
            guess = None

            try:
                sig = parse_signature(signature)
            except Exception:
                sig = None

            if isinstance(sig, FieldSig):
                ftype = sig.field_type
                if isinstance(ftype, SzArrayTypeSig):
                    element = ftype.element
                    if element.byte_size is not None and element.byte_size > 0:
                        fname, guess = _guess_array_info(
                            _index, signature,
                            element.name, element.byte_size, fname)
                elif ftype.byte_size is not None and ftype.byte_size > 0:
                    guess = FieldInfo(ftype.name, 1, ftype.byte_size, 0)

            if guess is None:
                fname, guess = _guess_field_info(_index, signature, fname)

            if guess is None or fname is None:
                self.log_warn(lambda: F'field {k:0{iwidth}d} with signature {field.Signature.hex()}: unable to guess type information')
                continue
            if not fname.isprintable() or name_count[fname] > 1:
                fname = F'Field{k + 1:0{name_width}d}'
            type = guess.type.lower()
            if guess.elements > 1:
                type += F'[{guess.elements}]'
            self.log_debug(
                F'field {k:0{iwidth}d}; token 0x{_index:06X}; RVA 0x{rv.RVA:04X}; count {guess.elements}; type {guess.type}; name {fname}')
            end = offset + guess.elements * guess.size
            path = cpaths.method_path(guess.offset) if guess.offset else ''
            unpack.append(UnpackResult(F'{path}/{fname}', memory[offset:end], name=fname, type=type))

        remaining_field_indices = list(remaining_field_indices)
        token_pattern = B'|'.join(
            (re.escape((i + 1).to_bytes(3, 'little')) for i in remaining_field_indices))
        token_matches: dict[int, list[re.Match[bytes]]] = {}

        for match in re.finditer((
            BR'\x72(?P<token>...)\x70'          # ldstr
            BR'(?:\x6F(?P<function>...)\x0A)?'  # call GetBytes
            BR'\x80(?P<t>%s)\x04'               # stsfld
        ) % token_pattern, memory, re.DOTALL):
            i = int.from_bytes(match['t'], 'little') - 1
            matches = token_matches.setdefault(i, [])
            matches.append(match)

        for _index in remaining_field_indices:
            field = tables.Field[_index]
            matches = [_index]
            name = field.Name
            if field.Flags.HasFieldRVA:
                self.log_warn(F'field {name} has RVA flag set, but no RVA was found')
            values: dict[bytes, list[int]] = {}
            for match in token_matches.get(_index, ()):
                md = match.groupdict()
                fn_token = md.get('function')
                fn_index = fn_token and int.from_bytes(fn_token, 'little') or None
                if fn_index is not None:
                    fn_name = tables.MemberRef[fn_index].Name
                    if fn_name != 'GetBytes':
                        self.log_info(F'skipping string assignment passing through call to {fn_name}')
                        continue
                k = int.from_bytes(md['token'], 'little')
                offsets = values.setdefault(header.meta.Streams.US[k].encode(self.codec), [])
                offsets.append(match.start())
            if not values:
                continue
            if len(values) == 1:
                value, offsets = values.popitem()
                for offset in offsets:
                    try:
                        path = cpaths.method_path(offset)
                    except Exception:
                        continue
                    else:
                        unpack.append(UnpackResult(F'{path}/{name}', value, name=name, type='string'))
                        break

        unpack.sort(key=lambda u: u.path)
        yield from unpack
