"""
Parser for Microsoft Access database files (.mdb / .accdb). Supported are:

|  Type | Program               |
|------:|:----------------------|
|  Jet3 | Access 97             |
|  Jet4 | Access 2000/2002/2003 |
| ACE12 | Access 2007           |
| ACE14 | Access 2010+          |
"""
from __future__ import annotations

import codecs
import enum
import math
import struct

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Literal, NamedTuple, overload
from uuid import UUID

from refinery.lib.structures import StructReader

_ACCESS_EPOCH = datetime(1899, 12, 30)

_TABLE_MAGIC = b'\x02\x01'
_DATA_MAGIC = b'\x01\x01'

_SYSTEM_FLAGS = {-0x80000000, -2, 0x80000000, 2}


class JetVersion(enum.IntEnum):
    V3 = 0x00
    V4 = 0x01
    V5 = 0x02
    V2010 = 0x03


class ColumnType(enum.IntEnum):
    BOOLEAN = 1
    INT8 = 2
    INT16 = 3
    INT32 = 4
    MONEY = 5
    FLOAT32 = 6
    FLOAT64 = 7
    DATETIME = 8
    BINARY = 9
    TEXT = 10
    OLE = 11
    MEMO = 12
    GUID = 15
    NUMERIC = 16
    COMPLEX = 18


class _Column(NamedTuple):
    type: int
    column_id: int
    variable_column_number: int
    column_index: int
    fixed_length: bool
    fixed_offset: int
    length: int
    name: str = ''
    collation: int | None = None
    code_page: int | None = None
    precision: int | None = None
    scale: int | None = None


class _VarLenMeta(NamedTuple):
    field_count: int
    field_offsets: list[int]
    var_len_count: int
    jump_table: list[int]
    metadata_end: int


def _mdb_date(raw: int) -> datetime | None:
    try:
        value, = struct.unpack('<d', struct.pack('<Q', raw))
        frac, whole = math.modf(value)
        result = _ACCESS_EPOCH + timedelta(days=whole) + timedelta(days=frac)
        if result == _ACCESS_EPOCH:
            return None
        return result
    except (OverflowError, ValueError, struct.error):
        return None


def _numeric_to_string(data: bytes | memoryview, scale: int = 6) -> str:
    neg, n1, n2, n3, n4 = struct.unpack_from('<BIIII', data)
    full = (n1 << 96) + (n2 << 64) + (n3 << 32) + n4
    digits = str(full)
    if len(digits) > scale:
        dot = len(digits) - scale
        digits = F'{digits[:dot]}.{digits[dot:]}'
    return F'-{digits}' if neg else digits


def _decode_text(data: bytes | memoryview) -> str:
    try:
        return codecs.decode(data, 'utf-8')
    except (UnicodeDecodeError, ValueError):
        return codecs.decode(data, 'latin-1')


@overload
def _parse_type(column_type: Literal[
    ColumnType.INT8,
    ColumnType.INT16,
    ColumnType.INT32,
    ColumnType.MONEY,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> int:
    pass


@overload
def _parse_type(column_type: Literal[
    ColumnType.FLOAT32,
    ColumnType.FLOAT64,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> float:
    pass


@overload
def _parse_type(column_type: Literal[
    ColumnType.OLE,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> bytes:
    pass


@overload
def _parse_type(column_type: Literal[
    ColumnType.TEXT,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> str:
    pass


@overload
def _parse_type(column_type: Literal[
    ColumnType.DATETIME,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> datetime | None:
    pass


@overload
def _parse_type(column_type: Literal[
    ColumnType.GUID,
], data: bytes | memoryview, length: int | None = None, is_v3: bool = True) -> UUID:
    pass


@overload
def _parse_type(
    column_type: int, data: bytes | memoryview, length: int | None = None, is_v3: bool = True
) -> int | float | str | bytes | datetime | UUID | None:
    pass


def _parse_type(
    column_type: int,
    data: bytes | memoryview,
    length: int | None = None,
    is_v3: bool = True,
) -> int | float | str | bytes | datetime | UUID | None:
    if column_type == ColumnType.INT8:
        return struct.unpack_from('b', data)[0]
    if column_type == ColumnType.INT16:
        return struct.unpack_from('<h', data)[0]
    if column_type in (ColumnType.INT32, ColumnType.COMPLEX):
        return struct.unpack_from('<i', data)[0]
    if column_type == ColumnType.MONEY:
        return struct.unpack_from('<q', data)[0]
    if column_type == ColumnType.FLOAT32:
        return struct.unpack_from('<f', data)[0]
    if column_type == ColumnType.FLOAT64:
        return struct.unpack_from('<d', data)[0]
    if column_type == ColumnType.DATETIME:
        raw = struct.unpack_from('<Q', data)[0]
        return _mdb_date(raw)
    if column_type == ColumnType.BINARY:
        if length is not None:
            return bytes(data[:length])
        return bytes(data)
    if column_type == ColumnType.OLE:
        return bytes(data)
    if column_type == ColumnType.GUID:
        return UUID(bytes_le=bytes(data[:16]))
    if column_type == ColumnType.NUMERIC:
        return bytes(data[:17])
    if column_type == ColumnType.TEXT:
        if not is_v3:
            if data[:2] in (b'\xfe\xff', b'\xff\xfe'):
                text = _decode_text(data[2:])
            else:
                text = codecs.decode(data, 'utf-16-le', errors='ignore')
        else:
            text = _decode_text(data)
        return text.replace('\x00', '')
    return bytes(data)


def _parse_data_page_header(reader: StructReader[memoryview], is_v3: bool) -> tuple[int, list[int]]:
    magic = reader.read(2)
    if bytes(magic) != _DATA_MAGIC:
        raise ValueError('invalid data page magic')
    reader.u16()
    owner = reader.u32()
    if not is_v3:
        reader.u32()
    record_count = reader.u16()
    offsets = [reader.u16() for _ in range(record_count)]
    return owner, offsets


def _parse_tdef_header(reader: StructReader[memoryview]) -> tuple[int, int]:
    magic = reader.read(2)
    if bytes(magic) != _TABLE_MAGIC:
        raise ValueError('invalid table definition magic')
    reader.u16()
    next_page = reader.u32()
    header_end = reader.tell()
    return next_page, header_end


class _TableHead(NamedTuple):
    next_page: int
    row_count: int
    variable_columns: int
    column_count: int
    index_count: int
    real_index_count: int
    header_end: int


def _parse_table_head(reader: StructReader[memoryview], is_v3: bool) -> _TableHead:
    next_page, _ = _parse_tdef_header(reader)
    reader.skip(4 if is_v3 else 8)
    row_count = reader.u32()
    reader.skip(7 if is_v3 else 23)
    variable_columns = reader.u16()
    column_count = reader.u16()
    index_count = reader.u32()
    real_index_count = reader.u32()
    reader.skip(8)
    header_end = reader.tell()
    return _TableHead(
        next_page=next_page,
        row_count=row_count,
        variable_columns=variable_columns,
        column_count=column_count,
        index_count=index_count,
        real_index_count=real_index_count,
        header_end=header_end,
    )


def _parse_columns(
    reader: StructReader[memoryview],
    column_count: int,
    real_index_count: int,
    index_count: int,
    is_v3: bool,
) -> list[_Column]:
    for _ in range(real_index_count):
        reader.skip(12 if not is_v3 else 8)

    raw_columns = []
    for _ in range(column_count):
        col_type = reader.u8()
        if not is_v3:
            reader.skip(4)
        col_id = reader.u16()
        var_col_num = reader.u16()
        col_index = reader.u16()

        collation: int | None = None
        code_page: int | None = None
        precision: int | None = None
        scale: int | None = None
        if col_type in (
            ColumnType.BINARY,
            ColumnType.TEXT,
            ColumnType.OLE,
            ColumnType.MEMO,
        ):
            if is_v3:
                collation = reader.u16()
                code_page = reader.u16()
                reader.skip(2)
            else:
                collation = reader.u16()
                reader.skip(2)
        elif col_type == ColumnType.NUMERIC:
            precision = reader.u8()
            scale = reader.u8()
            reader.skip(4 if is_v3 else 2)
        elif col_type in (
            ColumnType.BOOLEAN,
            ColumnType.INT8,
            ColumnType.INT16,
            ColumnType.INT32,
            ColumnType.MONEY,
            ColumnType.FLOAT32,
            ColumnType.FLOAT64,
            ColumnType.DATETIME,
        ):
            reader.skip(6 if is_v3 else 4)
        else:
            reader.skip(6 if is_v3 else 4)

        flags_byte = reader.u8()
        fixed_length = bool(flags_byte & 0x01)
        if not is_v3:
            reader.skip(5)

        fixed_offset = reader.u16()
        length = reader.u16()
        raw_columns.append(_Column(
            type=col_type,
            column_id=col_id,
            variable_column_number=var_col_num,
            column_index=col_index,
            fixed_length=fixed_length,
            fixed_offset=fixed_offset,
            length=length,
            collation=collation,
            code_page=code_page,
            precision=precision,
            scale=scale,
        ))

    columns = []
    for col in raw_columns:
        if is_v3:
            name_len = reader.u8()
            name = codecs.decode(reader.read(name_len), 'utf-8', errors='replace')
        else:
            name_len = reader.u16()
            name = codecs.decode(reader.read(name_len), 'utf-16-le', errors='replace')
        columns.append(col._replace(name=name))

    for _ in range(real_index_count):
        reader.skip(52 if not is_v3 else 39)

    for _ in range(index_count):
        reader.skip(28 if not is_v3 else 20)

    return columns


def _parse_var_length_metadata(
    reverse_data: memoryview,
    is_v3: bool,
    jump_table_count: int = 0,
) -> _VarLenMeta | None:
    reader = StructReader[memoryview](reverse_data)
    reader.bigendian = True
    try:
        if is_v3:
            field_count = reader.u8()
            jump_table = [reader.u8() for _ in range(jump_table_count)]
            offsets = [reader.u8() for _ in range(field_count)]
            var_len_count = reader.u8()
        else:
            field_count = reader.u16()
            jump_table = []
            count = field_count & 0xFF
            offsets = [reader.u16() for _ in range(count)]
            var_len_count = reader.u16()
        return _VarLenMeta(
            field_count=field_count,
            field_offsets=offsets,
            var_len_count=var_len_count,
            jump_table=jump_table,
            metadata_end=reader.tell(),
        )
    except Exception:
        return None


class _TableObj:

    __slots__ = 'offset', 'value', 'linked_pages'

    def __init__(self, offset: int, value: memoryview, /):
        self.offset = offset
        self.value = value
        self.linked_pages: list[memoryview] = []


class AccessDatabase:
    """
    Parser for Microsoft Access database files. Accepts raw bytes as input and
    provides a `catalog` mapping table names to IDs and a `parse_table` method
    that returns `dict[str, list]` (column name to list of row values).
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        mv = memoryview(data)
        self._data = mv
        self._parse_header()
        self._table_defs, self._data_pages = self._categorize_pages()
        self._tables_with_data = self._link_tables_to_data()
        self.catalog: dict[str, int] = self._parse_catalog()

    def _parse_header(self):
        reader = StructReader[memoryview](self._data)
        magic = reader.read(4)
        if bytes(magic) != b'\x00\x01\x00\x00':
            raise ValueError('not a valid Access database file')
        while reader.u8():
            pass
        raw_version = reader.u32()
        try:
            version = JetVersion(raw_version)
        except ValueError:
            version = JetVersion.V3
        self._version = version
        self._is_v3 = version == JetVersion.V3
        self._page_size = 0x800 if self._is_v3 else 0x1000

    def _categorize_pages(self):
        table_defs: dict[int, memoryview] = {}
        data_pages: dict[int, memoryview] = {}
        ps = self._page_size
        data = self._data
        for offset in range(0, len(data), ps):
            page = data[offset:offset + ps]
            if len(page) < 2:
                continue
            sig = bytes(page[:2])
            if sig == _TABLE_MAGIC:
                table_defs[offset] = page
            elif sig == _DATA_MAGIC:
                data_pages[offset] = page
        return table_defs, data_pages

    def _link_tables_to_data(self) -> dict[int, _TableObj]:
        tables: dict[int, _TableObj] = {}
        ps = self._page_size
        for offset, page in self._data_pages.items():
            try:
                reader = StructReader[memoryview](page)
                owner, _ = _parse_data_page_header(reader, self._is_v3)
            except Exception:
                continue
            page_offset = owner * ps
            if page_offset not in self._table_defs:
                continue
            if page_offset not in tables:
                tables[page_offset] = _TableObj(page_offset, self._table_defs[page_offset])
            tables[page_offset].linked_pages.append(page)
        return tables

    def _parse_catalog(self) -> dict[str, int]:
        catalog_offset = 2 * self._page_size
        if catalog_offset not in self._tables_with_data:
            return {}
        catalog_table = self._tables_with_data[catalog_offset]
        parsed = self._do_parse_table(catalog_table)
        if not parsed:
            return {}
        names = parsed.get('Name', [])
        ids = parsed.get('Id', [])
        types = parsed.get('Type', [])
        flags = parsed.get('Flags', [])
        mapping: dict[str, int] = {}
        for i, name in enumerate(names):
            if not isinstance(name, str):
                continue
            if name == 'MSysObjects':
                if i < len(ids):
                    mapping[name] = ids[i]
                continue
            if i < len(types) and types[i] == 1:
                if i < len(flags) and flags[i] not in _SYSTEM_FLAGS:
                    if i < len(ids):
                        mapping[name] = ids[i]
        return mapping

    def parse_table(self, name: str) -> dict[str, list]:
        """
        Parse a table by name. Returns a dictionary mapping column names to
        lists of row values.
        """
        table_id = self.catalog.get(name)
        if table_id is None:
            return {}
        table_offset = table_id * self._page_size
        table_obj = self._tables_with_data.get(table_offset)
        if table_obj is None:
            table_def = self._table_defs.get(table_offset)
            if table_def is not None:
                table_obj = _TableObj(table_offset, table_def)
            else:
                return {}
        return self._do_parse_table(table_obj)

    def _do_parse_table(self, table_obj: _TableObj) -> dict[str, list]:
        try:
            columns, variable_columns, column_count = self._get_table_columns(table_obj)
        except Exception:
            return {}
        if not columns:
            return {}

        parsed: dict[str, list] = defaultdict(list)

        if not table_obj.linked_pages:
            for col in columns.values():
                parsed[col.name] = []
            return dict(parsed)

        for data_chunk in table_obj.linked_pages:
            try:
                reader = StructReader[memoryview](data_chunk)
                _, record_offsets = _parse_data_page_header(reader, self._is_v3)
            except Exception:
                continue

            last_offset: int | None = None
            for rec_offset in record_offsets:
                if rec_offset & 0x8000:
                    last_offset = rec_offset & 0xFFF
                    continue
                if rec_offset & 0x4000:
                    ptr_offset = rec_offset & 0xFFF
                    last_offset = ptr_offset
                    if ptr_offset + 4 <= len(data_chunk):
                        overflow_ptr = struct.unpack_from('<I', data_chunk, ptr_offset)[0]
                        record = self._get_overflow_record(overflow_ptr)
                        if record:
                            self._parse_row(
                                record, columns, variable_columns, column_count, parsed)
                    continue

                if last_offset is None:
                    record = data_chunk[rec_offset:]
                else:
                    record = data_chunk[rec_offset:last_offset]
                last_offset = rec_offset
                if record:
                    self._parse_row(
                        record, columns, variable_columns, column_count, parsed)

        return dict(parsed)

    def _get_table_columns(self, table_obj: _TableObj):
        reader = StructReader[memoryview](table_obj.value)
        head = _parse_table_head(reader, self._is_v3)

        merged = table_obj.value[head.header_end:]
        if head.next_page:
            extra = self._merge_tdef_pages(head.next_page)
            merged = memoryview(bytes(merged) + bytes(extra))

        col_reader = StructReader[memoryview](merged)
        columns_list = _parse_columns(
            col_reader, head.column_count, head.real_index_count,
            head.index_count, self._is_v3)

        offset = min(c.column_index for c in columns_list) if columns_list else 0
        column_dict = {c.column_index - offset: c for c in columns_list}
        if len(column_dict) != len(columns_list):
            column_dict = {c.column_id: c for c in columns_list}

        return column_dict, head.variable_columns, head.column_count

    def _merge_tdef_pages(self, first_page_num: int) -> memoryview:
        parts = bytearray()
        page_data = self._table_defs.get(first_page_num * self._page_size)
        if page_data is None:
            return memoryview(parts)
        reader = StructReader[memoryview](page_data)
        next_page, header_end = _parse_tdef_header(reader)
        parts.extend(page_data[header_end:])
        while next_page:
            page_data = self._table_defs.get(next_page * self._page_size)
            if page_data is None:
                break
            reader = StructReader[memoryview](page_data)
            next_page, header_end = _parse_tdef_header(reader)
            parts.extend(page_data[header_end:])
        return memoryview(parts)

    def _parse_row(
        self,
        record: memoryview,
        columns: dict[int, _Column],
        variable_columns_count: int,
        column_count: int,
        parsed: dict[str, list],
    ):
        if len(record) < 1:
            return
        null_table_len = (column_count + 7) // 8
        if null_table_len >= len(record):
            return
        null_bytes = record[-null_table_len:]
        null_table = [
            ((null_bytes[i // 8]) & (1 << (i % 8))) != 0
            for i in range(null_table_len * 8)
        ]

        if not self._is_v3:
            if len(record) < 2:
                return
            row_data = record[2:]
        else:
            row_data = record[1:]

        var_columns: dict[int, _Column] = {}
        for i, column in columns.items():
            if not column.fixed_length:
                var_columns[i] = column
                continue
            col_name = column.name
            has_value = True
            if column.column_id < len(null_table):
                has_value = null_table[column.column_id]
            if column.type == ColumnType.BOOLEAN:
                parsed[col_name].append(has_value)
                continue
            if not has_value:
                parsed[col_name].append(None)
                continue
            if column.fixed_offset >= len(row_data):
                parsed[col_name].append(None)
                continue
            field_data = row_data[column.fixed_offset:]
            value = _parse_type(column.type, field_data, column.length, self._is_v3)
            parsed[col_name].append(value)

        if not var_columns:
            return

        var_columns = dict(sorted(var_columns.items()))
        reverse_record = record[::-1]
        reverse_after_null = reverse_record[null_table_len:]

        if self._is_v3:
            jump_table_count = (len(record) - 1) // 256
        else:
            jump_table_count = 0

        metadata = _parse_var_length_metadata(
            memoryview(reverse_after_null), self._is_v3, jump_table_count)

        if metadata is None:
            return

        if self._is_v3 and metadata.field_count != variable_columns_count:
            search_byte = variable_columns_count & 0xFF
            pos = bytes(reverse_after_null).find(bytes([search_byte]))
            if pos != -1 and pos < 10:
                adjusted = memoryview(reverse_after_null[pos:])
                metadata = _parse_var_length_metadata(
                    adjusted, self._is_v3, jump_table_count)
                if metadata is not None:
                    metadata = metadata._replace(
                        metadata_end=metadata.metadata_end + pos)
            else:
                return

        if not metadata or not metadata.field_offsets:
            return

        offsets = metadata.field_offsets
        jump_addition = 0
        for i, col_index in enumerate(var_columns):
            column = var_columns[col_index]
            col_name = column.name
            has_value = True
            if column.column_id < len(null_table):
                has_value = null_table[column.column_id]
            if not has_value:
                parsed[col_name].append(None)
                continue

            if self._is_v3 and i in metadata.jump_table:
                jump_addition += 0x100

            if i >= len(offsets):
                parsed[col_name].append(None)
                continue

            rel_start = offsets[i]
            if i + 1 < len(offsets):
                rel_end = offsets[i + 1]
            else:
                rel_end = metadata.var_len_count

            if rel_start == rel_end:
                parsed[col_name].append('')
                continue

            field_data = record[rel_start + jump_addition:rel_end + jump_addition]

            if column.type == ColumnType.MEMO:
                try:
                    value = self._parse_memo(field_data, raw=False)
                except Exception:
                    value = bytes(field_data)
            elif column.type == ColumnType.OLE:
                try:
                    value = self._parse_memo(field_data, raw=True)
                except Exception:
                    value = bytes(field_data)
            elif column.type == ColumnType.NUMERIC:
                if len(field_data) == 17:
                    scale = column.scale if column.scale is not None else 6
                    value = _numeric_to_string(field_data, scale)
                else:
                    value = bytes(field_data)
            else:
                value = _parse_type(column.type, field_data, len(field_data), self._is_v3)
            parsed[col_name].append(value)

    def _parse_memo(self, data: memoryview, raw: bool = False):
        if len(data) < 12:
            return bytes(data)
        memo_length = struct.unpack_from('<I', data, 0)[0]
        record_pointer = struct.unpack_from('<I', data, 4)[0]
        memo_end = 12

        if memo_length & 0x80000000:
            inline_length = memo_length & 0x3FFFFFFF
            if len(data) < memo_end + inline_length:
                memo_data = data[memo_end:]
            else:
                memo_data = data[memo_end:memo_end + inline_length]
        elif memo_length & 0x40000000:
            result = self._get_overflow_record(record_pointer)
            if result is None:
                return None
            memo_data = result
        else:
            rec_data = self._get_overflow_record(record_pointer)
            if rec_data is None:
                return None
            next_page = struct.unpack_from('<I', rec_data, 0)[0]
            parts = bytearray()
            while next_page:
                parts.extend(rec_data[4:])
                rec_data = self._get_overflow_record(next_page)
                if rec_data is None:
                    break
                next_page = struct.unpack_from('<I', rec_data, 0)[0]
            if rec_data is not None:
                parts.extend(rec_data[4:])
            memo_data = memoryview(parts)

        if not memo_data:
            return None
        if raw:
            return bytes(memo_data)
        return _parse_type(ColumnType.TEXT, memo_data, len(memo_data), self._is_v3)

    def _get_overflow_record(self, record_pointer: int) -> memoryview | None:
        record_offset = record_pointer & 0xFF
        page_num = record_pointer >> 8
        page = self._data_pages.get(page_num * self._page_size)
        if page is None:
            return None
        try:
            reader = StructReader[memoryview](page)
            _, offsets = _parse_data_page_header(reader, self._is_v3)
        except Exception:
            return None
        if record_offset >= len(offsets):
            return None
        start = offsets[record_offset]
        if start & 0x8000:
            start = start & 0xFFF
        if record_offset == 0:
            return page[start:]
        else:
            end = offsets[record_offset - 1]
            if end & 0x8000 and (end & 0xFF != 0):
                end = end & 0xFFF
            return page[start:end]
