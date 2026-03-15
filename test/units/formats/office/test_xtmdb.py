from __future__ import annotations

import struct
import unittest
import uuid

from datetime import datetime

from refinery.lib.access import (
    AccessDatabase,
    ColumnType,
    _decode_text,
    _mdb_date,
    _numeric_to_string,
    _parse_data_page_header,
    _parse_tdef_header,
    _parse_type,
    _parse_var_length_metadata,
)
from refinery.lib.structures import StructReader

from ... import TestUnitBase


class TestAccessExtractor(TestUnitBase):

    def _get_table_chunks(self, data, unit, table_name):
        chunks = {}
        for c in (data | unit | []):
            path = F'{c.meta["path"]}'
            if path.startswith(F'{table_name}/'):
                chunks[path] = c
        return chunks

    def test_all_column_types(self):
        unit = self.load()
        data = self.download_sample(
            'afdf496b673b9db6f695ab79edfb7d7b59aae1e732470f6085f7954cfc86a744')
        chunks = self._get_table_chunks(data, unit, 'AllTypes')
        self.assertGreater(len(chunks), 0)
        self.assertEqual(bytes(chunks['AllTypes/0/BoolCol']), b'True')
        self.assertEqual(bytes(chunks['AllTypes/1/BoolCol']), b'False')
        self.assertEqual(bytes(chunks['AllTypes/0/ByteCol']), b'42')
        self.assertEqual(bytes(chunks['AllTypes/0/IntCol']), b'1000')
        self.assertEqual(bytes(chunks['AllTypes/0/LongCol']), b'99999')
        self.assertEqual(bytes(chunks['AllTypes/1/LongCol']), b'2147483647')
        self.assertAlmostEqual(
            float(bytes(chunks['AllTypes/0/SingleCol'])), 3.14, places=1)
        self.assertAlmostEqual(
            float(bytes(chunks['AllTypes/0/DoubleCol'])), 2.718281828, places=6)
        self.assertEqual(
            bytes(chunks['AllTypes/0/DateCol']), b'2024-06-15 10:30:00')
        self.assertEqual(bytes(chunks['AllTypes/0/TextCol']), b'Hello World')
        self.assertEqual(
            bytes(chunks['AllTypes/0/MemoCol']),
            b'This is a memo field with some text.')
        self.assertEqual(bytes(chunks['AllTypes/2/TextCol']), b'sparse row')
        self.assertIn(b'-', bytes(chunks['AllTypes/0/GuidCol']))
        self.assertEqual(
            bytes(chunks['AllTypes/0/BinaryCol']),
            b'\xde\xad\xbe\xef' * 4)

    def test_multi_table(self):
        unit = self.load()
        data = self.download_sample(
            '3dd8253db12a8f799efd3daba79533df3df259db43d0daaed369335012d609a4')
        all_chunks = {F'{c.meta["path"]}': c for c in (data | unit | [])}
        tables = {p.split('/')[0] for p in all_chunks}
        self.assertIn('TableA', tables)
        self.assertIn('TableB', tables)
        self.assertIn('TableC', tables)
        self.assertEqual(bytes(all_chunks['TableA/0/Name']), b'alpha')
        self.assertEqual(bytes(all_chunks['TableA/1/Name']), b'bravo')
        self.assertEqual(bytes(all_chunks['TableA/2/Name']), b'charlie')
        self.assertEqual(bytes(all_chunks['TableA/0/Value']), b'1')
        self.assertEqual(bytes(all_chunks['TableA/1/Value']), b'2')
        self.assertEqual(bytes(all_chunks['TableA/2/Value']), b'3')
        self.assertAlmostEqual(
            float(bytes(all_chunks['TableB/0/X'])), 1.0, places=1)
        self.assertAlmostEqual(
            float(bytes(all_chunks['TableB/0/Y'])), 2.0, places=1)
        self.assertEqual(bytes(all_chunks['TableC/0/Label']), b'only row')
        self.assertNotIn('EmptyTable', tables)

    def test_long_memo(self):
        unit = self.load()
        data = self.download_sample(
            '1858693a66aafdacf78a254d5c392e6165b909696d1ed953d93610f4e6be7126')
        chunks = self._get_table_chunks(data, unit, 'LargeData')
        memo = bytes(chunks['LargeData/0/LongMemo'])
        self.assertEqual(memo, b'ABCDEFGHIJ' * 1000)
        self.assertEqual(
            bytes(chunks['LargeData/1/LongMemo']),
            b'Short memo for comparison.')
        ole = bytes(chunks['LargeData/0/LargeOLE'])
        self.assertEqual(ole, bytes(range(256)) * 32)
        self.assertEqual(bytes(chunks['LargeData/1/LargeOLE']), b'\x00\x01\x02\x03')

    def test_nullable(self):
        unit = self.load()
        data = self.download_sample(
            '089b0c5ad2962ffc066c9dcf5cc5722b7c4935b67d2d6a0e30b48830acc7a268')
        chunks = self._get_table_chunks(data, unit, 'NullHeavy')
        self.assertGreater(len(chunks), 0)
        self.assertEqual(bytes(chunks['NullHeavy/0/A']), b'42')
        self.assertEqual(bytes(chunks['NullHeavy/3/A']), b'100')
        self.assertEqual(bytes(chunks['NullHeavy/1/B']), b'only-B')
        self.assertEqual(bytes(chunks['NullHeavy/3/B']), b'full row')
        self.assertAlmostEqual(
            float(bytes(chunks['NullHeavy/2/C'])), 9.99, places=1)
        self.assertEqual(bytes(chunks['NullHeavy/3/D']), b'memo text')
        self.assertNotIn('NullHeavy/0/B', chunks)
        self.assertNotIn('NullHeavy/0/C', chunks)
        self.assertNotIn('NullHeavy/0/D', chunks)
        self.assertNotIn('NullHeavy/0/F', chunks)

    def test_unknown_table_name(self):
        data = self.download_sample(
            'afdf496b673b9db6f695ab79edfb7d7b59aae1e732470f6085f7954cfc86a744')
        db = AccessDatabase(data)
        result = db.parse_table('nonexistent_table_xyz')
        self.assertEqual(result, {})

    def test_real_world_01(self):
        data = self.download_sample(
            'f711327f40e17453a70c12155fe6a628ea67d3d2457356a4a95bb2f87d94790e')
        unit = self.load()
        results = data | unit | {str}
        self.assertIn('2011-12-07 09:57:31', results)

    def test_handles_ace_magic(self):
        header = b'\0\x01\0\0Standard ACE DB' + b'\0' * 100
        self.assertTrue(self.unit().handles(header))

    def test_handles_jet_magic(self):
        header = b'\0\x01\0\0Standard Jet DB' + b'\0' * 100
        self.assertTrue(self.unit().handles(header))

    def test_handles_unknown(self):
        self.assertFalse(self.unit().handles(b'PK\x03\x04' + b'\0' * 100))

    def test_invalid_header(self):
        with self.assertRaises(ValueError):
            AccessDatabase(b'\x00' * 32)

    def test_end_to_end_unpack(self):
        unit = self.load()
        data = self.download_sample('afdf496b673b9db6f695ab79edfb7d7b59aae1e732470f6085f7954cfc86a744')
        chunks = data | unit | []
        paths = [F'{c.meta["path"]}' for c in chunks]
        self.assertTrue(any('AllTypes' in p for p in paths))
        self.assertTrue(any('/BoolCol' in p for p in paths))
        self.assertTrue(any('/ByteCol' in p for p in paths))
        self.assertTrue(any('/TextCol' in p for p in paths))
        for chunk in chunks:
            self.assertIsInstance(bytes(chunk), bytes)

    def test_v3_multipage_tdef(self):
        data = self.download_sample(
            '1b39977019ade7e4de616596dd827ec6233c056a368f30035bde5175ce8036e0')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        self.assertIn('tblMitgliederkartei', db.catalog)
        result = db.parse_table('tblMitgliederkartei')
        self.assertGreaterEqual(len(result), 76)

    def test_v3_deleted_and_overflow_records(self):
        data = self.download_sample(
            '219e5aed6ceed235d7b5267fded044d4b4f0e64269b825ee2fbe893a52a85928')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        self.assertIn('biblioteca', db.catalog)
        result = db.parse_table('biblioteca')
        self.assertIn('TIPO', result)
        self.assertGreater(len(result['TIPO']), 0)

    def test_v3_tdef_chain(self):
        data = self.download_sample(
            '40b4fe5250ad72931a28022fcc21f10abfcab1824b1f73b0588642d3b34c6808')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        self.assertIn('TRAB', db.catalog)
        result = db.parse_table('TRAB')
        self.assertGreaterEqual(len(result), 100)

    def test_v3_metadata_adjustment(self):
        data = self.download_sample(
            '89bd6f49a0b66e56919ce6dbe8fc989f00814034c9b424a9d834d8b3565f0196')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        tables = [n for n in db.catalog if not n.startswith('MSys')]
        self.assertEqual(len(tables), 1)
        result = db.parse_table(tables[0])
        self.assertGreater(len(result), 0)

    def test_v3_multiple_user_tables(self):
        data = self.download_sample(
            '555367be91e53fffa5680946ef1c379e6102202c8fefe836d7c1760ad6654ff9')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        for name in db.catalog:
            db.parse_table(name)
        tables = {n for n in db.catalog if not n.startswith('MSys')}
        self.assertIn('Camera', tables)
        self.assertIn('Mesh', tables)

    def test_v3_jump_table(self):
        data = self.download_sample(
            '2b7f9dbea0f850943d317cdfce5601b856caee39e932a13a098d503a648107ac')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        for name in db.catalog:
            db.parse_table(name)
        result = db.parse_table('Schuetzendaten')
        self.assertIn('M_Name', result)
        self.assertEqual(len(result['M_Name']), 2)

    def test_v3_memo_field(self):
        data = self.download_sample(
            '597a7b6b151575cd629434af706ccd8662262d2da59e0ca0e6d554c900afa74d')
        db = AccessDatabase(data)
        self.assertTrue(db._is_v3)
        for name in db.catalog:
            db.parse_table(name)
        result = db.parse_table('cada')
        self.assertIn('cliente', result)
        self.assertEqual(len(result['cliente']), 6)


class TestAccessLib(unittest.TestCase):

    def test_mdb_date_valid(self):
        value = 45678.5
        raw = struct.unpack('<Q', struct.pack('<d', value))[0]
        result = _mdb_date(raw)
        self.assertIsInstance(result, datetime)
        assert isinstance(result, datetime)
        self.assertEqual(result.year, 2025)

    def test_mdb_date_epoch(self):
        raw = struct.unpack('<Q', struct.pack('<d', 0.0))[0]
        result = _mdb_date(raw)
        self.assertIsNone(result)

    def test_mdb_date_overflow(self):
        raw = 0xFFFFFFFFFFFFFFFF
        result = _mdb_date(raw)
        self.assertIsNone(result)

    def test_mdb_date_huge_positive(self):
        raw = struct.unpack('<Q', struct.pack('<d', 1e300))[0]
        result = _mdb_date(raw)
        self.assertIsNone(result)

    def test_numeric_positive(self):
        data = struct.pack('<BIIII', 0, 0, 0, 0, 1234567890)
        result = _numeric_to_string(data, scale=6)
        self.assertIn('1234', result)
        self.assertNotIn('-', result)

    def test_numeric_negative(self):
        data = struct.pack('<BIIII', 1, 0, 0, 0, 1000000)
        result = _numeric_to_string(data, scale=6)
        self.assertTrue(result.startswith('-'))

    def test_numeric_no_decimal(self):
        data = struct.pack('<BIIII', 0, 0, 0, 0, 5)
        result = _numeric_to_string(data, scale=6)
        self.assertNotIn('.', result)
        self.assertEqual(result, '5')

    def test_numeric_with_decimal(self):
        data = struct.pack('<BIIII', 0, 0, 0, 0, 123456789)
        result = _numeric_to_string(data, scale=4)
        self.assertIn('.', result)
        self.assertEqual(result, '12345.6789')

    def test_decode_text_utf8(self):
        result = _decode_text('Hello World'.encode('utf-8'))
        self.assertEqual(result, 'Hello World')

    def test_decode_text_latin1_fallback(self):
        data = b'\xe4\xf6\xfc'
        result = _decode_text(data)
        self.assertEqual(result, '\xe4\xf6\xfc')

    def test_parse_type_int8(self):
        data = struct.pack('b', -5)
        self.assertEqual(_parse_type(ColumnType.INT8, data), -5)

    def test_parse_type_int16(self):
        data = struct.pack('<h', -1000)
        self.assertEqual(_parse_type(ColumnType.INT16, data), -1000)

    def test_parse_type_int32(self):
        data = struct.pack('<i', 42)
        self.assertEqual(_parse_type(ColumnType.INT32, data), 42)

    def test_parse_type_money(self):
        data = struct.pack('<q', 12345)
        self.assertEqual(_parse_type(ColumnType.MONEY, data), 12345)

    def test_parse_type_float32(self):
        data = struct.pack('<f', 3.14)
        result = _parse_type(ColumnType.FLOAT32, data)
        self.assertIsInstance(result, float)
        assert isinstance(result, float)
        self.assertAlmostEqual(result, 3.14, places=2)

    def test_parse_type_float64(self):
        data = struct.pack('<d', 2.718)
        result = _parse_type(ColumnType.FLOAT64, data)
        self.assertIsInstance(result, float)
        assert isinstance(result, float)
        self.assertAlmostEqual(result, 2.718, places=3)

    def test_parse_type_datetime(self):
        data = struct.pack('<d', 45000.0)
        result = _parse_type(ColumnType.DATETIME, data)
        self.assertIsInstance(result, datetime)

    def test_parse_type_binary_with_length(self):
        data = b'\x01\x02\x03\x04\x05'
        result = _parse_type(ColumnType.BINARY, data, length=3)
        self.assertEqual(result, b'\x01\x02\x03')

    def test_parse_type_binary_without_length(self):
        data = b'\xDE\xAD\xBE\xEF'
        result = _parse_type(ColumnType.BINARY, data)
        self.assertEqual(result, b'\xDE\xAD\xBE\xEF')

    def test_parse_type_ole(self):
        data = b'\x01\x02\x03'
        result = _parse_type(ColumnType.OLE, data)
        self.assertEqual(result, b'\x01\x02\x03')

    def test_parse_type_guid(self):
        data = b'\x12\x34\x56\x78' * 4
        result = _parse_type(ColumnType.GUID, data)
        self.assertIsInstance(result, uuid.UUID)
        self.assertIn('-', str(result))

    def test_parse_type_numeric(self):
        data = b'\x00' * 17
        result = _parse_type(ColumnType.NUMERIC, data)
        self.assertEqual(len(result), 17)

    def test_parse_type_text_v4_utf16(self):
        data = 'Test'.encode('utf-16-le')
        result = _parse_type(ColumnType.TEXT, data, is_v3=False)
        self.assertEqual(result, 'Test')

    def test_parse_type_text_v4_bom(self):
        data = b'\xff\xfe' + 'Hello'.encode('utf-8')
        result = _parse_type(ColumnType.TEXT, data, is_v3=False)
        self.assertIn('Hello', result)

    def test_parse_type_text_v4_feff_bom(self):
        data = b'\xfe\xff' + 'World'.encode('utf-8')
        result = _parse_type(ColumnType.TEXT, data, is_v3=False)
        self.assertIn('World', result)

    def test_parse_type_text_v3(self):
        data = 'Hello'.encode('utf-8')
        result = _parse_type(ColumnType.TEXT, data, is_v3=True)
        self.assertEqual(result, 'Hello')

    def test_parse_type_complex(self):
        data = struct.pack('<i', 999)
        result = _parse_type(ColumnType.COMPLEX, data)
        self.assertEqual(result, 999)

    def test_parse_type_unknown(self):
        data = b'\x01\x02\x03'
        result = _parse_type(255, data)
        self.assertEqual(result, b'\x01\x02\x03')

    def test_invalid_data_page_magic(self):
        data = memoryview(bytearray(b'\xFF\xFF' + b'\x00' * 30))
        reader = StructReader[memoryview](data)
        with self.assertRaises(ValueError):
            _parse_data_page_header(reader, is_v3=False)

    def test_invalid_tdef_magic(self):
        data = memoryview(bytearray(b'\xFF\xFF' + b'\x00' * 30))
        reader = StructReader[memoryview](data)
        with self.assertRaises(ValueError):
            _parse_tdef_header(reader)

    def test_valid_data_page_header_v4(self):
        page = bytearray(32)
        page[0:2] = b'\x01\x01'
        page[2:4] = b'\x00\x00'
        page[4:8] = struct.pack('<I', 3)
        page[8:12] = b'\x00' * 4
        page[12:14] = struct.pack('<H', 0)
        reader = StructReader[memoryview](memoryview(page))
        owner, offsets = _parse_data_page_header(reader, is_v3=False)
        self.assertEqual(owner, 3)
        self.assertEqual(offsets, [])

    def test_valid_data_page_header_v3(self):
        page = bytearray(16)
        page[0:2] = b'\x01\x01'
        page[2:4] = b'\x00\x00'
        page[4:8] = struct.pack('<I', 7)
        page[8:10] = struct.pack('<H', 1)
        page[10:12] = struct.pack('<H', 100)
        reader = StructReader[memoryview](memoryview(page))
        owner, offsets = _parse_data_page_header(reader, is_v3=True)
        self.assertEqual(owner, 7)
        self.assertEqual(offsets, [100])

    def test_valid_tdef_header(self):
        page = bytearray(16)
        page[0:2] = b'\x02\x01'
        page[2:4] = b'\x00\x00'
        page[4:8] = struct.pack('<I', 5)
        reader = StructReader[memoryview](memoryview(page))
        next_page, header_end = _parse_tdef_header(reader)
        self.assertEqual(next_page, 5)
        self.assertEqual(header_end, 8)

    def test_var_length_metadata_v4(self):
        field_count = 3
        var_len_count = 10
        data = bytearray()
        data.extend(struct.pack('>H', field_count))
        for i in range(field_count & 0xFF):
            data.extend(struct.pack('>H', (i + 1) * 10))
        data.extend(struct.pack('>H', var_len_count))
        result = _parse_var_length_metadata(memoryview(data), is_v3=False)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.field_count, field_count)
        self.assertEqual(result.var_len_count, var_len_count)
        self.assertEqual(len(result.field_offsets), field_count & 0xFF)

    def test_var_length_metadata_v3(self):
        data = bytearray()
        data.append(2)
        data.append(10)
        data.append(20)
        data.append(5)
        result = _parse_var_length_metadata(
            memoryview(data), is_v3=True, jump_table_count=0)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.field_count, 2)
        self.assertEqual(result.var_len_count, 5)

    def test_var_length_metadata_error(self):
        result = _parse_var_length_metadata(memoryview(b''), is_v3=False)
        self.assertIsNone(result)

    def test_invalid_header_short(self):
        with self.assertRaises(Exception):
            AccessDatabase(b'\x00' * 2)

    def test_invalid_header_wrong_magic(self):
        with self.assertRaises(ValueError):
            AccessDatabase(b'\xFF\xFF\xFF\xFF' + b'\x00' * 100)

    def test_access_database_catalog_empty(self):
        header = bytearray(0x2000)
        header[0:4] = b'\x00\x01\x00\x00'
        header[4] = 0
        header[5:9] = struct.pack('<I', 0x01)
        db = AccessDatabase(bytes(header))
        self.assertIsInstance(db.catalog, dict)

    def test_access_database_parse_table_no_data_pages(self):
        ps = 0x1000
        data = bytearray(ps * 4)
        data[0:4] = b'\x00\x01\x00\x00'
        data[4] = 0
        data[5:9] = struct.pack('<I', 0x01)
        db = AccessDatabase(bytes(data))
        result = db.parse_table('anything')
        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main()
