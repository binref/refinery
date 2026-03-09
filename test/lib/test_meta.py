from typing import Iterable, List

from refinery.lib.meta import metavars
from refinery.lib.frame import Chunk
from refinery.lib.loader import load_pipeline as L, load_detached as U
from refinery.lib.meta import LazyMetaOracle
from refinery.units import Unit

from .. import TestBase


class TestMeta(TestBase):

    def test_binary_printer_for_integer_arrays(self):
        data = Chunk()
        data['k'] = [t for t in b'refinery']
        meta = metavars(data)
        self.assertEqual(meta.format_bin('{k:itob}', 'utf8', data), b'refinery')

    def test_binary_formatter_fallback(self):
        data = self.generate_random_buffer(3210)
        meta = metavars(data)
        self.assertEqual(meta.format_bin('{size!r}', 'utf8', data).strip(), b'03.210 kB')

    def test_binary_formatter_literal(self):
        meta = metavars(B'')
        self.assertEqual(meta.format_bin('{726566696E657279!H}', 'utf8'), b'refinery')

    def test_hex_byte_strings(self):
        pl = L('emit Hello [| cm -2 | pf {sha256!r} ]')
        self.assertEqual(pl(), b'185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')

    def test_intrinsic_properties_are_recomputed(self):
        pl = L('emit FOO-BAR [| cm size | snip :1 | pf {size} ]')
        self.assertEqual(pl(), B'1')

    def test_magic_values_update(self):
        pl = L('emit FOO-BAR [| cm sha256 | snip :3 | pf {sha256} ]')
        self.assertEqual(pl(), b'9520437ce8902eb379a7d8aaa98fc4c94eeb07b6684854868fa6f72bf34b0fd3')

    def test_costly_variable_is_discarded(self):
        out, = L('emit rep[0x2000]:X [| cm sha256 | snip 1: ]')
        self.assertNotIn('sha256', out.meta.keys())

    def test_cheap_variable_is_not_discarded(self):
        out, = L('emit rep[0x100]:X [| cm sha256 | snip 1: | mvg ]')
        self.assertIn('sha256', set(out.meta.keys()))
        self.assertEqual(out.meta['sha256'], '439d26737c1313821f1b5e953a866e680a3712086f7b27ffc2e3e3f224e04f3f')

    def test_history_storage(self):
        class spy(Unit):
            chunks: List[Chunk] = []

            def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
                for chunk in inputs:
                    spy.chunks.append(chunk.copy())
                    yield chunk

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x alpha') | spy | U('nop ]]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0), (True, 0)]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x alpha') | U('mvg ]') | spy | U('nop ]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0)]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x beta') | spy | U('nop ]]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0), (False, b'beta')]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x beta') | U('mvg ]') | spy | U('nop ]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (False, b'beta')]})

    def test_regression_nulled_history(self):
        pl = L('emit FOO [[| put b [| emit BAR ]| rex . | swap k | swap b | pf {}/{k} | sep / ]]')
        self.assertEqual(pl(), B'FOO/B/FOO/A/FOO/R')

    def test_wrapper_works_after_deserialization(self):
        e1 = L('emit range:0x100 [| cm entropy | pf {entropy!r} ]') | str
        e2 = L('emit range:0x100 | pf {entropy!r}') | str
        self.assertEqual(e1, e2)
        self.assertEqual(e1, '100.00%')

    def test_metavar_size(self):
        data = Chunk(b'Hello World')
        meta = metavars(data)
        self.assertEqual(meta['size'], 11)

    def test_metavar_md5(self):
        import hashlib
        data = Chunk(b'Hello World')
        meta = metavars(data)
        expected = hashlib.md5(b'Hello World').hexdigest()
        self.assertEqual(meta['md5'], expected)

    def test_metavar_sha256(self):
        import hashlib
        data = Chunk(b'Hello World')
        meta = metavars(data)
        expected = hashlib.sha256(b'Hello World').hexdigest()
        self.assertEqual(meta['sha256'], expected)

    def test_metavar_crc32(self):
        import zlib
        data = Chunk(b'Hello World')
        meta = metavars(data)
        expected_crc = F'{zlib.crc32(b"Hello World") & 0xFFFFFFFF:08X}'
        crc_value = meta['crc32']
        if isinstance(crc_value, (bytes, bytearray)):
            crc_value = crc_value.decode('ascii')
        self.assertEqual(crc_value.upper(), expected_crc.upper())

    def test_format_bin_basic(self):
        data = Chunk(b'test data')
        meta = metavars(data)
        result = meta.format_bin('{size}', 'utf8', data)
        self.assertEqual(result, b'9')

    def test_format_str_basic(self):
        data = Chunk(b'test data')
        meta = metavars(data)
        result = meta.format_str('{size}', 'utf8', data)
        self.assertEqual(result, '9')

    def test_meta_pipeline_index(self):
        pl = L('emit FOO BAR BAZ [| pf {index} ]')
        results = [bytes(r) for r in pl]
        self.assertEqual(results, [b'0', b'1', b'2'])

    def test_meta_custom_variable_roundtrip(self):
        pl = L('emit DATA [| put x hello | pf {x} ]')
        self.assertEqual(pl(), b'hello')


class TestLazyMetaOracle(TestBase):

    def test_magic_variable_size(self):
        oracle = LazyMetaOracle(b'Hello World')
        self.assertEqual(oracle['size'], 11)

    def test_magic_variable_size_empty(self):
        oracle = LazyMetaOracle(b'')
        self.assertEqual(oracle['size'], 0)

    def test_magic_variable_entropy(self):
        oracle = LazyMetaOracle(bytes(range(256)))
        ent = oracle['entropy']
        self.assertAlmostEqual(float(ent), 1.0, places=2)

    def test_magic_variable_entropy_uniform(self):
        oracle = LazyMetaOracle(b'\x00' * 100)
        ent = oracle['entropy']
        self.assertAlmostEqual(float(ent), 0.0, places=4)

    def test_magic_variable_md5(self):
        import hashlib
        data = b'test data for md5'
        oracle = LazyMetaOracle(data)
        expected = hashlib.md5(data).hexdigest()
        self.assertEqual(str(oracle['md5']), expected)

    def test_magic_variable_sha256(self):
        import hashlib
        data = b'test data for sha256'
        oracle = LazyMetaOracle(data)
        expected = hashlib.sha256(data).hexdigest()
        self.assertEqual(str(oracle['sha256']), expected)

    def test_magic_variable_sha1(self):
        import hashlib
        data = b'test data for sha1'
        oracle = LazyMetaOracle(data)
        expected = hashlib.sha1(data).hexdigest()
        self.assertEqual(str(oracle['sha1']), expected)

    def test_magic_variable_crc32(self):
        import zlib
        data = b'test data for crc32'
        oracle = LazyMetaOracle(data)
        expected = (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'big').hex()
        self.assertEqual(str(oracle['crc32']), expected)

    def test_magic_variable_ext(self):
        oracle = LazyMetaOracle(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
        ext = str(oracle['ext'])
        self.assertIsInstance(ext, str)

    def test_magic_variable_mime(self):
        oracle = LazyMetaOracle(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
        mime = str(oracle['mime'])
        self.assertIsInstance(mime, str)

    def test_format_str_with_size(self):
        data = b'ABCDE'
        oracle = LazyMetaOracle(data)
        result = oracle.format_str('{size}', 'utf8', data)
        self.assertEqual(result, '5')

    def test_format_str_with_repr_size(self):
        data = b'A' * 3210
        oracle = LazyMetaOracle(data)
        result = oracle.format_str('{size!r}', 'utf8', data)
        self.assertIn('kB', result)

    def test_format_str_with_md5(self):
        import hashlib
        data = b'hello'
        oracle = LazyMetaOracle(data)
        result = oracle.format_str('{md5}', 'utf8', data)
        self.assertEqual(result, hashlib.md5(data).hexdigest())

    def test_format_bin_returns_bytes(self):
        data = b'test'
        oracle = LazyMetaOracle(data)
        result = oracle.format_bin('{size}', 'utf8', data)
        self.assertIsInstance(result, (bytes, bytearray, memoryview))
        self.assertEqual(bytes(result), b'4')

    def test_format_bin_hex_literal(self):
        oracle = LazyMetaOracle(b'')
        result = oracle.format_bin('{48454C4C4F!h}', 'utf8')
        self.assertEqual(bytes(result), b'HELLO')

    def test_format_bin_repr_entropy(self):
        data = bytes(range(256))
        oracle = LazyMetaOracle(data)
        result = oracle.format_bin('{entropy!r}', 'utf8', data)
        self.assertIn(b'%', result)

    def test_chunk_update_dict(self):
        oracle = LazyMetaOracle(b'data')
        oracle['foo'] = 'bar'
        oracle.update({'baz': 'qux'})
        self.assertEqual(str(oracle['baz']), 'qux')

    def test_chunk_update_oracle(self):
        oracle1 = LazyMetaOracle(b'data1')
        oracle1['x'] = 'hello'
        oracle2 = LazyMetaOracle(b'data2')
        oracle2.update(oracle1)
        self.assertEqual(str(oracle2['x']), 'hello')

    def test_chunk_get_with_default(self):
        oracle = LazyMetaOracle(b'data')
        result = oracle.get('nonexistent', 'default_val')
        self.assertEqual(result, 'default_val')

    def test_chunk_get_existing(self):
        oracle = LazyMetaOracle(b'data')
        oracle['myvar'] = 'myval'
        result = oracle.get('myvar')
        self.assertIsNotNone(result)

    def test_chunk_items_includes_index(self):
        oracle = LazyMetaOracle(b'data')
        oracle.index = 7
        items_dict = dict(oracle.items())
        self.assertIn('index', items_dict)
        self.assertEqual(items_dict['index'], 7)

    def test_chunk_discard(self):
        oracle = LazyMetaOracle(b'data')
        oracle['temp'] = 'value'
        oracle.discard('temp')
        with self.assertRaises(KeyError):
            oracle['temp']

    def test_chunk_discard_nonexistent(self):
        oracle = LazyMetaOracle(b'data')
        oracle.discard('nonexistent')

    def test_serialize_empty_scope(self):
        oracle = LazyMetaOracle(b'data')
        oracle['x'] = 'val'
        result = oracle.serialize(0)
        self.assertEqual(result, {})

    def test_serialize_with_scope(self):
        oracle = LazyMetaOracle(b'data', scope=0)
        oracle['x'] = 'val'
        result = oracle.serialize(2)
        self.assertIn('x', result)

    def test_contains_derivation(self):
        oracle = LazyMetaOracle(b'data')
        self.assertIn('size', oracle)
        self.assertIn('md5', oracle)
        self.assertIn('index', oracle)
        self.assertNotIn('nonexistent_var_xyz', oracle)

    def test_len_counts_current_and_temp(self):
        oracle = LazyMetaOracle(b'data')
        initial_len = len(oracle)
        oracle['var1'] = 'a'
        oracle['var2'] = 'b'
        self.assertEqual(len(oracle), initial_len + 2)
