import gzip

from ... import TestUnitBase


class TestExtractGzip(TestUnitBase):

    def test_simple_gzip(self):
        content = b'Hello, this is test data for gzip compression!'
        compressed = gzip.compress(content)
        unit = self.load()
        results = compressed | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), content)

    def test_gzip_with_filename(self):
        import io
        content = b'Named gzip content'
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', filename='test.txt') as f:
            f.write(content)
        compressed = buf.getvalue()
        unit = self.load()
        results = compressed | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), content)

    def test_handles_gzip_magic(self):
        from refinery.units.formats.archive.xtgz import xtgz
        self.assertTrue(xtgz.handles(b'\x1F\x8B\x08\x00'))
        self.assertFalse(xtgz.handles(b'\x50\x4B\x03\x04'))

    def test_extract_simple(self):
        data = gzip.compress(b'Hello World')
        unit = self.load()
        result = unit(data)
        self.assertEqual(result, b'Hello World')

    def test_extract_with_filename(self):
        import io
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', filename='test.txt') as f:
            f.write(b'content')
        unit = self.load()
        chunks = buf.getvalue() | unit | []
        self.assertTrue(len(chunks) > 0)
        self.assertEqual(bytes(chunks[0]), b'content')

    def test_handles_method(self):
        from refinery.units.formats.archive.xtgz import xtgz
        data = gzip.compress(b'test')
        self.assertTrue(xtgz.handles(data))
        self.assertFalse(xtgz.handles(b'not gzip'))
