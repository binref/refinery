import json
import struct

from ... import TestUnitBase


class TestExtractASAR(TestUnitBase):

    @staticmethod
    def _make_asar(files: dict) -> bytes:
        directory = {"files": {}}
        offset = 0
        payloads = []
        for name, content in files.items():
            directory["files"][name] = {"offset": str(offset), "size": len(content)}
            payloads.append(content)
            offset += len(content)
        dir_json = json.dumps(directory).encode('utf-8')
        dir_size = len(dir_json)
        header = struct.pack('<IIII', 4, dir_size + 8, 0, dir_size) + dir_json
        return header + b''.join(payloads)

    def test_extract_single_file(self):
        asar = self._make_asar({'hello.txt': b'Hello ASAR'})
        unit = self.load()
        results = asar | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), b'Hello ASAR')

    def test_extract_multiple_files(self):
        asar = self._make_asar({
            'alpha.bin': b'AAAA',
            'bravo.log': b'BBBBB',
            'charlie.dat': b'CCCCCC',
        })
        results = asar | self.load() | {bytes}
        self.assertSetEqual(results, {b'AAAA', b'BBBBB', b'CCCCCC'})

    def test_handles_detection(self):
        from refinery.units.formats.archive.xtasar import xtasar
        valid = self._make_asar({'t.txt': b'x'})
        self.assertTrue(xtasar.handles(valid))
        self.assertFalse(xtasar.handles(b'\x00\x00\x00\x00' + b'\x00' * 32))
        self.assertFalse(xtasar.handles(b'this is not an asar archive'))
        self.assertFalse(xtasar.handles(b''))

    def test_empty_directory(self):
        asar = self._make_asar({})
        unit = self.load()
        results = asar | unit | []
        self.assertEqual(len(results), 0)
