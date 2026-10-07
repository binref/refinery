import hashlib
import json
import lzma
import struct

from unittest import mock

from refinery.lib.frame import Chunk
from refinery.lib.nsis.archive import NSArchive, NSHeader, NSMethod
from refinery.units.formats.archive.xtnsis import xtnsis

from ... import TestUnitBase

SOLID_LZMA_INSTALLER = '19ccf1d4389f624fb166c5828c1633ea4234c976e044e5b61e53000f4a098be8'
INSTALLERS_WITH_EVERY_METHOD = 'bf777a9a51cbea4b27b97c9dd81076e68aceb22edb535fdd0c16321d5ac2f6f8'
ARCHIVE_SIZE = 24


def contents(data):
    result = {}
    for item in list(xtnsis().unpack(Chunk(data))):
        try:
            result[item.path] = hashlib.sha256(item.get_data()).digest()
        except Exception as error:
            result[item.path] = error
    return result


class TestNSISExtractor(TestUnitBase):

    def test_modified_archive_deflate1(self):
        data = self.download_sample('e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384')
        unit = self.load()
        result = data | unit | self.ldu('xt7z') | self.ldu('pemeta') | json.loads
        self.assertEqual(result['Signature']['Fingerprint'], '6509312e581ef5ba12be11ed427a66f8fd80e819')

    def test_modified_archive_lzma_solid(self):
        data = self.download_sample('19ccf1d4389f624fb166c5828c1633ea4234c976e044e5b61e53000f4a098be8')
        unit = self.load('diskpart.vbe')
        result = str(data | unit | self.ldu('recode') | self.ldu('wshenc'))
        self.assertIn(U'Извините, вы не указали размер диска!', result)

    def test_modified_archive_lzma_nonsolid(self):
        data = self.download_sample('ff4ef0ee0915af58ea1388f72730c63c746856a64760e17e4fcdfc559a8b4555')
        unit = self.load('csrss.bat')
        result = str(data | unit | self.ldu('recode', 'cp1251'))
        self.assertIn(U'КАК РАСШИФРОВАТЬ ФАЙЛЫ.TXT', result)

    def test_all_modes_and_methods(self):
        data = self.download_sample('bf777a9a51cbea4b27b97c9dd81076e68aceb22edb535fdd0c16321d5ac2f6f8')
        test = data | self.ldu('xtzip') [ self.load('filetwo.txt') ]| {str} # noqa
        self.assertEqual(len(test), 1)
        test = next(iter(test)).splitlines(False)
        for k, line in enumerate([
            r'  /  |                            ',
            r' _$$ |_    __   __   __   ______  ',
            r'/ $$   |  /  | /  | /  | /      \ ',
            r'$$$$$$/   $$ | $$ | $$ |/$$$$$$  |',
            r'  $$ | __ $$ | $$ | $$ |$$ |  $$ |',
            r'  $$ |/  |$$ \_$$ \_$$ |$$ \__$$ |',
            r'  $$  $$/ $$   $$   $$/ $$    $$/ ',
            r'   $$$$/   $$$$$/$$$$/   $$$$$$/  ',
        ], 1):
            self.assertEqual(line, test[k])

    def test_lzma_bcj_solid(self):
        import hashlib
        data = self.download_sample('4caa12766e4e16f5d275d2aaadc01484f1875b80819234e5bf49506dedcc5330')
        test = data | self.load() | {'path': bytes}
        test = {k.decode().rpartition('/')[-1]: hashlib.sha256(v).hexdigest()
            for k, v in test.items() if b'$PLUGINSDIR' in k}
        self.assertDictEqual(test, {
            'System.dll'         : '02493e0d7e4d7951104559f6603fc2aab14d7c07cf1c3fdddae206cb60d86885',
            'RCWidgetPlugin.dll' : '14ef3bf106392331c8c1fb6dfaf460df89d2f934f9584ba6083185ae82ef7ccc',
            'FileInfo.dll'       : 'ab3d7b37215753a48ed60cf59a080bb8b92cf535c35ccd435c57c954073b8a2e',
        })

    def test_items_after_the_end_of_a_cut_solid_stream_fail_without_decoding_it_again(self):
        data = self.download_sample(SOLID_LZMA_INSTALLER)
        intact = contents(data)
        offset = xtnsis._find_archive_offset(bytearray(data))
        assert offset is not None
        size, = struct.unpack_from('<I', data, offset + ARCHIVE_SIZE)
        end = offset + size * 6 // 10
        cut = bytearray(data[:end])
        struct.pack_into('<I', cut, offset + ARCHIVE_SIZE, end - offset)
        with mock.patch('refinery.lib.nsis.archive.lzma.LZMAFile', wraps=lzma.LZMAFile) as decoder:
            result = contents(cut)
        self.assertEqual(decoder.call_count, 1)
        failed = [path for path, digest in result.items() if isinstance(digest, EOFError)]
        self.assertGreater(len(failed), 1)
        for path, digest in result.items():
            if path not in failed:
                self.assertEqual(digest, intact[path], path)

    def test_every_pass_over_a_solid_stream_uses_the_decompressor_that_decoded_its_header(self):
        """
        The header of an NSIS 2 installer selects a different decompressor for separately
        compressed items; the header classification is forced on an authentic installer.
        """
        data = self.download_sample(INSTALLERS_WITH_EVERY_METHOD) | self.ldu('xtzip', 'zlib_solid.exe') | bytes
        methods = []
        decompress_items = NSArchive._decompress_items

        def recorded(archive, reader, method):
            methods.append(method)
            return decompress_items(archive, reader, method)

        with (
            mock.patch.object(NSHeader, 'nsis_deflate', new=property(lambda _: True)),
            mock.patch.object(NSArchive, '_decompress_items', autospec=True, side_effect=recorded),
        ):
            from_xtnsis = {chunk['path']: chunk['sha256'] for chunk in data | self.load() | [...]}
            from_xt = {chunk['path']: chunk['sha256'] for chunk in data | self.ldu('xt') | [...]}
        self.assertEqual(from_xt, from_xtnsis)
        self.assertGreater(methods.count(NSMethod.Deflate), 1)
        self.assertEqual(set(methods), {NSMethod.Deflate})
