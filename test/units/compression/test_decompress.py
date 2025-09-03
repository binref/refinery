import time

from .. import TestUnitBase
from . import KADATH1, KADATH2


class TestAutoDecompressor(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.buffers = [buf[:0x5000] for buf in {
            1: B'AAFOOBAR/BAR' * 2000,
            2: bytes(self.download_sample('6a1bc124f945ddfde62b4137d627f3958b23d8a2a6507e3841cab84416c54eea')),
            3: bytes(self.download_sample('07e25cb7d427ac047f53b3badceacf6fc5fb395612ded5d3566a09800499cd7d')),
            4: bytes(self.download_sample('40f97cf37c136209a65d5582963a72352509eb802da7f1f5b4478a0d9e0817e8')),
            5: bytes(self.download_sample('52e488784d46b3b370836597b1565cf18a5fa4a520d0a71297205db845fc9d26'))[0x8000:],
            6: bytes(self.download_sample('38c9b858c32fcc6b484272a182ae6e7f911dea53a486396037d8f7956d2110be')),
            7: bytes(self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')),
            8: KADATH1.encode('utf8'),
            9: KADATH2.encode('utf8'),
        }.values()]

    def _mangle(self, data: bytes, engine: str):
        def prepend(x):
            return x + data

        yield data

        if engine == 'lznt1':
            return

        yield prepend(B'\0\0\0\0')
        yield prepend(B'\xF4')

        if engine in ('aplib', 'lzf'):
            return

        yield prepend(B'\x01\x40')
        yield prepend(B'\x00\x00\xFE\xCD')
        yield prepend(B'\x01\x00')

    def perform_mangled_buffer_test(self, name: str, k: int):
        engine = self.ldu(name)
        buffer = self.buffers[k - 1]
        compressed = next(buffer | -engine)
        unit = self.load()
        for m, sample in enumerate(self._mangle(compressed, name), 1):
            start = time.process_time()
            result = next(sample | unit)
            delta = time.process_time() - start
            self.assertLessEqual(delta, 20, F'decompress of mangling {m} took {delta} seconds')
            method = result.meta.get("method", "uncompressed")
            if method not in {'lzf', 'flz'}:
                # These are too difficult to tell apart. All we can hope for here is to get back the
                # original input.
                self.assertEqual(method, name,
                    F'mangling {m} for {name} incorrectly identified as {method}')
            _assert = self.assertEqual if m == 1 else self.assertIn
            _assert(buffer, result, msg=F'mangling {m} did not decompress')

    def test_mangled_zstd_01(self): self.perform_mangled_buffer_test('zstd', 1)
    def test_mangled_zstd_02(self): self.perform_mangled_buffer_test('zstd', 2)
    def test_mangled_zstd_03(self): self.perform_mangled_buffer_test('zstd', 3)
    def test_mangled_zstd_04(self): self.perform_mangled_buffer_test('zstd', 4)
    def test_mangled_zstd_05(self): self.perform_mangled_buffer_test('zstd', 5)
    def test_mangled_zstd_06(self): self.perform_mangled_buffer_test('zstd', 6)
    def test_mangled_zstd_07(self): self.perform_mangled_buffer_test('zstd', 7)
    def test_mangled_zstd_08(self): self.perform_mangled_buffer_test('zstd', 8)
    def test_mangled_zstd_09(self): self.perform_mangled_buffer_test('zstd', 9)

    def test_mangled_bz2_01(self): self.perform_mangled_buffer_test('bz2', 1)
    def test_mangled_bz2_02(self): self.perform_mangled_buffer_test('bz2', 2)
    def test_mangled_bz2_03(self): self.perform_mangled_buffer_test('bz2', 3)
    def test_mangled_bz2_04(self): self.perform_mangled_buffer_test('bz2', 4)
    def test_mangled_bz2_05(self): self.perform_mangled_buffer_test('bz2', 5)
    def test_mangled_bz2_06(self): self.perform_mangled_buffer_test('bz2', 6)
    def test_mangled_bz2_07(self): self.perform_mangled_buffer_test('bz2', 7)
    def test_mangled_bz2_08(self): self.perform_mangled_buffer_test('bz2', 8)
    def test_mangled_bz2_09(self): self.perform_mangled_buffer_test('bz2', 9)

    def test_mangled_zl_01(self): self.perform_mangled_buffer_test('zl', 1)
    def test_mangled_zl_02(self): self.perform_mangled_buffer_test('zl', 2)
    def test_mangled_zl_03(self): self.perform_mangled_buffer_test('zl', 3)
    def test_mangled_zl_04(self): self.perform_mangled_buffer_test('zl', 4)
    def test_mangled_zl_05(self): self.perform_mangled_buffer_test('zl', 5)
    def test_mangled_zl_06(self): self.perform_mangled_buffer_test('zl', 6)
    def test_mangled_zl_07(self): self.perform_mangled_buffer_test('zl', 7)
    def test_mangled_zl_08(self): self.perform_mangled_buffer_test('zl', 8)
    def test_mangled_zl_09(self): self.perform_mangled_buffer_test('zl', 9)

    def test_mangled_lzf_01(self): self.perform_mangled_buffer_test('lzf', 1)
    def test_mangled_lzf_02(self): self.perform_mangled_buffer_test('lzf', 2)
    def test_mangled_lzf_03(self): self.perform_mangled_buffer_test('lzf', 3)
    def test_mangled_lzf_04(self): self.perform_mangled_buffer_test('lzf', 4)
    def test_mangled_lzf_05(self): self.perform_mangled_buffer_test('lzf', 5)
    def test_mangled_lzf_06(self): self.perform_mangled_buffer_test('lzf', 6)
    def test_mangled_lzf_07(self): self.perform_mangled_buffer_test('lzf', 7)
    def test_mangled_lzf_08(self): self.perform_mangled_buffer_test('lzf', 8)
    def test_mangled_lzf_09(self): self.perform_mangled_buffer_test('lzf', 9)

    def test_mangled_flz_01(self): self.perform_mangled_buffer_test('flz', 1)
    def test_mangled_flz_02(self): self.perform_mangled_buffer_test('flz', 2)
    def test_mangled_flz_03(self): self.perform_mangled_buffer_test('flz', 3)
    def test_mangled_flz_04(self): self.perform_mangled_buffer_test('flz', 4)
    def test_mangled_flz_05(self): self.perform_mangled_buffer_test('flz', 5)
    def test_mangled_flz_06(self): self.perform_mangled_buffer_test('flz', 6)
    def test_mangled_flz_07(self): self.perform_mangled_buffer_test('flz', 7)
    def test_mangled_flz_08(self): self.perform_mangled_buffer_test('flz', 8)
    def test_mangled_flz_09(self): self.perform_mangled_buffer_test('flz', 9)

    def test_mangled_lzma_01(self): self.perform_mangled_buffer_test('lzma', 1)
    def test_mangled_lzma_02(self): self.perform_mangled_buffer_test('lzma', 2)
    def test_mangled_lzma_03(self): self.perform_mangled_buffer_test('lzma', 3)
    def test_mangled_lzma_04(self): self.perform_mangled_buffer_test('lzma', 4)
    def test_mangled_lzma_05(self): self.perform_mangled_buffer_test('lzma', 5)
    def test_mangled_lzma_06(self): self.perform_mangled_buffer_test('lzma', 6)
    def test_mangled_lzma_07(self): self.perform_mangled_buffer_test('lzma', 7)
    def test_mangled_lzma_08(self): self.perform_mangled_buffer_test('lzma', 8)
    def test_mangled_lzma_09(self): self.perform_mangled_buffer_test('lzma', 9)

    def test_mangled_aplib_01(self): self.perform_mangled_buffer_test('aplib', 1)
    def test_mangled_aplib_02(self): self.perform_mangled_buffer_test('aplib', 2)
    def test_mangled_aplib_03(self): self.perform_mangled_buffer_test('aplib', 3)
    def test_mangled_aplib_04(self): self.perform_mangled_buffer_test('aplib', 4)
    def test_mangled_aplib_05(self): self.perform_mangled_buffer_test('aplib', 5)
    def test_mangled_aplib_06(self): self.perform_mangled_buffer_test('aplib', 6)
    def test_mangled_aplib_07(self): self.perform_mangled_buffer_test('aplib', 7)
    def test_mangled_aplib_08(self): self.perform_mangled_buffer_test('aplib', 8)
    def test_mangled_aplib_09(self): self.perform_mangled_buffer_test('aplib', 9)

    def test_mangled_brotli_01(self): self.perform_mangled_buffer_test('brotli', 1)
    def test_mangled_brotli_02(self): self.perform_mangled_buffer_test('brotli', 2)
    def test_mangled_brotli_03(self): self.perform_mangled_buffer_test('brotli', 3)
    def test_mangled_brotli_04(self): self.perform_mangled_buffer_test('brotli', 4)
    def test_mangled_brotli_05(self): self.perform_mangled_buffer_test('brotli', 5)
    def test_mangled_brotli_06(self): self.perform_mangled_buffer_test('brotli', 6)
    def test_mangled_brotli_07(self): self.perform_mangled_buffer_test('brotli', 7)
    def test_mangled_brotli_08(self): self.perform_mangled_buffer_test('brotli', 8)
    def test_mangled_brotli_09(self): self.perform_mangled_buffer_test('brotli', 9)

    def test_mangled_blz_01(self): self.perform_mangled_buffer_test('blz', 1)
    def test_mangled_blz_02(self): self.perform_mangled_buffer_test('blz', 2)
    def test_mangled_blz_03(self): self.perform_mangled_buffer_test('blz', 3)
    def test_mangled_blz_04(self): self.perform_mangled_buffer_test('blz', 4)
    def test_mangled_blz_05(self): self.perform_mangled_buffer_test('blz', 5)
    def test_mangled_blz_06(self): self.perform_mangled_buffer_test('blz', 6)
    def test_mangled_blz_07(self): self.perform_mangled_buffer_test('blz', 7)
    def test_mangled_blz_08(self): self.perform_mangled_buffer_test('blz', 8)
    def test_mangled_blz_09(self): self.perform_mangled_buffer_test('blz', 9)

    def test_mangled_lzjb_01(self): self.perform_mangled_buffer_test('lzjb', 1)
    def test_mangled_lzjb_02(self): self.perform_mangled_buffer_test('lzjb', 2)
    def test_mangled_lzjb_03(self): self.perform_mangled_buffer_test('lzjb', 3)
    def test_mangled_lzjb_04(self): self.perform_mangled_buffer_test('lzjb', 4)
    def test_mangled_lzjb_05(self): self.perform_mangled_buffer_test('lzjb', 5)
    def test_mangled_lzjb_06(self): self.perform_mangled_buffer_test('lzjb', 6)
    def test_mangled_lzjb_07(self): self.perform_mangled_buffer_test('lzjb', 7)
    def test_mangled_lzjb_08(self): self.perform_mangled_buffer_test('lzjb', 8)
    def test_mangled_lzjb_09(self): self.perform_mangled_buffer_test('lzjb', 9)

    def test_mangled_lznt1_01(self): self.perform_mangled_buffer_test('lznt1', 1)
    def test_mangled_lznt1_02(self): self.perform_mangled_buffer_test('lznt1', 2)
    def test_mangled_lznt1_03(self): self.perform_mangled_buffer_test('lznt1', 3)
    def test_mangled_lznt1_04(self): self.perform_mangled_buffer_test('lznt1', 4)
    def test_mangled_lznt1_05(self): self.perform_mangled_buffer_test('lznt1', 5)
    def test_mangled_lznt1_06(self): self.perform_mangled_buffer_test('lznt1', 6)
    def test_mangled_lznt1_07(self): self.perform_mangled_buffer_test('lznt1', 7)
    def test_mangled_lznt1_08(self): self.perform_mangled_buffer_test('lznt1', 8)
    def test_mangled_lznt1_09(self): self.perform_mangled_buffer_test('lznt1', 9)
