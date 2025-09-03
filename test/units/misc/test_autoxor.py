from .. import TestUnitBase


class TestAutoXOR(TestUnitBase):

    def test_real_world_01(self):
        from refinery import iff, hex, autoxor, vbastr
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        # flake8: noqa
        out = list(data | vbastr [ iff('size >= 100') | hex | autoxor ])
        self.assertSetEqual({o['key'] for o in out}, {
            B'An2Lcw6Gseh',
            bytes.fromhex('81a09675497f5903f05bec10ff1bacd9bb4140f6c701a3103f47188fb3'),
        })

    def test_real_world_02(self):
        from refinery import xkey
        data = self.download_sample('1664cb04cdbf4bebf2c6addb92a9ed1f09c6738b3901f1b7e8ae7405008f5039')
        self.assertEqual(data | xkey | bytes, b'Mlitqcfqr')

    def test_very_short_input(self):
        pl = self.load_pipeline('emit A B C "" [| autoxor ]')
        self.assertEqual(pl(), B'ABC')

    def test_chunk_scope_regression(self):
        data = self.generate_random_buffer(2000)
        pl = self.load_pipeline('autoxor [| nop ]')
        self.assertEqual(len(data), data | pl | len)

    def test_b64_encoded_and_encrypted(self):
        from refinery.units import Chunk
        data = Chunk(self.generate_random_buffer(4000))
        key = self.generate_random_buffer(10)
        pl = self.load_pipeline(F'b64 -R | add h:{key.hex()} | autoxor | b64')
        test = next(data | pl)
        self.assertEqual(test['method'], 'sub')
        self.assertEqual(test['key'], key)
        self.assertEqual(test, data)

    def test_text_autoxor(self):
        data = bytes.fromhex(
            '55 69 68 72 21 71 73 6E 66 73 60 6C 21 62 60 6F 6F 6E 75 21 63 64'
            '21 73 74 6F 21 68 6F 21 45 4E 52 21 6C 6E 65 64 2F')
        self.assertEqual(data | self.load() | str, 
            'This program cannot be run in DOS mode.')
