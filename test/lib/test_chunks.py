from refinery.lib import chunks
from .. import TestBase


class TestChunks(TestBase):

    def test_odd_block_size(self):
        data = bytearray(range(1, 3 * 5 + 2))
        unpacked = list(chunks.unpack(data, 3, bigendian=True))
        self.assertEqual(unpacked, [0x010203, 0x040506, 0x070809, 0x0A0B0C, 0x0D0E0F])

    def test_padded_final_chunk_is_zero_extended_at_its_end(self):
        data = bytes.fromhex('41424344454647')
        for blocksize, little, big in (
            (2, [0x4241, 0x4443, 0x4645, 0x47], [0x4142, 0x4344, 0x4546, 0x4700]),
            (3, [0x434241, 0x464544, 0x47], [0x414243, 0x444546, 0x470000]),
            (4, [0x44434241, 0x474645], [0x41424344, 0x45464700]),
        ):
            with self.subTest(blocksize=blocksize):
                self.assertEqual(list(chunks.unpack(data, blocksize, bigendian=False, pad=True)), little)
                self.assertEqual(list(chunks.unpack(data, blocksize, bigendian=True, pad=True)), big)
                self.assertEqual(chunks.pack(big, blocksize, bigendian=True)[:len(data)], data)
                self.assertEqual(chunks.pack(little, blocksize, bigendian=False)[:len(data)], data)
