from .. import TestUnitBase
from . import KADATH1


class TestFLZ(TestUnitBase):

    def test_invertible_01(self):
        data = KADATH1
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=0)
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=1)
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_02(self):
        data = KADATH1 * (0x10000 // len(KADATH1) + 1)
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=1)
        self.assertEqual(data | -unit | unit | str, data)
        unit = self.load(level=0)
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_03(self):
        data = 'Hello World'
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)

    def test_invertible_04(self):
        data = 'Binary Refinery ' * 20
        unit = self.load()
        self.assertEqual(data | -unit | unit | str, data)

    def test_real_world(self):
        data = bytes.fromhex(
            '3f 28 c0 73 68 69 6d 31 2e 6b 70 67 62 6f 64 79' # ?(.shim1.kpgbody
            '2e 63 6f 6d 2f 67 61 74 65 77 61 79 2f 78 63 63' # .com/gateway/xcc
            '6c 0b 62 37 61 35 2e 39 73 64 63 6a 2b c0 80 29' # l.b7a5.9sdcj+..)
            '09 70 68 61 6e 67 61 6e 68 75 62 e0 12 2c 00 29' # .phanganhub..,.)
            '60 2c 06 32 2e 74 61 78 69 2d 20 5b e0 1b 2a 06' # `,.2.taxi- [..*.
            '72 6f 70 69 78 67 6f e0 10 2a 01 63 6a'          # ropixgo..*.cj
        ) | self.load() | bytes
        test = data | self.load_pipeline('struct -m {n:B}x{:n}') | {str}
        self.assertSetEqual(test, {
            'shim1.kpgbody.''com/gateway/xcclb7a5.9sdcj',
            'shim1.phanganhub.''com/gateway/xcclb7a5.9sdcj',
            'shim2.taxi-kpg.''com/gateway/xcclb7a5.9sdcj',
            'shim2.tropixgo.''com/gateway/xcclb7a5.9sdcj',
        })
