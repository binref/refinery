from .. import TestUnitBase


class TestLZ4(TestUnitBase):

    def test_decompress_kevin(self):
        unit = self.load()
        data = bytes.fromhex(
            '04224D186440A729000000F60C4B6576696E277320676F7420746865206D6167'
            '6963202D20616E641000032000604B6576696E2E000000003FAB8D14'
        )
        self.assertEqual(
            b"Kevin's got the magic - and the magic's got Kevin.",
            unit(data)
        )
