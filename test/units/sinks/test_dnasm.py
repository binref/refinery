
from .. import TestUnitBase


class TestDnASM(TestUnitBase):

    def test_asm(self):
        dnasm = self.load('-IAH', '-c2')
        data = bytes.fromhex('666665')
        result = dnasm(data).decode('utf-8')
        self.assertEqual(['not', 'not'], result.splitlines())
