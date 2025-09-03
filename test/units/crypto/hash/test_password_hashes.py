from ... import TestUnitBase


class TestNTLMHash(TestUnitBase):

    def test_ntlm(self):
        ntlm = self.ldu('ntlm')
        self.assertEqual(bytes(B'Binary Refinery' | ntlm), bytes.fromhex('0926451370fb30a8132a4fed78c19ce0'))
