from ... import TestUnitBase


class TestCommentRemover(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.unit = self.load()

    def test_simple(self):
        self.assertEqual(self.unit.deobfuscate(r'''
            ' Test
            b = a
            ' Test''').strip(), r'b = a')
