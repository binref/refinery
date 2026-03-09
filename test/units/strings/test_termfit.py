from .. import TestUnitBase


class TestTermFit(TestUnitBase):

    def test_reformat_text(self):
        unit = self.load(width=40)
        data = b'This is a very long line of text that should be wrapped at the specified width.'
        result = data | unit | bytes
        for line in result.split(b'\n'):
            self.assertLessEqual(len(line), 40)

    def test_explicit_width(self):
        unit = self.load(width=20)
        data = b'Short words in a test.'
        result = data | unit | bytes
        for line in result.split(b'\n'):
            self.assertLessEqual(len(line), 20)

    def test_tight_mode(self):
        unit = self.load(width=80, tight=True)
        data = b'First paragraph.\n\nSecond paragraph.'
        result = unit(data)
        self.assertNotIn(b'\n\n', result)
