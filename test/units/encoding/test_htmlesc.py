from .. import TestUnitBase


class TestHTMLEsc(TestUnitBase):

    def test_unescape_named(self):
        unit = self.load()
        self.assertEqual(unit(b'&amp;'), b'&')

    def test_unescape_numeric(self):
        unit = self.load()
        self.assertEqual(unit(b'&#60;&#62;'), b'<>')

    def test_escape(self):
        unit = self.load()
        self.assertEqual(b'<b>test</b>' | -unit | str, '&lt;b&gt;test&lt;/b&gt;')

    def test_roundtrip(self):
        unit = self.load()
        data = b'1 < 2 & 3 > 2'
        self.assertEqual(data | -unit | unit | bytes, data)

    def test_complex_entities(self):
        test = b'&lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt;' | self.load() | bytes
        goal = b"<script>alert('xss')</script>"
        self.assertEqual(test, goal)
