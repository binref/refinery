from .. import TestUnitBase


class TestCarveRTF(TestUnitBase):

    def test_carve_simple_rtf(self):
        unit = self.load()
        rtf = b'{\\rtf1\\ansi Hello World}'
        data = b'GARBAGE' + rtf + b'MORE GARBAGE'
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), rtf)

    def test_carve_nested_rtf(self):
        unit = self.load()
        rtf = b'{\\rtf1\\ansi {\\b Bold} text}'
        data = b'PREFIX' + rtf + b'SUFFIX'
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), rtf)

    def test_no_rtf_found(self):
        unit = self.load()
        data = b'This is just plain text with no RTF content.'
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_multiple_rtf_documents(self):
        unit = self.load()
        rtf1 = b'{\\rtf1 first}'
        rtf2 = b'{\\rtf1 second}'
        data = rtf1 + b'BETWEEN' + rtf2
        results = data | unit | []
        self.assertEqual(len(results), 2)
