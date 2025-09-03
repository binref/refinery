from .. import TestUnitBase


class TestCarveXML(TestUnitBase):

    def test_wikipedia_unicode_example(self):
        xstr = '<?xml version="1.0" encoding="UTF-8"?><俄语 լեզու="ռուսերեն">данные</俄语>'
        unit = self.load()
        norm = xstr.encode(unit.codec)
        for encoding in ['UTF8', 'UTF-16LE']:
            xbin = xstr.encode(encoding)
            data = self.generate_random_buffer(200) + xbin + self.generate_random_buffer(100)
            self.assertEqual(unit(data), norm)
