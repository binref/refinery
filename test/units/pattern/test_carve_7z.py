import base64
from .. import TestUnitBase


class TestCarve7Zip(TestUnitBase):

    def test_01(self):
        unit = self.load()
        data = base64.b64decode(
            'N3q8ryccAAT9xtacpQAAAAAAAAAiAAAAAAAAAEerl+XBRlkrcJwwoqgijCyu'
            'Eh0SqLfjamv2F2vNJGFGyHDfpAAAgTMHrg/QDrA8nzkQnJ+m1TPasi6xAvSH'
            'zZaZrISLD+EsvFULZ44Kf7Ewy47PApbKruXCaOSUsjzeqpG8VBcx66h2cV/l'
            'nGDfUjtVsyGBHmmmTaSI/atXtuwiN5mGrqyFZTC/V2VEohWua1Yk1K+jXy+3'
            '2hBwnK2clyr3rN5LAbv5g2wXBiABCYCFAAcLAQABIwMBAQVdABAAAAyAlgoB'
            'ouB4BAAA'
        )
        for prefix in (
            unit.HEADER_SIGNATURE + self.generate_random_buffer(20),
            unit.HEADER_SIGNATURE * 3,
            self.generate_random_buffer(64) + unit.HEADER_SIGNATURE + b'AAAA'
        ):
            for pf in (2, 4, 90, 200, 2048):
                blob = prefix + data + self.generate_random_buffer(pf)
                self.assertEqual(blob | unit | bytearray, data)
