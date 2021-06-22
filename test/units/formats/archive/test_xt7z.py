#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64

from ... import TestUnitBase


class Test7zipFileExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAT9xtacpQAAAAAAAAAiAAAAAAAAAEerl+XBRlkrcJwwoqgijCyu'
            'Eh0SqLfjamv2F2vNJGFGyHDfpAAAgTMHrg/QDrA8nzkQnJ+m1TPasi6xAvSH'
            'zZaZrISLD+EsvFULZ44Kf7Ewy47PApbKruXCaOSUsjzeqpG8VBcx66h2cV/l'
            'nGDfUjtVsyGBHmmmTaSI/atXtuwiN5mGrqyFZTC/V2VEohWua1Yk1K+jXy+3'
            '2hBwnK2clyr3rN5LAbv5g2wXBiABCYCFAAcLAQABIwMBAQVdABAAAAyAlgoB'
            'ouB4BAAA'
        )
        self.assertEqual(str(data | self.load('foo.txt', pwd='boom')), 'binary')
        self.assertEqual(str(data | self.load('bar.txt', pwd='boom')), 'refinery')
        self.assertEqual(str(data | self.load(pwd='boom')), 'refinery\nbinary')
