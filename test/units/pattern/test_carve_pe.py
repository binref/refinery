#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
from .. import TestUnitBase


class TestCarvePE(TestUnitBase):

    def test_wikipedia_unicode_example(self):

        samples = [self.download_from_malshare(h) for h in [
            'c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916',
            'ce1cd24a782932e1c28c030da741a21729a3c5930d8358079b0f91747dd0d832',
            '426ace19debaba6f262dcd3ce429dc8fc0b233f3fa02262375c4641d9f466709',
        ]]

        unit = self.load()
        data = self.generate_random_buffer(312)

        data += samples[0]
        data += B'AAMMMZMZMZMZMZMZMZMZMZMZ'
        data += samples[1]
        data += self.generate_random_buffer(200) + B'MZ00000000000' + self.generate_random_buffer(21)
        data += bytes.fromhex(
            '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00'  # MZ..............
            'B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00'  # ........@.......
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
            '00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00'  # ................
            '0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68'  # ........!..L.!Th
            '69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'  # is.program.canno
            '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20'  # t.be.run.in.DOS.
            '6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'  # mode....$.......
        )
        data += samples[2]
        data += self.generate_random_buffer(24)

        result = list(unit.process(data))
        self.assertEqual(len(result), 4)
        self.assertEqual(hashlib.sha256(result.pop()).hexdigest(),
            '84ecbad107cfa8012799c66f98d0e20fb3b8fb269d8c5c198a0f76f25e2c7902')
        for a, b in zip(samples, result):
            self.assertEqual(a, b)
