#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import sys

from .. import TestUnitBase


class TestPeek(TestUnitBase):

    def test_hex_peek(self):
        peek = self.load(width=8, lines=14, meta=True)
        sys_stderr = sys.stderr
        sys.stderr = io.StringIO()
        peek(bytes.fromhex(
            '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00'  # MZ..............
            'B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00'  # ........@.......
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'  # ................
            '00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00'  # ................
            '0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68'  # ........!..L.!Th
            '69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'  # is.program.canno
            '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20'  # t.be.run.in.DOS.
            '6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'  # mode....$.......
        ))

        output = sys.stderr.getvalue()
        sys.stderr = sys_stderr

        for info in ('entropy = 45.87%', 'MS-DOS'):
            self.assertIn(info, output)

        self.assertIn((
            '00: 4D 5A 90 00 03 00 00 00  MZ......\n'
            '08: 04 00 00 00 FF FF 00 00  ........\n'
            '10: B8 00 00 00 00 00 00 00  ........\n'
            '18: 40 00 00 00 00 00 00 00  @.......\n'
            '20: 00 00 00 00 00 00 00 00  ........\n'
            '..: === repeats 2 times ===  ========\n'
            '38: 00 00 00 00 F8 00 00 00  ........\n'
            '40: 0E 1F BA 0E 00 B4 09 CD  ........\n'
            '48: 21 B8 01 4C CD 21 54 68  !..L.!Th\n'
            '50: 69 73 20 70 72 6F 67 72  is.progr\n'
            '58: 61 6D 20 63 61 6E 6E 6F  am.canno\n'
            '60: 74 20 62 65 20 72 75 6E  t.be.run\n'
            '68: 20 69 6E 20 44 4F 53 20  .in.DOS.\n'
            '70: 6D 6F 64 65 2E 0D 0D 0A  mode....\n'),
            output
        )
