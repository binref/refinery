#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from . import errbuf


class TestIEMap(TestUnitBase):

    def test_java_class_file(self):
        iemap = self.load()
        from refinery.lib.environment import environment
        environment.term_size.value = 80
        with errbuf() as stderr:
            iemap(self.download_sample('31055a528f9a139104a0ce8f4da6b4b89a37a800715292ae7f8f190b2a7b6582'))
            output = stderr.getvalue()

        self.assertEqual(
            output,
            '['
            '\x1b[37m'
            '\x1b[92m#####'
            '\x1b[94m##########'
            '\x1b[92m#####################'
            '\x1b[96m######################'
            '\x1b[94m#####'
            '\x1b[96m#####'
            '\x1b[40m\x1b[37m\x1b[0m'
            '] [---.--%]'
            '\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08'
            '] [ 70.82%]\n'
        )
