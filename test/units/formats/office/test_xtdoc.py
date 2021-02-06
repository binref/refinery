
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from ... import TestUnitBase
from refinery.lib.loader import load as L


class TestDocExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('969ff75448ea54feccc0d5f652e00172af8e1848352e9a5877d705fc97fa0238')
        pipeline = L('xtdoc', 'WordDoc') | L('push') \
            [ L('drp')
            | L('pop', 'junk')
            | L('repl', 'var:junk')
            | L('carve', '-ds', 'b64')
            | L('u16')
            | L('deob-ps1')
            | L('repl', 'var:junk', 'http')
            | L('xtp', 'url')
            ]
        c2s = pipeline(data)
        self.assertIn(B'http://depannage-vehicule-maroc'B'.com/wp-admin/c/', c2s)
