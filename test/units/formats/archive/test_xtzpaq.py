#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestZPAQExtractor(TestUnitBase):

    def test_hedgehog_sample(self):
        data = self.download_sample('1c33eef0d22dc54bb2a41af485070612cd4579529e31b63be2141c4be9183eb6')
        test = data | self.load_pipeline('xtzpaq | pestrip | dnstr [| iffp url ]') | str
        self.assertEqual(test, 'https'':''//''www.mediafire''.''com/file/vgvujtm9ke2lj1c/Gnwwcgocwzl.wav/file')
