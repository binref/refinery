#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

from refinery.lib.frame import FrameUnpacker

from .. import TestUnitBase


class TestMetaBase(TestUnitBase):

    def load(self, *args, **kwargs):
        unit = super().load(*args, '[', **kwargs)

        def wrapper(*inputs):
            with open(os.devnull, 'rb') as stream:
                unpacker = FrameUnpacker(stream | self.ldu('emit', '[', data=list(inputs)) | unit)
                results = []
                while unpacker.nextframe():
                    results.extend((bytes(item) for item in unpacker))
                return results
        return wrapper
