#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.java import JvClassFile


class jvstr(Unit):
    """
    Extract string constants from Java class files.
    """
    def process(self, data):
        jc = JvClassFile(data)
        for string in jc.strings:
            yield string.encode(self.codec)
