#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class cupper(Unit):
    """
    Stands for "Convert to UPPER case"; The unit simply converts all latin alphabet chacters in the
    input to uppercase.
    """
    def process(self, data):
        return data.upper()
