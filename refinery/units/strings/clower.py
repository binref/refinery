#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit


class clower(Unit):
    """
    Stands for "Convert to LOWER case"; The unit simply converts all latin alphabet chacters in the
    input to lowercase.
    """
    def process(self, data):
        return data.lower()
