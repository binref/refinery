#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit


class cupper(Unit):
    """
    Transforms the input data to uppercase.
    """
    def process(self, data):
        return data.upper()
