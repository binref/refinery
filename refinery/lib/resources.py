#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A wrapper module to read local data resources.
"""
from importlib import resources

import sys


def datapath(name: str):
    if sys.version_info >= (3, 9):
        from refinery import data
        return resources.files(data).joinpath(name)
    with resources.path('refinery', 'data') as data:
        return data / name
