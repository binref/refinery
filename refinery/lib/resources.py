#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A wrapper module to read local data resources.
"""
from refinery import data
from importlib import resources

import sys


def datapath(name: str):
    if sys.version_info >= (3, 9):
        return resources.files(data).joinpath(name)
    else:
        return resources.path(data, name)
