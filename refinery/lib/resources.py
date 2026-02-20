"""
A wrapper module to read local data resources.
"""
from __future__ import annotations

import sys


def datapath(name: str):
    from importlib import resources
    if sys.version_info >= (3, 9):
        from refinery import data
        return resources.files(data).joinpath(name)
    with resources.path('refinery', 'data') as data:
        return data / name
