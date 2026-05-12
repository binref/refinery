"""
A wrapper module to read local data resources.
"""
from __future__ import annotations

from importlib import resources

from refinery import data


def datapath(name: str):
    return resources.files(data).joinpath(name)
