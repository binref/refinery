#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This module contains functions to identify certain file formats; these functions are used by units
who operate on the same file format to implement the `refinery.units.Unit.handles` method.
"""
from __future__ import annotations


def is_likely_pe(data: bytearray):
    """
    Tests whether the input data is likely a PE file by checking the first two bytes and the magic
    bytes at the beginning of what should be the NT header.
    """
    if data[:2] != B'MZ':
        return False
    ntoffset = data[0x3C:0x3E]
    if len(ntoffset) < 2:
        return False
    ntoffset = int.from_bytes(ntoffset, 'little')
    return data[ntoffset:ntoffset + 2] == B'PE'


def is_likely_pe_dotnet(data: bytearray):
    """
    Tests whether the input data is likely a .NET PE file by running `refinery.lib.id.is_likely_pe`
    and also checking for the characteristic strings `BSJB`, `#Strings`, and `#Blob`.
    """
    if not is_likely_pe(data):
        return False
    if data.find(b'BSJB') < 0:
        return False
    if data.find(b'#Strings') < 0:
        return False
    if data.find(b'#Blob') < 0:
        return False
    return True
