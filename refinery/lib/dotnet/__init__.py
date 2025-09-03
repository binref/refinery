"""
A library to parse .NET headers and metadata.
"""
from __future__ import annotations


def integer_from_ldc(ins: bytes):
    """
    This function parses an integer value from the bytes representing an LDC instruction.
    """
    if len(ins) == 1:
        return ins[0] - 0x16
    if ins[0] == 0x1F:
        return ins[1]
    return int.from_bytes(ins[1:], 'little')
