#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The Python array module provides efficient arrays of numeric values, but it uses a type code
to specify the item size, and the corresponding block length depends on the underlying system
architecture. This module is a small wrapper around the standard library module which allows
to create arrays with a given block length.
"""
from __future__ import annotations
from typing import Iterable, Union

import array

from refinery.lib.tools import NoLogging


CodeMap: dict[tuple[bool, int], str] = {}
"""
Maps a tuple `(unsigned, size)` to a Python array type code that represents an integer type of the
given size and signedness.
"""

with NoLogging(NoLogging.Mode.WARNING):
    for code in array.typecodes:
        unsigned = code.isupper()
        itemsize = array.array(code).itemsize
        CodeMap[unsigned, itemsize] = code


def make_array(
    itemsize: int,
    length: int = 0,
    unsigned: bool = True,
    init: Union[int, Iterable[int]] = 0
) -> array.array[int]:
    """
    Create an array of the given length and itemsize. Optionally specify whether it should
    contain (un)signed integers and what initial value each cell should have.
    """
    try:
        code = CodeMap[unsigned, itemsize]
    except KeyError as KE:
        un = 'un' if unsigned else ''
        raise LookupError(F'Cannot build array of {un}signed integers of width {itemsize}.') from KE
    if isinstance(init, int) and length > 0:
        fill = (init & ((1 << (itemsize * 8)) - 1))
        init = (fill for _ in range(length))
    if init:
        return array.array(code, init)
    else:
        return array.array(code)
