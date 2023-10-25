#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various hashing algorithms.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units import Arg, Unit, abc

if TYPE_CHECKING:
    from typing import Protocol, Union

    class _Hash(Protocol):
        def digest(self) -> bytes: ...


class HashUnit(Unit, abstract=True):

    @abc.abstractmethod
    def _algorithm(self, data: bytes) -> Union[_Hash, bytes]:
        raise NotImplementedError

    def __init__(self, text: Arg('-t', help='Output a hexadecimal representation of the hash.') = False, **kwargs):
        super().__init__(text=text, **kwargs)

    def process(self, data: bytes) -> bytes:
        digest = self._algorithm(data)
        try:
            digest = digest.digest()
        except AttributeError:
            pass
        if self.args.text:
            digest = digest.hex().encode(self.codec)
        return digest
