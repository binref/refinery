#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements various hashing algorithms.
"""
from refinery.units import arg, Unit, abc
from typing import ByteString, Protocol, Union


class HashType(Protocol):
    def digest(self) -> ByteString: ...


class HashUnit(Unit, abstract=True):

    @abc.abstractmethod
    def _algorithm(self, data: bytes) -> Union[ByteString, HashType]:
        raise NotImplementedError

    def __init__(self, text: arg('-t', help='Output a hexadecimal representation of the hash.') = False, **kwargs):
        super().__init__(text=text, **kwargs)

    def process(self, data: bytes) -> bytes:
        digest = self._algorithm(data)
        try: digest = digest.digest()
        except AttributeError: pass
        if self.args.text:
            digest = digest.hex().encode(self.codec)
        return digest
