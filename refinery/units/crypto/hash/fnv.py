"""
The Fowler-Noll-Vo (FNV) hash function.
"""
from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.crypto.hash import HashUnit

_FNV_SPEC = {
    0x0020: (
        0x01000193,
        0x811c9dc5,
    ),
    0x0040: (
        0x00000100_000001b3,
        0xcbf29ce4_84222325,
    ),
    0x0080: (
        0x0000000001000000000000000000013b,
        0x6c62272e07bb014262b821756295c58d,
    ),
    0x0100: (
        (1 << 168) | (1 << 8) | 0x63,
        int('dd268dbcaac550362d98c384c4e576cc'
            'c8b1536847b6bbb31023b4c8caee0535', 16),
    ),
    0x200: (
        (1 << 344) | (1 << 8) | 0x57,
        int('b86db0b1171f4416dca1e50f309990ac'
            'ac87d059c90000000000000000000d21'
            'e948f68a34c192f62ea79bc942dbe7ce'
            '182036415f56e34bac982aac4afe9fd9', 16),
    ),
    0x400: (
        (1 << 680) | (1 << 8) | 0x8D,
        int('0000000000000000005f7a76758ecc4d'
            '32e56d5a591028b74b29fc4223fdada1'
            '6c3bf34eda3674da9a21d90000000000'
            '00000000000000000000000000000000'
            '00000000000000000000000000000000'
            '0000000000000000000000000004c6d7'
            'eb6e73802734510a555f256cc005ae55'
            '6bde8cc9c6a93b21aff4b16c71ee90b3', 16),
    )
}


class FNVUnit(HashUnit, abstract=True):
    def __init__(
        self,
        bits: Param[int, Arg.Number('-x',
            help='Specify the bit size, the default is {default}')] = 32,
        reps: int = 1,
        text: bool = False,
    ):
        super().__init__(reps, text, type=type, bits=bits)

    def _spec(self):
        bits = self.args.bits
        try:
            prime, base = _FNV_SPEC[bits]
        except KeyError:
            bit_options = ', '.join(str(b) for b in _FNV_SPEC)
            raise ValueError(
                F'Invalid bit size {bits}, only the following are supported: {bit_options}.')
        else:
            size = bits // 8
            mask = ~(-1 << size)
            return mask, size, prime, base


class fnv0(FNVUnit):
    """
    The Fowler-Noll-Vo (FNV) hash version 0
    """
    def _algorithm(self, data) -> bytes:
        mask, size, prime, _ = self._spec()
        h = 0
        for b in data:
            h *= prime
            h &= mask
            h ^= b
        return h.to_bytes(size, 'big')


class fnv1(FNVUnit):
    """
    The Fowler-Noll-Vo (FNV) hash version 1
    """
    def _algorithm(self, data) -> bytes:
        mask, size, prime, h = self._spec()
        for b in data:
            h *= prime
            h &= mask
            h ^= b
        return h.to_bytes(size, 'big')


class fnv1a(FNVUnit):
    """
    The Fowler-Noll-Vo (FNV) hash version 1a
    """
    def _algorithm(self, data) -> bytes:
        mask, size, prime, h = self._spec()
        for b in data:
            h ^= b
            h *= prime
            h &= mask
        return h.to_bytes(size, 'big')


class fnv1x64(fnv1, docs='{0},{s}bit size fixed to 64'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(64, reps, text)


class fnv1x128(fnv1, docs='{0},{s}bit size fixed to 128'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(128, reps, text)


class fnv1x256(fnv1, docs='{0},{s}bit size fixed to 256'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(256, reps, text)


class fnv1x512(fnv1, docs='{0},{s}bit size fixed to 512'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(512, reps, text)


class fnv1ax64(fnv1a, docs='{0},{s}bit size fixed to 64'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(64, reps, text)


class fnv1ax128(fnv1a, docs='{0},{s}bit size fixed to 128'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(128, reps, text)


class fnv1ax256(fnv1a, docs='{0},{s}bit size fixed to 256'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(256, reps, text)


class fnv1ax512(fnv1a, docs='{0},{s}bit size fixed to 512'):
    def __init__(self, reps: int = 1, text: bool = False):
        super().__init__(512, reps, text)
