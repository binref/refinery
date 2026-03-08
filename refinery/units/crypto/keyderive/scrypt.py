from __future__ import annotations

import hashlib

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class scrypt(Unit):
    """
    Implements scrypt-based key derivation as specified in RFC 7914. scrypt is a memory-hard
    password-based key derivation function designed by Colin Percival. It is intentionally slow
    and memory-intensive, making brute-force attacks expensive. The cost is controlled by three
    parameters: N (CPU/memory cost, must be a power of 2), R (block size), and P (parallelism).
    scrypt is used in cryptocurrency mining (Litecoin, Dogecoin), disk encryption tools, and
    for password hashing.
    """

    def __init__(
        self,
        size: Param[int, Arg.Number(metavar='n', help='number of bytes to generate')],
        salt: Param[buf, Arg.Binary(metavar='S', help='salt bytes')],
        memorycost: Param[int, Arg.Number(metavar='N',
            help='CPU/memory cost parameter, must be a power of 2, defaults to {default}')] = 1 << 14,
        blocksize: Param[int, Arg.Number(metavar='R',
            help='block size parameter, defaults to {default}')] = 8,
        parallelism: Param[int, Arg.Number(metavar='P',
            help='parallelism parameter, defaults to {default}')] = 1,
    ):
        super().__init__(size=size, salt=salt, n=memorycost, r=blocksize, p=parallelism)

    def process(self, data):
        return hashlib.scrypt(
            bytes(data),
            salt=bytes(self.args.salt),
            n=self.args.n,
            r=self.args.r,
            p=self.args.p,
            dklen=self.args.size,
        )
