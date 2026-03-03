from __future__ import annotations

from refinery.lib.fast.argon2 import (
    ARGON2D,
    ARGON2I,
    ARGON2ID,
    argon2hash,
)
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class argon2(Unit):
    """
    Implements Argon2-based key derivation.
    """
    def __init__(
        self,
        size: Param[int, Arg.Number(metavar='n', help='number of bytes to generate')],
        salt: Param[buf, Arg.Binary(metavar='S', help='salt bytes')],
        iter: Param[int, Arg.Number(metavar='t', help='number of iterations, defaults to {default}')] = 1,
        jobs: Param[int, Arg.Number(metavar='p', help='parallelism, defaults to {default}')] = 1,
        cost: Param[int, Arg.Number(metavar='m', help='memory cost in kibibytes, defaults to the minimum of 8192 per job.')] = 0,
        skey: Param[buf, Arg.Binary(metavar='K', help='optional secret key')] = b'',
        more: Param[buf, Arg.Binary(metavar='X', help='optional additional data')] = b'',
        resist_tmto: Param[bool, Arg.Switch('-i',
            help='Use Argon2i, maximizing resistance to time-memory trade-off (TMTO) attacks. Default is Argon2id.')] = False,
        resist_side: Param[bool, Arg.Switch('-d',
            help='Use Argon2d, maximizing resistance to side-channel attacks. Default is Argon2id.')] = False,
    ):
        if resist_tmto and resist_side:
            resist_tmto = resist_side = False
        super().__init__(
            size=size,
            salt=salt,
            iter=iter,
            skey=skey,
            jobs=jobs,
            cost=cost,
            more=more,
            i=resist_tmto,
            d=resist_side,
        )

    def process(self, data):
        m = self.args.cost
        p = self.args.jobs
        S = bytes(self.args.salt)
        K = self.args.skey
        n = self.args.size
        X = self.args.more
        t = self.args.iter
        K = bytes(K) if K else b''
        X = bytes(X) if X else b''
        m = m or 8192 * p
        if self.args.i:
            v = ARGON2I
        elif self.args.d:
            v = ARGON2D
        else:
            v = ARGON2ID
        return argon2hash(
            password=bytes(data),
            salt=S,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            tag_length=n,
            variant=v,
            secret=K,
            associated_data=X,
        )
