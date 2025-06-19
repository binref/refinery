#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, Arg


class argon2id(Unit):
    """
    Implements Argon2id-based key derivation.
    """

    def __init__(
        self,
        size: Arg.Number(metavar='n', help='number of bytes to generate'),
        salt: Arg.Binary(metavar='S', help='salt bytes'),
        iter: Arg.Number(metavar='t', help='number of iterations, defaults to {default}') = 1,
        jobs: Arg.Number(metavar='p', help='parallelism, defaults to {default}') = 1,
        cost: Arg.Number(metavar='m', help='memory cost in kibibytes, defaults to the minimum of 8192 per job.') = None,
        skey: Arg.Binary(metavar='K', help='optional secret key') = None,
        more: Arg.Binary(metavar='X', help='optional additional data') = None,
    ):
        super().__init__(size=size, salt=salt, iter=iter, skey=skey, jobs=jobs, cost=cost, more=more)

    @Unit.Requires('cryptography', 'default', 'extended')
    def _argon2id():
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id

    def process(self, data):
        m = self.args.cost
        p = self.args.jobs
        S = self.args.salt
        K = self.args.skey
        n = self.args.size
        X = self.args.more
        t = self.args.iter
        K = K and bytes(K) or None
        X = X and bytes(X) or None
        S = bytes(S)
        m = m or 8192 * p
        a2id = self._argon2id(
            salt=S, length=n, iterations=t, lanes=p, memory_cost=m, ad=X, secret=K)
        return a2id.derive(data)
