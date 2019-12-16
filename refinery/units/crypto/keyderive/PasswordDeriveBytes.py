#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import KeyDerivation


class PasswordDeriveBytes(KeyDerivation):
    """
    An implementation of the PasswordDeriveBytes routine available from the .NET
    standard library. According to documentation, it is an extension of PBKDF1.
    """

    _DEFAULT_SALT = None
    _DEFAULT_HASH = 'SHA1'
    _DEFAULT_ITER = 100

    def process(self, data):
        # TODO move this into a test
        if self.codec != 'UTF8':
            data = data.decode(self.codec).encode('UTF8') + self.salt
        for _ in range(self.iterations - 1):
            data = self.algorithm.new(data).digest()
        seedhash = data
        counter = 1
        data = self.algorithm.new(data).digest()

        while len(data) < self.args.size:
            data += self.algorithm.new(B'%d%s' % (counter, seedhash)).digest()
            counter += 1

        return data[:self.args.size]
