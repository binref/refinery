#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import KeyDerivation


class PasswordDeriveBytes(KeyDerivation):
    """
    An implementation of the PasswordDeriveBytes routine available from the .NET
    standard library. According to documentation, it is an extension of PBKDF1.
    """
    def __init__(self, size, salt, iter=100, hash='SHA1'):
        self.superinit(super(), **vars())

    def process(self, data):
        if self.codec != 'UTF8':
            data = data.decode(self.codec).encode('UTF8')
        data += self.args.salt
        for _ in range(self.args.iter - 1):
            data = self.hash.new(data).digest()
        counter, seedhash = 1, data
        data = self.hash.new(data).digest()
        while len(data) < self.args.size:
            data += self.hash.new(B'%d%s' % (counter, seedhash)).digest()
            counter += 1
        return data[:self.args.size]
