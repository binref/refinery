#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from ...crypto.cipher.secstr import secstr
from ...blockwise.pack import pack
from ....lib.patterns import formats


class deob_ps1_secstr(Deobfuscator):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)

        self._pack = pack()
        self._secstr = secstr()

        self._pattern = re.compile(
            R'\s{{0,20}}'.join([
                R'''(['"])({b})\1''',
                R'\|', R'\.?', R'&?',
                R'''(['"]?)ConvertTo-SecureString\3''',
                R'-ke?y?',
                R'''(\(?)({a}|{i}\s{{0,20}}\.\.\s{{0,20}}{i})''',
                R'((?:\)\s{{0,20}}){{0,10}})?'
            ]).format(
                b=formats.b64,
                a=formats.intarray,
                i=formats.integer
            ),
            flags=re.IGNORECASE | re.DOTALL
        )

    def _decrypt_block(self, data, match):
        if '..' in match[5]:
            a, b = [int(x.strip(), 0) for x in match[5].split('..')]
            key = range(min(a, b), max(a, b) + 1)
            if a > b:
                key = reversed(key)
            self._secstr.args.key = bytes(bytearray(key))
        else:
            self._secstr.args.key = self._pack(match[5].encode(self.codec))
        decoded = self._secstr(match[2].encode(self.codec))
        decoded = decoded.decode(self.codec)
        result = F'\n\n{decoded}\n\n'
        brackets = match[6].count(')')
        start = match.start()
        if match[4]:
            brackets -= 1
        if brackets <= 0:
            if brackets < 0:
                result += ')'
            return start, result
        while brackets:
            start -= 1
            if data[start] == '(':
                brackets -= 1
            if data[start] == ')':
                brackets += 1
        return start, result

    def deobfuscate(self, data):
        while True:
            match = self._pattern.search(data)
            if not match:
                break
            start, result = self._decrypt_block(data, match)
            data = data[:start] + result + data[match.end():]
        return data
