#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Tuple

from refinery.units import Arg, Unit


class trim(Unit):
    """
    Removes byte sequences at beginning and end of input data.
    """

    def __init__(
        self, *junk: Arg(help='Binary strings to be removed, default are all whitespace characters.'),
        unpad: Arg.Switch('-u', help='Also trim partial occurrences of the junk string.') = False,
        left: Arg.Switch('-r', '--right-only', group='SIDE', help='Do not trim left.') = True,
        right: Arg.Switch('-l', '--left-only', group='SIDE', help='Do not trim right.') = True,
        nocase: Arg.Switch('-i', help='Ignore capitalization for alphabetic characters.') = False,
    ):
        super().__init__(junk=junk, left=left, right=right, unpad=unpad, nocase=nocase)

    def _trimfast(self, view: memoryview, *junks: bytes, right=False) -> Tuple[bool, memoryview]:
        done = False
        pos = 0
        while not done:
            done = True
            for junk in junks:
                temp = junk
                size = len(junk)
                done = True
                if right and self.args.unpad:
                    for k in range(size):
                        n = size - k
                        if view[pos:pos + n] == junk[k:]:
                            pos += n
                            done = False
                            break
                if view[pos:pos + size] == temp:
                    m = len(temp)
                    while True:
                        mm = m << 1
                        if view[pos + m:pos + mm] != temp:
                            break
                        temp += temp
                        m = mm
                    temp = memoryview(temp)
                    while m >= size:
                        if view[pos:pos + m] == temp[:m]:
                            done = False
                            pos += m
                        m //= 2
                if right or not self.args.unpad:
                    continue
                while size > 0:
                    if view[pos:pos + size] == temp[:size]:
                        done = False
                        pos += size
                        break
                    size -= 1
        return pos

    def process(self, data: bytearray):
        junk = list(self.args.junk)
        if not junk:
            import string
            space = string.whitespace.encode('ascii')
            junk = [space[k - 1:k] for k in range(1, len(space))]
        lpos = 0
        rpos = 0
        if self.args.nocase:
            work = data.lower()
            junk = [j.lower() for j in junk]
        else:
            work = data
        if self.args.left:
            lpos = self._trimfast(memoryview(work), *junk)
        if self.args.right:
            work.reverse()
            junk = [bytes(reversed(j)) for j in junk]
            rpos = self._trimfast(memoryview(work), *junk, right=True)
            work.reverse()
        view = memoryview(data)
        if lpos:
            view = view[+lpos:]
        if rpos:
            view = view[:-rpos]
        return view
