#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class trim(Unit):
    """
    Removes byte sequences at beginning and end of input data.
    """

    def __init__(
        self, *junk: arg.help('Binary strings to be removed, default are all whitespace characters.'),
        left: arg.switch('-r', '--right-only', group='SIDE', help='Do not trim left.') = True,
        right: arg.switch('-l', '--left-only', group='SIDE', help='Do not trim right.') = True
    ):
        if not junk:
            import string
            strips = string.whitespace.encode('ascii')
        else:
            strips = bytes(j[0] for j in junk if len(j) == 1)
            junk = [j for j in junk if len(j) >= 2]

        strip = None

        if strips:
            if left and right:
                def strip(b):
                    if b[0] in strips or b[-1] in strips:
                        return True, b.strip(strips)
                    return False, b
            elif left:
                def strip(b):
                    if b[0] in strips:
                        return True, b.lstrip(strips)
                    return False, b
            elif right:
                def strip(b):
                    if b[-1] in strips:
                        return True, b.rstrip(strips)
                    return False, b

        super().__init__(strip=strip, junk=junk, left=left, right=right)

    def process(self, data: bytearray):
        dirty = True
        synch = True
        mview = memoryview(data)

        while dirty:
            dirty = False

            if self.args.strip:
                dirty, data = self.args.strip(data)
                if dirty:
                    mview = memoryview(data)
                    synch = True

            for junk in self.args.junk:

                # For large repeated patches of junk, performance is increased significantly by
                # performing less comparisons in Python code. The following code determines a
                # binary representation of the number N of trimmable junk pieces by performing
                # at most 2 log(N) comparisons. Furthermore, exactly K trimming operations are
                # done, where K is the number of bits in the binary representation of N that are
                # set.

                if self.args.left and mview[:len(junk)] == junk:
                    dirty = True
                    synch = False
                    t = junk
                    while mview[:len(t)] == t:
                        mview = mview[len(t):]
                        t += t
                    t = memoryview(t)
                    while t:
                        if mview[:len(t)] == t: mview = mview[len(t):]
                        t = t[:len(t) // 2]

                if self.args.right and mview[-len(junk):] == junk:
                    dirty = True
                    synch = False
                    t = junk
                    while mview[-len(t):] == t:
                        mview = mview[:-len(t)]
                        t += t
                    t = memoryview(t)
                    while t:
                        if mview[-len(t):] == t: mview = mview[:-len(t)]
                        t = t[:len(t) // 2]

        return bytearray(mview) if not synch else data
