#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import Counter
from refinery import Unit, Arg
from refinery.lib.argformats import sliceobj


class xkey(Unit):
    """
    The unit expects encrypted input which was encrypted byte-wise with a polyalphabetic key, and
    which also has one letter that occurs with overwhelming frequency. This is often the case for
    the zero byte in binary formats such as PE files, and the space character in text files. Based
    on this assumption, the unit computes the most likely key. This can be useful to decrypt PE
    and uncompressed text files that were encrypted byte-wise using a short key.
    """
    def __init__(
        self,
        range: Arg(type=sliceobj, help='range of length values to try, the default is 1:128.') = slice(1, 129),
    ):
        super().__init__(range=range)

    def process(self, data: bytearray):
        score = 0
        guess = None
        bounds: slice = self.args.range
        data = memoryview(data)

        n = len(data)

        start = bounds.start or 1
        stop = min(bounds.stop or n, n)

        if bounds.step is not None:
            step = bounds.step
            if bounds.start is None:
                start *= step
        else:
            step = 1

        self.log_debug(F'redeived input range [{bounds.start}:{bounds.stop}:{bounds.step}], using [{start}:{stop}:{step}]')

        for length in range(start, stop, step):
            _guess = [Counter(data[j::length]).most_common(1)[0] for j in range(length)]
            _score = sum(count for _, count in _guess)
            if _score == score and guess and len(_guess) % len(guess) == 0 and len(guess) >= 3:
                self.log_info('found same score at multiple of length of best performer, exiting')
                break
            if _score > score:
                self.log_info(F'got score {_score*100/n:5.2f}% for length {length}')
                score = _score
                guess = (value for value, _ in _guess)
                guess = bytearray(guess)

        return guess
