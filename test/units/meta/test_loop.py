#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestLoop(TestUnitBase):

    _DATA = (
        B'!!=8R6TTZLNO+D0IJSvm7iUXVnWtPakrZvZtMcQudk5AsuSBuY124VQcCt2s'
        B'mw8nFby95dWRHYn3d/EfobJu7EP0bvYYdJgX2nZccP3q7vGAQvA6yr8AOHaW'
        B'ljD1OEzHfmPmloKEXbcIwWsoZ3JUCGvWd7ytuIN+jktfrCm/YMWHYsFPcL9X'
        B'z1U/OUT53gmhXDsVn/m/TElA92Q9XW2TBtHLWWpWcS63Kuy+4adFmHU7d+lj'
        B'Hk4yg4FCFV1bQ8XHkHjE60IEyP5qmrQj/oE4SM4RkjOv542PZpWpnYVn/BjT'
        B'nGCsw9kyEHZ7CjIy1hN/1BiK6qvTiYAujc6wSDd4vcsm0cWywNNo4NRYG7f8'
        B'/SVrOBRuSuZyFWZ+0LXXpyS4wl+rshqn1HXMdKhXp+rkftwjH+KqmR/JwFUM'
        B'wuS2NS1IRWC1YF3MLyMxrPkDoU/r0C9W/s4zh1+SOvqfKg514lDl4qQmG38c'
        B'z6NKpfqgnBAjr4E3FtrwGh3GtnqETF/C7oGoJdcf7DGmEjop5mtw2zaEUdHr'
        B'nZwsu7dqkUnOKx/50ng/p+9Tf4UKCRxoRGYLmEmFCKvUEqlGVItR2sQDAAAN'
        B'mFJ5cF!!'
    )

    def test_default(self):
        data = self._DATA
        test = data | self.load(15, 'rev:csd[b64]:zl') | str
        self.assertEqual(test, 'refinery')

    def test_abort_gracefully_on_error(self):
        data = self._DATA
        test = data | self.load(1000, 'rev:csd[b64]:zl', lenient=1) | str
        self.assertEqual(test, 'refinery')

    def test_abort_with_condition(self):
        data = self._DATA
        test = data | self.load(1000, 'rev:csd[b64]:zl', do_until=b'fine') | str
        self.assertEqual(test, 'refinery')
