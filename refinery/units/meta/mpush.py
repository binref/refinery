#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ..strings.rep import rep


class mpush(rep):
    """
    The unit operates almost exactly as `refinery.rep`, except that the last copy of the
    data is moved out of scope. This chunk is considered the "original" data, while all
    other chunks are to be used as intermediate results. For example:

        emit key=value | mpush [[| rex =(.*)$ $1 | mpop v ]| repl var:v censored ]

    will output `key=censored`. The application of `refinery.rex` turns the (duplicated)
    data into just the value, which is then stored in the variable `v`. The application
    of `refinery.repl` replaces this value with the hard-coded string `censored`.
    """
    def process(self, data):
        for _ in range(self.args.count - 1):
            yield data
        if self.args.nesting > 0:
            data.set_next_scope(False)
        else:
            try:
                data.visible = False
            except AttributeError:
                self.log_warn('application has no effect outside frame.')
        yield data
