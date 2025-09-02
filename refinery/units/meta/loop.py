#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import RefineryPartialResult
from refinery.units.pattern import Arg, RegexUnit
from refinery.lib.argformats import regexp, DelayedBinaryArgument
from refinery.lib.tools import exception_to_string


class loop(RegexUnit):
    """
    Applies a given multibin suffix to the input chunk repeatedly. For example, the following
    command would carve the largest base64-encoded buffer from the input, decode it, and then
    decompress the result 20 times:

        emit data | loop 20 csd[b64]:zl

    Notably, the argument after the count is a suffix, which means that handlers are applied
    from left to right (not from right to left). The loop is aborted and the previous result
    returned if the newly computed result is empty. If the an error occurs while computing
    the suffix and the unit is lenient (i.e. the `-L` switch is set), the last known result
    is returned.
    """

    def __init__(
        self,
        count: Arg.Number(metavar='count', help='The number of repeated applications of the suffix.'),
        suffix: Arg(type=str, help='A multibin expression suffix.'),
        do_while: Arg('-w', '--while', type=regexp, metavar='RE',
            help='Halt when the given regular expression does not match the data.'),
        do_until: Arg('-u', '--until', type=regexp, metavar='RE',
            help='Halt when the given regular expression matches the data.'),
        fullmatch=False, multiline=False, ignorecase=False,
    ):
        super().__init__(
            count=count,
            suffix=suffix,
            do_while=do_while,
            do_until=do_until,
            fullmatch=fullmatch,
            multiline=multiline,
            ignorecase=ignorecase,
        )

    def process(self, data):
        _count = self.args.count
        _width = len(str(_count))
        _while = self._while
        _until = self._until

        for k in range(_count):
            if _while and not _while(data):
                self.log_info(F'step {k:0{_width}}: stopping, while-condition violated')
                break
            if _until and _until(data):
                self.log_info(F'step {k:0{_width}}: stopping, until-condition satisfied')
                break
            try:
                out = DelayedBinaryArgument(
                    self.args.suffix, reverse=True, seed=data)(data)
            except Exception as error:
                self.log_info(F'step {k:0{_width}}: error;', exception_to_string(error))
                msg = F'Stopped after {k} steps, increase verbosity for additional details.'
                raise RefineryPartialResult(msg, data) from error
            if not out:
                self.log_info(F'step {k:0{_width}}: stopping after empty result')
                break
            data[:] = out
            self.log_debug(F'step {k:0{_width}}: data =', data, clip=True)

        return data

    @property
    def _while(self):
        return self._make_matcher(self.args.do_while)

    @property
    def _until(self):
        return self._make_matcher(self.args.do_until)
