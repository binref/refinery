#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import arg, RegexUnit, TransformSubstitutionFactory


class rex(RegexUnit):
    """
    A binary grep which can apply a transformation to each match. Each match is an
    individual output and standard forking settings apply. Two additional special
    multibin handlers are available for regular expressions:
    """

    def __init__(self, regex,
        # TODO: Use positional only in Python 3.8
        # /,
        *transformation: arg(type=utf8, help=(
            'An optional sequence of transformations to be applied to each match. '
            'Each transformation produces one output in the order in which they   '
            'are given. The default transformation is $0, i.e. the entire match.  '
        )),
        multiline=False, ignorecase=False, min=1, max=None, len=None, stripspace=False,
        unique=False, longest=False, take=None, utf16=False
    ):
        self.superinit(super(), **vars())

        if self.log_debug('regular expression:', self.args.regex):
            for t in transformation:
                self.log_debug(F'transformation:', t)

        self.args.transforms = [
            TransformSubstitutionFactory(t) for t in transformation]

    def process(self, data):
        yield from self.matches_processed(
            memoryview(data),
            self.args.regex,
            transforms=self.args.transforms
        )
