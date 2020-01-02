#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import RegexUnit, TransformSubstitutionFactory


class rex(RegexUnit):
    """
    A binary grep which can apply a transformation to each match. Each match is an
    individual output and standard forking settings apply. Two additional special
    multibin handlers are available for regular expressions:
    """

    def interface(self, argp):
        argp = super().interface(argp)
        argp.add_argument(
            dest='transformations',
            metavar='transformation',
            type=utf8,
            nargs='*',
            default=None,
            help=(
                'An optional sequence of transformations to be applied to each match. '
                'Each transformation produces one output in the order in which they '
                'are given. The default transformation is $0, i.e. the entire match. '
            )
        )
        return argp

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.transforms = [TransformSubstitutionFactory(f) for f in self.args.transformations]
        if self.log_debug():
            self.log_debug('regular expression:', self.args.regex)
            for k, transform in enumerate(self.args.transformations, 1):
                self.log_debug(F'transformation {k}:', transform)

    def process(self, data):
        yield from self.matches_processed(data, self.args.regex, transforms=self.transforms)
