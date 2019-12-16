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
        argp.add_argument('format', type=utf8, nargs='?', default=None,
            help='An optional transformation to be applied to each match.')
        return argp

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.transform = self.args.format and TransformSubstitutionFactory(self.args.format)
        self.log_debug('using regexp:', self.args.regex)
        self.log_debug('using format:', self.args.format)

    def process(self, data):
        yield from self.matches_processed(data, self.args.regex, transform=self.transform)
