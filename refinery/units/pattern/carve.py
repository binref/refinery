#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import PatternExtractor
from ...lib.patterns import formats


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """

    def interface(self, argp):
        choices = [p.name for p in formats]
        argp.add_argument(
            'format', type=str, choices=choices, metavar='FORMAT',
            help='Specify one of the following formats: {}'.format(', '.join(choices))
        )
        return super().interface(argp)

    def process(self, data):
        yield from self.matches_processed(data, formats[self.args.format].value)
