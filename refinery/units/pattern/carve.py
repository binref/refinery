#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, PatternExtractor
from ...lib.patterns import formats


class carve(PatternExtractor):
    """
    Extracts patches of data in particular formats from the input.
    """
    def __init__(
        self, format: arg.choice(choices=[p.name for p in formats], metavar='format',
            help='Specify one of the following formats: {choices}'),
        min=1, max=None, len=None, whitespace=False, unique=False, longest=False, take=None
    ):
        self.superinit(super(), **vars(), utf16=True, ascii=True)
        self.args.format = format

    def process(self, data):
        yield from self.matches_processed(data, bytes(formats[self.args.format]))
