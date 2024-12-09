#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.pattern import SingleRegexUnit
from refinery.units.meta import ConditionalUnit


class iffx(SingleRegexUnit, ConditionalUnit, extend_docs=True):
    """
    Filter incoming chunks by discarding those that do not match the given
    regular expression.
    """
    def match(self, chunk):
        return bool(self.matcher(chunk))
