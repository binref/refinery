#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import html as html_

from .. import Unit
from ...lib.decorators import unicoded


class htmlesc(Unit):
    """
    Encodes and decodes HTML entities.
    """

    @unicoded
    def process(self, data: str) -> str:
        return html_.unescape(data)

    @unicoded
    def reverse(self, data: str) -> str:
        return html_.escape(data)
