#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import html as html_

from .. import Unit
from ...lib.decorators import unicoded


class html(Unit):
    """
    Encodes and decodes common ASCII escape sequences.
    """

    @unicoded
    def process(self, data: str) -> str:
        return html_.unescape(data)

    @unicoded
    def reverse(self, data: str) -> str:
        return html_.escape(data)
