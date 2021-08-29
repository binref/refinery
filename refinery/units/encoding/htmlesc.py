#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import html as html_entities

from .. import Unit
from ...lib.decorators import unicoded


class htmlesc(Unit):
    """
    Encodes and decodes HTML entities.
    """

    @unicoded
    def process(self, data: str) -> str:
        return html_entities.unescape(data)

    @unicoded
    def reverse(self, data: str) -> str:
        return html_entities.escape(data)
