from __future__ import annotations

import html as html_entities

from refinery.lib.decorators import unicoded
from refinery.units import Unit


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
