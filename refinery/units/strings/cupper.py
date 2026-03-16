from __future__ import annotations

from refinery.units import Unit


class cupper(Unit):
    """
    Convert all latin alphabet characters in the input to uppercase.
    """
    def process(self, data):
        return data.upper()
