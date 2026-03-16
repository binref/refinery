from __future__ import annotations

from refinery.units import Unit


class clower(Unit):
    """
    Convert all latin alphabet characters in the input to lowercase.
    """
    def process(self, data):
        return data.lower()
