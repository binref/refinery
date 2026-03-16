from __future__ import annotations

from refinery.units import Unit


class escvb(Unit):
    """
    Convert from and to Visual Basic (VB/VBA/VBS/VB.NET) string literals using doubled-quote
    escaping.
    """
    def process(self, data):
        if data[:1] == B'"' and data[-1:] == B'"':
            data = data[1:-1]
        return data.replace(B'""', B'"')

    def reverse(self, data):
        return B'"%s"' % data.replace(B'"', B'""')
