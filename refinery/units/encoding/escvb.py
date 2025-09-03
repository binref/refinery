from __future__ import annotations

from refinery.units import Unit


class escvb(Unit):
    """
    Escapes and unescapes Visual Basic strings.
    """
    def process(self, data):
        if data[:1] == B'"' and data[-1:] == B'"':
            data = data[1:-1]
        return data.replace(B'""', B'"')

    def reverse(self, data):
        return B'"%s"' % data.replace(B'"', B'""')
