from __future__ import annotations

from refinery.units import Unit
from refinery.lib.java import JvClassFile


class jvstr(Unit):
    """
    Extract string constants from Java class files.
    """
    def process(self, data):
        jc = JvClassFile(data)
        for string in jc.strings:
            yield string.encode(self.codec)

    @classmethod
    def handles(cls, data):
        return data[:4] == B'\xCA\xFE\xBA\xBE'
