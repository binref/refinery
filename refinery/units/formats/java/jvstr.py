from __future__ import annotations

from refinery.lib.java import JvClassFile
from refinery.units import Unit


class jvstr(Unit):
    """
    Extract string constants from Java class files.
    """
    def process(self, data):
        jc = JvClassFile.Parse(data)
        for string in jc.strings:
            yield string.encode(self.codec)

    @classmethod
    def handles(cls, data):
        return data[:4] == B'\xCA\xFE\xBA\xBE'
