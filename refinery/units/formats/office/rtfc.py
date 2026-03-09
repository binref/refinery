from __future__ import annotations

from refinery.units import Unit


class rtfc(Unit):
    """
    Implements the RTF compression format. This compression algorithm is used, for example, to
    compress RTF data in Outlook messages.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        if len(data) >= 12 and data[8:12] == b'LZFu':
            return True

    def process(self, data):
        from refinery.lib.rtfc import decompress
        return decompress(data)

    def reverse(self, data):
        from refinery.lib.rtfc import compress
        return compress(data)
