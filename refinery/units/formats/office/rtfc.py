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

    @Unit.Requires('compressed_rtf', ['formats', 'office', 'default', 'extended'])
    def _rtfc():
        import compressed_rtf
        return compressed_rtf

    def process(self, data):
        return self._rtfc.decompress(data)

    def reverse(self, data):
        return self._rtfc.compress(data)
