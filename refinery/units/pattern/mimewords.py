from __future__ import annotations

import codecs
import re

from email.header import decode_header

from refinery.lib.decorators import unicoded
from refinery.units import Unit


class mimewords(Unit):
    """
    Implements the decoding of MIME encoded-word syntax from RFC-2047.
    """
    @classmethod
    def convert(cls, word: str) -> str:
        """
        Converts the MIME word.
        """
        def replacer(match):
            decoded, = decode_header(match[0])
            raw, codec = decoded
            if not isinstance(codec, str):
                codec = cls.codec
            return codecs.decode(raw, codec, errors='surrogateescape')
        return re.sub(R"=(?:\?[^\?]*){3}\?=", replacer, word)

    @unicoded
    def process(self, data):
        return self.convert(data)
