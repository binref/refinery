#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import codecs

from email.header import decode_header

from .. import Unit
from ...lib.decorators import unicoded


class mimewords(Unit):
    """
    Implements the decoding of MIME encoded-word syntax from RFC-2047.
    """

    @unicoded
    def process(self, data: str) -> str:
        def replacer(match):
            self.log_info('encoded mime word:', match[0])
            decoded, = decode_header(match[0])
            raw, codec = decoded
            return codecs.decode(raw, codec, errors='surrogateescape')
        return re.sub(R"=(?:\?[^\?]*){3}\?=", replacer, data)
