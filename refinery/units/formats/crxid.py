#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib

from refinery.units import Unit


class crxid(Unit):
    """
    Calculates Chrome Extension ID based off of the base64 decoded public key from the manifest.json.
    """

    def process(self, data):
        return ''.join([chr(ord('a') + int(c, 16)) for c in hashlib.sha256(data).hexdigest()[:32]]).encode(self.codec)
