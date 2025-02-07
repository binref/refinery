from typing import Optional, Dict

import hashlib
import os
import urllib.request

from refinery.units.crypto.cipher.aes import aes


class SampleStore:
    cache: Dict[str, bytes]

    def __init__(self):
        self.cache = {}

    def download(self, sha256hash: str, key: Optional[str] = None):
        def tobytearray(r):
            if isinstance(r, bytearray):
                return r
            return bytearray(r)
        key = key or 'REFINERYTESTDATA'
        key = key.encode('latin1')
        sha256hash = sha256hash.lower()
        timeout = 60
        req = F'https://github.com/binref/refinery-test-data/blob/master/{sha256hash}.enc?raw=true'
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                encoded_sample = tobytearray(response.read())
        except Exception:
            api = os.environ['MALSHARE_API']
            req = F'https://malshare.com/api.php?api_key={api}&action=getfile&hash={sha256hash}'
            with urllib.request.urlopen(req, timeout=timeout) as response:
                result = tobytearray(response.read())
        else:
            result = encoded_sample | aes(mode='CBC', key=key) | bytearray
            if not result or hashlib.sha256(result).hexdigest().lower() != sha256hash:
                raise ValueError('sample did not decode correctly')
        self.cache[sha256hash] = result
        return result

    def get(self, sha256hash: str, key: Optional[str] = None):
        for cached, value in self.cache.items():
            if cached.casefold() == sha256hash.casefold():
                return value
        else:
            return self.download(sha256hash, key)

    def __getitem__(self, sha256hash: str):
        return self.get(sha256hash)
