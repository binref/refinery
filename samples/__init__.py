from typing import Optional, Dict

import threading
import pathlib

from refinery.units.crypto.cipher.aes import aes


class SampleStore:
    cache: Dict[str, bytes]

    def __init__(self):
        self.cache = {}
        self._lock = threading.Lock()

    def decode(self, sha256hash: str, key: Optional[str] = None):
        key = key or 'REFINERYTESTDATA'
        key = key.encode('latin1')
        sha256hash = sha256hash.lower()
        path = pathlib.Path(__file__).parent / F'{sha256hash}.enc'
        with path.open('rb') as fd:
            result = fd | aes(mode='CBC', key=key) | bytearray
        self.cache[sha256hash] = result
        return result

    def get(self, sha256hash: str, key: Optional[str] = None):
        sha256hash = sha256hash.lower()
        with self._lock:
            try:
                return self.cache[sha256hash]
            except KeyError:
                return self.decode(sha256hash, key)

    def __getitem__(self, sha256hash: str):
        return self.get(sha256hash)
