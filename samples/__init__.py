from typing import Optional, Dict

import hashlib
import urllib.error
import urllib.request
import time
import threading

from refinery.units.crypto.cipher.aes import aes


class SampleStore:
    cache: Dict[str, bytes]

    def __init__(self):
        self.cache = {}
        self._lock = threading.Lock()
        self._wait = 0.1

    def _download(self, sha256hash: str, key: Optional[str] = None, timeout: int = 60):
        def tobytearray(r):
            if isinstance(r, bytearray):
                return r
            return bytearray(r)
        key = key or 'REFINERYTESTDATA'
        key = key.encode('latin1')
        remaining = timeout
        wait = self._wait
        backoff = 0
        req = F'https://github.com/binref/refinery-test-data/blob/master/{sha256hash}.enc?raw=true'
        while remaining > 0:
            clock = time.time()
            time.sleep(wait)
            try:
                with urllib.request.urlopen(req, timeout=remaining) as response:
                    encoded_sample = tobytearray(response.read())
            except urllib.error.HTTPError as error:
                if error.code != 429:
                    raise
                backoff += 1
                wait *= 2
            else:
                if not backoff:
                    wait = max(0.1, wait / 2)
                self._wait = wait
                result = encoded_sample | aes(mode='CBC', key=key) | bytearray
                if not result or hashlib.sha256(result).hexdigest().lower() != sha256hash:
                    raise ValueError(F'The sample {sha256hash} did not decode correctly with key {key}.')
                self.cache[sha256hash] = result
                return result
            remaining -= time.time() - clock
        raise LookupError(F'Timeout exceeded while looking for {sha256hash}, backed off {backoff} times.')

    def get(self, sha256hash: str, key: Optional[str] = None):
        sha256hash = sha256hash.lower()
        with self._lock:
            for cached, value in self.cache.items():
                if cached == sha256hash:
                    return value
            else:
                return self._download(sha256hash, key)

    def __getitem__(self, sha256hash: str):
        return self.get(sha256hash)
