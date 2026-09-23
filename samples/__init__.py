
import hashlib
import http.client
import os
import pathlib
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request

from refinery.units.crypto.cipher.aes import aes
from refinery.lib.environment import environment


if not (_sample_path := environment.storepath.value) or not _sample_path.is_dir():
    for _ancestor in pathlib.Path(__file__).absolute().parents:
        _sample_path = _ancestor / 'refinery-test-data'
        if _sample_path.is_dir() and (_sample_path / '_encode.bat').exists():
            break
    else:
        _sample_path = None


class ScriptHostRefused(RuntimeError):
    """
    A script host was about to start where a decoded sample is within reach: in the test that
    decoded one, or anywhere in a process that decoded one outside of a test.
    """


def _current_test() -> str | None:
    test = os.environ.get('PYTEST_CURRENT_TEST')
    if test is None:
        return None
    name, _, _ = test.rpartition(' (')
    return name or test


_DECODED_IN: set[str | None] = set()


def refuse_script_host_near_a_sample(host: str) -> None:
    """
    Raise `ScriptHostRefused` when *host* would start where a decoded sample is within reach. Every
    place that starts a script host calls this first, because the corpus holds live malware and a
    sample must never run. A decode outside of a test holds for the rest of the process.
    """
    if None in _DECODED_IN or _current_test() in _DECODED_IN:
        raise ScriptHostRefused(F'{host} may not start where a sample was decoded')


class SampleStore:
    lock = threading.Lock()

    if _sample_path is None:
        temp = tempfile.TemporaryDirectory(prefix='binary-refinery.test-data.')
        root = pathlib.Path(temp.name)
    else:
        root = _sample_path

    def __init__(self):
        self.wait = 0.1

    def _download(self, sha256hash: str, timeout: int = 80):
        def tobytearray(r):
            if isinstance(r, bytearray):
                return r
            return bytearray(r)
        remaining = timeout
        wait = self.wait
        backoff = 0
        req = F'https://github.com/binref/refinery-test-data/blob/master/{sha256hash}.enc?raw=true'
        while remaining > 0:
            clock = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=remaining) as response:
                    encoded_sample = tobytearray(response.read())
            except (
                http.client.RemoteDisconnected,
                socket.timeout,
                urllib.error.URLError,
            ):
                time.sleep(wait)
                wait *= 2
                backoff += 1
            else:
                if not backoff:
                    wait = max(0.1, wait / 2)
                self.wait = wait
                return encoded_sample
            remaining -= time.monotonic() - clock
        raise LookupError(F'Timeout exceeded while looking for {sha256hash}, backed off {backoff} times.')

    def decode(self, data: bytes, key: str | None = None):
        if key is None:
            key = 'REFINERYTESTDATA'
        _DECODED_IN.add(_current_test())
        result = data | aes(mode='CBC', key=key.encode('latin1')) | bytearray
        return result

    def download(self, sha256hash: str, key: str | None = None):
        encoded = self._download(sha256hash.lower())
        return self.decode(encoded, key)

    def get(self, sha256hash: str, key: str | None = None):
        sha256hash = sha256hash.lower()
        path = self.root / F'{sha256hash}.enc'
        with self.lock:
            try:
                with path.open('rb') as fd:
                    encoded = fd.read()
            except FileNotFoundError:
                on_disk = False
                encoded = self._download(sha256hash)
            else:
                on_disk = True
            result = self.decode(encoded, key)
            checksum = hashlib.sha256(result).hexdigest().lower()
            if not result or checksum != sha256hash:
                raise ValueError(F'The sample {sha256hash} did not decode correctly with key {key}.')
            if not on_disk:
                with path.open('wb') as fd:
                    fd.write(encoded)
            return result

    def __getitem__(self, sha256hash: str):
        return self.get(sha256hash)
