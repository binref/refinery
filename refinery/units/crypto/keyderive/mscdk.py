"""
Reference:
https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
"""
from __future__ import annotations

from refinery.units.crypto.keyderive import HASH, KeyDerivation


class mscdk(KeyDerivation):
    """
    An implementation of the CryptDeriveKey routine available from the Win32 API.
    """

    def __init__(self, size, hash='MD5'):
        super().__init__(size=size, salt=None, hash=hash)

    def keystream(self, seed):
        def digest(x):
            return hn(x).digest()
        hf = self._hash_interface()
        hn = hf.new
        if self.args.hash in (HASH.SHA224, HASH.SHA256, HASH.SHA384, HASH.SHA512):
            return digest(seed)
        else:
            buffer1 = bytearray([0x36] * 64)
            buffer2 = bytearray([0x5C] * 64)
            for k, b in enumerate(digest(seed)):
                buffer1[k] ^= b
                buffer2[k] ^= b
            return digest(buffer1) + digest(buffer2)
