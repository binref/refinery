from __future__ import annotations

from Cryptodome.Cipher import ARC4

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.lib.types import Param
from refinery.units.crypto.cipher import Arg, StandardCipherUnit

ARC4.key_size = range(1, 257)


class rc4(StandardCipherUnit, cipher=PyCryptoFactoryWrapper(ARC4)):
    """
    RC4 encryption and decryption.
    """
    def __init__(
        self, key,
        discard: Param[int, Arg.Number('-d', help='Discard the first {varname} bytes of the keystream, {default} by default.')] = 0,
    ):
        super().__init__(key, discard=discard)

    def _new_cipher(self, **optionals):
        return super()._new_cipher(drop=self.args.discard, **optionals)
