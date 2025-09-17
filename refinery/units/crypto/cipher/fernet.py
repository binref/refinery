from __future__ import annotations

from datetime import datetime

from Cryptodome.Hash import HMAC, SHA256

from refinery.lib.structures import StructReader
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit
from refinery.units.crypto.cipher.aes import aes
from refinery.units.encoding.b64 import b64


class fernet(Unit):
    """
    Decrypt Fernet messages.
    """
    def __init__(self, key: Param[buf, Arg(help='A fernet key, either in base64 or raw binary.')]):
        super().__init__(key=key)

    def _b64(self, data):
        try:
            return data | b64(urlsafe=True) | bytearray
        except Exception:
            return data

    def process(self, data):
        fk = self._b64(self.args.key)
        if len(fk) != 32:
            raise ValueError(F'The given Fernet key has length {len(fk)}, expected 32 bytes.')
        signing_key = fk[:16]
        encryption_key = fk[16:]
        decoded = self._b64(data)
        reader = StructReader(memoryview(decoded), bigendian=True)
        signed_data = reader.peek(reader.remaining_bytes - 32)
        version = reader.u8()
        timestamp = datetime.fromtimestamp(reader.u64())
        iv = reader.read(16)
        if version != 0x80:
            self.log_warn(F'The Fernet version is 0x{version:02X}, the only documented one is 0x80.')
        ciphertext = reader.read(reader.remaining_bytes - 32)
        if len(ciphertext) % 16 != 0:
            raise ValueError('The encoded ciphertext is not 16-byte block aligned.')
        signature = reader.read(32)
        hmac = HMAC.new(signing_key, digestmod=SHA256)
        hmac.update(signed_data)
        if hmac.digest() != signature:
            self.log_warn('HMAC verification failed; the message has been tampered with.')
            self.log_info(F'computed signature: {hmac.hexdigest().upper()}')
            self.log_info(F'provided signature: {signature.hex().upper()}')
        plaintext = ciphertext | aes(mode='cbc', iv=iv, key=encryption_key) | bytearray
        return self.labelled(plaintext, timestamp=timestamp.isoformat(' ', 'seconds'))
