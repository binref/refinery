#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ARC2

from refinery.units.crypto.cipher import StandardBlockCipherUnit, CipherInterface


class rc2(StandardBlockCipherUnit, cipher=ARC2):
    """
    RC2 encryption and decryption.
    """

    def _get_cipher_instance(self, **optionals) -> CipherInterface:
        optionals.update(effective_keylen=max(ARC2.key_size))
        return super()._get_cipher_instance(**optionals)
