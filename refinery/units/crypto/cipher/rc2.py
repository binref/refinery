#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import ARC2

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units.crypto.cipher import StandardBlockCipherUnit, CipherInterface


class rc2(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(ARC2)):
    """
    RC2 encryption and decryption.
    """

    def _new_cipher(self, **optionals) -> CipherInterface:
        optionals.update(effective_keylen=max(ARC2.key_size))
        return super()._new_cipher(**optionals)
