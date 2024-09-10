#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Cryptodome.Cipher import ARC2

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.units import Arg
from refinery.units.crypto.cipher import StandardBlockCipherUnit, CipherInterface


class rc2(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(ARC2)):
    """
    RC2 encryption and decryption.
    """

    def __init__(
        self, key, iv=b'', *,
        eks: Arg.Number('-k', '--eks', group='EKS',
            help='Set the effective key size. Default is {default}.') = 1024,
        derive_eks: Arg.Switch('-d', '--dks', group='EKS',
            help='Act as .NET and derive the effective key size from the key length.') = False,
        padding=None,
        mode=None,
        raw=False,
        little_endian=False,
        segment_size=0,
        mac_len=0,
        assoc_len=0,
        **keywords
    ):
        super().__init__(
            key,
            iv,
            eks=eks,
            derive_eks=derive_eks,
            padding=padding,
            mode=mode,
            raw=raw,
            little_endian=little_endian,
            segment_size=segment_size,
            mac_len=mac_len,
            assoc_len=assoc_len,
            **keywords
        )

    def _new_cipher(self, **optionals) -> CipherInterface:
        eks = len(self.args.key) * 8 if self.args.derive_eks else self.args.eks
        optionals.update(effective_keylen=eks)
        return super()._new_cipher(**optionals)
