from __future__ import annotations

from Cryptodome.Cipher import ARC2

from refinery.lib.crypto import PyCryptoFactoryWrapper
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.crypto.cipher import CipherInterface, StandardBlockCipherUnit


class rc2(StandardBlockCipherUnit, cipher=PyCryptoFactoryWrapper(ARC2)):
    """
    RC2 encryption and decryption.
    """

    def __init__(
        self, key, *,
        iv=b'',
        eks: Param[int, Arg.Number('-k', '--eks', group='EKS',
            help='Set the effective key size. Default is {default}.')] = 1024,
        derive_eks: Param[bool, Arg.Switch('-d', '--dks', group='EKS',
            help='Act as .NET and derive the effective key size from the key length.')] = False,
        padding=None,
        mode=None,
        raw=False,
        little_endian=False,
        segment_size=0,
        tag=None,
        aad=None,
        **keywords
    ):
        super().__init__(
            key,
            iv=iv,
            eks=eks,
            derive_eks=derive_eks,
            padding=padding,
            mode=mode,
            raw=raw,
            little_endian=little_endian,
            segment_size=segment_size,
            tag=tag,
            aad=aad,
            **keywords
        )

    def _new_cipher(self, **optionals) -> CipherInterface:
        eks = len(self.args.key) * 8 if self.args.derive_eks else self.args.eks
        optionals.update(effective_keylen=eks)
        return super()._new_cipher(**optionals)
