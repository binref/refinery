from __future__ import annotations

from refinery.lib.crypto import BlockCipherFactory
from refinery.lib.crypto.twofish import Twofish
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class twofish(StandardBlockCipherUnit, cipher=BlockCipherFactory(Twofish)):
    """
    Twofish encryption and decryption. Twofish is a symmetric block cipher with a 128-bit block
    size, designed by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, and
    Niels Ferguson. It was one of the five AES finalists. The cipher uses key-dependent S-boxes,
    a 16-round Feistel network, an MDS matrix, and a pseudo-Hadamard transform (PHT). It supports
    key sizes of 128, 192, and 256 bits. Twofish is commonly encountered in disk encryption
    software, VPN protocols, and password managers.
    """
