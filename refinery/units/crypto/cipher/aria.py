from __future__ import annotations

from refinery.lib.crypto import BlockCipherFactory
from refinery.lib.crypto.aria import ARIA
from refinery.units.crypto.cipher import StandardBlockCipherUnit


class aria(StandardBlockCipherUnit, cipher=BlockCipherFactory(ARIA)):
    """
    ARIA encryption and decryption. ARIA is a South Korean block cipher standard (KS X 1213:2004)
    with a 128-bit block size, designed by a group of Korean researchers and adopted as a Korean
    national standard. It is structurally similar to AES, using a substitution-permutation network
    (SPN) with two types of substitution layers and a diffusion layer, but with a different key
    schedule. ARIA supports key sizes of 128, 192, and 256 bits and performs 12, 14, or 16 rounds
    respectively. It is specified in RFC 5794 and is mandatory in South Korean government and
    financial applications.
    """
