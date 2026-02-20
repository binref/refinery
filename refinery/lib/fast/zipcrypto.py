from __future__ import annotations


def decrypt(
    password: bytes | bytearray | memoryview,
    data: bytes | bytearray | memoryview,
    X: int,
    Y: int,
    Z: int
) -> tuple[bytearray, int, int, int]:
    if not (T := _CRC32_TABLE):
        for c in range(256):
            for _ in range(8):
                c, x = divmod(c, 2)
                c ^= x * 0xEDB88320
            T.append(c)
    output = bytearray()
    append = output.append
    for c in password:
        X = (X >> 8) ^ T[(X ^ c) & 0xFF]
        Y += X & 0xFF
        Y &= 0xFFFFFFFF
        Y *= 134775813
        Y += 1
        Y &= 0xFFFFFFFF
        Z = (Z >> 8) ^ T[(Z ^ (Y >> 24)) & 0xFF]
    for c in data:
        k = Z | 2
        c ^= ((k * (k ^ 1)) >> 8) & 0xFF
        X = (X >> 8) ^ T[(X ^ c) & 0xFF]
        Y += X & 0xFF
        Y &= 0xFFFFFFFF
        Y *= 134775813
        Y += 1
        Y &= 0xFFFFFFFF
        Z = (Z >> 8) ^ T[(Z ^ (Y >> 24)) & 0xFF]
        append(c)
    return output, X, Y, Z


_CRC32_TABLE: list[int] = []
