from __future__ import annotations


def decrypt(
    password: bytes | bytearray | memoryview,
    data: bytes | bytearray | memoryview,
    state1: int,
    state2: int,
    state3: int
) -> tuple[bytearray, int, int, int]:
    ...
