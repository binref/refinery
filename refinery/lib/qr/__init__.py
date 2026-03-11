from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PIL.Image import Image


def decode(image: Image) -> list[bytes]:
    from refinery.lib.qr.decode import decode_qr_grid
    from refinery.lib.qr.locate import locate_qr_codes
    results: list[bytes] = []
    for grid in locate_qr_codes(image):
        try:
            payload = decode_qr_grid(grid.modules, grid.version)
        except Exception:
            continue
        if payload:
            results.append(payload)
    return results
