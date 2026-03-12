"""
A cross-platform interface for file type identification using pure-magic-rs.
"""
from __future__ import annotations

from pure_magic_rs import MagicDb

_db = MagicDb()


def magicparse(data, mime=False) -> str:
    if not isinstance(data, bytes):
        data = bytes(data)
    try:
        result = _db.best_magic_buffer(data)
        return result.mime_type if mime else result.message
    except (ValueError, TypeError):
        pass
    if mime:
        return 'application/octet-stream'
    return 'data'
