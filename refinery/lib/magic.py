"""
A cross-platform interface for file type identification using pure-magic-rs.
"""
from __future__ import annotations

from typing import NamedTuple

from pure_magic_rs import MagicDb

_db = MagicDb()


class MagicType(NamedTuple):
    mime: str
    description: str


def magicparse(data) -> MagicType:
    if not isinstance(data, bytes):
        data = bytes(data)
    try:
        result = _db.best_magic_buffer(data)
        return MagicType(result.mime_type, result.message)
    except (ValueError, TypeError):
        return MagicType('application/octet-stream', 'data')
