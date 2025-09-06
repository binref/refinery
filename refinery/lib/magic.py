"""
A cross-platform interface to libmagic.
"""
from __future__ import annotations

try:
    from winmagic import magic
except ModuleNotFoundError:
    import os
    if os.name == 'nt':
        # Attempting to import magic on Windows without winmagic being
        # installed may result in an uncontrolled crash.
        magic = None
    else:
        try:
            import magic
        except ImportError:
            magic = None


def magicparse(data, *args, **kwargs) -> str:
    if magic:
        data = bytes(data) if not isinstance(data, bytes) else data
        try:
            return magic.Magic(*args, **kwargs).from_buffer(data)
        except magic.MagicException:
            pass
    return 'application/octet-stream'
