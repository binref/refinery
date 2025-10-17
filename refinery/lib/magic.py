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
    if magic is not None:
        if not isinstance(data, bytes):
            data = bytes(data)
        try:
            return magic.Magic(*args, **kwargs).from_buffer(data)
        except magic.MagicException:
            pass
    elif kwargs.get('mime', False) is True:
        return 'application/octet-stream'
    else:
        return 'data'
