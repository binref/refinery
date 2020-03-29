#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A cross platform interface to libmagic.
"""
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


def magicparse(data, *args, **kwargs):
    if magic:
        data = bytes(data) if not isinstance(data, bytes) else data
        return magic.Magic(*args, **kwargs).from_buffer(data)
