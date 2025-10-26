"""
This module implements an emulator abstraction layer.
"""
from __future__ import annotations

from .abstract import (
    CC,
    Arch,
    EmulationError,
    Emulator,
    Hook,
    Register,
)
from .ic import IcicleEmulator
from .se import SpeakeasyEmulator
from .uc import UnicornEmulator

__all__ = [
    'Arch',
    'CC',
    'EmulationError',
    'Emulator',
    'Hook',
    'IcicleEmulator',
    'Register',
    'SpeakeasyEmulator',
    'UnicornEmulator',
]
