"""
This module implements an emulator abstraction layer.
"""
from __future__ import annotations

import enum

from .abstract import (
    CC,
    Arch,
    EmulationError,
    Emulator,
    Hook,
    NopCodeByArch,
    NopCodeMaxLen,
    Register,
    RetCodeByArch,
    RetCodeMaxLen,
)
from .ic import IcicleEmulator
from .se import SpeakeasyEmulator
from .uc import UnicornEmulator


class Engine(enum.Enum):
    speakeasy = SpeakeasyEmulator
    icicle = IcicleEmulator
    unicorn = UnicornEmulator


__all__ = [
    'Arch',
    'CC',
    'EmulationError',
    'Emulator',
    'Engine',
    'Hook',
    'IcicleEmulator',
    'NopCodeByArch',
    'NopCodeMaxLen',
    'Register',
    'RetCodeByArch',
    'RetCodeMaxLen',
    'SpeakeasyEmulator',
    'UnicornEmulator',
]
