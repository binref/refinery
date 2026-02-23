"""
This module implements an emulator abstraction layer.
"""
from __future__ import annotations

import enum
import importlib

from typing import TYPE_CHECKING

from .abstract import (
    CC,
    Arch,
    EmulationError,
    Emulator,
    Hook,
    MemAccess,
    NopCodeByArch,
    NopCodeMaxLen,
    Register,
    RetCodeByArch,
    RetCodeMaxLen,
)

if TYPE_CHECKING:
    from .ic import IcicleEmulator
    from .se import SpeakeasyEmulator
    from .uc import UnicornEmulator


class Engine(enum.Enum):
    speakeasy = 'se', 'SpeakeasyEmulator'
    icicle = 'ic', 'IcicleEmulator'
    unicorn = 'uc', 'UnicornEmulator'

    def __init__(self, mod_name: str, cls_name: str):
        self._mod_name = mod_name
        self._cls_name = cls_name
        self._emulator = None

    @property
    def cls(self):
        if (emu := self._emulator) is None:
            module = importlib.import_module(F'.{self._mod_name}', __package__)
            self._emulator = emu = getattr(module, self._cls_name)
        return emu


def __getattr__(name: str):
    for engine in Engine:
        if engine.value[1] == name:
            emu = engine.cls
            globals()[name] = emu
            return emu
    else:
        raise AttributeError(name)


__all__ = [
    'Arch',
    'CC',
    'EmulationError',
    'Emulator',
    'Engine',
    'Hook',
    'IcicleEmulator',
    'MemAccess',
    'NopCodeByArch',
    'NopCodeMaxLen',
    'Register',
    'RetCodeByArch',
    'RetCodeMaxLen',
    'SpeakeasyEmulator',
    'UnicornEmulator',
]
