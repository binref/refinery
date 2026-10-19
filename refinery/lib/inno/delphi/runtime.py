"""
The state that Delphi's run-time library keeps for a process and that its functions read.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.inno.delphi.numbers import FormatSettings
from refinery.lib.inno.delphi.x87 import FPU


class Platform(enum.Enum):
    """
    The platforms that Delphi compiles Inno Setup for.
    """
    Win32 = 32
    Win64 = 64


@dataclass
class Runtime:
    """
    The control word of the x87, which decides how floats are rounded and which float errors raise
    exceptions, and the regional settings that numbers are formatted and parsed with.
    """
    fpu: FPU = field(default_factory=FPU)
    settings: FormatSettings = field(default_factory=FormatSettings)
