from __future__ import annotations

from refinery.lib.batch import BatchFileEmulator
from refinery.units import Unit


class bat(Unit):
    """
    Emulates the execution of a batch file. Each command line that would be executed is emitted
    as an individual chunk. This can remove simple obfuscation based on expansion of environment
    variables.
    """

    def process(self, data):
        emu = BatchFileEmulator(data)
        for cmd in emu.emulate():
            yield cmd.encode(self.codec)
