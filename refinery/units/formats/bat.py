from __future__ import annotations

import codecs
import uuid

from refinery.lib.batch import BatchEmulator
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class bat(Unit):
    """
    Emulates the execution of a batch file. Each command line that would be executed is emitted
    as an individual chunk. This can remove simple obfuscation based on expansion of environment
    variables.
    """
    def __init__(
        self,
        name: Param[buf | None, Arg.Binary(
            help='The emulated file name, a random name is chosen by default.')] = None,
        *args: Param[buf, Arg.Binary(
            help='All remaining arguments are passed to the Batch emulation.')]
    ):
        super().__init__(name=name, args=args)

    def process(self, data):
        if (name := self.args.name):
            name = codecs.decode(name, self.codec)
        else:
            name = F'{uuid.uuid4()!s}.bat'
        args = [name]
        for arg in self.args.args:
            args.append(codecs.decode(arg, self.codec))
        emu = BatchEmulator(data)
        for cmd in emu.emulate(0, args):
            yield cmd.encode(self.codec)
