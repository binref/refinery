from __future__ import annotations

import codecs
import uuid

from refinery.lib.batch import BatchEmulator, BatchState
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
            help='All remaining arguments are passed to the Batch emulation.')],
        show_junk: Param[bool, Arg.Switch('-j',
            help='Synthesize emulated commands that look like junk; hidden by default.')] = False,
        show_nops: Param[bool, Arg.Switch('-n',
            help='Synthesize emulated commands that have no effect; hidden by default.')] = False,
        show_sets: Param[bool, Arg.Switch('-s',
            help='Synthesize environment variable assignments; hidden by default.')] = False,
    ):
        super().__init__(
            name=name,
            args=args,
            show_junk=show_junk,
            show_nops=show_nops,
            show_sets=show_sets,
        )

    def process(self, data):
        state = BatchState()
        batch = BatchEmulator(
            data,
            state,
            show_nops=self.args.show_nops,
            show_junk=self.args.show_junk,
            show_sets=self.args.show_sets,
        )
        if (name := self.args.name):
            state.name = codecs.decode(name, self.codec)
        else:
            state.name = F'{uuid.uuid4()!s}.bat'
        state.command_line = ' '.join(
            codecs.decode(arg, self.codec) for arg in self.args.args)
        for cmd in batch.emulate():
            yield cmd.encode(self.codec)
