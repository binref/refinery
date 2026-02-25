from __future__ import annotations

import codecs
import uuid

from refinery.lib.batch import BatchEmulator, BatchState
from refinery.lib.batch.emulator import BatchEmulatorConfig
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
        show_labels: Param[bool, Arg.Switch('-l', help=(
            'Synthesize labels. These are shown at the time the emulator encounters them, which is '
            'not necessarily where they occur in the file.'))] = False,
        show_nops: Param[bool, Arg.Switch('-n',
            help='Synthesize emulated commands that have no effect; hidden by default.')] = False,
        show_comments: Param[bool, Arg.Switch('-r',
            help='Synthesize REM and :: comments. These are hidden by default.')] = False,
        show_sets: Param[bool, Arg.Switch('-s',
            help='Synthesize environment variable assignments; hidden by default.')] = False,
        skip_goto: Param[bool, Arg.Switch('-G',
            help='Do not trace into GOTO statements; emulation resumes at the next line instead.')] = False,
        skip_call: Param[bool, Arg.Switch('-C',
            help='Do not trace into CALL statements; emulation resumes at the next line instead.')] = False,
        skip_exit: Param[bool, Arg.Switch('-E',
            help='Do not respect EXIT commands; continue execution regardless.')] = False,
    ):
        super().__init__(
            name=name,
            args=args,
            show_junk=show_junk,
            show_labels=show_labels,
            show_nops=show_nops,
            show_comments=show_comments,
            show_sets=show_sets,
            skip_goto=skip_goto,
            skip_call=skip_call,
            skip_exit=skip_exit,
        )

    def process(self, data):
        state = BatchState()
        cfg = BatchEmulatorConfig(
            show_nops=self.args.show_nops,
            show_labels=self.args.show_labels,
            show_junk=self.args.show_junk,
            show_comments=self.args.show_comments,
            show_sets=self.args.show_sets,
            skip_goto=self.args.skip_goto,
            skip_call=self.args.skip_call,
            skip_exit=self.args.skip_exit,
        )
        if (name := self.args.name):
            state.name = codecs.decode(name, self.codec)
        else:
            state.name = F'{uuid.uuid4()!s}.bat'
        state.command_line = ' '.join(
            codecs.decode(arg, self.codec) for arg in self.args.args)
        emulator = BatchEmulator(data, state, cfg)
        for cmd in emulator.emulate():
            yield cmd.encode(self.codec)
