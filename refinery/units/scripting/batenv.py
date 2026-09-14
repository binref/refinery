from __future__ import annotations

import codecs
import uuid

from refinery.lib.meta import MV
from refinery.lib.scripts.bat import BatchEmulator, BatchState
from refinery.lib.scripts.bat.emulator import BatchEmulatorConfig
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class batenv(Unit):
    """
    Extract environment variables created by an input batch script, based on emulation.
    """
    def __init__(
        self,
        name: Param[buf | None, Arg.Binary(
            help='The emulated file name, a random name is chosen by default.')] = None,
        *args: Param[buf, Arg.Binary(
            help='All remaining arguments are passed to the Batch emulation.')],
        skip_goto: Param[bool, Arg.Switch('-G',
            help='Do not trace into GOTO statements; emulation resumes at the next line instead.')] = False,
        skip_call: Param[bool, Arg.Switch('-C',
            help='Do not trace into CALL statements; emulation resumes at the next line instead.')] = False,
        skip_exit: Param[bool, Arg.Switch('-E',
            help='Do not respect EXIT commands; continue execution regardless.')] = False,
        delayed_expand: Param[bool, Arg.Switch('-D',
            help='Set delayed expansion of variables.')] = False,
        cmdline: Param[bool, Arg.Switch('-m',
            help='Use command-line mode where for-loop variables use single percent signs.')] = False,
    ):
        super().__init__(
            name=name,
            args=args,
            skip_goto=skip_goto,
            skip_call=skip_call,
            skip_exit=skip_exit,
            delayed_expand=delayed_expand,
            cmdline=cmdline,
        )

    def process(self, data):
        state = BatchState()
        cfg = BatchEmulatorConfig(
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
        emulator.state.delayexpand = self.args.delayed_expand
        emulator.state.cmdline = self.args.cmdline
        environment_variables: dict[str, str] = {}
        for _ in emulator.emulate():
            for name, value in emulator.state.environment.items():
                try:
                    prev = environment_variables[name]
                except KeyError:
                    prev = None
                if prev == value:
                    continue
                environment_variables[name] = value
                yield self.labelled(value.encode(self.codec), **{MV.NAME: name})
