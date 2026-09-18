from __future__ import annotations

import codecs
import uuid

from refinery.lib.meta import MV
from refinery.lib.scripts.bat import BatchEmulator, BatchState
from refinery.lib.scripts.bat.emulator import BatchEmulatorConfig
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class BatchEmulatorUnit(Unit, abstract=True):
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
        **kwargs
    ):
        super().__init__(
            name=name,
            args=args,
            skip_goto=skip_goto,
            skip_call=skip_call,
            skip_exit=skip_exit,
            delayed_expand=delayed_expand,
            cmdline=cmdline,
            **kwargs
        )

    def _emulator(self, data: buf | str):
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
        return emulator


class bat(BatchEmulatorUnit):
    """
    Emulate batch file execution and extract command lines.

    Each command line that would be executed is emitted as an individual chunk. This can
    remove simple obfuscation based on expansion of environment variables.
    """
    def __init__(
        self,
        name=None,
        *args,
        skip_goto=False,
        skip_call=False,
        skip_exit=False,
        delayed_expand=False,
        cmdline=False,
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
    ):
        super().__init__(
            name, *args,
            show_sets=show_sets,
            skip_goto=skip_goto,
            skip_call=skip_call,
            skip_exit=skip_exit,
            delayed_expand=delayed_expand,
            cmdline=cmdline,
            show_junk=show_junk,
            show_labels=show_labels,
            show_nops=show_nops,
            show_comments=show_comments,
        )

    def process(self, data):
        emulator = self._emulator(data)
        for cmd in emulator.emulate():
            yield cmd.encode(self.codec)


class batev(BatchEmulatorUnit):
    """
    Extract environment variables created by an input batch script, based on emulation.
    """
    def process(self, data):
        emulator = self._emulator(data)
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


class batfs(BatchEmulatorUnit):
    """
    Extract file system artifacts that would be created by a batch script based on emulation.
    """
    def process(self, data):
        def _events():
            yield from emulator.emulate()
            yield None # trigger final sweep
        import ntpath
        emulator = self._emulator(data)
        previous_content: dict[str, str] = dict(emulator.state.file_system)
        was_changed: dict[str, bool] = {}
        for event in _events():
            for path, new in emulator.state.file_system.items():
                if new == (old := previous_content.get(path, '')):
                    continue
                previous_content[path] = new
                was_changed[path] = True
                if not old:
                    continue
                if len(new) < len(old) or event is None and was_changed.get(path):
                    relpath = ntpath.relpath(path, emulator.state.cwd)
                    yield self.labelled(old.encode(self.codec), **{MV.PATH: relpath})
