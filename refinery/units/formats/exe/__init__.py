"""
A package with units for generic executables. Usually, PE, ELF, and MachO formats are covered.
"""
from __future__ import annotations

import re

from refinery.lib.argformats import sliceobj
from refinery.lib.emulator import Arch, Engine
from refinery.lib.executable import Executable, Symbol
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


class EmulatingUnit(Unit, abstract=True):
    """
    A unit that can use multiple emulators from `refinery.lib.emulator`.
    """
    def __init__(
        self,
        base: Param[int | None, Arg.Number('-b', metavar='Addr',
            help='Optionally specify a custom base address B.')] = None,
        arch: Param[str | Arch, Arg.Option('-a', metavar='Arch',
            help='Specify for blob inputs: {choices}', choices=Arch)] = Arch.X32,
        engine: Param[str | Engine, Arg.Option('-e', group='EMU', choices=Engine, metavar='E',
            help='The emulator engine. The default is {default}, options are: {choices}')] = Engine.unicorn,
        se: Param[bool, Arg.Switch(group='EMU', help='Equivalent to --engine=speakeasy')] = False,
        ic: Param[bool, Arg.Switch(group='EMU', help='Equivalent to --engine=icicle')] = False,
        uc: Param[bool, Arg.Switch(group='EMU', help='Equivalent to --engine=unicorn')] = False,
        **kwargs
    ):
        if sum((se, uc, ic)) > 1:
            raise ValueError('Too many emulators selected.')
        elif se:
            engine = Engine.speakeasy
        elif ic:
            engine = Engine.icicle
        elif uc:
            engine = Engine.unicorn

        super().__init__(
            base=base,
            arch=Arg.AsOption(arch, Arch),
            engine=Arg.AsOption(engine, Engine),
            **kwargs
        )

    def _engine(self) -> Engine:
        return self.args.engine

    def _parse_address(self, chunk: Chunk, exe: Executable, a: str) -> slice[int, int | None, None]:
        try:
            sliced = sliceobj(a, chunk, intok=True)
        except Exception:
            def c1(s: Symbol):
                return s.get_name().casefold() == a.casefold()

            def c2(s: Symbol):
                return s.get_name() == a

            def c3(s: Symbol):
                return s.function

            def c4(s: Symbol):
                return s.exported

            if m := re.fullmatch('(?i)(?:sub_|fun_|0x)?([A-F0-9]+)H?', a):
                return slice(int(m[1], 16), None)

            symbols = list(exe.symbols())

            for filter in [c1, c2, c3, c4]:
                symbols = [s for s in symbols if filter(s)]
                if len(symbols) == 1:
                    return slice(symbols[0].address, None)

            if len(symbols) > 1:
                raise RuntimeError(
                    F'there are {len(symbols)} exported function symbol named "{a}", please specify the address')
            else:
                raise LookupError(F'no symbol with name "{a}" was found')
        else:
            if isinstance(sliced, int):
                sliced = slice(sliced, None)
            elif sliced.step and sliced.step != 1:
                if sliced.stop is not None:
                    raise RuntimeError(F'invalid emulation range: {a}')
                sliced = slice(sliced.start, sliced.start + sliced.step, None)
            return sliced
