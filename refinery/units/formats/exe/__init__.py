#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package with units for generic executables. Usually, PE, ELF, and MachO formats are covered.
"""


class ParsingFailure(ValueError):
    def __init__(self, kind):
        super().__init__(F'unable to parse input as {kind} file')


def exeroute(data, handler_elf, handler_macho, handler_pe, *args, **kwargs):
    if data[:2] == B'MZ':
        from pefile import PE as PEFile

        try:
            parsed = PEFile(data=data, fast_load=True)
        except Exception as E:
            raise ParsingFailure('PE') from E
        else:
            return handler_pe(parsed, *args, **kwargs)

    if data[:4] == B'\x7FELF':
        from ....lib.structures import MemoryFile
        from elftools.elf.elffile import ELFFile

        try:
            parsed = ELFFile(MemoryFile(data))
        except Exception as E:
            raise ParsingFailure('ELF') from E
        else:
            return handler_elf(parsed, *args, **kwargs)

    if set(data[:4]) <= {0xFE, 0xED, 0xFA, 0xCE, 0xCF}:
        from ....lib.structures import MemoryFile
        import macholib
        import macholib.mach_o
        import macholib.MachO

        class InMemoryMachO(macholib.MachO.MachO):
            def __init__(self):
                self.graphident = None
                self.filename = None
                self.loader_path = None
                self.fat = None
                self.headers = []
                self.load(MemoryFile(data))
        try:
            parsed = InMemoryMachO()
            assert parsed.headers
        except Exception as E:
            raise ParsingFailure('MachO') from E
        else:
            return handler_macho(parsed, *args, **kwargs)

    raise ValueError('Unknown executable format')
