#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Arg, Unit
from refinery.lib.executable import Executable
from refinery.lib.argformats import metavars


class vaddr(Unit):
    """
    Converts a metadata variable holding a file offset to a virtual address. This unit only works when the
    chunk body contains a PE, ELF, or MachO executable. The variable will be substituted in place. If you
    would like to retain the original value, it is recommended to use the `refinery.put` unit first to create
    a copy of an already existing variable, and then convert the copy.
    """

    def __init__(
        self, *name: Arg(type=str, help='The name of a metadata variable holding an integer.'),
        base : Arg.Number('-b', metavar='ADDR', help='Optionally specify a custom base address B.') = None
    ):
        return super().__init__(names=name, base=base)

    def process(self, data):
        try:
            exe = Executable.Load(data, self.args.base)
        except Exception:
            self.log_warn('unable to parse input as executable; no variable conversion was performed')
            return data
        meta = metavars(data)
        for name in self.args.names:
            value = meta[name]
            meta[name] = exe.location_from_offset(value).virtual.position
        return data

    def reverse(self, data):
        try:
            exe = Executable.Load(data, self.args.base)
        except Exception:
            self.log_warn('unable to parse input as executable; no variable conversion was performed')
            return data
        meta = metavars(data)
        for name in self.args.names:
            value = meta[name]
            meta[name] = exe.location_from_address(value).physical.position
        return data
