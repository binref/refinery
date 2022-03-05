#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import defaultdict
from typing import Generator, Iterable

from refinery.units import arg, Unit, Chunk
from refinery.lib.meta import check_variable_name


class groupby(Unit):
    """
    Group incoming chunks by the contents of a meta variable. Note that the unit
    blocks and cannot stream any output until the input frame is consumed: It has
    to read every input chunk to make sure that all groupings are complete.
    """
    def __init__(self, name: arg(type=str, help='name of the meta variable')):
        super().__init__(name=check_variable_name(name))

    def process(self, data):
        yield from data.temp

    def filter(self, chunks: Iterable[Chunk]) -> Generator[Chunk, None, None]:
        name = self.args.name
        members = defaultdict(list)
        for chunk in chunks:
            try:
                value = chunk.meta[name]
            except KeyError:
                value = None
            members[value].append(chunk)
        for chunklist in members.values():
            dummy = chunklist[0]
            dummy.temp = chunklist
            yield dummy
