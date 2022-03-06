#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import math
import itertools
import random

from refinery.units import Unit
from refinery.lib.tools import get_terminal_size, entropy
from refinery.lib.structures import MemoryFile
from refinery.lib.meta import metavars


class iemap(Unit):
    """
    The information entropy map displays a colored bar on the terminal visualizing the file's local
    entropy from beginning to end.
    """
    def __init__(
        self,
        background: Unit.Arg.switch('-b', help='Generate the bar by coloring the background.') = False,
        block_char: Unit.Arg('-c', '--block-char', type=str, metavar='C',
            help='Character used for filling the bar, default is {default}') = '#',
        *label: Unit.Arg(type=str, metavar='label-part', help=(
            'The remaining command line specifies a format string expression that will be printed '
            'over the heat map display of each processed chunk.'
        ))
    ):
        super().__init__(label=' '.join(label), background=background, block_char=block_char)

    @Unit.Requires('colorama')
    def _colorama():
        import colorama
        return colorama

    def process(self, data):
        colorama = self._colorama
        colorama.init(autoreset=False, convert=True)
        from sys import stderr

        nobg = not self.args.background
        meta = metavars(data)

        label = meta.format_str(self.args.label, self.codec, [data])
        if label and not label.endswith(' '):
            label += ' '

        bgmap = [
            colorama.Back.BLACK,
            colorama.Back.WHITE,
            colorama.Back.YELLOW,
            colorama.Back.CYAN,
            colorama.Back.BLUE,
            colorama.Back.GREEN,
            colorama.Back.LIGHTRED_EX,
            colorama.Back.MAGENTA,
        ]
        fgmap = [
            colorama.Fore.LIGHTBLACK_EX,
            colorama.Fore.LIGHTWHITE_EX,
            colorama.Fore.LIGHTYELLOW_EX,
            colorama.Fore.LIGHTCYAN_EX,
            colorama.Fore.LIGHTBLUE_EX,
            colorama.Fore.LIGHTGREEN_EX,
            colorama.Fore.LIGHTRED_EX,
            colorama.Fore.LIGHTMAGENTA_EX,
        ]

        _reset = colorama.Back.BLACK + colorama.Fore.WHITE + colorama.Style.RESET_ALL

        clrmap = fgmap if nobg else bgmap
        footer = '{}] [{:>7}]\n'.format(_reset, repr(meta['entropy']))
        header = '[{1}{0}] ['.format(_reset, ''.join(F'{bg}{k}' for k, bg in enumerate(clrmap, 1)))
        header_length = 4 + len(clrmap)
        footer_length = 4 + len(str(meta['entropy']))

        width = get_terminal_size() - header_length - footer_length
        if width < 16:
            raise RuntimeError(F'computed terminal width {width} is too small for heatmap')

        def entropy_select(value, map):
            index = min(len(map) - 1, math.floor(value * len(map)))
            return map[index]

        view = memoryview(data)
        size = len(data)
        chunk_size = 0

        for block_size in range(1, width + 1):
            block_count = width // block_size
            chunk_size = size // block_count
            if chunk_size > 1024:
                break

        q, remainder = divmod(width, block_size)
        assert q == block_count
        indices = list(range(q))
        random.seed(sum(view[:1024]))
        random.shuffle(indices)

        block_sizes = [block_size] * q
        q, r = divmod(remainder, block_count)
        for i in indices:
            block_sizes[i] += q
        for i in indices[:r]:
            block_sizes[i] += 1
        assert sum(block_sizes) == width

        q, remainder = divmod(size, block_count)
        assert q == chunk_size
        chunk_sizes = [chunk_size] * block_count
        for i in indices[:remainder]:
            chunk_sizes[i] += 1
        assert sum(chunk_sizes) == size

        stream = MemoryFile(view)
        filler = self.args.block_char if nobg else ' '

        try:
            stderr.write(header)
            if label is not None:
                stderr.write(colorama.Fore.WHITE)
                stderr.flush()
            it = itertools.chain(label, itertools.cycle(filler))
            for chunk_size, block_size in zip(chunk_sizes, block_sizes):
                chunk = stream.read(chunk_size)
                chunk_entropy = entropy(chunk)
                string = entropy_select(chunk_entropy, clrmap) + ''.join(
                    itertools.islice(it, block_size))
                stderr.write(string)
                stderr.flush()
        except BaseException:
            eraser = ' ' * width
            stderr.write(F'\r{_reset}{eraser}\r')
            raise
        else:
            stderr.write(footer)
            stderr.flush()
        if not self.isatty:
            yield data
