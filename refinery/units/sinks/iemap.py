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
        legend: Unit.Arg.Switch('-l', help='Show entropy color legend.') = False,
        background: Unit.Arg.Switch('-b', help='Generate the bar by coloring the background.') = False,
        block_char: Unit.Arg('-c', '--block-char', type=str, metavar='C',
            help='Character used for filling the bar, default is {default}') = '#',
        *label: Unit.Arg(type=str, metavar='label-part', help=(
            'The remaining command line specifies a format string expression that will be printed '
            'over the heat map display of each processed chunk.'
        ))
    ):
        super().__init__(label=' '.join(label), background=background, legend=legend, block_char=block_char)

    @Unit.Requires('colorama', 'display', 'default')
    def _colorama():
        import colorama
        return colorama

    def process(self, data):
        from sys import stderr
        from os import name as os_name
        colorama = self._colorama
        colorama.init(autoreset=False, convert=(os_name == 'nt'))

        nobg = not self.args.background
        meta = metavars(data)

        label = meta.format_str(self.args.label, self.codec, [data])
        if label:
            if not label.endswith(' '):
                label = F'{label} '
            if not label.startswith(' '):
                label = F' {label}'

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
        header = '['
        header_length = 1
        footer_length = 4 + 7

        if self.args.legend:
            header = '[{1}{0}] {2}'.format(_reset, ''.join(F'{bg}{k}' for k, bg in enumerate(clrmap, 1)), header)
            header_length += 3 + len(clrmap)

        _tw = get_terminal_size()
        width = _tw - header_length - footer_length
        if width < 16:
            raise RuntimeError(F'computed terminal width {_tw} is too small for heatmap')

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
            it = itertools.chain(itertools.repeat(filler, 3), label, itertools.cycle(filler))
            cp = None
            for chunk_size, block_size in zip(chunk_sizes, block_sizes):
                chunk = stream.read(chunk_size)
                chunk_entropy = entropy(chunk)
                pp = entropy_select(chunk_entropy, clrmap)
                string = ''.join(itertools.islice(it, block_size))
                if pp != cp:
                    string = F'{pp}{string}'
                cp = pp
                stderr.write(string)
                stderr.flush()
        except BaseException:
            eraser = ' ' * width
            stderr.write(F'\r{_reset}{eraser}\r')
            raise
        else:
            stderr.write(F'{_reset}] [---.--%]')
            te = meta['entropy']
            stderr.write('\b' * footer_length)
            stderr.write(F'] [{te!r:>7}]\n')
            stderr.flush()
        if not self.isatty:
            yield data
