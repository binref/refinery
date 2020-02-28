#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Miscellaneous helper functions.
"""
import os
import sys


def format_size(num: int, align=False, default='{} BYTE') -> str:
    """
    Given a number of bytes, produce a human-readable expression for this
    size using common units such as kB and MB.
    """
    step = 1000.0
    result = num
    for unit in ['#B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
        if result / step < 0.1:
            break
        result /= step
    if unit == '#B' and not align:
        return default.format(num)
    else:
        width = 6 if align else ''
        return F'{result:{width}.3f} {unit}'


def lookahead(iterator):
    """
    Implements a new iterator from a given one which returns elements
    `(last, item)` where each `item` is taken from the original iterator
    and `last` is a boolean indicating whether this is the last item.
    """
    last = False
    it = iter(iterator)
    try:
        peek = next(it)
    except StopIteration:
        return
    while not last:
        item = peek
        try:
            peek = next(it)
        except StopIteration:
            last = True
        yield last, item


def get_terminal_size():
    """
    Returns the size of the currently attached terminal. If the environment variable
    `REFINERY_TERMSIZE` is set to an integer value, it takes prescedence. If the width
    of the terminal cannot be determined, the function returns zero.
    """
    try:
        return int(os.environ['REFINERY_TERMSIZE'])
    except (KeyError, ValueError):
        pass
    try:
        return os.get_terminal_size(sys.stderr.fileno()).columns - 1
    except OSError:
        return 0


def terminalfit(text: str, delta: int = 0, width: int = 0, **kw) -> str:
    """
    Reformats text to fit the given width while not mangling bullet point lists.
    """
    import textwrap
    width = width or get_terminal_size()
    width = width - delta

    def bulletpoint(line):
        wrapped = textwrap.wrap(line, width - 2, **kw)
        wrapped[1:] = ['  {}'.format(l) for l in wrapped[1:]]
        return '\n'.join(wrapped)

    def fitted(paragraphs):
        for k, p in enumerate(paragraphs):
            if p.startswith(' '):
                yield p
                continue
            if p.startswith('-'):
                input_lines = p.splitlines(keepends=False)
                unwrapped_line = input_lines[0].rstrip()
                lines = []
                if all(t.startswith('-') or t.startswith('  ') for t in input_lines):
                    for line in input_lines[1:]:
                        if not line.startswith('-'):
                            unwrapped_line += ' ' + line.strip()
                            continue
                        lines.append(bulletpoint(unwrapped_line))
                        unwrapped_line = line.rstrip()
                    lines.append(bulletpoint(unwrapped_line))
                    yield '\n'.join(lines)
                    continue
            yield '\n'.join(textwrap.wrap(p, width, **kw))

    return '\n\n'.join(fitted(text.split('\n\n')))


def documentation(unit):
    """
    Return the documentation string of a given unit as it should be displayed
    on the command line. Certain pdoc3-specific reference strings are removed.
    """
    import inspect
    import re
    docs = inspect.getdoc(unit)
    docs = re.sub(R'`refinery\.(?:\w+\.)*(\w+)`', R'\1', docs)
    return docs.replace('`', '')
