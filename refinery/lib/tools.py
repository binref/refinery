#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Miscellaneous helper functions.
"""
import os
import sys

from math import log


def format_size(num: int, explain_bytes=True, default='{} Bytes') -> str:
    """
    Given a number of bytes, produce a human-readable expression for this
    size using common units such as KB and MB. Unless the `explain_bytes`
    paramter is set to `False`, the returned expression also includes the
    total number of bytes in brackets.
    """
    step = 1000.0
    result = num
    for unit in ['', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
        if result < step:
            break
        result /= step
    if not unit:
        return default.format(num)
    else:
        width = int(log(result, 10))
        fmt = '{:{a}.{b}f} {} ({n} Bytes)' if explain_bytes else '{:{5-w}.{4-w}f} {}'
        return fmt.format(result, unit, n=num, a=5 - width, b=4 - width)


try:
    import numpy

    def _np_entropy(data: bytearray) -> float:
        value, counts = numpy.unique(data, return_counts=True)
        probs = counts / len(data)
        # 8 bits are the maximum number of bits of information in a byte
        return 0.0 + -sum(p * log(p, 2) for p in probs) / 8.0

except ImportError:
    _np_entropy = None


def entropy(data: bytearray) -> float:
    """
    Computes the entropy of `data` over the alphabet of all bytes.
    """
    if not data:
        return 0.0
    if _np_entropy:
        return _np_entropy(data)
    else:
        from collections import defaultdict
        histogram = defaultdict(int)
        for b in data:
            histogram[b] += 1
        p = 1. / len(data)
        S = [histogram[b] * p for b in histogram]
        return 0.0 + -sum(q * log(q, 2) for q in S) / 8.0


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
