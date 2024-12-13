#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A commandline script to search for binary refinery units based on keywords.
"""
import re
import argparse

from refinery.lib.tools import documentation, terminalfit, get_terminal_size
from refinery.units import ArgparseError
from refinery.lib.argparser import RawDescriptionHelpFormatter

import refinery
import refinery.units


def highlight(text, expression, color):
    """
    Uses ANSI color codes to highlight matches of the given regular `expression`
    in `text`.
    """
    return expression.sub(
        lambda m: '\033[' + color + 'm' + m[0] + '\033[0m',
        text
    )


def highlight_word(text, word, color):
    """
    Uses ANSI color codes to highlight matches of the string `word` in `text`.
    """
    return highlight(text, re.compile('(?i)' + re.escape(word)), color)


def get_help_string(unit, brief=False, width=None, remove_generic=False):
    """
    Retrieves the help string from a given refinery unit.
    """
    if brief:
        return terminalfit(documentation(unit), width=width)
    else:
        from io import StringIO
        from refinery.lib.environment import environment
        _ts = environment.term_size.value
        environment.term_size.value = width
        try:
            argp = unit.argparser()
        except ArgparseError as fail:
            argp = fail.parser
        else:
            buffer = StringIO('w')
            argp.print_help(buffer)
            info = buffer.getvalue()
            if remove_generic:
                info, _, _ = info.partition('\ngeneric options:\n')
            return info.strip()
        finally:
            environment.term_size.value = _ts


def explorer(keyword_color='91', unit_color='93'):
    """
    Main routine of the Binary Refinery Explorer.
    """

    try:
        import colorama
        colorama.init()
    except ModuleNotFoundError:
        pass

    headline = (
        R'_________ __       __________     ______' '\n'
        R'\_____   \__| ____/   ______/____/ ____/' '\n'
        R' ||  | __/  |/    \  /__|  / __ \   __/ ' '\n'
        R' ||  |   \  |   |  \_  _| \  ___/|  |   ' '\n'
        R' ||____  /__|___|__/  / |  \____]|__|   ' '\n'
        R' ======\/=========\  /==|__|============' '\n'
        R'   binary refinery \/ full text search  ' '\n'
    )

    argp = argparse.ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter, description=headline)

    argp.add_argument(
        'keywords',
        metavar='keyword',
        type=lambda s: s.lower(),
        nargs='+',
        help='Provide keywords; if any of these keywords match the help description of '
             'a unit, it will be listed.'
    )
    argp.add_argument(
        '-o', '--or',
        dest='quantifier',
        action='store_const',
        const=any,
        default=all,
        help='Any keywords may match rather than requiring all of them to match.'
    )
    argp.add_argument(
        '-a', '--all',
        action='store_true',
        help='Search full help output (not just unit descriptions).'
    )
    argp.add_argument(
        '-c', '--case-sensitive',
        action='store_true',
        help='Make the search case sensitive.'
    )
    argp.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Be verbose.'
    )
    argp.add_argument(
        '-w', '--words',
        action='store_true',
        help='Keywords only match if they appear as words, not as substrings.'
    )
    argp.add_argument(
        '-x', '--no-wildcards',
        dest='wildcards',
        action='store_false',
        help='Do not allow wildcards in search string'
    )
    args = argp.parse_args()
    width = get_terminal_size()
    separator = '-' * width
    result = False

    def pattern(keyword):
        kw = re.escape(keyword)
        if args.wildcards:
            kw = kw.replace(R'\*', R'\S*')
            kw = kw.replace(R'\?', R'\S')
        if args.words:
            kw = RF'(?<!\w)(?:{kw})(?!\w)'
        if not args.case_sensitive:
            kw = '(?i)' + kw
        if args.verbose:
            print(F'-- final regex: {kw}')
        return re.compile(kw)

    args.keywords = [pattern(k) for k in args.keywords]

    for name in refinery.__all__:
        unit = getattr(refinery, name, None)

        try:
            if not issubclass(unit, refinery.units.Entry) or unit is refinery.units.Entry:
                continue
        except TypeError:
            continue

        info = get_help_string(unit, not args.all, width, remove_generic=True)

        if not args.quantifier(k.search(name) or k.search(info) for k in args.keywords):
            continue

        result = True

        for kw in args.keywords:
            info = highlight(info, kw, keyword_color)

        if not args.all:
            header = '{e:-<4}[{}]{e:-<{w}}'.format(name, w=width - len(name) - 6, e='')
            header = highlight_word(header, name, unit_color)
        else:
            info = highlight_word(info, name, unit_color)
            header = separator

        print(header, info, sep='\n')

    print(separator if result else (
        'No matching unit was found.'
    ))


if __name__ == '__main__':
    explorer()
