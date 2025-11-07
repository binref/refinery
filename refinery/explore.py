"""
A commandline script to search for binary refinery units based on keywords.
"""
from __future__ import annotations

import argparse
import io
import re

import refinery
import refinery.units

from refinery.lib.argparser import RawDescriptionHelpFormatter
from refinery.lib.environment import environment
from refinery.lib.loader import get_all_entry_points
from refinery.lib.tools import documentation, get_terminal_size, normalize_to_display, terminalfit
from refinery.units import ArgparseError, Unit


def highlight(text: str, expression: re.Pattern[str], color: str):
    """
    Uses ANSI color codes to highlight matches of the given regular `expression`
    in `text`.
    """
    return expression.sub(
        lambda m: '\033[' + color + 'm' + m[0] + '\033[0m',
        text
    )


def highlight_word(text: str, word: str, color: str):
    """
    Uses ANSI color codes to highlight matches of the string `word` in `text`.
    """
    return highlight(text, re.compile('(?i)' + re.escape(word)), color)


def get_help_string(unit: type[Unit], brief: bool = False, width: int = 0, remove_generic: bool = False):
    """
    Retrieves the help string from a given refinery unit.
    """
    if brief:
        return terminalfit(documentation(unit), width=width)
    else:
        term_size = environment.term_size.value
        if width > 0:
            environment.term_size.value = width
        try:
            argp = unit.argparser()
        except ArgparseError as fail:
            argp = fail.parser
        else:
            buffer = io.StringIO('w')
            argp.print_help(buffer)
            info = buffer.getvalue()
            if remove_generic:
                info, _, _ = info.partition('\ngeneric options:\n')
            return info.strip()
        finally:
            if width > 0:
                environment.term_size.value = term_size


def explorer(keyword_color: str = '91', unit_color: str = '93'):
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
        R' ======\/=========\  /==|__|==({ver})===' '\n'
        R'   binary refinery \/ full text search  ' '\n'
    ).format(ver=refinery.__version__)

    argp = argparse.ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter, description=headline)

    argp.add_argument(
        'keywords',
        metavar='keyword',
        type=lambda s: s.lower(),
        nargs='*',
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
        '-V', '--version',
        action='store_true',
        help='Only show the currently installed version of binary refinery and exit.'
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

    if args.version:
        print(refinery.__version__)
        return

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

    keywords = [pattern(k) for k in args.keywords]

    for unit in get_all_entry_points():
        name = unit.name

        if not isinstance(unit, type):
            continue
        if not issubclass(unit, Unit):
            continue
        if not issubclass(unit, refinery.units.Entry):
            continue
        if unit is refinery.units.Entry:
            continue

        info = get_help_string(unit, not args.all, width, remove_generic=True)

        if info is None:
            continue

        if not args.quantifier(k.search(name) or k.search(info) for k in keywords):
            continue

        result = True

        for kw in keywords:
            info = highlight(info, kw, keyword_color)

        name = normalize_to_display(name)

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
