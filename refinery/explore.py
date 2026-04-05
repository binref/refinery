"""
A commandline script to search for binary refinery units based on keywords.
"""
from __future__ import annotations

import argparse
import io
import re
import textwrap

import refinery
import refinery.units

from refinery.lib.argparser import RawDescriptionHelpFormatter
from refinery.lib.environment import environment
from refinery.lib.loader import get_all_entry_points
from refinery.lib.tools import documentation, get_terminal_size, normalize_to_display, terminalfit
from refinery.units import ArgparseError, Unit

_AGENT_DETAIL_LIST = [
    'autoxor',
    'asm',
    'base',
    'carve',
    'chop',
    'decompress',
    'defu',
    'dnds',
    'dnfields',
    'dnhdr',
    'dnmr',
    'dnrc',
    'dnstr',
    'dump',
    'ef',
    'emit',
    'esc',
    'group',
    'map',
    'mscdk',
    'mspdb',
    'pack',
    'peek',
    'perc',
    'pestrip',
    'pf',
    'qb',
    'qf',
    'qp',
    'reduce',
    'rep',
    'resub',
    'rex',
    'snip',
    'struct',
    'vbamc',
    'vbapc',
    'vsect',
    'vsnip',
    'vstack',
    'wshenc',
    'xlxtr',
    'xt',
    'xtp',
]


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
            argp.print_help(buffer, generics=not remove_generic)
            return buffer.getvalue().strip()
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

    mode = argp.add_argument_group('output formatting (choose only one)').add_mutually_exclusive_group()

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
    mode.add_argument(
        '-a', '--all',
        action='store_true',
        help='Search full help output (not just unit descriptions).'
    )
    mode.add_argument(
        '-b', '--brief',
        action='count',
        default=0,
        help='List units with a one-line description only.'
    )
    mode.add_argument(
        '-g', '--agent',
        action='store_true',
        dest='glossary',
        help='Produce a unit overview for AI agents.'
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

    if (brief := args.brief) or args.glossary:
        E = refinery.units.Entry
        entries = {}
        ciphers = {}
        hashers = {}
        blockop = {}

        for unit in get_all_entry_points():
            name = unit.name
            if not isinstance(unit, type):
                continue
            if not issubclass(unit, Unit):
                continue
            if not issubclass(unit, E):
                continue
            if unit is E:
                continue
            doc = documentation(unit)
            if not doc:
                continue
            if name in ('p1', 'p2', 'p3', 'csb', 'csd', 'd2p'):
                continue
            first_line = doc.split('\n\n', 1)[0].replace('\n', ' ').strip()
            if keywords:
                searchable = F'{name} {first_line}'.lower()
                if not args.quantifier(k.search(searchable) for k in keywords):
                    continue
            for base in unit.mro():
                if base.__name__ == 'CipherUnit':
                    ciphers[name] = first_line
                    break
                if base.__name__ == 'HashUnit':
                    hashers[name] = first_line
                    break
                if base.__name__ == 'ArithmeticUnit':
                    blockop[name] = first_line
                    break
            entries[name] = first_line
        if not entries:
            print('No matching unit was found.')
        elif brief > 1:
            print(', '.join(entries))
        elif brief > 0:
            pad = max(len(name) for name in entries) + 1
            for name, info in entries.items():
                sep = ': '
                gap = ' ' * (pad + len(sep))
                info = '\n'.join(textwrap.wrap(info, width - pad, subsequent_indent=gap))
                for kw in keywords:
                    info = highlight(info, kw, keyword_color)
                print(F'{name:>{pad}}{sep}{info}')
        else:
            print('The following is a list of all refinery units:')
            print(', '.join(entries))
            print('\nThese units perform atomic operations on bytes, words, or by otherwise dividing the input:')
            print(', '.join(blockop))
            print('\nHere are the brief descriptions of some units:')
            pad = max(len(name) for name in _AGENT_DETAIL_LIST) + 1
            for name in _AGENT_DETAIL_LIST:
                info = entries.pop(name)
                sep = ': '
                gap = ' ' * (pad + len(sep))
                info = '\n'.join(textwrap.wrap(info, width - pad, subsequent_indent=gap))
                for kw in keywords:
                    info = highlight(info, kw, keyword_color)
                print(F'{name:>{pad}}{sep}{info}')
            print('\nUse the binref tool to look up what a unit does or to find units relevant to a task.'
                ' Unit names are often abbreviations - always search by concept, not just by name.')
        return

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
