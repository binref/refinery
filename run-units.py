"""
Generates the unit map and type stubs for refinery.
"""
from __future__ import annotations

import pathlib
import re

from refinery.lib.loader import get_all_entry_points


def sortkey(u: tuple[str, str]):
    def natural(text: str):
        return [int(c) if c.isdigit() else c.lower() for c in re.split(r'(\d+)', text)]
    a, b = u
    return (natural(a), natural(b))


def generate():
    root = pathlib.Path(__file__).parent / 'refinery'

    units = ((u.__module__, u.__name__) for u in get_all_entry_points())
    units = sorted(units, key=sortkey)
    width = max(len(repr(name)) for name, _ in units)

    with (root / '__unit__.py').open('w', encoding='utf8', newline='\n') as stream:
        stream.write('UNITS = {\n')
        for module, name in units:
            stream.write(F'    {name!r:{width}s} : {module!r},\n')
        stream.write('}\n')

    with (root / '__init__.pyi').open('w', encoding='utf8', newline='\n') as stream:
        for t in ('Arg', 'Unit'):
            stream.write(F'from refinery.units import {t} as {t}\n')
        for module, name in units:
            stream.write(F'from {module} import {name} as {name}\n')
        stream.write('\n__version__: str')
        stream.write('\n__distribution__: str')
        stream.write('\n__all__: list[str]\n')
        stream.write('\ndef load(name: str) -> type[Unit] | None:')
        stream.write('\n    ...\n')


if __name__ == '__main__':
    generate()
