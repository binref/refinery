"""
Generates the unit map and type stubs for refinery.
"""
from __future__ import annotations

import pathlib

from refinery.lib.loader import get_all_entry_points


def generate():
    root = pathlib.Path(__file__).parent / 'refinery'
    units = sorted(
        ((u.__name__, u.__module__) for u in get_all_entry_points()))
    width = max(len(repr(name)) for name, _ in units)

    with (root / '__unit__.py').open('w', encoding='utf8', newline='\n') as stream:
        stream.write('UNITS = {\n')
        for name, module in units:
            stream.write(F'    {name!r:{width}s} : {module!r},\n')
        stream.write('}\n')

    with (root / '__init__.pyi').open('w', encoding='utf8', newline='\n') as stream:
        stream.write('from refinery.units import Arg as Arg, Unit as Unit\n\n')       
        for name, module in units:
            stream.write(F'from {module} import {name} as {name}\n')
        stream.write('\n__version__: str')
        stream.write('\n__distribution__: str')
        stream.write('\n__all__: list[str]\n')
        stream.write('\ndef load(name: str) -> type[Unit] | None:')
        stream.write('\n    ...\n')


if __name__ == '__main__':
    generate()
