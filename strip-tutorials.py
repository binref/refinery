#!/usr/bin/env python3
"""
Strips the Jupyter Notebooks in the Tutorial section of run count information.
"""
import json
import pathlib

CK = 'execution_count'

for path in pathlib.Path.cwd().glob('tutorials/notebooks/*.ipynb'):
    print(F'fixing {path}')
    ctr = 0
    with path.open('r', encoding='utf8') as fd:
        notebook = json.load(fd)
    for cell in notebook['cells']:
        if CK in cell:
            cell[CK] = ctr = ctr + 1
    with path.open('w') as fd:
        json.dump(notebook, fd, indent=1)
