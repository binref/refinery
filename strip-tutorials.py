#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strips the Jupyter Notebooks in the Tutorial section of run count information.
"""
import json
import pathlib

CK = 'execution_count'

for path in pathlib.Path.cwd().glob('./tutorials/*.ipynb'):
    with path.open('r') as fd:
        notebook = json.load(fd)
    for cell in notebook['cells']:
        if CK in cell:
            cell[CK] = 1
    with path.open('w') as fd:
        json.dump(notebook, fd, indent=1)
