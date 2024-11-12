#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strips the Jupyter Notebooks in the Tutorial section of run count information.
"""
import json
import pathlib

for path in pathlib.Path.cwd().glob('./tutorials/*.ipynb'):
    with path.open('r') as fd:
        notebook = json.load(fd)
    for cell in notebook['cells']:
        cell.pop('execution_count', None)
    with path.open('w') as fd:
        json.dump(notebook, fd, indent=1)
