#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os.path
import sys

from inspect import stack
from glob import glob
from flake8.api import legacy as flake8

if __name__ != '__main__':
    raise ImportError('This script should not be imported.')

here = os.path.dirname(os.path.abspath(stack()[0][1]))

rules = flake8.get_style_guide(ignore=[
    'E128',  # A continuation line is under-indented for a visual indentation.
    'E203',  # Colons should not have any space before them.
    'E701',  # Multiple statements on one line (colon)
    'E704',  # Multiple statements on one line (def)
    'W503',  # Line break occurred before a binary operator
], max_line_length=140)

report = rules.check_files(glob(
    os.path.join(here, 'refinery', '**', '*.py'), recursive=True))
errors = len(report.get_statistics('E'))

if not errors:
    print('Success! No FLAKE8 violations were found.')

sys.exit(errors)
