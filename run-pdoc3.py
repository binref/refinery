#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the refinery documentation.
"""
import argparse
import os
import warnings
import subprocess
import sys
import shutil

_SAFETY_FLAG = '--current-environment'
_TEMPLATEDIR = os.path.abspath('pdoc3-template')
_DOCUMENTDIR = os.path.abspath('html')

if __name__ == '__main__':
    def venv(path):
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise argparse.ArgumentTypeError(F'not a directory: {path}')
        p = os.path.join(path, 'bin', 'python') if os.name != 'nt' else (
            os.path.join(path, 'Scripts', 'python.exe')
        )
        if not os.path.exists(p):
            raise argparse.ArgumentTypeError(F'interpreter not found: {p}')
        return p

    argp = argparse.ArgumentParser()
    where = argp.add_mutually_exclusive_group()
    where.add_argument('venv', nargs='?', type=venv, default=None,
        help='Specify the virtual environment to use.')
    where.add_argument(_SAFETY_FLAG, dest='safety', action='store_true', help=(
        'If no virtual environment is specified, you have to provide this '
        'flag to force use of the current environment. This flag exists to '
        'prevent users from accidentally running this script outside a '
        'virtual environment.'
    ))
    args = argp.parse_args()

    if args.venv:
        virtualized = subprocess.Popen([args.venv, __file__, _SAFETY_FLAG])
        sys.exit(virtualized.wait())
    elif not args.safety:
        argp.error(F'You have to either specify a virtual environment or provide the flag {_SAFETY_FLAG}.')

    for second_attempt in (False, True):
        try:
            from pdoc.cli import main as pdoc3_main
        except ImportError:
            if second_attempt:
                raise
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', 'pdoc3'])
        else:
            warnings.filterwarnings('ignore')
            sys.argv = [
                'pdoc3', '--html', '--force', '--template-dir', _TEMPLATEDIR, 'refinery']
            pdoc3_main()
            break

    shutil.copyfile(
        os.path.join(_TEMPLATEDIR, 'FixedSysEx.ttf'),
        os.path.join(_DOCUMENTDIR, 'refinery', 'FixedSysEx.ttf')
    )
