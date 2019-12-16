#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates the refinery documentation.
"""
import argparse
import os
import shlex
import subprocess
import sys
import shutil

_SAFETY_FLAG = '--current-environment'
_TEMPLATEDIR = os.path.abspath('pdoc3-template')

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

    def run(cmd):
        return subprocess.check_call(shlex.split(cmd))

    py = shlex.quote(sys.executable)
    pd = shlex.quote(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), 'pdoc3'))
    td = shlex.quote(_TEMPLATEDIR)

    run(F'{py} -m pip install pdoc3')
    run(F'{pd} --html --force --template-dir {td} refinery')

    shutil.copyfile(
        os.path.join(_TEMPLATEDIR, 'FixedSysEx.ttf'),
        os.path.join('html', 'refinery', 'FixedSysEx.ttf')
    )
