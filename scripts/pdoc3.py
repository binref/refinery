#!/usr/bin/env python3
"""
Generates the refinery documentation.
"""
import argparse
import os
import warnings
import subprocess
import sys
import shutil

from pathlib import Path

here = Path(__file__).parent
assert here.parts[-1] == 'scripts'
root = here.parent
os.chdir(str(root))
sys.path.insert(0, str(root))

_SAFETY_FLAG = '--current-environment'
_TEMPLATEDIR = str(root / 'pdoc3-template')
_DOCUMENTDIR = str(root / 'html')

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
    where.add_argument('-c', _SAFETY_FLAG, dest='safety', action='store_true', help=(
        'If no virtual environment is specified, you have to provide this '
        'flag to force use of the current environment. This flag exists to '
        'prevent users from accidentally running this script outside a '
        'virtual environment.'
    ))
    args = argp.parse_args()

    _local_venv = os.path.abspath(os.path.join(os.path.dirname(__file__), 'venv'))
    _using_venv = sys.executable.startswith(_local_venv + os.sep)

    if args.venv:
        virtualized = subprocess.Popen([args.venv, __file__, _SAFETY_FLAG])
        sys.exit(virtualized.wait())
    elif not args.safety and not _using_venv:
        argp.error(F'You have to either specify a virtual environment or provide the flag {_SAFETY_FLAG}.')

    warnings.filterwarnings('ignore')
    try:
        import defusedxml  # noqa: F401
    except ImportError:
        pass
    for second_attempt in (False, True):
        try:
            from pdoc.cli import main as pdoc3_main
        except ImportError:
            if second_attempt:
                raise
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', 'pdoc3'])
        else:
            if not sys.warnoptions:
                sys.warnoptions.append('ignore')
            sys.argv = [
                'pdoc3', '--html', '--force', '--skip-errors', '--template-dir', _TEMPLATEDIR, 'refinery']
            pdoc3_main()
            break

    shutil.copyfile(
        os.path.join(_TEMPLATEDIR, 'FixedSysEx.ttf'),
        os.path.join(_DOCUMENTDIR, 'refinery', 'FixedSysEx.ttf')
    )
