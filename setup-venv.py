#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import inspect
import os
import os.path
import shlex
import subprocess

from argparse import ArgumentParser

assert __name__ == '__main__', 'this module is not supposed to be imported.'

script_location = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))

argp = ArgumentParser()
argp.add_argument('-w', '--wheel', action='store_true',
    help='install as wheel')
argp.add_argument('-p', '--prefix', metavar='PRE', type=str, default='',
    help='optionally select a prefix that every refinery command will receive')
argp.add_argument('venv', nargs='?', default='venv',
    help='name of the folder to contain the virtual environment')
args = argp.parse_args()

os.environ['REFINERY_PREFIX'] = args.prefix
os.chdir(script_location)

if (sys.version_info.major, sys.version_info.minor) < (3, 7):
    print('-- python version at least 3.7 is required', file=sys.stderr)
    sys.exit(1)


def exec(command, **kw):
    print('-- executing:', ' '.join(shlex.quote(x) for x in command))
    return subprocess.run(command, **kw)


def venv_required():
    if os.path.exists(args.venv):
        if os.name == 'nt':
            activator = os.path.join(args.venv, 'Scripts', 'Activate.ps1')
        else:
            activator = os.path.join(args.venv, 'bin', 'activate')
        if not os.path.exists(activator):
            print('-- error: the directory {} exists, but no activation script was found.'.format(args.venv))
            sys.exit(2)
        return False
    return True


if not venv_required():
    print('-- virtual environment exists')
else:
    proc = exec([sys.executable, '-m', 'venv', args.venv],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print('-- critical error: the command terminated with error code {}'.format(proc.returncode))
        if os.name != 'nt':
            print('-- you might need to install this package: {}-venv'.format(os.path.basename(sys.executable)))
        sys.exit(proc.returncode)

scriptname, _ = os.path.splitext(os.path.basename(__file__))
shell, ext = ('powershell', 'ps1') if os.name == 'nt' else ('bash', 'sh')
cmd = [shell, os.path.join(script_location, '{}.{}'.format(scriptname, ext))]

if args.wheel:
    cmd.append('-wheel')

exec(cmd + ['-venv', args.venv])
