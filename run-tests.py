#!/usr/bin/env python3
"""
Runs all tests from the command line.
"""
import argparse
import unittest
import os
import sys
from inspect import stack

from refinery.lib.environment import environment, LogLevel

here = os.path.dirname(os.path.abspath(stack()[0][1]))

argp = argparse.ArgumentParser()
argp.add_argument('pattern', type=lambda s: str(s).strip('*'), nargs='?', default='*',
    help='run all tests whose file name contains the given pattern.')
args = argp.parse_args()

os.chdir('test')
os.environ[environment.verbosity.key] = LogLevel.DETACHED.name

suite = unittest.TestLoader().discover('test', F'test_*{args.pattern}*')
tests = unittest.TextTestRunner(verbosity=2)
result = tests.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
