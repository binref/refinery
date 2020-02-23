#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Runs all tests from the command line.
"""
import argparse
import unittest
import os
import sys

argp = argparse.ArgumentParser()
argp.add_argument('pattern', type=str, nargs='?', default='*')
args = argp.parse_args()

os.chdir('test')
os.environ['REFINERY_VERBOSITY'] = 'DETACHED'

suite = unittest.TestLoader().discover('test', F'test_{args.pattern}')
tests = unittest.TextTestRunner(verbosity=2)
result = tests.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
