#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Runs all tests from the command line.
"""
import unittest
import os
import sys

os.chdir('test')
os.environ['REFINERY_VERBOSITY'] = 'DETACHED'

suite = unittest.TestLoader().discover('test')
tests = unittest.TextTestRunner(verbosity=2)
result = tests.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
