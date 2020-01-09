#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Runs all tests from the command line.
"""
import unittest
import os

os.chdir('test')
os.environ['REFINERY_VERBOSITY'] = 'DETACHED'

suite = unittest.TestLoader().discover('test')
tests = unittest.TextTestRunner(verbosity=2)
tests.run(suite)
