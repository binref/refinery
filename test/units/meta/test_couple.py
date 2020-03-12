#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shlex

from .. import TestUnitBase


class TestCoupler(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.sleep = ('sleep',) if os.name != 'nt' else shlex.split(
            '-- powershell -ExecutionPolicy Bypass -Command Start-Sleep'
        )

    def test_simple_echo(self):
        cmd = ['echo', 'Hello World']
        if os.name == 'nt':
            cmd = ['cmd', '/c'] + cmd
        result = self.load(*cmd)()
        self.assertIn(B'Hello World', result)

    def test_timeout_easy(self):
        with self.assertRaises(RuntimeError):
            self.load(*self.sleep, '2', timeout=0.5)()

    def test_timeout_close(self):
        self.assertEqual(
            self.load(*self.sleep, '1', timeout=2)(), B'')
        with self.assertRaises(RuntimeError):
            self.load(*self.sleep, '1', timeout=0.95)()
