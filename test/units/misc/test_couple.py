#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import logging
import shlex

from .. import TestUnitBase


class TestCoupler(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.sleep = ('sleep',) if os.name != 'nt' else shlex.split(
            'powershell -ExecutionPolicy Bypass -Command Start-Sleep'
        )
        self.echo = ['echo', 'Hello World']
        if os.name == 'nt':
            self.echo = ['cmd', '/c'] + self.echo

    def test_simple_echo_01(self):
        result = self.load(timeout=0, buffer=False, *self.echo)()
        self.assertIn(B'Hello World', result)

    def test_simple_echo_02(self):
        result = self.load(timeout=0, buffer=True, *self.echo)()
        self.assertIn(B'Hello World', result)

    def test_simple_echo_04(self):
        result = self.load(timeout=9, buffer=True, *self.echo)()
        self.assertIn(B'Hello World', result)

    def test_simple_echo_timeout_race_condition(self):
        for k in range(1, 100):
            result = self.load(timeout=9, buffer=False, *self.echo)()
            self.assertIn(B'Hello World', result, msg=F'Race condition in iteration {k}')

    def test_grep(self):
        data = self.generate_random_text(200) + B'HABBA'
        expect = B'A\n' * data.count(B'A'[0])
        try:
            result = self.load('grep', '-o', '-h', 'A')(data)
        except FileNotFoundError:
            if os.name != 'nt':
                raise
            log = logging.getLogger()
            log.warning('Omitting grep test on Windows.')
        else:
            self.assertEqual(result, expect)

    def test_timeout_easy(self):
        with self.assertRaises(RuntimeError):
            self.load(*self.sleep, '2', timeout=0.5)()

    def test_timeout_close(self):
        self.assertEqual(
            self.load(*self.sleep, '1', timeout=2)(), B'')
        with self.assertRaises(RuntimeError):
            self.load(*self.sleep, '1', timeout=0.7)()
