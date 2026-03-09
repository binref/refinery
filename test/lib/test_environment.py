import logging
import os

from pathlib import Path

from test import TestBase
from refinery.lib.environment import (
    LogLevel,
    RefineryFormatter,
    logger,
    EVBool,
    EVPath,
    EVInt,
    EVLog,
)


class TestEnvironment(TestBase):

    def test_log_level_from_verbosity(self):
        self.assertEqual(LogLevel.FromVerbosity(0), LogLevel.WARNING)
        self.assertEqual(LogLevel.FromVerbosity(1), LogLevel.INFO)
        self.assertEqual(LogLevel.FromVerbosity(2), LogLevel.DEBUG)
        self.assertEqual(LogLevel.FromVerbosity(-1), LogLevel.DETACHED)
        self.assertEqual(LogLevel.FromVerbosity(5), LogLevel.DEBUG)

    def test_log_level_verbosity_property(self):
        self.assertEqual(LogLevel.DEBUG.verbosity, 2)
        self.assertEqual(LogLevel.WARNING.verbosity, 0)
        self.assertEqual(LogLevel.INFO.verbosity, 1)
        self.assertEqual(LogLevel.DETACHED.verbosity, -1)

    def test_evbool_true_values(self):
        key = 'REFINERY_TEST_BOOL'
        for value in ('yes', '1', 'true', 'on', 'enabled'):
            os.environ[key] = value
            try:
                ev = EVBool('TEST_BOOL')
                self.assertTrue(ev.value, F'Expected True for {value!r}')
            finally:
                del os.environ[key]

    def test_evbool_false_values(self):
        key = 'REFINERY_TEST_BOOL'
        for value in ('no', '0', 'false', 'off', 'disabled'):
            os.environ[key] = value
            try:
                ev = EVBool('TEST_BOOL')
                self.assertFalse(ev.value, F'Expected False for {value!r}')
            finally:
                del os.environ[key]

    def test_evbool_empty(self):
        ev = EVBool.__new__(EVBool)
        self.assertFalse(ev.read(''))

    def test_evbool_unknown(self):
        ev = EVBool.__new__(EVBool)
        self.assertIsNone(ev.read('maybe'))

    def test_evint_parsing(self):
        key = 'REFINERY_TEST_INT'
        os.environ[key] = '42'
        try:
            ev = EVInt('TEST_INT')
            self.assertEqual(ev.value, 42)
        finally:
            del os.environ[key]

        os.environ[key] = '0xFF'
        try:
            ev = EVInt('TEST_INT')
            self.assertEqual(ev.value, 255)
        finally:
            del os.environ[key]

    def test_evint_invalid(self):
        ev = EVInt.__new__(EVInt)
        self.assertIsNone(ev.read('not_a_number'))

    def test_evpath_parsing(self):
        key = 'REFINERY_TEST_PATH'
        os.environ[key] = '/tmp/test'
        try:
            ev = EVPath('TEST_PATH')
            self.assertEqual(ev.value, Path('/tmp/test'))
        finally:
            del os.environ[key]

    def test_evlog_by_name(self):
        ev = EVLog.__new__(EVLog)
        result = ev.read('DEBUG')
        self.assertEqual(result, LogLevel.DEBUG)

    def test_evlog_by_digit(self):
        ev = EVLog.__new__(EVLog)
        result = ev.read('2')
        self.assertEqual(result, LogLevel.DEBUG)

    def test_logger_creates_handler(self):
        name = 'test_env_logger_unique_42'
        log = logger(name)
        self.assertIsInstance(log, logging.Logger)
        self.assertFalse(log.propagate)

    def test_refinery_formatter(self):
        fmt = RefineryFormatter(
            '{custom_level_name}: {message}',
            style='{',
        )
        record = logging.LogRecord(
            name='test',
            level=logging.WARNING,
            pathname='',
            lineno=0,
            msg='hello',
            args=(),
            exc_info=None,
        )
        output = fmt.format(record)
        self.assertIn('warning', output)
        self.assertEqual(record.custom_level_name, 'warning')
