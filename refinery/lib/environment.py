#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A common interface to all binary refinery configuration settings available via environment
variables. This module is also host to the logging configuration.
"""
from __future__ import annotations

import os
import logging

from enum import IntEnum
from typing import Any, Optional


class LogLevel(IntEnum):
    """
    An enumeration representing the current log level:
    """
    DETACHED = logging.CRITICAL + 100
    """
    This unit is not attached to a terminal but has been instantiated in
    code. This means that the only way to communicate problems is to throw
    an exception.
    """
    NONE = logging.CRITICAL + 50

    @classmethod
    def FromVerbosity(cls, verbosity: int):
        if verbosity < 0:
            return cls.DETACHED
        return {
            0: cls.WARNING,
            1: cls.INFO,
            2: cls.DEBUG
        }.get(verbosity, cls.DEBUG)

    NOTSET   = logging.NOTSET    # noqa
    CRITICAL = logging.CRITICAL  # noqa
    FATAL    = logging.FATAL     # noqa
    ERROR    = logging.ERROR     # noqa
    WARNING  = logging.WARNING   # noqa
    WARN     = logging.WARN      # noqa
    INFO     = logging.INFO      # noqa
    DEBUG    = logging.DEBUG     # noqa

    @property
    def verbosity(self) -> int:
        if self.value >= LogLevel.DETACHED:
            return -1
        if self.value >= LogLevel.WARNING:
            return +0
        if self.value >= LogLevel.INFO:
            return +1
        if self.value >= LogLevel.DEBUG:
            return +2
        else:
            return -1


logging.addLevelName(logging.CRITICAL, 'failure') # noqa
logging.addLevelName(logging.ERROR,    'failure') # noqa
logging.addLevelName(logging.WARNING,  'warning') # noqa
logging.addLevelName(logging.INFO,     'comment') # noqa
logging.addLevelName(logging.DEBUG,    'verbose') # noqa


def logger(name: str) -> logging.Logger:
    """
    Obtain a logger which is configured with the default refinery format.
    """
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(
            '({asctime}) {levelname} in {name}: {message}',
            style='{',
            datefmt='%H:%M:%S'
        ))
        logger.addHandler(stream)
    logger.propagate = False
    return logger


class EnvironmentVariableSetting:
    key: str
    value: Any

    def __init__(self, name: str):
        self.key = F'REFINERY_{name}'
        self.value = self.read()

    def read(self):
        return None


class EVBool(EnvironmentVariableSetting):
    value: bool

    def read(self):
        value = os.environ.get(self.key, None)
        if value is None:
            return False
        else:
            value = value.lower().strip()
        if not value:
            return False
        if value.isdigit():
            return bool(int(value))
        return value not in {'no', 'off', 'false'}


class EVInt(EnvironmentVariableSetting):
    value: int

    def read(self) -> int:
        try:
            return int(os.environ[self.key], 0)
        except (KeyError, ValueError):
            return 0


class EVLog(EnvironmentVariableSetting):
    value: Optional[LogLevel]

    def read(self):
        try:
            loglevel = os.environ[self.key]
        except KeyError:
            return None
        if loglevel.isdigit():
            return LogLevel.FromVerbosity(int(loglevel))
        try:
            loglevel = LogLevel[loglevel]
        except KeyError:
            levels = ', '.join(ll.name for ll in LogLevel)
            logger(__name__).warning(
                F'ignoring unknown verbosity "{loglevel!r}"; pick from: {levels}')
            return None
        else:
            return loglevel


class environment:
    verbosity = EVLog('VERBOSITY')
    term_size = EVInt('TERM_SIZE')
    silence_ps1_warning = EVBool('SILENCE_PS1_WARNING')
    disable_ps1_bandaid = EVBool('DISABLE_PS1_BANDAID')
