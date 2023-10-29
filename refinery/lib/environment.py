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
from typing import Optional, TypeVar, Generic

_T = TypeVar('_T')

Logger = logging.Logger


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


class RefineryFormatter(logging.Formatter):

    NAMES = {
        logging.CRITICAL : 'failure',
        logging.ERROR    : 'failure',
        logging.WARNING  : 'warning',
        logging.INFO     : 'comment',
        logging.DEBUG    : 'verbose',
    }

    def __init__(self, format, **kwargs):
        super().__init__(format, **kwargs)

    def formatMessage(self, record: logging.LogRecord) -> str:
        record.custom_level_name = self.NAMES[record.levelno]
        return super().formatMessage(record)


def logger(name: str) -> logging.Logger:
    """
    Obtain a logger which is configured with the default refinery format.
    """
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        stream = logging.StreamHandler()
        stream.setFormatter(RefineryFormatter(
            '({asctime}) {custom_level_name} in {name}: {message}',
            style='{',
            datefmt='%H:%M:%S',
        ))
        logger.addHandler(stream)
    logger.propagate = False
    return logger


class EnvironmentVariableSetting(Generic[_T]):
    key: str
    value: Optional[_T]

    def __init__(self, name: str):
        self.key = F'REFINERY_{name}'
        self.value = self.read()

    def read(self) -> _T:
        return None


class EVBool(EnvironmentVariableSetting[bool]):
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


class EVInt(EnvironmentVariableSetting[int]):
    def read(self):
        try:
            return int(os.environ[self.key], 0)
        except (KeyError, ValueError):
            return 0


class EVLog(EnvironmentVariableSetting[Optional[LogLevel]]):
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
    colorless = EVBool('COLORLESS')
    disable_size_format = EVBool('DISABLE_SIZE_FORMAT')
    silence_ps1_warning = EVBool('SILENCE_PS1_WARNING')
    disable_ps1_bandaid = EVBool('DISABLE_PS1_BANDAID')
