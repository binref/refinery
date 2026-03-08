"""
A common interface to all binary refinery configuration settings available via environment
variables. This module is also host to the logging configuration.
"""
from __future__ import annotations

import abc
import logging
import os

from enum import IntEnum
from pathlib import Path
from typing import Generic, TypeVar

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
    ALWAYS = logging.CRITICAL + 80
    """
    This log level is used to output messages that should appear always.
    """
    NONE = logging.CRITICAL + 50
    PROFILE = logging.CRITICAL + 10

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
    """
    The binary refinery log formatter class.
    """

    NAMES = {
        logging.CRITICAL : 'failure',
        logging.ERROR    : 'failure',
        logging.WARNING  : 'warning',
        logging.INFO     : 'comment',
        logging.DEBUG    : 'verbose',
        LogLevel.PROFILE : 'profile',
        LogLevel.ALWAYS  : 'message',
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


class EnvironmentVariableSetting(abc.ABC, Generic[_T]):
    """
    Abstraction of an environment variable based setting.
    """
    key: str
    value: _T | None

    def __init__(self, name: str):
        key = F'REFINERY_{name}'
        try:
            value = os.environ[key]
        except KeyError:
            value = None
        else:
            value = self.read(value)
        self.key = key
        self.value = value

    @abc.abstractmethod
    def read(self, value: str) -> _T | None:
        return None


class EVBool(EnvironmentVariableSetting[bool]):
    """
    Boolean setting stored in an environment variable.
    """
    def read(self, value: str):
        if value := value.lower().strip():
            if value.isdigit():
                return bool(int(value))
            elif value in {'no', 'off', 'false', 'disable', 'disabled'}:
                return False
            elif value in {'yes', 'on', 'true', 'enable', 'enabled', 'active'}:
                return True
            else:
                return None
        else:
            return False


class EVPath(EnvironmentVariableSetting[Path]):
    """
    A system path stored in an environment variable.
    """
    def read(self, value: str):
        return Path(value)


class EVInt(EnvironmentVariableSetting[int]):
    """
    An integer value stored in an environment variable.
    """
    def read(self, value: str):
        try:
            return int(value, 0)
        except (KeyError, ValueError):
            return None


class EVLog(EnvironmentVariableSetting[LogLevel]):
    """
    A log level stored in an environment variable. This can be specified as either the name of the
    log level or its integer value.
    """
    def read(self, value: str):
        if value.isdigit():
            return LogLevel.FromVerbosity(int(value))
        try:
            return LogLevel[value]
        except KeyError:
            levels = ', '.join(ll.name for ll in LogLevel)
            logger(__name__).warning(
                F'ignoring unknown verbosity "{value!r}"; pick from: {levels}')
            return None


class environment:
    """
    Provides access to refinery-related configuration in environment variables.
    """
    verbosity = EVLog('VERBOSITY')
    term_size = EVInt('TERM_SIZE')
    colorless = EVBool('COLORLESS')
    storepath = EVPath('STOREPATH')
    disable_size_format = EVBool('DISABLE_SIZE_FORMAT')
    silence_ps1_warning = EVBool('SILENCE_PS1_WARNING')
    disable_ps1_bandaid = EVBool('DISABLE_PS1_BANDAID')
