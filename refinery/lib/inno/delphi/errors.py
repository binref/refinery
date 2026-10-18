"""
Exceptions of the Delphi run-time library and their messages.
"""
from __future__ import annotations

import enum


class SysConst(enum.StrEnum):
    """
    Messages of exceptions that the Delphi run-time library raises, named as in its unit `SysConst`.
    """
    SDivByZero = 'Division by zero'
    SIntOverflow = 'Integer overflow'
    SOperationAborted = 'Operation aborted'


class DelphiException(Exception):
    """
    An exception that a function of the Delphi run-time library raises, with the message that
    Delphi gives it.
    """


class EConvertError(DelphiException, ValueError):
    """
    Delphi's exception for a value that cannot be converted. The function `format` raises it for an
    invalid format and for an argument that is missing or does not fit its format specifier.
    """
