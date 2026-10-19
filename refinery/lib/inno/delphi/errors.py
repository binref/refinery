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
    SInvalidInteger = '\'%s\' is not a valid integer value'
    SInvalidOp = 'Invalid floating point operation'
    SZeroDivide = 'Floating point division by zero'
    SOverflow = 'Floating point overflow'
    SUnderflow = 'Floating point underflow'


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


class EMathError(DelphiException, ArithmeticError):
    """
    The base of Delphi's exceptions for floating-point errors that the floating-point unit raises
    when its control word does not mask them.
    """


class EInvalidOp(EMathError):
    """
    An invalid floating-point operation, like zero divided by zero.
    """
    def __init__(self):
        super().__init__(SysConst.SInvalidOp)


class EZeroDivide(EMathError):
    """
    A floating-point division of a number other than zero by zero.
    """
    def __init__(self):
        super().__init__(SysConst.SZeroDivide)


class EOverflow(EMathError):
    """
    A floating-point result beyond the largest value of its format.
    """
    def __init__(self):
        super().__init__(SysConst.SOverflow)


class EUnderflow(EMathError):
    """
    A floating-point result too small for the normal values of its format.
    """
    def __init__(self):
        super().__init__(SysConst.SUnderflow)


class EDivByZero(DelphiException, ZeroDivisionError):
    """
    An integer division by zero.
    """
    def __init__(self):
        super().__init__(SysConst.SDivByZero)


class EIntOverflow(DelphiException, OverflowError):
    """
    An integer result beyond the range of its type.
    """
    def __init__(self):
        super().__init__(SysConst.SIntOverflow)


class EVariantError(DelphiException):
    """
    The base of Delphi's exceptions for operations on Variants.
    """


class EVariantTypeCastError(EVariantError):
    """
    A Variant whose value cannot be converted to the requested type.
    """
    def __init__(self, source: str, target: str):
        super().__init__(F'Could not convert variant of type ({source}) into type ({target})')


class EVariantOverflowError(EVariantError):
    """
    A Variant whose value lies outside the range of the requested type.
    """
    def __init__(self, source: str, target: str):
        super().__init__(F'Overflow while converting variant of type ({source}) into type ({target})')


class EVariantInvalidOpError(EVariantError):
    """
    An operation that Delphi does not define for the types of its Variant operands.
    """
    def __init__(self):
        super().__init__('Invalid variant operation')


class Undefined(Exception):
    """
    Delphi's result depends on state that the model does not have, such as the memory after a
    table or a buffer that Delphi reads or writes beyond its end.
    """
