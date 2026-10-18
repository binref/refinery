"""
An emulator for Inno Setup executables. The implementation is unlikely to be 100% correct as it
was engineered by making various malicious scripts execute reasonably well, not by implementing
an exact copy of [the (only) reference implementation][PS]. This grew and grew as I wrote it,
and seems mildly insane in hindsight.

[PS]: https://github.com/remobjects/pascalscript
"""
from __future__ import annotations

import bisect
import fnmatch
import hashlib
import inspect
import io
import math
import ntpath
import operator
import random
import re
import shlex
import struct

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, IntEnum, IntFlag, StrEnum, auto
from functools import cached_property, partial, wraps
from pathlib import Path
from string import Formatter
from time import process_time
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    ClassVar,
    Generator,
    Generic,
    NamedTuple,
    Sequence,
    TypeVar,
    get_origin,
)
from urllib.parse import unquote

from refinery.lib import json
from refinery.lib.inno import CaseInsensitiveDict, delphi
from refinery.lib.inno.archive import Flags, InnoArchive
from refinery.lib.inno.delphi import DelphiException, SysConst, VarRec, VType
from refinery.lib.inno.ifps import (
    TC,
    AOp,
    COp,
    EHType,
    Function,
    IFPSFile,
    IFPSType,
    Instruction,
    Op,
    Operand,
    TArray,
    TPrimitive,
    TRecord,
    TSet,
    TStaticArray,
    Value,
    VariableBase,
    VariableSpec,
    VariableType,
)
from refinery.lib.patterns import formats
from refinery.lib.resources import datapath
from refinery.lib.tools import copy_exception, exception_to_string

if TYPE_CHECKING:
    from typing import ParamSpec
    _P = ParamSpec('_P')

_T = TypeVar('_T')
_Y = TypeVar('_Y')


ERROR_NO_MORE_FILES = 0x100123


class OleObject:
    """
    A dummy object representing an OLE interface created by an IFPS script. All it does so far is
    to remember the name of the object that was requested.
    """
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return F'OleObject({self.name!r})'

    def __str__(self):
        return self.name


_VariantType = TPrimitive(TC.Variant)


class Variable(VariableBase, Generic[_T]):
    """
    This class represents a global or stack variable in the IFPS runtime.
    """
    data: list[Variable] | _T | None
    """
    The variable's value. This is a list of `refinery.lib.inno.emulator.Variable`s for container
    types, a `refinery.lib.inno.emulator.Variable` for pointer types, and a basic type otherwise.
    """
    path: tuple[int, ...]
    """
    A tuple of integers that specify the seuqnce of indices required to access it, relative to the
    base variable given via `spec`.
    """

    __slots__ = (
        'data',
        'path',
        '_range',
    )

    @property
    def container(self):
        """
        A boolean indicating whether the given variable is a container.
        """
        return self.type.container

    @property
    def pointer(self):
        """
        A boolean indicating whether the given variable is a pointer.
        """
        return self.type.code == TC.Pointer

    def __len__(self):
        return len(self.data)

    def __bool__(self):
        return True

    def __getitem__(self, key: int):
        var = self.deref()
        if var.container:
            return var.at(key).get()
        else:
            return var.data[key]

    def __setitem__(self, key: int, v: _T):
        var = self.deref()
        if var.container:
            var.at(key).set(v)
        else:
            var.data[key] = var._wrap(v)

    def at(self, k: int):
        """
        Provides index access for the variable. If the variable is a pointer, it is dereferenced
        before accessing the data.
        """
        return self.deref().data[k]

    def deref(var):
        """
        Dereferences the variable until it is no longer a pointer and returns the result. If the
        variable is not a pointer, this function returns the variable itself.
        """
        while True:
            val = var.data
            if not isinstance(val, Variable):
                return var
            var = val

    def __init__(
        self,
        type: IFPSType,
        spec: VariableSpec | None = None,
        path: tuple[int, ...] = (),
        data: _T | list | None = None
    ):
        super().__init__(type, spec)
        self.path = path
        self._range = type.code.integer_range
        self.setdefault()
        if data is not None:
            self.set(data)

    def setdefault(self):
        """
        Set this variable's data to the default value for its type. This also initializes the
        values of any contained variables recursively.
        """
        spec = self.spec
        path = self.path

        def default(type: IFPSType, *sub_path):
            if isinstance(type, TRecord):
                return [Variable(t, spec, (*path, *sub_path, k)) for k, t in enumerate(type.members)]
            if isinstance(type, TStaticArray):
                t = type.type
                return [Variable(t, spec, (*path, *sub_path, k)) for k in range(type.size)]
            if isinstance(type, TArray):
                return []
            if sub_path:
                return Variable(type, spec, (*path, *sub_path))
            elif type.code == TC.Pointer:
                return Variable(_VariantType)
            else:
                return type.default()

        self.data = default(self.type)

    def _wrap(self, value: Value | _T, key: int | None = None) -> _T:
        if (t := self.type.py_type(key)) and not isinstance(value, t):
            if issubclass(t, int) and isinstance(value, str) and len(value) == 1:
                return self._wrap(ord(value), key)
            if issubclass(t, int) and isinstance(value, float):
                return self._wrap(int(value), key)
            if issubclass(t, str) and isinstance(value, int):
                return chr(value)
            if issubclass(t, float) and isinstance(value, int):
                return float(value)
            raise TypeError(F'Assigning value {value!r} to variable of type {self.type}.')
        if (valid := self._range) is not None and isinstance(value, int):
            start = valid.start
            return start + (value - start) % (valid.stop - start)
        return value

    def resize(self, n: int):
        """
        This function is only valid for container type variables. It re-sizes the data list to
        ensure that the container stores exactly `n` sub-variables, or none if `n` is negative.
        """
        t = self.type
        if t.code != TC.Array:
            if t.code not in (TC.StaticArray, TC.Record):
                raise TypeError
            if n == t.size:
                return
            raise ValueError(F'Attempt to resize {t} of size {t.size} to {n}.')
        data = self.data
        del data[max(n, 0):]
        for k in range(len(data), n):
            data.append(Variable(t.type, self.spec, (*self.path, k)))

    def setptr(self, var: Variable, copy: bool = False):
        """
        This method is used to point a pointer variable to a target. This is different from calling
        the `refinery.lib.inno.emulator.Variable.set` method as the latter would try to dereference
        the pointer and assign to its target; this method sets the value of the pointer itself. As
        in Pascal Script, a pointer never points to a pointer: Set to a pointer, it receives the
        target of that pointer, or a copy of that target with its type.
        """
        if not self.pointer:
            raise TypeError
        if not isinstance(var, Variable):
            raise TypeError
        var = var.deref()
        if copy:
            var = Variable(var.type, data=var)
        self.data = var

    def set(self, value: _T | Sequence | Variable):
        """
        Assign a new value to the variable. This can either be an immediate value or a variable.
        For container types, it can also be a sequence of those. A container variable is copied
        element by element, and a pointer element as Pascal Script copies it: A pointer to a
        variable of the script points to the same variable, and a pointer that owns its target
        points to a copy of that target. A Variant that receives a Boolean holds a truth value, as
        Pascal Script converts a Boolean into a Variant.
        """
        if self.pointer:
            return self.deref().set(value)
        origin = None
        assigned = value
        if isinstance(value, Variable):
            source = value.deref()
            if self.container and source.container:
                return self._copy_elements(source)
            origin = source.type
            assigned = source.get()
        elif isinstance(value, Value):
            origin = value.type
            assigned = value.value
        elif isinstance(value, Enum):
            assigned = value.value
        if self.container:
            if not isinstance(assigned, (list, tuple)):
                raise TypeError
            self.resize(len(assigned))
            for k, v in enumerate(assigned):
                self.data[k].set(v)
        else:
            if origin is not None and self.type.code is TC.Variant and origin.boolean:
                assigned = bool(assigned)
            self.data = self._wrap(assigned)

    def _copy_elements(self, source: Variable):
        if (
            not isinstance(elements := source.data, list)
            or not isinstance(destination := self.data, list)
        ):
            raise TypeError
        self.resize(len(elements))
        for element, copied in zip(destination, elements):
            if not element.pointer:
                element.set(copied)
            elif isinstance(target := copied.data, Variable):
                element.setptr(target, copy=target.spec is None)
            else:
                raise _type_mismatch()

    def get(self) -> _T:
        """
        Return a representation of this variable that consists only of base types. For example, the
        result for a container type will not be a list of `refinery.lib.inno.emulator.Variable`s,
        but a list of their contents.
        """
        if self.pointer:
            return self.deref().get()
        if self.container:
            data: list[Variable] = self.data
            return [v.get() for v in data]
        return self.data

    @property
    def name(self):
        """
        Return the name of the variable as given by its spec.
        """
        if self.spec is None:
            return 'Unbound'
        name = F'{self.spec!s}'
        for k in self.path:
            name = F'{name}[{k}]'
        return name

    def __repr__(self):
        rep = self.name
        if (val := self.data) is None:
            return rep
        if self.type.code is TC.Set:
            val = F'{val:b}'
        elif self.pointer:
            val: Variable
            return F'{rep} -> {val.name}'
        elif isinstance(val, (str, int, float, list)):
            val = repr(self.get())
        else:
            return rep
        return F'{rep} = {val}'


class NeedSymbol(NotImplementedError):
    """
    An exception raised by `refinery.lib.inno.emulator.IFPSEmulator` if the runtime calls out to
    an external symbol that is not implemented.
    """


class OpCodeNotImplemented(NotImplementedError):
    """
    An exception raised by `refinery.lib.inno.emulator.IFPSEmulator` if an unsupported opcode is
    encountered during emulation.
    """


class EmulatorException(RuntimeError):
    """
    A generic exception representing any error that occurs during emulation. It ends the emulation;
    the emulated script cannot handle it.
    """


class AbortEmulation(EmulatorException):
    """
    This exception can be raised by an external function handler to signal the emulator that script
    execution should be aborted.
    """


class PSError(IntEnum):
    """
    The kinds of runtime error that Pascal Script distinguishes, numbered as Pascal Script numbers
    them. Pascal Script keeps the kind with every error of the script.
    """
    OutOfRange = 10
    TypeMismatch = 12
    DivideByZero = 15
    MathError = 16
    OutOfRecordRange = 18
    Exception = 20

    @property
    def text(self) -> str:
        """
        The message that Pascal Script gives an error of this kind when it carries no exception of
        Delphi.
        """
        return _PS_ERROR_TEXT[self]


_PS_ERROR_TEXT = {
    PSError.OutOfRange       : 'Out Of Range',
    PSError.TypeMismatch     : 'Type Mismatch',
    PSError.DivideByZero     : 'divide by Zero',
    PSError.MathError        : 'Math error',
    PSError.OutOfRecordRange : 'Out of Record Fields Range',
    PSError.Exception        : 'Exception: ',
}


class IFPSException(RuntimeError):
    """
    An error of the script, which its exception handlers can handle. Pascal Script keeps the `kind`
    of every error, and the exception of Delphi that raised it, if any. The script reads the
    `message` of that exception with `GetExceptionMessage`, or the text of the kind when there is
    no exception. An error that escapes from a call of an emulated function names the `called`
    function in its report.
    """
    def __init__(
        self,
        message: str | None = None,
        kind: PSError = PSError.Exception,
        called: str | None = None,
    ):
        message = kind.text if message is None else str(message)
        report = message if called is None else F'Error calling {called}: {message}'
        super().__init__(report)
        self.kind = kind
        self.message = message
        self.called = called


class EmulatorTimeout(EmulatorException, TimeoutError):
    """
    The emulation timed out based on the given time limit in the configuration.
    """


class EmulatorExecutionLimit(EmulatorException, TimeoutError):
    """
    The emulation timed out based on the given execution limit in the configuration.
    """


class EmulatorMaxStack(EmulatorException, MemoryError):
    """
    The emulation was aborted because the stack limit given in the configuration was exceeded.
    """


class EmulatorMaxCalls(EmulatorException, MemoryError):
    """
    The emulation was aborted because the call stack limit given in the configuration was exceeded.
    """


class EmulatorMaxArray(EmulatorException, MemoryError):
    """
    The script requested an array longer than the array length limit given in the configuration.
    """


def _type_mismatch() -> IFPSException:
    return IFPSException(kind=PSError.TypeMismatch)


def _signed32(value: int) -> int:
    return ((value + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def _ordinal(code: TC, value) -> int:
    """
    Reads an operand as Pascal Script reads it for integer arithmetic and comparisons: an integer as
    its value and a character as its code point. Any other operand is a type mismatch.
    """
    if code.integer:
        return value
    if code.character:
        return ord(value)
    raise _type_mismatch()


def _truncated_division(a: int, b: int) -> tuple[int, int]:
    """
    Divides as Delphi's `div` and `mod` do: The quotient is truncated toward zero, and the remainder
    has the sign of the dividend.
    """
    if b == 0:
        raise ZeroDivisionError('division by zero')
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return quotient, a - quotient * b


def _python_division(a, b):
    return a // b if isinstance(a, int) and isinstance(b, int) else a / b


_PYTHON_ARITHMETIC = {
    AOp.Add: operator.add,
    AOp.Sub: operator.sub,
    AOp.Mul: operator.mul,
    AOp.Div: _python_division,
    AOp.Mod: operator.mod,
    AOp.Shl: operator.lshift,
    AOp.Shr: operator.rshift,
    AOp.And: operator.and_,
    AOp.BOr: operator.or_,
    AOp.Xor: operator.xor,
}

_SET_ARITHMETIC = {
    AOp.Add: operator.or_,
    AOp.Sub: lambda a, b: a & ~b,
    AOp.Mul: operator.and_,
}

_BIT_EXACT_ARITHMETIC = frozenset((
    AOp.Add,
    AOp.Sub,
    AOp.Mul,
    AOp.And,
    AOp.BOr,
    AOp.Xor,
))


def _integer_arithmetic(aop: AOp, target: TC, a: int, source: TC, b) -> int:
    """
    Pascal Script's arithmetic for a destination of an integer type. Addition, subtraction,
    multiplication, and the bitwise operators give the bits that the destination keeps however the
    operands are read. For division and shifts, the destination's type decides how the source is
    read and how wide the computation is: 64 bits for an Int64 destination and for a 32-bit
    destination with an Int64 source, 32 bits otherwise, unsigned for an unsigned destination.
    """
    b = _ordinal(source, b)
    if aop in _BIT_EXACT_ARITHMETIC:
        return _PYTHON_ARITHMETIC[aop](a, b)
    wide = target.width > 4
    if aop is AOp.Shl:
        return a << (b & (63 if wide else 31))
    if aop is AOp.Shr:
        if wide:
            return (a & 0xFFFFFFFFFFFFFFFF) >> (b & 63)
        return (a & 0xFFFFFFFF) >> (b & 31)
    if not wide and (target.width < 4 or source.width <= 4):
        if target.signed:
            b = _signed32(b)
            if a == -0x80000000 and b == -1:
                raise OverflowError('Integer overflow')
        else:
            b &= 0xFFFFFFFF
    quotient, remainder = _truncated_division(a, b)
    return quotient if aop is AOp.Div else remainder


def _calculate(aop: AOp, target: TC, a, source: TC, b):
    """
    Pascal Script's arithmetic for a destination with type code `target` that holds `a` and a
    source with type code `source` that holds `b`. Python's operators compute it for destinations
    of other types than integers and sets, and for Variant sources.
    """
    if source is not TC.Variant:
        if target.integer:
            return _integer_arithmetic(aop, target, a, source, b)
        if target is TC.Set:
            if (calculate := _SET_ARITHMETIC.get(aop)) is None:
                raise _type_mismatch()
            return calculate(a, b)
    return _PYTHON_ARITHMETIC[aop](a, b)


_PYTHON_COMPARISON = {
    COp.GE: operator.ge,
    COp.LE: operator.le,
    COp.GT: operator.gt,
    COp.LT: operator.lt,
    COp.NE: operator.ne,
    COp.EQ: operator.eq,
    COp.IN: lambda a, b: a in b,
    COp.IS: operator.is_,
}


def _integer_comparands(left: TC, a: int, right: TC, b) -> tuple:
    """
    Reads the operands of a comparison whose left operand has an integer type as Pascal Script
    reads them. The left operand's type decides how the right operand is read.
    """
    if left is TC.S32:
        if right is TC.U32:
            return a, _signed32(b)
        if right.integer or right in (TC.Single, TC.Double, TC.Extended):
            return a, b
        if right.character:
            return a, ord(b)
        raise _type_mismatch()
    if left is TC.U08 and right in (TC.AnsiString, TC.PChar):
        return chr(a), b
    b = _ordinal(right, b)
    if left.width > 4:
        return a, b
    if left.signed:
        return a, _signed32(b)
    return a, b & 0xFFFFFFFF


def _set_contains(members: int, set_type: TSet, code: TC, element) -> bool:
    ordinal = _ordinal(code, element) & 0xFFFFFFFF
    if ordinal >= set_type.size:
        raise IFPSException(kind=PSError.OutOfRecordRange)
    return bool((members >> ordinal) & 1)


def _compare(cop: COp, left: IFPSType, a, right: IFPSType, b) -> bool:
    """
    Pascal Script's comparison of `a`, which has the type `left`, with `b`, which has the type
    `right`. Python's operators compare operands of other types than integers and sets, and
    Variants.
    """
    lc = left.code
    rc = right.code
    if cop is COp.IN:
        if isinstance(right, TSet) and lc is not TC.Variant:
            return _set_contains(b, right, lc, a)
    elif cop is not COp.IS and lc is not TC.Variant and rc is not TC.Variant:
        if lc.integer:
            a, b = _integer_comparands(lc, a, rc, b)
        elif lc is TC.Set:
            if cop is COp.GE:
                return b & ~a == 0
            if cop is COp.LE:
                return a & ~b == 0
            if cop is not COp.EQ and cop is not COp.NE:
                raise _type_mismatch()
    return _PYTHON_COMPARISON[cop](a, b)


class _CallState(NamedTuple):
    fn: Function
    ip: int
    sp: int


@dataclass
class ExceptionHandler:
    """
    An exception handler of the IFPS runtime: one try statement whose try block runs or whose
    blocks have not all ended. A block that an error enters can no longer be entered by an error.
    The second finally block that the end of the try block enters can still be entered once by an
    error, as in Pascal Script.
    """
    finally_one: int | None
    """
    Code offset of the first finally block, while it can be entered.
    """
    catch_error: int | None
    """
    Code offset of the except block, while it can be entered.
    """
    finally_two: int | None
    """
    Code offset of the second finally block, while it can be entered.
    """
    handler_end: int
    """
    Code offset of the first instruction after the try statement.
    """
    function: Function
    """
    The function that contains the try statement.
    """
    frame: int
    """
    The number of call frames below the function that contains the try statement.
    """
    sp: int
    """
    The stack base of the function that contains the try statement.
    """
    depth: int
    """
    The size of the data stack when the handler was installed. The stack is cut back to this size
    when an error enters one of the blocks of the handler.
    """
    exception: IFPSException | None = None
    """
    The error that entered the except block.
    """

    def resume(self, ip: int) -> _CallState:
        """
        The position at the given offset of the function that contains the try statement.
        """
        return _CallState(self.function, ip, self.sp)


class _ErrorInFlight:
    """
    The error that passes through a finally block, raised again when that block ends. A run of
    the script and all runs nested in it have one error in flight.
    """
    __slots__ = 'error',

    def __init__(self):
        self.error: IFPSException | None = None


class _ScriptRun:
    """
    One run of the script from the call of one of its functions until that function returns, as
    Pascal Script runs it: the data stack, the frames of the functions that called the running one,
    the try statements that have not ended, and the return that waits for finally blocks. A run
    that starts while an emulated function runs for another run, as one that expands a code
    constant, is nested in that run: it shares the error in flight and the script sees the
    handlers of both, but an error that no handler of the nested run takes ends the nested run.
    """
    def __init__(self, caller: _ScriptRun | None = None):
        self.stack: list[Variable] = []
        self.frames: list[_CallState] = []
        self.handlers: list[ExceptionHandler] = []
        self.exit_point: int | None = None
        self.caller = caller
        if caller is None:
            self.in_flight = _ErrorInFlight()
            self.depth = 0
        else:
            self.in_flight = caller.in_flight
            self.in_flight.error = None
            self.depth = caller.depth + len(caller.frames) + 1

    @property
    def current_exception(self) -> IFPSException | None:
        """
        The error that `GetExceptionMessage` reads: the one that entered the except block of the
        innermost try statement if an error did, else the error in flight when no try statement
        is left.
        """
        run = self
        while run is not None:
            if handlers := run.handlers:
                return handlers[-1].exception
            run = run.caller
        return self.in_flight.error

    def install(self, operands: Sequence, function: Function, sp: int):
        """
        Installs the handler of a try statement that begins in the given function.
        """
        finally_one, catch_error, finally_two, handler_end = operands
        if handler_end is None:
            raise RuntimeError('The try statement has no end.')
        self.handlers.append(ExceptionHandler(
            finally_one,
            catch_error,
            finally_two,
            handler_end,
            function,
            len(self.frames),
            sp,
            len(self.stack),
        ))

    def throw(self, error: IFPSException):
        """
        Puts the given error in flight. The run keeps a copy without traceback.
        """
        self.in_flight.error = copy_exception(error)

    def unwind(self) -> _CallState:
        """
        Moves the error in flight to the innermost handler of this run that can take it, which is
        the first of its finally block, its except block or its second finally block that can
        still be entered. Handlers with none left are removed. An error that enters the except
        block is no longer in flight. When no handler of this run is left, the error ends the run.
        """
        in_flight = self.in_flight
        handlers = self.handlers
        while handlers:
            eh = handlers[-1]
            del self.stack[eh.depth:]
            del self.frames[eh.frame:]
            if (ip := eh.finally_one) is not None:
                eh.finally_one = None
            elif (ip := eh.catch_error) is not None:
                eh.catch_error = None
                eh.exception, in_flight.error = in_flight.error, None
            elif (ip := eh.finally_two) is not None:
                eh.finally_two = None
            else:
                handlers.pop()
                continue
            return eh.resume(ip)
        error, in_flight.error = in_flight.error, None
        if error is None:
            raise RuntimeError('No error is in flight.')
        try:
            raise error
        finally:
            del error

    def end_block(self, block: EHType) -> _CallState | None:
        """
        Ends a block of the innermost try statement, which must belong to the running function.
        The result is where the run goes on, or `None` when the error in flight unwinds.
        """
        handlers = self.handlers
        if not handlers or (eh := handlers[-1]).frame != len(self.frames):
            raise RuntimeError(F'The end of a {block.name} block has no try statement in this function.')
        in_flight = self.in_flight
        if block is EHType.Try:
            if (ip := eh.finally_one) is not None:
                eh.finally_one = None
                return eh.resume(ip)
            if (ip := eh.finally_two) is not None:
                eh.catch_error = None
                return eh.resume(ip)
        elif block is EHType.Finally:
            if in_flight.error is not None and (ip := eh.catch_error) is not None:
                eh.catch_error = None
                eh.exception, in_flight.error = in_flight.error, None
                return eh.resume(ip)
            if (ip := eh.finally_two) is not None:
                eh.finally_two = None
                return eh.resume(ip)
        elif block is EHType.Catch:
            eh.catch_error = None
            if (ip := eh.finally_two) is not None:
                eh.finally_two = None
                return eh.resume(ip)
            handlers.pop()
            return eh.resume(self._after(eh))
        handlers.pop()
        if in_flight.error is not None:
            return None
        return eh.resume(self._after(eh))

    def exit(self, function: Function, offset: int, sp: int) -> _CallState | None:
        """
        Begins the return of the running function at the given offset: it first runs each finally
        block of its try statements, and the end of each comes back to the return. The result is
        the next finally block, or `None` when the function returns.
        """
        self.exit_point = offset
        handlers = self.handlers
        frame = len(self.frames)
        while handlers and (eh := handlers[-1]).frame >= frame:
            del self.stack[eh.depth:]
            if (ip := eh.finally_one) is not None:
                eh.finally_one = None
            elif (ip := eh.finally_two) is not None:
                eh.finally_two = None
            else:
                handlers.pop()
                continue
            return _CallState(function, ip, sp)
        self.exit_point = None
        return None

    def _after(self, eh: ExceptionHandler) -> int:
        if (exit_point := self.exit_point) is not None:
            return exit_point
        return eh.handler_end


def _incompatible_call(handler: IFPSEmulatedFunction, argc: int, void: bool) -> str:
    def shape(argc: int, void: bool):
        arguments = 'argument' if argc == 1 else 'arguments'
        result = 'no result' if void else 'a result'
        return F'{argc} {arguments} and {result}'
    return F'the emulation takes {shape(handler.argc, handler.void)}, the call passes {shape(argc, void)}'


class _WizardForm:
    """
    Stands in for the wizard form of a setup: a script can keep it and pass it to the methods of
    its controls, which do not read it.
    """
    def __repr__(self):
        return 'WizardForm'


class IFPSEmulatedFunction(NamedTuple):
    """
    Represents an emulated external symbol.
    """
    call: Callable
    """
    The actual callable function that implements the symbol.
    """
    spec: list[bool]
    """
    A list of boolean values, one for each parameter of the function. Each boolean indicates
    whether the parameter at that index is passed by reference.
    """
    void: bool = False
    """
    Indicates whether the handler implements a procedure rather than a function in the IFPS
    runtime.
    """
    caller: bool = False
    """
    Indicates whether the handler receives the run of the script that calls it as its keyword
    argument `caller`. Inno Setup passes its functions the runtime that calls them.
    """

    @property
    def argc(self):
        """
        The argument count for this handler.
        """
        return len(self.spec)


_OPEN_ARRAY_KINDS = {
    TC.U08           : VType.Integer,
    TC.S08           : VType.Integer,
    TC.U16           : VType.Integer,
    TC.S16           : VType.Integer,
    TC.U32           : VType.Integer,
    TC.S32           : VType.Integer,
    TC.S64           : VType.Int64,
    TC.Single        : VType.Extended,
    TC.Double        : VType.Extended,
    TC.Extended      : VType.Extended,
    TC.Char          : VType.Char,
    TC.WideChar      : VType.WideChar,
    TC.AnsiString    : VType.AnsiString,
    TC.PChar         : VType.PChar,
    TC.WideString    : VType.WideString,
    TC.UnicodeString : VType.UnicodeString,
    TC.Variant       : VType.Variant,
    TC.Class         : VType.Object,
    TC.Interface     : VType.Interface,
}


def _open_array_element(element: Variable) -> VarRec:
    """
    Converts an element of an `array of const` into the argument that Pascal Script passes for it
    to a function of Delphi. Pascal Script passes an element of any other type as the Integer 0.
    """
    target = element.deref()
    if (kind := _OPEN_ARRAY_KINDS.get(target.type.code)) is None:
        return VarRec(VType.Integer, 0)
    value = target.get()
    if kind is VType.Integer:
        value = _signed32(value)
    return VarRec(kind, value)


def _now_in_whole_seconds() -> datetime:
    """
    The current time without its fraction of a second. The emulated clock starts there, so that what
    a script computes from the clock does not depend on the fraction of the second in which the
    emulation starts.
    """
    return datetime.now().replace(microsecond=0)


@dataclass
class IFPSEmulatorConfig:
    """
    The configuration for `refinery.lib.inno.emulator.IFPSEmulator`s.
    """
    x64: bool = True
    admin: bool = True
    windows_os_version: tuple[int, int, int] = (10, 0, 10240)
    windows_sp_version: tuple[int, int] = (2, 0)
    throw_abort: bool = False
    log_calls: bool = False
    log_passwords: bool = True
    log_mutexes: bool = True
    log_opcodes: bool = False
    wizard_silent: bool = True
    max_opcodes: int = 0
    max_seconds: int = 10
    start_time: datetime = field(default_factory=_now_in_whole_seconds)
    milliseconds_per_instruction: float = 0.0001
    sleep_scale: float = 0.0
    max_data_stack: int = 1_000_000
    max_array_length: int = 0x100000
    max_call_stack: int = 4096
    environment: dict[str, str] = field(default_factory=dict)
    user_name: str = 'Frank'
    temp_path: str = ''
    host_name: str = 'Frank-PC'
    inno_name: str = 'ThisInstall'
    language: str = 'en'
    executable: str = 'C:\\Install.exe'
    install_to: str = 'I:\\'
    allow_process_listing: bool = False
    processes = {
        1001: 'explorer.exe',
        1002: None, # represents self
        1023: 'svchost.exe',
        1024: 'svchost.exe',
        1060: 'rundll32.exe',
        1061: 'rundll32.exe',
        2223: 'csrss.exe',
        1200: 'winlogon.exe',
        1300: 'wininit.exe',
        1301: 'dllhost.exe',
        1305: 'notepad.exe',
        5305: 'chrome.exe',
    }
    lcid: int = 0x0409

    @property
    def cwd(self):
        return Path(self.executable).parent


class TSetupStep(int, Enum):
    """
    An IFPS enumeration that classifies different setup steps.
    """
    ssPreInstall = 0
    ssInstall = auto()
    ssPostInstall = auto()
    ssDone = auto()


class TSplitType(int, Enum):
    """
    An IFPS enumeration that classifies different strategies for splitting strings.
    """
    stAll = 0
    stExcludeEmpty = auto()
    stExcludeLastEmpty = auto()


class TUninstallStep(int, Enum):
    """
    An IFPS enumeration that classifies uninstaller steps.
    """
    usAppMutexCheck = 0
    usUninstall = auto()
    usPostUninstall = auto()
    usDone = auto()


class TSetupProcessorArchitecture(int, Enum):
    """
    An IFPS enumeration that classifies different processor architectures.
    """
    paUnknown = 0
    paX86 = auto()
    paX64 = auto()
    paArm32 = auto()
    paArm64 = auto()


class PageID(int, Enum):
    """
    An IFPS enumeration that classifies the different installer pages.
    """
    wpWelcome = 1
    wpLicense = auto()
    wpPassword = auto()
    wpInfoBefore = auto()
    wpUserInfo = auto()
    wpSelectDir = auto()
    wpSelectComponents = auto()
    wpSelectProgramGroup = auto()
    wpSelectTasks = auto()
    wpReady = auto()
    wpPreparing = auto()
    wpInstalling = auto()
    wpInfoAfter = auto()
    wpFinished = auto()


class SetupEvent(StrEnum):
    """
    The setup events that `InnoSetupEmulator.emulate_installation` sends to the script. The value of
    each event is the name of the function of the script that handles it.
    """
    InitializeSetup = 'InitializeSetup'
    InitializeWizard = 'InitializeWizard'
    CurStepChanged = 'CurStepChanged'
    ShouldSkipPage = 'ShouldSkipPage'
    CurPageChanged = 'CurPageChanged'
    PrepareToInstall = 'PrepareToInstall'
    CheckPassword = 'CheckPassword'
    NextButtonClick = 'NextButtonClick'
    DeinitializeSetup = 'DeinitializeSetup'


class NewFunctionCall(NamedTuple):
    """
    An event generated by `refinery.lib.inno.emulator.IFPSEmulator.emulate_function` which
    represents a call to the function with the given name and arguments.
    """
    name: str
    args: tuple


class NewPassword(str):
    """
    An event generated by `refinery.lib.inno.emulator.IFPSEmulator.emulate_function` for each
    password that is entered by the emulated setup script to a password edit control.
    """


class NewMutex(str):
    """
    An event generated by `refinery.lib.inno.emulator.IFPSEmulator.emulate_function` for each
    mutex registered by the script.
    """


class NewScriptError(NamedTuple):
    """
    An event generated by `InnoSetupEmulator.emulate_installation` for each setup event that ends
    with a script error which the script does not handle. It holds the event, the arguments of its
    function and the message of the error.
    """
    name: SetupEvent
    args: tuple
    message: str

    def __str__(self):
        return F'script error in {self.name}{self.args!r}: {self.message}'


class NewEmulationError(NamedTuple):
    """
    An event generated by `refinery.lib.inno.emulator.IFPSEmulator.emulate_function` for each call
    of an emulated function that fails with an error of the emulator rather than one of the
    script. The script sees the failure as an error that it can handle. It holds the name of the
    function and the message of the failure.
    """
    name: str
    message: str

    def __str__(self):
        return F'emulation of {self.name} failed: {self.message}'


class NewInstruction(NamedTuple):
    """
    An event generated by `refinery.lib.inno.emulator.IFPSEmulator.emulate_function` for each
    executed instruction.
    """
    function: Function
    instruction: Instruction
    offset: int


class EventCall(Generic[_Y, _T]):
    """
    This class is a wrapper for generator functions that can also capture their return value.
    It is used for `refinery.lib.inno.emulator.IFPSEmulator.emulate_function`.
    """
    def __init__(self, call: Generator[_Y, Any, _T]):
        self._call = call
        self._done = False
        self._buffer: list[_Y] = []
        self._value = None

    @classmethod
    def Wrap(cls, method: Callable[_P, Generator[_Y, Any, _T]]) -> Callable[_P, EventCall[_Y, _T]]:
        """
        Used for decorating generator functions.
        """
        @wraps(method)
        def wrapped(*args, **kwargs):
            return cls(method(*args, **kwargs))
        return wrapped

    @property
    def value(self) -> _T | None:
        """
        The return value of the wrapped function.
        """
        if not self._done:
            self._buffer = list(self)
        return self._value

    def __iter__(self):
        if self._done:
            yield from self._buffer
            assert self._value is not None
            self._buffer.clear()
        else:
            self._value = yield from self._call
            self._done = True
        return self._value


class FPUControl(IntFlag):
    """
    An integer flag representing FPU control words.
    """
    InvalidOperation    = 0b0_00_0_00_00_00_000001 # noqa
    DenormalizedOperand = 0b0_00_0_00_00_00_000010 # noqa
    ZeroDivide          = 0b0_00_0_00_00_00_000100 # noqa
    Overflow            = 0b0_00_0_00_00_00_001000 # noqa
    Underflow           = 0b0_00_0_00_00_00_010000 # noqa
    PrecisionError      = 0b0_00_0_00_00_00_100000 # noqa
    Reserved1           = 0b0_00_0_00_00_01_000000 # noqa
    Reserved2           = 0b0_00_0_00_00_10_000000 # noqa
    ExtendPrecision     = 0b0_00_0_00_01_00_000000 # noqa
    DoublePrecision     = 0b0_00_0_00_10_00_000000 # noqa
    MaxPrecision        = 0b0_00_0_00_11_00_000000 # noqa
    RoundDown           = 0b0_00_0_01_00_00_000000 # noqa
    RoundUp             = 0b0_00_0_10_00_00_000000 # noqa
    RoundTowardZero     = 0b0_00_0_11_00_00_000000 # noqa
    AffineInfinity      = 0b0_00_1_00_00_00_000000 # noqa
    Reserved3           = 0b0_01_0_00_00_00_000000 # noqa
    Reserved4           = 0b0_10_0_00_00_00_000000 # noqa
    ReservedBits        = 0b0_11_0_00_00_11_000000 # noqa


class IFPSEmulator:
    """
    The core IFPS emulator.
    """
    def __init__(
        self,
        archive: InnoArchive | IFPSFile,
        options: IFPSEmulatorConfig | None = None,
        **more
    ):
        with datapath('winapi.json').open('rb') as stream:
            self.winapi: dict[str, list[str]] = json.loads(stream.read())
            base = 0x70000000
            self.winapi_module_to_addr = _ml = {name: base + k * 0x100000 for k, name in enumerate(self.winapi)}
            self.winapi_addr_to_module = {addr: module for module, addr in _ml.items()}
            self.winapi_symbol_to_addr = _sl = {
                symbol: _ml[module] + k * 0x1000 for module, symbols in self.winapi.items() for k, symbol in enumerate(symbols)}
            self.winapi_addr_to_symbol = {addr: module for module, addr in _sl.items()}

        if isinstance(archive, InnoArchive):
            self.setup_info = archive.setup_info
            ifps = archive.ifps
            if ifps is None:
                raise ValueError('The input archive does not contain a script.')
        else:
            self.setup_info = None
            ifps = archive
        self.ifps = ifps
        self.config = options or IFPSEmulatorConfig(**more)
        self._wizard_form = _WizardForm()
        self._globals: list[Variable] | None = None
        self.mutexes: set[str] = set()
        self.symbols: dict[str, Function] = CaseInsensitiveDict()
        self.reset()
        for pfn in ifps.functions:
            self.symbols[pfn.name] = pfn

    def __repr__(self):
        return self.__class__.__name__

    def reset(self):
        """
        Reset the emulator timing, FPU word, and mutexes. The script starts over with new global
        variables that hold their default values.
        """
        self.seconds_slept = 0.0
        self.clock = 0
        self.fpucw = FPUControl.MaxPrecision | FPUControl.RoundTowardZero
        self.mutexes.clear()
        self._globals = None
        self._win32api_last_error = 0
        self._win32api_sorted_process_ids = sorted(self.config.processes)
        return self

    @property
    def globals(self) -> list[Variable]:
        """
        The global variables of the script.
        """
        if (script_globals := self._globals) is None:
            script_globals = self._globals = [Variable(v.type, v.spec) for v in self.ifps.globals]
        return script_globals

    def unimplemented(self, function: Function, arguments: list[Variable], result: Variable | None):
        """
        The base IFPS emulator raises `refinery.lib.inno.emulator.NeedSymbol` when an external
        symbol is unimplemented. Child classes can override this function to handle the missing
        symbol differently; it receives the arguments of the call and the variable for its result,
        if the symbol is a function.
        """
        raise NeedSymbol(function.name)

    @EventCall.Wrap
    def emulate_function(self, function: Function, *args):
        """
        Emulate a function call to the given function, passing the given arguments. The method
        returns the return value of the emulated function call if it is not a procedure.
        """
        return (yield from self._execute(_ScriptRun(), function, args))

    def _execute(self, run: _ScriptRun, function: Function, args: Sequence):
        decl = function.decl
        if decl is None:
            raise NotImplementedError(F'Do not know how to call {function!s}.')
        if (n := len(decl.parameters)) != (m := len(args)):
            raise ValueError(
                F'Function {function!s} expects {n} arguments, only {m} were given.')
        stack = run.stack
        for index, (argument, parameter) in enumerate(zip(args, decl.parameters), 1):
            variable = Variable(parameter.type, VariableSpec(index, VariableType.Local))
            variable.set(argument)
            stack.append(variable)
        stack.reverse()
        if not decl.void:
            result = Variable(decl.return_type, VariableSpec(0, VariableType.Argument))
            stack.append(result)
        yield from self._interpret(run, function)
        if not decl.void:
            return result.get()

    def _interpret(self, run: _ScriptRun, function: Function):
        """
        Emulates the given run of the script from the start of the given function.
        """

        def resolve(spec: VariableSpec) -> Variable:
            t, i = spec.type, spec.index
            if t is VariableType.Argument:
                if function.decl.void:
                    i -= 1
                return stack[sp - i]
            if t is VariableType.Global:
                return script_globals[i]
            if t is VariableType.Local:
                return stack[sp + i]
            raise TypeError

        def getvar(op: VariableSpec | Operand) -> Variable:
            if not isinstance(op, Operand):
                return resolve(op)
            if (spec := op.variable) is None:
                raise TypeError('Attempting to retrieve variable for an immediate operand.')
            var = resolve(spec)
            if isinstance(k := op.index, VariableSpec):
                k = resolve(k).get()
            if k is None:
                return var
            if not 0 <= k < len(var := var.deref()):
                raise IFPSException(kind=PSError.OutOfRange)
            return var.at(k)

        def getval(op: Operand):
            if op.immediate:
                return op.value.value
            return getvar(op).get()

        def gettyped(op: Operand) -> tuple[IFPSType, Any]:
            if op.immediate and (constant := op.value) is not None:
                return constant.type, constant.value
            var = getvar(op).deref()
            return var.type, var.get()

        def setval(op: Operand, new):
            if op.immediate:
                raise RuntimeError('attempt to assign to an immediate')
            getvar(op).set(new)

        frames = run.frames
        depth = run.depth
        script_globals = self.globals
        exec_start = process_time()
        stack = run.stack
        _cfg_max_call_stack = self.config.max_call_stack
        _cfg_max_data_stack = self.config.max_data_stack
        _cfg_max_seconds = self.config.max_seconds
        _cfg_max_opcodes = self.config.max_opcodes
        _cfg_log_opcodes = self.config.log_opcodes

        ip: int = 0
        sp: int = len(stack) - 1
        raised: IFPSException | None = None
        unwind = False
        jump = False

        while True:
            if raised is not None:
                run.throw(raised)
                raised = None
                unwind = True
            if unwind:
                unwind = False
                function, ip, sp = run.unwind()
            if 0 < _cfg_max_call_stack < depth + len(frames):
                raise EmulatorMaxCalls

            if function.body is None:
                namespace = ''

                if decl := function.decl:
                    namespace = decl.classname or decl.module or ''

                name = function.name
                registry: dict[str, IFPSEmulatedFunction] = self.external_symbols.get(namespace, {})
                handler = registry.get(name)

                if decl:
                    void = decl.void
                    argc = decl.argc
                elif handler:
                    void = handler.void
                    argc = handler.argc
                else:
                    void = True
                    argc = 0

                try:
                    rpos = 0 if void else 1
                    args: list = [stack[~k] for k in range(rpos, argc + rpos)]
                except IndexError:
                    raise EmulatorException(
                        F'Cannot call {function!s}; {argc} arguments + {rpos} return values expected,'
                        F' but stack size is only {len(stack)}.')

                if self.config.log_calls:
                    yield NewFunctionCall(str(function), tuple(a.get() for a in args))

                if handler is None:
                    self.unimplemented(function, args, None if void else stack[-1])
                elif handler.argc != argc or handler.void and not void:
                    failure = _incompatible_call(handler, argc, void)
                    raised = IFPSException(failure, called=name)
                    yield NewEmulationError(name, failure)
                else:
                    for k, (var, byref) in enumerate(zip(args, handler.spec)):
                        if not byref:
                            args[k] = var.get()
                    args.insert(0, self)
                    keywords = {'caller': run} if handler.caller else {}
                    failure = None
                    try:
                        return_value = handler.call(*args, **keywords)
                        if inspect.isgenerator(return_value):
                            return_value = yield from return_value
                    except EmulatorException:
                        raise
                    except RecursionError as RE:
                        raise EmulatorMaxCalls(F'Calling {name} exceeded the recursion limit of Python.') from RE
                    except IFPSException as error:
                        raised = IFPSException(error.message, error.kind, name)
                    except DelphiException as error:
                        raised = IFPSException(str(error), called=name)
                    except Exception as error:
                        failure = exception_to_string(error)
                        raised = IFPSException(failure, called=name)
                    else:
                        if not void:
                            stack[-1].set(return_value)
                    if failure is not None:
                        yield NewEmulationError(name, failure)
                if not frames:
                    if raised is None:
                        return
                    continue
                function, ip, sp = frames.pop()
                continue

            while insn := function.code.get(ip, None):
                if 0 < _cfg_max_seconds < process_time() - exec_start:
                    raise EmulatorTimeout
                if 0 < _cfg_max_opcodes < self.clock:
                    raise EmulatorExecutionLimit
                if 0 < _cfg_max_data_stack < len(stack):
                    raise EmulatorMaxStack
                if _cfg_log_opcodes:
                    yield NewInstruction(function, insn, ip)
                try:
                    opc = insn.opcode
                    ip += insn.size
                    self.clock += 1

                    if opc == Op.Nop:
                        continue
                    elif opc == Op.Assign:
                        dst = getvar(insn.op(0))
                        src = insn.op(1)
                        if src.immediate:
                            dst.set(src.value)
                        else:
                            dst.set(getvar(src))
                    elif opc == Op.Calculate:
                        if not isinstance((aop := insn.operator), AOp):
                            raise TypeError(F'Operator for {opc} was of type {aop.__class__.__name__} rather than AOp.')
                        target = getvar(insn.op(0)).deref()
                        st, sv = gettyped(insn.op(1))
                        dv = target.get()
                        fpu = isinstance(sv, float) or isinstance(dv, float)
                        try:
                            result = _calculate(aop, target.type.code, dv, st.code, sv)
                            if fpu and not isinstance(result, float):
                                raise FloatingPointError
                        except FloatingPointError as FPE:
                            if not self.fpucw & FPUControl.InvalidOperation:
                                result = float('nan')
                            else:
                                raise IFPSException('invalid operation', PSError.MathError) from FPE
                        except OverflowError as OFE:
                            if not fpu:
                                raise IFPSException(SysConst.SIntOverflow) from OFE
                            if self.fpucw & FPUControl.Overflow:
                                result = float('nan')
                            else:
                                raise IFPSException('arithmetic overflow', PSError.MathError) from OFE
                        except ZeroDivisionError as ZDE:
                            if not fpu:
                                raise IFPSException(SysConst.SDivByZero, PSError.DivideByZero) from ZDE
                            if self.fpucw & FPUControl.ZeroDivide:
                                result = float('nan')
                            else:
                                raise IFPSException('division by zero', PSError.DivideByZero) from ZDE
                        target.set(result)
                    elif opc == Op.Push:
                        # TODO: I do not actually know how this works
                        stack.append(getval(insn.op(0)))
                    elif opc == Op.PushVar:
                        stack.append(getvar(insn.op(0)))
                    elif opc == Op.Pop:
                        stack.pop()
                    elif opc == Op.Call:
                        frames.append(_CallState(function, ip, sp))
                        function = insn.callee()
                        ip = 0
                        sp = len(stack) - 1
                        break
                    elif opc == Op.Jump:
                        ip = insn.operands[0]
                    elif opc == Op.JumpTrue:
                        if getval(insn.op(1)):
                            ip = insn.operands[0]
                    elif opc == Op.JumpFalse:
                        if not getval(insn.op(1)):
                            ip = insn.operands[0]
                    elif opc == Op.Ret:
                        if (position := run.exit(function, insn.offset, sp)) is not None:
                            function, ip, sp = position
                            continue
                        del stack[sp + 1:]
                        if not frames:
                            if run.in_flight.error is None:
                                return
                            unwind = True
                            break
                        function, ip, sp = frames.pop()
                        break
                    elif opc == Op.StackType:
                        raise OpCodeNotImplemented(str(opc))
                    elif opc == Op.PushType:
                        stack.append(Variable(
                            insn.operands[0],
                            VariableSpec(len(stack) - sp, VariableType.Local)
                        ))
                    elif opc == Op.Compare:
                        if not isinstance((cop := insn.operator), COp):
                            raise TypeError(F'Operator for {opc} was of type {cop.__class__.__name__} rather than COp.')
                        lt, lv = gettyped(insn.op(1))
                        rt, rv = gettyped(insn.op(2))
                        getvar(insn.op(0)).set(_compare(cop, lt, lv, rt, rv))
                    elif opc == Op.CallVar:
                        call = getval(insn.op(0))
                        if isinstance(call, int):
                            call = self.ifps.functions[call]
                        if isinstance(call, Function):
                            frames.append(_CallState(function, ip, sp))
                            function = call
                            ip = 0
                            sp = len(stack) - 1
                            break
                    elif opc == Op.SetPtr:
                        getvar(insn.op(0)).setptr(getvar(insn.op(1)))
                    elif opc == Op.SetPtrToCopy:
                        dst = getvar(insn.op(0))
                        src = insn.op(1)
                        if (constant := src.value) is None:
                            dst.setptr(getvar(src), copy=True)
                        else:
                            dst.setptr(Variable(constant.type, data=constant.value))
                    elif opc == Op.BooleanNot:
                        setval(a := insn.op(0), not getval(a))
                    elif opc == Op.IntegerNot:
                        setval(a := insn.op(0), ~getval(a))
                    elif opc == Op.Neg:
                        setval(a := insn.op(0), -getval(a))
                    elif opc == Op.SetFlag:
                        condition, negated = insn.operands
                        jump = bool(getval(condition)) ^ negated
                    elif opc == Op.JumpFlag:
                        if jump:
                            ip = insn.operands[0]
                    elif opc == Op.PushEH:
                        run.install(insn.operands, function, sp)
                    elif opc == Op.PopEH:
                        if (position := run.end_block(EHType(insn.operands[0]))) is None:
                            unwind = True
                            break
                        function, ip, sp = position
                    elif opc == Op.Inc:
                        counter = getvar(insn.op(0)).deref()
                        if not counter.type.code.integer:
                            raise _type_mismatch()
                        counter.set(counter.get() + 1)
                    elif opc == Op.Dec:
                        counter = getvar(insn.op(0)).deref()
                        if not counter.type.code.integer:
                            raise _type_mismatch()
                        counter.set(counter.get() - 1)
                    elif opc == Op.JumpPop1:
                        stack.pop()
                        ip = insn.operands[0]
                    elif opc == Op.JumpPop2:
                        stack.pop()
                        stack.pop()
                        ip = insn.operands[0]
                    else:
                        raise RuntimeError(F'Function contains invalid opcode at 0x{ip:X}.')
                except IFPSException as EE:
                    raised = EE
                    break
                except EmulatorException:
                    raise
                except Exception as RE:
                    raise EmulatorException(
                        F'In {function.symbol} at 0x{insn.offset:X} (cycle {self.clock}), '
                        F'emulation of {insn!r} failed: {RE!s}')
            else:
                raise EmulatorException(F'In {function.symbol}, no instruction starts at 0x{ip:X}.')

    external_symbols: ClassVar[
        dict[str,                        # class name for methods or empty string for functions
        dict[str, IFPSEmulatedFunction]] # method or function name to emulation info
    ] = CaseInsensitiveDict()

    def external(*args, __reg: dict = external_symbols, **kwargs):
        def decorator(pfn):
            signature = inspect.signature(pfn)
            name: str = kwargs.get('name', pfn.__name__)
            csep: str = '.'
            if csep not in name:
                csep = '__'
            classname, _, name = name.rpartition(csep)
            if (registry := __reg.get(classname)) is None:
                registry = __reg[classname] = CaseInsensitiveDict()

            docs = F'{classname}::{name}' if classname else name
            docs = F'An emulated handler for the external symbol {docs}.'
            pfn.__doc__ = docs

            void = kwargs.get('void', signature.return_annotation == signature.empty)
            caller = kwargs.get('caller', False)
            parameters: list[bool] = []
            specs = iter(signature.parameters.values())
            next(specs) # skip self
            for spec in specs:
                if caller and spec.name == 'caller':
                    continue
                try:
                    hint = eval(spec.annotation, globals(), locals())
                except Exception as E:
                    raise RuntimeError(F'Invalid signature: {signature}') from E
                if not isinstance(hint, type):
                    hint = get_origin(hint)
                var = isinstance(hint, type) and issubclass(hint, Variable)
                parameters.append(var)
            registry[name] = e = IFPSEmulatedFunction(pfn, parameters, void, caller)
            aliases = kwargs.get('alias', [])
            if isinstance(aliases, str):
                aliases = [aliases]
            for name in aliases:
                registry[name] = e
            return pfn
        return decorator(args[0]) if args else decorator

    @external()
    def TInputDirWizardPage__GetValues(self, this: object, k: int) -> str:
        return F'$InputDir{k}'

    @external()
    def TInputFileWizardPage__GetValues(self, this: object, k: int) -> str:
        return F'$InputFile{k}'

    @external()
    def TPasswordEdit__SetText(self, this: object, value: str):
        if value:
            yield NewPassword(value)
        return value

    @external(alias=['ShellExecuteA', 'ShellExecuteW'])
    def shell32__ShellExecute(self, hwnd: int, operation: str, file: str, args: str, cwd: str, show: int) -> int:
        if file == self.config.executable:
            for arg in shlex.split(args):
                if arg.upper().startswith('/PASSWORD='):
                    yield NewPassword(arg[10:])
        return 0x40

    def _PROCESSENTRY32(self, record: list, pid: int):
        path = self.config.processes[pid]
        if path is None:
            _, path = ntpath.split(self.config.executable)
        ...                 # DWORD     dwSize
        record[1] = 0       # DWORD     cntUsage
        record[2] = pid     # DWORD     th32ProcessID
        record[3] = 0       # ULONG_PTR th32DefaultHeapID
        record[4] = 0       # DWORD     th32ModuleID
        record[5] = 1       # DWORD     cntThreads
        record[6] = 0       # DWORD     th32ParentProcessID
        record[7] = 0       # LONG      pcPriClassBase
        record[8] = 0       # DWORD     dwFlags
        szExe = record[9]   # CHAR      szExeFile[MAX_PATH]
        szExe[:len(path)] = path # noqa
        szExe[ len(path)] = '\0' # noqa

    @external()
    def kernel32__GetLastError(self) -> int:
        return self._win32api_last_error

    @external()
    def kernel32__SetLastError(self, code: int):
        self._win32api_last_error = code

    @external()
    def kernel32__CreateToolhelp32Snapshot(self, flags: int, process_id: int) -> int:
        if not self.config.allow_process_listing:
            return -1
        return random.randrange(0x10, 0x100000)

    @external(alias=['Process32FirstW'])
    def kernel32__Process32First(self, handle: int, p_record: Variable[list]) -> bool:
        if not (pids := self._win32api_sorted_process_ids):
            return False
        record = p_record.get()
        pid = pids[0]
        self._PROCESSENTRY32(record, pid)
        p_record.set(record)
        return True

    @external(alias=[
        'LoadLibraryW',
        'LoadLibraryA',
    ])
    def kernel32__LoadLibrary(self, name: str) -> int:
        name = name.lower()
        base, dot, ext = name.rpartition('.')
        if dot and ext.lower() == 'dll':
            name = base
        return self.winapi_module_to_addr.get(name, 0)

    @external(alias=['GetProcAddressA'])
    def kernel32__GetProcAddress(self, module: int, name: str) -> int:
        if module not in self.winapi_addr_to_module:
            return 0
        return self.winapi_symbol_to_addr.get(name, 0)

    @external(alias=['Process32NextW'])
    def kernel32__Process32Next(self, handle: int, p_record: Variable[list]) -> bool:
        record = p_record.get()
        pid = record[2]
        pids = self._win32api_sorted_process_ids
        k = bisect.bisect_right(pids, pid)
        if k < len(pids):
            pid = pids[k]
            self._PROCESSENTRY32(record, pid)
            p_record.set(record)
            return True
        else:
            self.kernel32__SetLastError(ERROR_NO_MORE_FILES)
            return False

    @external()
    def kernel32__GetTickCount(self) -> int:
        tick = self.clock
        tick *= self.config.milliseconds_per_instruction
        tick += self.seconds_slept * 1000
        return int(tick)

    @external()
    def user32__GetSystemMetrics(self, index: int) -> int:
        if index == 80:
            return 1
        if index == 43:
            return 2
        return 0

    @external()
    def IsX86Compatible(self) -> bool:
        return True

    @external(alias=[
        'IsArm64',
        'IsArm32Compatible',
        'Debugging',
        'IsUninstaller',
    ])
    def Terminated(self) -> bool:
        return False

    @external()
    def IsAdmin(self) -> bool:
        return self.config.admin

    @external(name='Sleep')
    @external()
    def kernel32__Sleep(self, ms: int):
        seconds = ms / 1000.0
        self.seconds_slept += seconds

    @external()
    def Random(self, top: int) -> int:
        return random.randrange(0, top)

    @external(alias='StrGet')
    def WStrGet(self, string: Variable[str], index: int) -> str:
        if index <= 0:
            raise ValueError
        return string[index - 1:index]

    @external(alias='StrSet')
    def WStrSet(self, char: str, index: int, dst: Variable[str]):
        old = dst.get()
        halt = index - 1
        dst.set(old[:halt] + char + old[index:])

    @external()
    def GetEnv(self, name: str) -> str:
        return self.config.environment.get(name, F'%{name}%')

    @external()
    def Beep(self):
        pass

    @external()
    def Abort(self):
        if self.config.throw_abort:
            raise AbortEmulation
        raise IFPSException(SysConst.SOperationAborted)

    @external()
    def DirExists(self, path: str) -> bool:
        return False

    @external()
    def ForceDirectories(self, path: str) -> bool:
        return True

    @external(alias='LoadStringFromLockedFile')
    def LoadStringFromFile(self, path: str, out: Variable[str]) -> bool:
        return True

    @external(alias='LoadStringsFromLockedFile')
    def LoadStringsFromFile(self, path: str, out: Variable[str]) -> bool:
        return True

    @cached_property
    def constant_map(self) -> dict[str, str]:
        cfg = self.config
        tmp = cfg.temp_path
        if not tmp:
            tmp = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))
            tmp = RF'C:\Windows\Temp\IS-{tmp}'
        map = {
            'app'               : cfg.install_to,
            'win'               : R'C:\Windows',
            'sys'               : R'C:\Windows\System',
            'sysnative'         : R'C:\Windows\System32',
            'src'               : str(Path(cfg.executable).parent),
            'sd'                : R'C:',
            'commonpf'          : R'C:\Program Files',
            'commoncf'          : R'C:\Program Files\Common Files',
            'tmp'               : tmp,
            'commonfonts'       : R'C:\Windows\Fonts',
            'dao'               : R'C:\Program Files\Common Files\Microsoft Shared\DAO',
            'dotnet11'          : R'C:\Windows\Microsoft.NET\Framework\v1.1.4322',
            'dotnet20'          : R'C:\Windows\Microsoft.NET\Framework\v3.0',
            'dotnet2032'        : R'C:\Windows\Microsoft.NET\Framework\v3.0',
            'dotnet40'          : R'C:\Windows\Microsoft.NET\Framework\v4.0.30319',
            'dotnet4032'        : R'C:\Windows\Microsoft.NET\Framework\v4.0.30319',
            'group'             : RF'C:\Users\{cfg.user_name}\Start Menu\Programs\{cfg.inno_name}',
            'localappdata'      : RF'C:\Users\{cfg.user_name}\AppData\Local',
            'userappdata'       : RF'C:\Users\{cfg.user_name}\AppData\Roaming',
            'userdesktop'       : RF'C:\Users\{cfg.user_name}\Desktop',
            'userdocs'          : RF'C:\Users\{cfg.user_name}\Documents',
            'userfavourites'    : RF'C:\Users\{cfg.user_name}\Favourites',
            'usersavedgames'    : RF'C:\Users\{cfg.user_name}\Saved Games',
            'usersendto'        : RF'C:\Users\{cfg.user_name}\SendTo',
            'userstartmenu'     : RF'C:\Users\{cfg.user_name}\Start Menu',
            'userprograms'      : RF'C:\Users\{cfg.user_name}\Start Menu\Programs',
            'userstartup'       : RF'C:\Users\{cfg.user_name}\Start Menu\Programs\Startup',
            'usertemplates'     : RF'C:\Users\{cfg.user_name}\Templates',
            'commonappdata'     : R'C:\ProgramData',
            'commondesktop'     : R'C:\ProgramData\Microsoft\Windows\Desktop',
            'commondocs'        : R'C:\ProgramData\Microsoft\Windows\Documents',
            'commonstartmenu'   : R'C:\ProgramData\Microsoft\Windows\Start Menu',
            'commonprograms'    : R'C:\ProgramData\Microsoft\Windows\Start Menu\Programs',
            'commonstartup'     : R'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
            'commontemplates'   : R'C:\ProgramData\Microsoft\Windows\Templates',
            'cmd'               : R'C:\Windows\System32\cmd.exe',
            'computername'      : cfg.host_name,
            'groupname'         : cfg.inno_name,
            'hwnd'              : '0',
            'wizardhwnd'        : '0',
            'language'          : cfg.language,
            'srcexe'            : cfg.executable,
            'sysuserinfoname'   : '{sysuserinfoname}',
            'sysuserinfoorg'    : '{sysuserinfoorg}',
            'userinfoname'      : '{userinfoname}',
            'userinfoorg'       : '{userinfoorg}',
            'userinfoserial'    : '{userinfoserial}',
            'username'          : cfg.user_name,
            'log'               : '',
        }

        if (setup_info := self.setup_info) is None or (setup_info.Header.Flags & Flags.Uninstallable):
            map['uninstallexe'] = RF'{cfg.install_to}\unins000.exe'

        if cfg.x64:
            map['syswow64'] = R'C:\Windows\SysWOW64'
            map['commonpf32'] = R'C:\Program Files (x86)'
            map['commoncf32'] = R'C:\Program Files (x86)\Common Files'
            map['commonpf64'] = R'C:\Program Files'
            map['commoncf64'] = R'C:\Program Files\Common Files'
            map['dotnet2064'] = R'C:\Windows\Microsoft.NET\Framework64\v3.0'
            map['dotnet4064'] = R'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
        else:
            map['syswow64'] = R'C:\Windows\System32'
            map['commonpf32'] = R'C:\Program Files'
            map['commoncf32'] = R'C:\Program Files\Common Files'

        if cfg.windows_os_version[0] >= 10:
            map['userfonts'] = RF'{map["localappdata"]}\Microsoft\Windows\Fonts'

        if cfg.windows_os_version[0] >= 7:
            map['usercf'] = RF'{map["localappdata"]}\Programs\Common'
            map['userpf'] = RF'{map["localappdata"]}\Programs'

        for auto_var, admin_var, user_var in [
            ('autoappdata',       'commonappdata',       'userappdata',   ), # noqa
            ('autocf',            'commoncf',            'usercf',        ), # noqa
            ('autocf32',          'commoncf32',          'usercf',        ), # noqa
            ('autocf64',          'commoncf64',          'usercf',        ), # noqa
            ('autodesktop',       'commondesktop',       'userdesktop',   ), # noqa
            ('autodocs',          'commondocs',          'userdocs',      ), # noqa
            ('autofonts',         'commonfonts',         'userfonts',     ), # noqa
            ('autopf',            'commonpf',            'userpf',        ), # noqa
            ('autopf32',          'commonpf32',          'userpf',        ), # noqa
            ('autopf64',          'commonpf64',          'userpf',        ), # noqa
            ('autoprograms',      'commonprograms',      'userprograms',  ), # noqa
            ('autostartmenu',     'commonstartmenu',     'userstartmenu', ), # noqa
            ('autostartup',       'commonstartup',       'userstartup',   ), # noqa
            ('autotemplates',     'commontemplates',     'usertemplates', ), # noqa
        ]:
            try:
                map[auto_var] = map[admin_var] if cfg.admin else map[user_var]
            except KeyError:
                continue

        for legacy, new in [
            ('cf',     'commoncf',    ), # noqa
            ('cf32',   'commoncf32',  ), # noqa
            ('cf64',   'commoncf64',  ), # noqa
            ('fonts',  'commonfonts', ), # noqa
            ('pf',     'commonpf',    ), # noqa
            ('pf32',   'commonpf32',  ), # noqa
            ('pf64',   'commonpf64',  ), # noqa
            ('sendto', 'usersendto',  ), # noqa
        ]:
            try:
                map[legacy] = map[new]
            except KeyError:
                continue

        return map

    @external(caller=True)
    def ExpandConstant(self, string: str, caller: _ScriptRun | None = None) -> str:
        return self.expand_constant(string, caller=caller)

    @external(caller=True)
    def ExpandConstantEx(
        self,
        string: str,
        custom_var: str,
        custom_val: str,
        caller: _ScriptRun | None = None,
    ) -> str:
        return self.expand_constant(string, custom_var, custom_val, caller=caller)

    def expand_constant(
        self,
        string: str,
        custom_var: str | None = None,
        custom_val: str | None = None,
        unescape: bool = False,
        caller: _ScriptRun | None = None,
    ):
        """
        Expands the constants in the given string. A code constant runs a function of the script;
        when the expansion is part of a run of the script, given as `caller`, that run is nested in
        it.
        """
        config = self.config
        expand = partial(self.expand_constant, unescape=True, caller=caller)
        string = re.sub(r'(\{\{.*?\}(?!\}))', '\\1}', string)

        with io.StringIO() as result:
            constants = self.constant_map
            formatter = Formatter()
            backslash = False
            try:
                parsed = list(formatter.parse(string))
            except ValueError as VE:
                raise IFPSException(F'invalid format string: {string!r}') from VE
            for prefix, spec, modifier, conversion in parsed:
                modifier = modifier or ''
                if backslash and prefix[:1] == '\\':
                    prefix = prefix[1:]
                if unescape:
                    prefix = unquote(prefix)
                result.write(prefix)
                if spec is None:
                    continue
                elif spec == '\\':
                    if modifier or conversion:
                        raise IFPSException('Invalid format string.')
                    value = spec
                elif spec == custom_var:
                    value = custom_val
                elif spec.startswith('%'):
                    name, p, default = spec[1:].partition('|')
                    name = expand(name)
                    default = expand(default)
                    try:
                        value = config.environment[name]
                    except KeyError:
                        value = default if p else F'%{name}%'
                elif spec == 'drive':
                    value = self.ExtractFileDrive(expand(modifier))
                elif spec == 'ini':
                    # {ini:Filename,Section,Key|DefaultValue}
                    _, _, default = modifier.partition('|')
                    value = expand(default)
                elif spec == 'code':
                    # {code:FunctionName|Param}
                    symbol, _, param = modifier.partition('|')
                    param = expand(param)
                    try:
                        function = self.symbols[symbol]
                    except KeyError as KE:
                        raise IFPSException(F'String formatter references missing function {symbol}.') from KE
                    emulation = EventCall(self._execute(_ScriptRun(caller), function, (param,)))
                    value = str(emulation.value)
                elif spec == 'cm':
                    # {cm:LaunchProgram,Inno Setup}
                    # The example above translates to "Launch Inno Setup" if English is the active language.
                    name, _, placeholders = modifier.partition(',')
                    value = self.CustomMessage(expand(name))
                    if placeholders:
                        def _placeholder(match: re.Match[str]):
                            try:
                                return placeholders[int(match[1]) - 1]
                            except Exception:
                                return match[0]
                        placeholders = [ph.strip() for ph in placeholders.split(',')]
                        value = re.sub('(?<!%)%([1-9]\\d*)', _placeholder, value)
                elif spec == 'reg':
                    # {reg:HKXX\SubkeyName,ValueName|DefaultValue}
                    _, _, default = modifier.partition('|')
                    value = expand(default)
                elif spec == 'param':
                    # {param:ParamName|DefaultValue}
                    _, _, default = modifier.partition('|')
                    value = expand(default)
                else:
                    try:
                        value = constants[spec]
                    except KeyError as KE:
                        raise IFPSException(F'invalid format field {spec}') from KE
                backslash = value.endswith('\\')
                result.write(value)
            return result.getvalue()

    @external()
    def DeleteFile(self, path: str) -> bool:
        return True

    @external()
    def FileExists(self, file_name: str) -> bool:
        return False

    @external()
    def Log(self, log: str):
        ...

    @external()
    def Inc(self, p: Variable[int]):
        p.set(p.get() + 1)

    @external()
    def Dec(self, p: Variable[int]):
        p.set(p.get() - 1)

    @external()
    def FindFirst(self, file_name: str, frec: Variable) -> bool:
        return False

    @external()
    def Trunc(self, x: float) -> int:
        return math.trunc(x)

    @external()
    def GetSpaceOnDisk(
        self,
        path: str,
        in_megabytes: bool,
        avail: Variable[int],
        space: Variable[int],
    ) -> bool:
        _a = 3_000_000
        _t = 5_000_000
        if not in_megabytes:
            _a *= 1000
            _t *= 1000
        avail.set(_a)
        space.set(_t)
        return True

    @external()
    def GetSpaceOnDisk64(
        self,
        path: str,
        avail: Variable[int],
        space: Variable[int],
    ) -> bool:
        avail.set(3_000_000_000)
        space.set(5_000_000_000)
        return True

    @external()
    def Exec(
        self,
        exe: str,
        cmd: str,
        cwd: str,
        show: int,
        wait: int,
        out: Variable[int],
    ) -> bool:
        out.set(0)
        return True

    @external()
    def GetCmdTail(self) -> str:
        return ''

    @external()
    def ParamCount(self) -> int:
        return 0

    @external()
    def ParamStr(self, index: int) -> str:
        return ''

    @external()
    def ActiveLanguage(self) -> str:
        return 'en'

    @external()
    def CustomMessage(self, msg_name: str) -> str:
        by_language = {}
        if (setup_info := self.setup_info) is None:
            return ''
        for msg in setup_info.Messages:
            if msg.EncodedName == msg_name and (lv := msg.get_language_value()):
                lng = lv.Name
                if lng == self.config.language:
                    return msg.Value
                by_language[lng] = msg.Value
        try:
            return by_language[0]
        except KeyError:
            pass
        try:
            return next(iter(by_language.values()))
        except StopIteration:
            raise IFPSException(F'Custom message with name {msg_name} not found.')

    @external()
    def FmtMessage(self, fmt: str, args: list[str]) -> str:
        def substitute(match: re.Match[str]):
            if (spec := match[1]) == '%':
                return '%'
            if (k := int(spec) - 1) < len(args):
                return args[k]
            return match[0]
        return re.sub('%([1-9%])', substitute, fmt)

    @external()
    def Format(self, fmt: str, args: Variable[list]) -> str:
        elements = args.deref()
        return delphi.format(fmt, [_open_array_element(elements.at(k)) for k in range(len(elements))])

    @external()
    def SetupMessage(self, id: int) -> str:
        try:
            if (setup_info := self.setup_info) is not None:
                return setup_info.Messages[id].Value
        except IndexError:
            pass
        return ''

    @external(alias=['Is64BitInstallMode', 'IsX64Compatible', 'IsX64OS'])
    def IsWin64(self) -> bool:
        return self.config.x64

    @external()
    def IsX86OS(self) -> bool:
        return not self.config.x64

    @external()
    def RaiseException(self, msg: str):
        raise IFPSException(msg)

    @external(caller=True)
    def GetExceptionMessage(self, caller: _ScriptRun | None = None) -> str:
        if caller is None or (error := caller.current_exception) is None:
            return '(There is no current exception)'
        return error.message

    @external()
    def ProcessorArchitecture(self) -> int:
        if self.config.x64:
            return TSetupProcessorArchitecture.paX64.value
        else:
            return TSetupProcessorArchitecture.paX86.value

    @external()
    def GetUserNameString(self) -> str:
        return self.config.user_name

    @external()
    def GetComputerNameString(self) -> str:
        return self.config.host_name

    @external()
    def GetUILanguage(self) -> int:
        return self.config.lcid

    @external()
    def GetArrayLength(self, array: Variable) -> int:
        array = array.deref()
        return len(array)

    @external()
    def SetArrayLength(self, array: Variable, n: int):
        if 0 < (limit := self.config.max_array_length) < n:
            raise EmulatorMaxArray(F'Requested array length {n} exceeds the limit {limit}.')
        array.deref().resize(n)

    @external()
    def WizardForm(self) -> object:
        return self._wizard_form

    @external()
    def Unassigned(self) -> None:
        return None

    @external()
    def Null(self) -> None:
        return None

    @external()
    def Set8087CW(self, cw: int):
        self.fpucw = FPUControl(cw)

    @external()
    def Get8087CW(self) -> int:
        return self.fpucw.value

    @external()
    def GetDateTimeString(
        self,
        fmt: str,
        date_separator: str,
        time_separator: str,
    ) -> str:

        now = self.config.start_time
        now = now + timedelta(
            milliseconds=(self.config.milliseconds_per_instruction * self.clock))
        now = now + timedelta(seconds=self.seconds_slept)

        date_separator = date_separator.lstrip('\0')
        time_separator = time_separator.lstrip('\0')

        def dt(m: re.Match[str]):
            spec = m[1]
            ampm = m[2]
            if ampm:
                am, _, pm = ampm.partition('/')
                spec = spec.upper()
                suffix = now.strftime('%p').lower()
                suffix = {'am': am, 'pm': pm}[suffix]
            else:
                suffix = ''
            if spec == 'dddddd' or spec == 'ddddd':
                return now.date().isoformat()
            if spec == 't':
                return now.time().isoformat('minutes')
            if spec == 'tt':
                return now.time().isoformat('seconds')
            if spec == 'd':
                return str(now.day)
            if spec == 'm':
                return str(now.month)
            if spec == 'h':
                return str(now.hour)
            if spec == 'n':
                return str(now.minute)
            if spec == 's':
                return str(now.second)
            if spec == 'H':
                return now.strftime('%I').lstrip('0') + suffix
            if spec == '/':
                return date_separator or spec
            if spec == ':':
                return time_separator or spec
            return now.strftime({
                'dddd'  : '%A',
                'ddd'   : '%a',
                'dd'    : '%d',
                'mmmm'  : '%B',
                'mmm'   : '%b',
                'mm'    : '%m',
                'yyyy'  : '%Y',
                'yy'    : '%y',
                'hh'    : '%H',
                'HH'    : '%I' + suffix,
                'nn'    : '%M',
                'ss'    : '%S',
            }.get(spec, m[0]))

        split = re.split(F'({formats.string!s})', fmt)
        for k in range(0, len(split), 2):
            split[k] = re.sub('(d+|m+|y+|h+|n+|s+|t+)((?:[aA][mM]?/[pP][mM]?)?)', dt, split[k])
        for k in range(1, len(split), 2):
            split[k] = split[k][1:-1]
        return ''.join(split)

    @external()
    def Chr(self, b: int) -> str:
        return chr(b)

    @external()
    def Ord(self, c: str) -> int:
        return ord(c)

    @external()
    def Copy(self, string: str, index: int, count: int) -> str:
        index -= 1
        return string[index:index + count]

    @external()
    def Length(self, string: str) -> int:
        return len(string)

    @external(alias='AnsiLowercase')
    def Lowercase(self, string: str) -> str:
        return string.lower()

    @external(alias='AnsiUppercase')
    def Uppercase(self, string: str) -> str:
        return string.upper()

    @external()
    def StringOfChar(self, c: str, count: int) -> str:
        return c * count

    @external()
    def Delete(self, string: Variable[str], index: int, count: int):
        index -= 1
        old = string.get()
        string.set(old[:index] + old[index + count:])

    @external()
    def Insert(self, string: str, dest: Variable[str], index: int):
        index -= 1
        old = dest.get()
        dest.set(old[:index] + string + old[index:])

    @external()
    def StringChange(self, string: Variable[str], old: str, new: str) -> int:
        return self.StringChangeEx(string, old, new, False)

    @external()
    def StringChangeEx(self, string: Variable[str], old: str, new: str, _: bool) -> int:
        haystack = string.get()
        count = haystack.count(old)
        string.set(haystack.replace(old, new))
        return count

    @external()
    def Pos(self, sub: str, string: str) -> int:
        if not sub:
            return 0
        return string.find(sub) + 1

    @external()
    def AddQuotes(self, string: str) -> str:
        if string and (string[0] != '"' or string[~0] != '"') and ' ' in string:
            string = F'"{string}"'
        return string

    @external()
    def RemoveQuotes(self, string: str) -> str:
        if string and string[0] == '"' and string[~0] == '"':
            string = string[1:-1]
        return string

    @external()
    def CompareText(self, a: str, b: str) -> int:
        return self.CompareStr(a.casefold(), b.casefold())

    @external()
    def CompareStr(self, a: str, b: str) -> int:
        if a > b:
            return +1
        if a < b:
            return -1
        return 0

    @external()
    def SameText(self, a: str, b: str) -> bool:
        return a.casefold() == b.casefold()

    @external()
    def SameStr(self, a: str, b: str) -> bool:
        return a == b

    @external()
    def IsWildcard(self, pattern: str) -> bool:
        return '*' in pattern or '?' in pattern

    @external()
    def WildcardMatch(self, text: str, pattern: str) -> bool:
        return fnmatch.fnmatch(text, pattern)

    @external()
    def Trim(self, string: str) -> str:
        return string.strip()

    @external()
    def TrimLeft(self, string: str) -> str:
        return string.lstrip()

    @external()
    def TrimRight(self, string: str) -> str:
        return string.rstrip()

    @external()
    def StringJoin(self, sep: str, values: list[str]) -> str:
        return sep.join(values)

    @external()
    def StringSplitEx(self, string: str, separators: list[str], quote: str, how: TSplitType) -> list[str]:
        if not quote:
            parts = [string]
        else:
            quote = re.escape(quote)
            parts = re.split(F'({quote}.*?{quote})', string)
        sep = '|'.join(re.escape(s) for s in separators)
        out = []
        if how == TSplitType.stExcludeEmpty:
            sep = F'(?:{sep})+'
        for k in range(0, len(parts)):
            if k & 1 == 1:
                out.append(parts[k])
                continue
            out.extend(re.split(sep, string))
        if how == TSplitType.stExcludeLastEmpty:
            for k in reversed(range(len(out))):
                if not out[k]:
                    out.pop(k)
                    break
        return out

    @external()
    def StringSplit(self, string: str, separators: list[str], how: TSplitType) -> list[str]:
        return self.StringSplitEx(string, separators, None, how)

    @external(alias='StrToInt64')
    def StrToInt(self, s: str) -> int:
        return int(s)

    @external(alias='StrToInt64Def')
    def StrToIntDef(self, s: str, d: int) -> int:
        try:
            return int(s)
        except Exception:
            return d

    @external()
    def StrToFloat(self, s: str) -> float:
        return float(s)

    @external(alias='FloatToStr')
    def IntToStr(self, i: int) -> str:
        return str(i)

    @external()
    def StrToVersion(self, s: str, v: Variable[int]) -> bool:
        try:
            packed = bytes(map(int, s.split('.')))
        except Exception:
            return False
        if len(packed) != 4:
            return False
        v.set(int.from_bytes(packed, 'little'))
        return True

    @external()
    def CharLength(self, string: str, index: int) -> int:
        return 1

    @external()
    def AddBackslash(self, string: str) -> str:
        if string and string[~0] != '\\':
            string = F'{string}\\'
        return string

    @external()
    def AddPeriod(self, string: str) -> str:
        if string and string[~0] != '.':
            string = F'{string}.'
        return string

    @external()
    def RemoveBackslashUnlessRoot(self, string: str) -> str:
        path = Path(string)
        if len(path.parts) == 1:
            return str(path)
        return self.RemoveBackslash(string)

    @external()
    def RemoveBackslash(self, string: str) -> str:
        return string.rstrip('\\/')

    @external()
    def ChangeFileExt(self, name: str, ext: str) -> str:
        if not ext.startswith('.'):
            ext = F'.{ext}'
        return str(Path(name).with_suffix(ext))

    @external()
    def ExtractFileExt(self, name: str) -> str:
        return Path(name).suffix

    @external(alias='ExtractFilePath')
    def ExtractFileDir(self, name: str) -> str:
        dirname = str(Path(name).parent)
        return '' if dirname == '.' else dirname

    @external()
    def ExtractFileName(self, name: str) -> str:
        if name:
            name = Path(name).parts[-1]
        return name

    @external()
    def ExtractFileDrive(self, name: str) -> str:
        if name:
            parts = Path(name).parts
            if len(parts) >= 2 and parts[0] == '\\' and parts[1] == '?':
                parts = parts[2:]
            if parts[0] == '\\':
                if len(parts) >= 3:
                    return '\\'.join(parts[:3])
            else:
                root = parts[0]
                if len(root) == 2 and root[1] == ':':
                    return root
        return ''

    @external()
    def ExtractRelativePath(self, base: str, dst: str) -> str:
        return str(Path(dst).relative_to(base))

    @external(alias='ExpandUNCFileName')
    def ExpandFileName(self, name: str) -> str:
        if self.ExtractFileDrive(name):
            return name
        return str(self.config.cwd / name)

    @external()
    def SetLength(self, target: Variable, size: int):
        target = target.deref()
        if target.container:
            self.SetArrayLength(target, size)
            return
        size = max(size, 0)
        old = target.get()
        old = old.ljust(size, '\0')
        target.set(old[:size])

    @external(alias='OemToCharBuff')
    def CharToOemBuff(self, string: Variable[str]):
        # TODO
        ...

    @external()
    def Utf8Encode(self, string: str) -> str:
        return string.encode('utf8').decode('latin1')

    @external()
    def Utf8Decode(self, string: str) -> str:
        return string.encode('latin1').decode('utf8')

    @external()
    def GetMD5OfString(self, string: str) -> str:
        return hashlib.md5(string.encode('latin1')).hexdigest()

    @external()
    def GetMD5OfUnicodeString(self, string: str) -> str:
        return hashlib.md5(string.encode('utf8')).hexdigest()

    @external()
    def GetSHA1OfString(self, string: str) -> str:
        return hashlib.sha1(string.encode('latin1')).hexdigest()

    @external()
    def GetSHA1OfUnicodeString(self, string: str) -> str:
        return hashlib.sha1(string.encode('utf8')).hexdigest()

    @external()
    def GetSHA256OfString(self, string: str) -> str:
        return hashlib.sha256(string.encode('latin1')).hexdigest()

    @external()
    def GetSHA256OfUnicodeString(self, string: str) -> str:
        return hashlib.sha256(string.encode('utf8')).hexdigest()

    @external()
    def SysErrorMessage(self, code: int) -> str:
        return F'[description for error {code & 0xFFFFFFFF:08X}]'

    @external()
    def MinimizePathName(self, path: str, font: object, max_len: int) -> str:
        return path

    @external()
    def CheckForMutexes(self, mutexes: str) -> bool:
        return any(m in self.mutexes for m in mutexes.split(','))

    @external()
    def CreateMutex(self, name: str):
        if self.config.log_mutexes:
            yield NewMutex(name)
        self.mutexes.add(name)

    @external()
    def GetWinDir(self) -> str:
        return self.expand_constant('{win}')

    @external()
    def GetSystemDir(self) -> str:
        return self.expand_constant('{sys}')

    @external()
    def GetWindowsVersion(self) -> int:
        version = int.from_bytes(
            struct.pack('>BBH', *self.config.windows_os_version), 'big')
        return version

    @external()
    def GetWindowsVersionEx(self, tv: Variable[int | bool]):
        tv[0], tv[1], tv[2] = self.config.windows_os_version # noqa
        tv[3], tv[4]        = self.config.windows_sp_version # noqa
        tv[5], tv[6], tv[7] = True, 0, 0

    @external()
    def GetWindowsVersionString(self) -> str:
        return '{}.{:02d}.{:04d}'.format(*self.config.windows_os_version)

    @external()
    def CreateOleObject(self, name: str) -> OleObject:
        return OleObject(name)

    @external()
    def GetActiveOleObject(self, name: str) -> OleObject:
        return OleObject(name)

    @external()
    def IDispatchInvoke(self, ole: OleObject, prop_set: bool, name: str, value: Any) -> int:
        return 0

    @external()
    def FindWindowByClassName(self, name: str) -> int:
        return 0

    @external()
    def FindWindowByWindowName(self, name: str) -> int:
        return 0

    @external()
    def WizardSilent(self) -> bool:
        return self.config.wizard_silent

    @external()
    def SizeOf(self, var: Variable) -> int:
        if var.pointer:
            return (self.config.x64 + 1) * 4
        if var.container:
            return sum(self.SizeOf(x) for x in var.data)
        return var.type.code.width

    del external


class InnoSetupEmulator(IFPSEmulator):
    """
    A specialized `IFPSEmulator` that can emulate the InnoSetup installation with a focus on
    continuing execution as much as possible.
    """

    def emulate_installation(self, password=''):
        """
        To the best of the author's knowledge, this function emulates the sequence of calls into
        the script that the IFPS runtime would make during a setup install. An event that ends with
        a script error is reported as a `NewScriptError` and the installation goes on with the next
        event. Setup would instead end or stay on the current page after an error in some events,
        but the emulator goes on, just as it ignores a `False` returned by `InitializeSetup` or by
        `NextButtonClick`: such an error is often a gap of the emulator rather than an error that
        the script would raise when it runs on Windows. Any other exception ends the emulation. A
        call of an emulated function that fails is reported as a `NewEmulationError`, also when the
        script handles its error.
        """

        yield from self._event(SetupEvent.InitializeSetup)
        yield from self._event(SetupEvent.InitializeWizard)
        yield from self._event(SetupEvent.CurStepChanged, TSetupStep.ssPreInstall)

        for page in PageID:

            skip = yield from self._event(SetupEvent.ShouldSkipPage, page)

            if not skip:
                yield from self._event(SetupEvent.CurPageChanged, page)
                if page == PageID.wpPreparing:
                    yield from self._event(SetupEvent.PrepareToInstall, False)
                if page == PageID.wpPassword:
                    yield from self._event(SetupEvent.CheckPassword, password)

            yield from self._event(SetupEvent.NextButtonClick, page)

            if page == PageID.wpPreparing:
                yield from self._event(SetupEvent.CurStepChanged, TSetupStep.ssInstall)
            if page == PageID.wpInfoAfter:
                yield from self._event(SetupEvent.CurStepChanged, TSetupStep.ssPostInstall)

        yield from self._event(SetupEvent.CurStepChanged, TSetupStep.ssDone)
        yield from self._event(SetupEvent.DeinitializeSetup)

    def _event(self, event: SetupEvent, *args):
        """
        Emulates the function of the script that handles the given setup event. When the script
        does not handle the event, the result is `False`. When the function ends with a script
        error, the error is reported as a `NewScriptError` and the result is `False`, which is what
        Setup assumes when `ShouldSkipPage` fails.
        """
        if not (pfn := self.symbols.get(event)):
            return False
        try:
            return (yield from self.emulate_function(pfn, *args))
        except IFPSException as error:
            message = str(error)
        yield NewScriptError(event, args, message)
        return False

    def unimplemented(self, function: Function, arguments: list[Variable], result: Variable | None):
        """
        Any unimplemented function is essentially skipped. Any arguments passed by reference and
        all return values that are of type integer are set to `1` in an attempt to indicate success
        wherever possible.
        """
        if result is not None and not result.container:
            rt = result.type.py_type()
            if isinstance(rt, type) and issubclass(rt, int):
                result.set(1)
        for ptr in arguments:
            if not ptr.pointer:
                continue
            var = ptr.deref()
            if var.container:
                continue
            vt = var.type.py_type()
            if isinstance(vt, type) and issubclass(vt, int):
                var.set(1)
