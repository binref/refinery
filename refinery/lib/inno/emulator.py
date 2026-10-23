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
import ntpath
import random
import re
import shlex
import struct

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from functools import wraps
from time import process_time
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    ClassVar,
    Generator,
    Generic,
    Iterable,
    Iterator,
    Mapping,
    NamedTuple,
    Sequence,
    TypeVar,
    get_origin,
)

from refinery.lib import json
from refinery.lib.inno import CaseInsensitiveDict, constants, expressions, pascal
from refinery.lib.inno.archive import InnoArchive, TextDirective
from refinery.lib.inno.delphi import formatting, numbers, strings, variants, x87
from refinery.lib.inno.delphi.errors import DelphiException, EIntOverflow, SysConst, Undefined
from refinery.lib.inno.delphi.formatting import VarRec, VType
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.delphi.variants import Variant, VarType
from refinery.lib.inno.emulation import (
    AbortEmulation,
    EmulatorException,
    EmulatorExecutionLimit,
    EmulatorMaxArray,
    EmulatorMaxCalls,
    EmulatorMaxStack,
    EmulatorMaxString,
    EmulatorMemoryError,
    EmulatorTimeout,
    EmulatorUndefined,
    EntryField,
    InternalError,
    NeedSymbol,
    NewEmulationError,
    NewFunctionCall,
    NewInstruction,
    NewMutex,
    NewPassword,
    OpCodeNotImplemented,
)
from refinery.lib.inno.host import (
    HostSetup,
    SetupConstants,
    architecture,
    machine_folders,
    processor,
)
from refinery.lib.inno.ifps import (
    TC,
    AOp,
    COp,
    Dialect,
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
    TStaticArray,
    Value,
    VariableBase,
    VariableSpec,
    VariableType,
)
from refinery.lib.inno.installation import (
    CODE_CONSTANT,
    ArgumentKind,
    CurrentFile,
    CurrentFolder,
    Installation,
    InstalledPaths,
    SetupCall,
    SetupEntries,
    user_info_edit_change,
)
from refinery.lib.inno.pascal import IFPSException, PSError, signed32, type_mismatch
from refinery.lib.inno.pathfunc import PathFuncError, expand_file_name
from refinery.lib.inno.symbols import parse_function
from refinery.lib.inno.wizard import (
    CheckList,
    CheckOperation,
    Expander,
    PageEvent,
    PageStyle,
    SetupHandler,
    StandIns,
    TEditCharCase,
    TextBox,
    WizardForm,
    WizardPage,
    comma_strings,
    comma_text,
    list_contains,
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

_OUT_OF_STRING_RANGE = 'Out of string range'
_INVALID_FLOAT = 'Invalid float'
_NIL_INVOKE = 'Variant is null, cannot invoke'
_LONGEST_WIDE_STRING = (0x7FFFFFFF - 14) // 2


def _index_error(array: Variable, index: int, dialect: Dialect) -> IFPSException:
    """
    The error of an index outside of an array: Pascal Script names the index and the length from
    Inno Setup 7 on.
    """
    if dialect is Dialect.Inno6:
        return IFPSException(kind=PSError.OutOfRange)
    kind = 'Static array' if array.type.code is TC.StaticArray else 'Array'
    message = F'{kind} index out of bounds ({signed32(index)}). Length is {len(array)}.'
    return IFPSException(message, PSError.CustomError)


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
_StringType = TPrimitive(TC.UnicodeString)


class _DynamicArray(list['Variable']):
    """
    The elements of a dynamic array of Pascal Script. Assignment shares the elements, and the
    number of variables that hold them decides whether a change of the length is made in place.
    """
    __slots__ = 'holders',

    def __init__(self, elements=()):
        super().__init__(elements)
        self.holders = 1


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
            var.data[key] = v

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
        spec: VariableSpec | str | None = None,
        path: tuple[int, ...] = (),
        data: _T | list | None = None
    ):
        super().__init__(type, spec)
        self.path = path
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
                return _DynamicArray()
            if sub_path:
                return Variable(type, spec, (*path, *sub_path))
            elif type.code == TC.Pointer:
                return Variable(_VariantType)
            else:
                return pascal.default(type)

        self.data = default(self.type)

    def resize(self, n: int):
        """
        This function is only valid for container type variables. It re-sizes the data list to
        ensure that the container stores exactly `n` sub-variables, or none if `n` is negative. A
        dynamic array that another variable holds too is copied before its length changes.
        """
        t = self.type
        if t.code != TC.Array:
            if t.code not in (TC.StaticArray, TC.Record):
                raise TypeError
            if n == t.size:
                return
            raise ValueError(F'Attempt to resize {t} of size {t.size} to {n}.')
        if not isinstance(t, TArray) or not isinstance(data := self.data, _DynamicArray):
            raise TypeError
        n = max(n, 0)
        if len(data) == n:
            return
        if data.holders > 1:
            data.holders -= 1
            kept = data[:n]
            self.data = data = _DynamicArray()
            for k, element in enumerate(kept):
                copy = Variable(t.type, self.spec, (*self.path, k))
                copy._copy_from(element)
                data.append(copy)
        del data[n:]
        for k in range(len(data), n):
            data.append(Variable(t.type, self.spec, (*self.path, k)))

    def _share(self, elements: _DynamicArray):
        if not isinstance(data := self.data, _DynamicArray):
            raise TypeError
        if data is elements:
            return
        data.holders -= 1
        elements.holders += 1
        self.data = elements

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
        points to a copy of that target. A dynamic array shares the elements of the dynamic array
        that it is assigned. A value of Python code is converted as
        `refinery.lib.inno.pascal.representation` converts it; the interpreter converts between the
        types of the script.
        """
        if self.pointer:
            return self.deref().set(value)
        assigned = value
        if isinstance(value, Variable):
            source = value.deref()
            if self.container and source.container:
                return self._copy_elements(source)
            if source.type == self.type and not source.container:
                self.data = source.data
                return
            assigned = source.get()
        elif isinstance(value, Value):
            assigned = value.value
        elif isinstance(value, Enum):
            assigned = value.value
        if self.container:
            if not isinstance(assigned, (list, tuple)):
                raise TypeError
            if self.type.code is TC.Array:
                self._share(_DynamicArray())
            self.resize(len(assigned))
            for k, v in enumerate(assigned):
                self.data[k].set(v)
        else:
            self.data = pascal.representation(self.type, assigned)

    def _copy_elements(self, source: Variable):
        if (
            not isinstance(elements := source.data, list)
            or not isinstance(self.data, list)
        ):
            raise TypeError
        if self.type.code is TC.Array:
            if isinstance(elements, _DynamicArray):
                return self._share(elements)
            self._share(_DynamicArray())
        self.resize(len(elements))
        for element, copied in zip(self.data, elements):
            element._copy_from(copied)

    def _copy_from(self, copied: Variable):
        if not self.pointer:
            self.set(copied)
        elif isinstance(target := copied.data, Variable):
            self.setptr(target, copy=target.spec is None)
        else:
            raise type_mismatch()

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


def _variables_held(type: IFPSType) -> int:
    """
    The number of variables that a variable of the given type holds, itself included: a record or
    a static array holds its elements, and a dynamic array holds none until it gets a length.
    """
    if isinstance(type, TStaticArray):
        return 1 + type.size * _variables_held(type.type)
    if isinstance(type, TRecord):
        return 1 + sum(_variables_held(member) for member in type.members)
    return 1


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
    exit_point: int | None = None
    """
    From Inno Setup 7 on, the offset of the return that entered a finally block of this handler.
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
    def __init__(self, dialect: Dialect, caller: _ScriptRun | None = None):
        self.dialect = dialect
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
        the next finally block, or `None` when the function returns. Before Inno Setup 7, Pascal
        Script keeps one return for the run, which any return of a function that a finally block
        calls clears; the end of that block then goes on after its try statement. From Inno Setup 7
        on, each try statement keeps the return that entered its finally block.
        """
        per_handler = self.dialect is Dialect.Inno7
        if not per_handler:
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
            if per_handler:
                eh.exit_point = offset
            return _CallState(function, ip, sp)
        self.exit_point = None
        return None

    def _after(self, eh: ExceptionHandler) -> int:
        exit_point = eh.exit_point if self.dialect is Dialect.Inno7 else self.exit_point
        if exit_point is not None:
            return exit_point
        return eh.handler_end


def _outside_file_entry(name: str, condition: str = '') -> InternalError:
    """
    Setup's error for a function of the current file called outside a function of a file entry
    that meets the given condition.
    """
    return InternalError(
        F'An attempt was made to call the "{name}" function from outside a "Check", '
        F'"BeforeInstall" or "AfterInstall" event function belonging to a "[Files]" entry{condition}'
    )


def _selected(names: list[str] | None, expression: str) -> bool:
    """
    Setup's test of the selected components or tasks in `WizardIsComponentSelected` and
    `WizardIsTaskSelected`: as `ShouldProcessEntry`, it tests no names without a list of them or
    for an empty expression.
    """
    expression = expression.replace('/', '\\')
    if names is None or not expression:
        return True
    return expressions.decide(expression, lambda name: list_contains(names, name))


def _wizard_page(page: object) -> WizardPage:
    """
    The page that the script passes, which the form gave it.
    """
    if not isinstance(page, WizardPage):
        raise TypeError(F'The emulator does not model the wizard page {page!r}.')
    return page


def _incompatible_call(handler: IFPSEmulatedFunction, argc: int, void: bool) -> str:
    def shape(argc: int, void: bool):
        arguments = 'argument' if argc == 1 else 'arguments'
        result = 'no result' if void else 'a result'
        return F'{argc} {arguments} and {result}'
    return F'the emulation takes {shape(handler.argc, handler.void)}, the call passes {shape(argc, void)}'


def _check_agreement(setup: HostSetup, ifps: IFPSFile, config: IFPSEmulatorConfig, source: str):
    """
    Refuses a script that its Setup cannot run: a script of a 64-bit Setup on 32-bit Windows, a
    release that contradicts the Pascal Script that compiled the script, and an installer whose
    platform is not the script's.
    """
    platform = ifps.platform
    if platform is Platform.Win64 and not config.x64:
        raise ValueError('The script runs in a 64-bit Setup, which 32-bit Windows does not run.')
    release = setup.release
    dialect = ifps.dialect
    if not release.is_current and release.since((7, 0, 0)) != (dialect is Dialect.Inno7):
        compiler = 'Inno Setup 7 or later' if dialect is Dialect.Inno7 else 'a version of Inno Setup before 7'
        raise ValueError(F'{source} names Inno Setup {release}, but the script was compiled by {compiler}.')
    if setup.platform is not platform:
        kind = '64-bit' if setup.platform is Platform.Win64 else '32-bit'
        raise ValueError(F'The installer is a {kind} Setup, but its script was compiled for {platform.name}.')


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
    TC.U64           : VType.Int64,
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


def _holds_integer(type: IFPSType) -> bool:
    """
    Whether a variable of the type holds an integer: an integer type, an enumeration, or a set.
    """
    code = type.code
    return code.integer or code is TC.Enum or code is TC.Set


def _split_spans(string: str, separators: list[str], quote: str) -> Iterator[tuple[int, int]]:
    """
    The start and end of each part of a string that Delphi's `string.Split` finds: it splits at the
    first of the separators that starts at the earliest position outside of quotes, and a quote
    character opens a quote that the next one closes.
    """
    alternatives = [re.escape(s) for s in separators if s]
    if len(quote) == 1:
        q = re.escape(quote)
        alternatives.insert(0, F'(?P<quoted>{q}[^{q}]*(?:{q}|\\Z))')
    start = 0
    if alternatives:
        for match in re.finditer('|'.join(alternatives), string):
            if match.lastgroup == 'quoted':
                continue
            yield start, match.start()
            start = match.end()
    yield start, len(string)


def _without_empty_last(spans: Iterable[tuple[int, int]]) -> Iterator[tuple[int, int]]:
    previous = None
    for span in spans:
        if previous is not None:
            yield previous
        previous = span
    if previous is not None and previous[0] < previous[1]:
        yield previous


def _failed_instruction(error: Exception, function: Function, insn: Instruction, clock: int) -> EmulatorException:
    """
    The error that ends an emulation whose instruction failed; a result of Delphi that the model
    does not have ends it as undefined.
    """
    position = F'In {function.symbol} at 0x{insn.offset:X} (cycle {clock})'
    if isinstance(error, Undefined):
        return EmulatorUndefined(F'{position}: {error!s}')
    return EmulatorException(F'{position}, emulation of {insn!r} failed: {error!s}')


def _open_array_element(element: Variable) -> VarRec:
    """
    Converts an element of an `array of const` into the argument that Pascal Script passes for it
    to a function of Delphi. Pascal Script passes a UInt64 as the Int64 of its bits, and an element
    of any other type as the Integer 0.
    """
    target = element.deref()
    if (kind := _OPEN_ARRAY_KINDS.get(target.type.code)) is None:
        return VarRec(VType.Integer, 0)
    value = target.get()
    if kind is VType.Integer:
        value = signed32(value)
    elif kind is VType.Int64:
        value = ((value + 0x8000000000000000) & 0xFFFFFFFFFFFFFFFF) - 0x8000000000000000
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
    max_string_length: int = 0x1000000
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
    setup_version: tuple[int, int, int] | None = None


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


class _Stopwatch:
    """
    The processor time that one emulation spends. It runs only while the emulator works, not while
    the caller handles the events that the emulation yields.
    """
    def __init__(self, limit: float):
        self.limit = limit
        self.spent = 0.0
        self.started = process_time()

    def resume(self):
        self.started = process_time()

    def pause(self):
        self.spent += process_time() - self.started

    def expired(self) -> bool:
        return 0 < self.limit < self.spent + process_time() - self.started


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

        self.config = config = options or IFPSEmulatorConfig(**more)
        if isinstance(archive, InnoArchive):
            self.setup_info = archive.setup_info
            ifps = archive.ifps
            if ifps is None:
                raise ValueError('The input archive does not contain a script.')
            self.setup = HostSetup.of_installer(archive, config)
            source = 'The installer'
        else:
            self.setup_info = None
            ifps = archive
            self.setup = HostSetup.of_bare_script(ifps.platform, config)
            source = 'The configured Setup version'
        _check_agreement(self.setup, ifps, config, source)
        self.machine_folders = machine_folders(self.setup, config)
        self.launch_folder = self.setup.path_func.extract_dir(config.executable)
        self.dialect = ifps.dialect
        self.ifps = ifps
        self._form_variables = [
            (index, name) for index, variable in enumerate(ifps.globals)
            if isinstance(variable.spec, str) and (name := variable.spec.upper()) in _FORM_VARIABLES
        ]
        self._stopwatch: _Stopwatch | None = None
        self._variables_held: dict[int, int] = {}
        self._globals: list[Variable] | None = None
        self.mutexes: set[str] = set()
        self.symbols: dict[str, Function] = CaseInsensitiveDict()
        self.reset()
        for pfn in ifps.functions:
            self.symbols[pfn.name] = pfn

    def __repr__(self):
        return self.__class__.__name__

    def reset(self, walked: bool = False):
        """
        Reset the emulator timing, the state of the Delphi run-time library, and mutexes. The
        script starts over with new global variables that hold their default values, in a new Setup
        process with a new wizard form, which Setup walks through when `walked` is set.
        """
        self.seconds_slept = 0.0
        self.clock = 0
        self.runtime = self.setup.runtime(numbers.FormatSettings.of_locale(self.config.lcid))
        self.machine = pascal.Machine(self.dialect, self.runtime)
        self.mutexes.clear()
        self.wizard_form = wizard = WizardForm(
            StandIns.of(self.config),
            walked=walked,
            entries_known=self.setup_info is not None,
            uninstallable=self.setup.uninstallable.answer is not False,
        )
        self.constants = SetupConstants(self.setup, self.config, wizard, self.machine_folders)
        self.current_folder = CurrentFolder(self.launch_folder)
        self.installed = InstalledPaths(self.current_folder)
        self.current_file: CurrentFile | None = None
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
            for v in self.ifps.globals:
                self._reserve_variables(v.type)
            script_globals = self._globals = [Variable(v.type, v.spec) for v in self.ifps.globals]
        return script_globals

    def _refresh_form_variables(self):
        """
        Sets the variables in which a script of Inno Setup 6 or later finds Setup's forms, as Setup
        does before each call into the script: each is empty until Setup created its form, and
        Setup never shows the form of the uninstaller.
        """
        if not (slots := self._form_variables):
            return
        form = self.wizard_form
        values = {
            'WIZARDFORM': form if form.created else None,
            'MAINFORM': form.main,
            'UNINSTALLPROGRESSFORM': None,
        }
        script_globals = self.globals
        for index, name in slots:
            script_globals[index].set(values[name])

    def _reserve_variables(self, type: IFPSType, count: int = 1):
        """
        Checks before they are built that the given number of variables of the given type, and the
        variables that they hold, stay within the array length limit.
        """
        if (limit := self.config.max_array_length) <= 0:
            return
        if not type.code.container:
            held = 1
        elif (held := self._variables_held.get(id(type))) is None:
            held = self._variables_held[id(type)] = _variables_held(type)
        if limit < (n := count * held):
            raise EmulatorMaxArray(F'Requested {n} variables of type {type}, beyond the limit {limit}.')

    def _reserve_text(self, length: int, wide: bool = True):
        """
        Checks a string of the given length before it is built: Delphi cannot compute the size of
        a UTF-16 string of more than `_LONGEST_WIDE_STRING` characters and raises an integer
        overflow, and a string beyond the configured limit ends the emulation.
        """
        if wide and length > _LONGEST_WIDE_STRING:
            raise pascal.delphi_error(EIntOverflow())
        if 0 < (limit := self.config.max_string_length) < length:
            raise EmulatorMaxString(F'Requested string length {length} exceeds the limit {limit}.')

    def _reserve_results(self, value: Any, arguments: list, result: Variable | None):
        """
        Checks what an emulated function returned before the script receives it: the text of its
        result and of the strings that it wrote into its arguments, and the elements of a list that
        becomes an array.
        """
        if isinstance(value, str):
            self._reserve_text(len(value))
        for var in arguments:
            if isinstance(var, Variable) and isinstance(text := var.deref().data, str):
                self._reserve_text(len(text))
        if (
            result is not None
            and isinstance(value, (list, tuple))
            and isinstance(array := result.deref().type, TArray)
        ):
            self._reserve_variables(array.type, len(value))

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
        return (yield from self._timed(self._execute(_ScriptRun(self.dialect), function, args)))

    def _timed(self, emulation: Generator[Any, Any, _T], max_seconds: float | None = None) -> Generator[Any, Any, _T]:
        """
        Runs one emulation under a time limit: the given number of seconds or else the number in
        the configuration, no limit when it is not positive. Only the time that the emulator works
        counts, and the runs that the emulation nests share the limit. An emulation that starts while
        another one works and is given no limit of its own runs under the limit of that one.
        """
        if max_seconds is None and self._stopwatch is not None:
            return (yield from emulation)
        watch = _Stopwatch(self.config.max_seconds if max_seconds is None else max_seconds)
        try:
            while True:
                outer, self._stopwatch = self._stopwatch, watch
                watch.resume()
                try:
                    event = next(emulation)
                except StopIteration as stop:
                    return stop.value
                finally:
                    watch.pause()
                    self._stopwatch = outer
                yield event
        finally:
            emulation.close()

    def _execute(
        self,
        run: _ScriptRun,
        function: Function,
        args: Sequence,
        types: Sequence[IFPSType] | None = None,
        result_type: IFPSType | None = None,
    ):
        """
        Runs the function with the given values. The caller that creates the variables it passes,
        as Setup does, gives their types and the type of the result for a declaration that does
        not record them.
        """
        decl = function.decl
        if decl is None:
            raise NotImplementedError(F'Do not know how to call {function!s}.')
        self._refresh_form_variables()
        if (n := len(decl.parameters)) != (m := len(args)):
            raise ValueError(
                F'Function {function!s} expects {n} arguments, only {m} were given.')
        stack = run.stack
        for index, (argument, parameter) in enumerate(zip(args, decl.parameters), 1):
            kind = parameter.type
            if kind is None and types is not None:
                kind = types[index - 1]
            variable = Variable(kind, VariableSpec(index, VariableType.Local))
            variable.set(argument)
            stack.append(variable)
        stack.reverse()
        if not decl.void:
            result = Variable(decl.return_type or result_type, VariableSpec(0, VariableType.Argument))
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
                raise _index_error(var, k, dialect)
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

        frames = run.frames
        depth = run.depth
        machine = self.machine
        dialect = machine.dialect
        script_globals = self.globals
        watch = self._stopwatch
        stack = run.stack
        _cfg_max_call_stack = self.config.max_call_stack
        _cfg_max_data_stack = self.config.max_data_stack
        _cfg_max_opcodes = self.config.max_opcodes
        _cfg_log_opcodes = self.config.log_opcodes

        ip: int = 0
        sp: int = len(stack) - 1
        raised: IFPSException | None = None
        failed_call = False
        unwind = False
        jump = False

        while True:
            if raised is not None:
                run.throw(raised)
                failed_call = raised.failed_call
                raised = None
                unwind = True
            if unwind:
                unwind = False
                function, ip, sp = run.unwind()
                if failed_call and run.in_flight.error is None:
                    raised = IFPSException(kind=PSError.CouldNotCallProc)
                    continue
                failed_call = False
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
                    argc = decl.argc + decl.method
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

                if namespace in _FORM_CLASSES and decl is not None and args and args[0].get() is None:
                    kind = PSError.NullPointerException if decl.method else PSError.CouldNotCallProc
                    raised = IFPSException(kind=kind, called=name, failed_call=True)
                elif handler is None:
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
                        self._reserve_results(return_value, args, None if void else stack[-1])
                    except EmulatorException:
                        raise
                    except RecursionError as RE:
                        raise EmulatorMaxCalls(F'Calling {name} exceeded the recursion limit of Python.') from RE
                    except MemoryError as ME:
                        raise EmulatorMemoryError(F'Calling {name} exhausted the memory of Python.') from ME
                    except Undefined as UE:
                        raise EmulatorUndefined(F'Calling {name}: {UE}') from UE
                    except IFPSException as error:
                        raised = IFPSException(error.message, error.kind, name, error.failed_call)
                    except DelphiException as error:
                        raised = IFPSException(self.setup.error_text(error), called=name)
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
                if watch is not None and watch.expired():
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
                        dst = getvar(insn.op(0)).deref()
                        src = insn.op(1)
                        if src.immediate:
                            source = src.value
                            st, sv = source.type, source.value
                        else:
                            source = getvar(src).deref()
                            st, sv = source.type, source.data
                        if dst.container or st.code is TC.Pointer:
                            if not pascal.assignable(dst.type, st, machine):
                                raise type_mismatch()
                            dst.set(source)
                        else:
                            if isinstance(source, Variable) and source.container:
                                sv = source.get()
                            dst.data = pascal.store(dst.type, st, sv, machine)
                    elif opc == Op.Calculate:
                        if not isinstance((aop := insn.operator), AOp):
                            raise TypeError(F'Operator for {opc} was of type {aop.__class__.__name__} rather than AOp.')
                        target = getvar(insn.op(0)).deref()
                        st, sv = gettyped(insn.op(1))
                        result = pascal.calculate(aop, target.type, target.data, st, sv, machine)
                        if isinstance(result, str):
                            self._reserve_text(len(result))
                        elif isinstance(result, Variant) and isinstance(result.value, str):
                            self._reserve_text(len(result.value))
                        target.data = result
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
                        if pascal.truth(*gettyped(insn.op(1))):
                            ip = insn.operands[0]
                    elif opc == Op.JumpFalse:
                        if not pascal.truth(*gettyped(insn.op(1))):
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
                        self._reserve_variables(insn.operands[0])
                        stack.append(Variable(
                            insn.operands[0],
                            VariableSpec(len(stack) - sp, VariableType.Local)
                        ))
                    elif opc == Op.Compare:
                        if not isinstance((cop := insn.operator), COp):
                            raise TypeError(F'Operator for {opc} was of type {cop.__class__.__name__} rather than COp.')
                        lt, lv = gettyped(insn.op(1))
                        rt, rv = gettyped(insn.op(2))
                        truth = pascal.compare(cop, lt, lv, rt, rv, machine)
                        into = getvar(insn.op(0)).deref()
                        into.data = pascal.boolean(into.type, truth, machine)
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
                        var = getvar(insn.op(0)).deref()
                        var.data = pascal.logical_not(var.type, var.data, machine.runtime)
                    elif opc == Op.IntegerNot:
                        var = getvar(insn.op(0)).deref()
                        var.data = pascal.invert(var.type, var.data, machine.runtime)
                    elif opc == Op.Neg:
                        var = getvar(insn.op(0)).deref()
                        var.data = pascal.negate(var.type, var.data, machine.runtime)
                    elif opc == Op.SetFlag:
                        condition, negated = insn.operands
                        jump = pascal.truth(*gettyped(condition)) ^ negated
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
                        counter.data = pascal.step(counter.type, counter.data, True, machine)
                    elif opc == Op.Dec:
                        counter = getvar(insn.op(0)).deref()
                        counter.data = pascal.step(counter.type, counter.data, False, machine)
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
                    raised = copy_exception(EE)
                    break
                except EmulatorException:
                    raise
                except Exception as RE:
                    raise _failed_instruction(RE, function, insn, self.clock) from RE
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
    def TWizardForm__GetPasswordEdit(self, this: object) -> object:
        return self.wizard_form.password_box

    @external()
    def TWizardForm__GetDirEdit(self, this: object) -> object:
        return self.wizard_form.dir_edit

    @external()
    def TWizardForm__GetGroupEdit(self, this: object) -> object:
        return self.wizard_form.group_edit

    @external()
    def TWizardForm__GetUserInfoNameEdit(self, this: object) -> object:
        return self.wizard_form.user_info_name_edit

    @external()
    def TWizardForm__GetUserInfoOrgEdit(self, this: object) -> object:
        return self.wizard_form.user_info_org_edit

    @external()
    def TWizardForm__GetUserInfoSerialEdit(self, this: object) -> object:
        return self.wizard_form.user_info_serial_edit

    @external()
    def TWizardForm__GetPrevAppDir(self, this: object) -> str:
        return ''

    def text_changed(self, box: TextBox) -> Generator[Any, Any, None]:
        """
        Runs the handler of a text box whose text changed, as the box's `OnChange` runs: a function
        of the script, or Setup's own handler. An error reaches the code that changed the text.
        """
        handler = box.on_change
        if isinstance(handler, Function):
            yield from self.call_from_setup(handler, (box,), _NOTIFY_CALL)
        elif handler is SetupHandler.UserInfoEditChange:
            yield from user_info_edit_change(self, box)

    def _box_text(self, this: object) -> str:
        return this.text if isinstance(this, TextBox) else ''

    def _set_box_text(self, this: object, value: str) -> Generator[Any, Any, None]:
        if isinstance(this, TextBox) and this.set_text(value):
            yield from self.text_changed(this)

    def _replace_box_selection(self, this: object, value: str) -> Generator[Any, Any, None]:
        if isinstance(this, TextBox):
            this.replace_selection(value)
            yield from self.text_changed(this)

    @external()
    def TEdit__GetText(self, this: object) -> str:
        return self._box_text(this)

    @external()
    def TCustomEdit__GetText(self, this: object) -> str:
        return self._box_text(this)

    @external()
    def TPasswordEdit__GetText(self, this: object) -> str:
        return self._box_text(this)

    @external()
    def TEdit__SetText(self, this: object, value: str):
        yield from self._set_box_text(this, value)

    @external()
    def TCustomEdit__SetText(self, this: object, value: str):
        yield from self._set_box_text(this, value)

    @external()
    def TPasswordEdit__SetText(self, this: object, value: str):
        yield from self._set_box_text(this, value)
        if value:
            yield NewPassword(value)

    @external()
    def TCustomEdit__Clear(self, this: object):
        if isinstance(this, TextBox):
            this.clear()
            yield from self.text_changed(this)

    @external()
    def TCustomEdit__ClearSelection(self, this: object):
        if isinstance(this, TextBox) and this.clear_selection():
            yield from self.text_changed(this)

    @external()
    def TCustomEdit__GetSelText(self, this: object) -> str:
        return this.selected_text if isinstance(this, TextBox) else ''

    @external()
    def TCustomEdit__SetSelText(self, this: object, value: str):
        yield from self._replace_box_selection(this, value)

    @external()
    def TCustomEdit__SelectAll(self, this: object):
        if isinstance(this, TextBox):
            this.select(0, -1)

    @external()
    def TCustomEdit__GetSelStart(self, this: object) -> int:
        return this.selection_start if isinstance(this, TextBox) else 0

    @external()
    def TCustomEdit__SetSelStart(self, this: object, value: int):
        if isinstance(this, TextBox):
            this.select(value, value)

    @external()
    def TCustomEdit__GetSelLength(self, this: object) -> int:
        return this.selection_length if isinstance(this, TextBox) else 0

    @external()
    def TCustomEdit__SetSelLength(self, this: object, value: int):
        if isinstance(this, TextBox):
            start = this.selection_start
            this.select(start, start + value)

    @external()
    def TEdit__SetCharCase(self, this: object, value: int):
        if isinstance(this, TextBox) and value in _EDIT_CHAR_CASES:
            this.set_case(TEditCharCase(value))

    def _set_box_handler(self, this: object, handler: object):
        if isinstance(this, TextBox):
            this.on_change = handler if isinstance(handler, Function) else None

    @external()
    def TEdit__SetOnChange(self, this: object, handler: object):
        self._set_box_handler(this, handler)

    @external()
    def TPasswordEdit__SetOnChange(self, this: object, handler: object):
        self._set_box_handler(this, handler)

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
    def IsArm32Compatible(self) -> bool:
        return architecture('arm32compatible', self.config.x64)

    @external()
    def IsArm64(self) -> bool:
        return architecture('arm64', self.config.x64)

    @external()
    def IsX64(self) -> bool:
        return architecture('x64', self.config.x64)

    @external()
    def IsX64OS(self) -> bool:
        return architecture('x64os', self.config.x64)

    @external()
    def IsX64Compatible(self) -> bool:
        return architecture('x64compatible', self.config.x64)

    @external()
    def IsX86(self) -> bool:
        return architecture('x86', self.config.x64)

    @external()
    def IsX86OS(self) -> bool:
        return architecture('x86os', self.config.x64)

    @external()
    def IsX86Compatible(self) -> bool:
        return architecture('x86compatible', self.config.x64)

    @external(alias=[
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
        text = string.get()
        if not 1 <= index <= len(text):
            raise IFPSException(
                _OUT_OF_STRING_RANGE,
                PSError.CustomError,
                failed_call=self.dialect is Dialect.Inno6,
            )
        return text[index - 1]

    @external(alias='StrSet')
    def WStrSet(self, char: str, index: int, dst: Variable[str]):
        old = dst.get()
        if not 1 <= index <= len(old):
            raise IFPSException(_OUT_OF_STRING_RANGE, PSError.CustomError)
        dst.set(old[:index - 1] + char + old[index:])

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
        return self.installed.directory_exists(path)

    @external()
    def FileOrDirExists(self, path: str) -> bool:
        return self.installed.exists(path)

    @external()
    def ForceDirectories(self, path: str) -> bool:
        return True

    @external(alias='LoadStringFromLockedFile')
    def LoadStringFromFile(self, path: str, out: Variable[str]) -> bool:
        return True

    @external(alias='LoadStringsFromLockedFile')
    def LoadStringsFromFile(self, path: str, out: Variable[str]) -> bool:
        return True

    def code_runner(self, caller: _ScriptRun | None) -> constants.CodeRunner:
        """
        Runs the function of a code constant inside the run of the caller, or in a new run of the
        script without one.
        """
        def run_code(function: str, argument: str) -> Generator[Any, Any, str]:
            value = yield from self.call_by_name(function, [argument], CODE_CONSTANT, caller)
            return str(value)
        return run_code

    @external(caller=True)
    def ExpandConstant(self, string: str, caller: _ScriptRun | None = None) -> Generator[Any, Any, str]:
        return self.constants.expand(string, self.code_runner(caller))

    @external(caller=True)
    def ExpandConstantEx(
        self,
        string: str,
        custom_var: str,
        custom_val: str,
        caller: _ScriptRun | None = None,
    ) -> Generator[Any, Any, str]:
        return self.constants.expand(string, self.code_runner(caller), {custom_var: custom_val})

    def expand_constant(self, string: str, custom_var: str | None = None, custom_val: str = '') -> str:
        """
        Expands the constants in the given string as Setup expands them, with one optional custom
        constant. A code constant runs a function of the script; its calls are not reported.
        """
        custom = None if custom_var is None else {custom_var: custom_val}
        expansion = EventCall(self._timed(self.constants.expand(string, self.code_runner(None), custom)))
        value = expansion.value
        assert value is not None
        return value

    @external()
    def DeleteFile(self, path: str) -> bool:
        self.installed.remove(path)
        return True

    @external()
    def FileExists(self, file_name: str) -> bool:
        return self.installed.file_exists(file_name)

    @external()
    def Log(self, log: str):
        ...

    @external()
    def Inc(self, p: Variable[int]):
        if not p.deref().type.code.integer:
            raise IFPSException(kind=PSError.CouldNotCallProc)
        p.set(p.get() + 1)

    @external()
    def Dec(self, p: Variable[int]):
        if not p.deref().type.code.integer:
            raise IFPSException(kind=PSError.CouldNotCallProc)
        p.set(p.get() - 1)

    @external()
    def FindFirst(self, file_name: str, frec: Variable) -> bool:
        return False

    @external()
    def Round(self, x: x87.Real) -> int:
        if self.setup.release.since((6, 6, 0)):
            return self.runtime.fpu.integer(x, x87.Rounding.Nearest)
        return self.runtime.fpu.integer(x)

    @external()
    def Trunc(self, x: x87.Real) -> int:
        return self.runtime.fpu.integer(x, x87.Rounding.TowardZero)

    @external()
    def Int(self, x: x87.Real) -> x87.Real:
        return self.runtime.fpu.round_integral(x, x87.Rounding.TowardZero)

    @external()
    def Abs(self, x: x87.Real) -> x87.Real:
        return self.runtime.fpu.absolute(x)

    @external()
    def Pi(self) -> x87.Real:
        return self.runtime.fpu.pi()

    @external()
    def Sqrt(self, x: x87.Real) -> x87.Real:
        return self.runtime.fpu.square_root(x)

    @external()
    def Sin(self, x: x87.Real) -> x87.Real:
        return self.runtime.fpu.sine(x)

    @external()
    def Cos(self, x: x87.Real) -> x87.Real:
        return self.runtime.fpu.cosine(x)

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
        return self.setup.language_name

    @external()
    def CustomMessage(self, msg_name: str) -> str:
        if (message := self.setup.custom_message(msg_name)) is None:
            raise InternalError(F'Unknown custom message name "{msg_name}"')
        return message

    @external()
    def FmtMessage(self, fmt: str, args: list[str]) -> str:
        return constants.fmt_message(fmt, args)

    @external()
    def Format(self, fmt: str, args: Variable[list]) -> str:
        elements = args.deref()
        arguments = [_open_array_element(elements.at(k)) for k in range(len(elements))]
        return formatting.format(fmt, arguments, self.runtime, self._reserve_text)

    @external()
    def SetupMessage(self, id: int) -> str:
        return self.setup.message(id)

    @external()
    def IsWin64(self) -> bool:
        return self.config.x64

    @external()
    def Is64BitInstallMode(self) -> bool:
        return self.setup.install_mode.decided()

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
        return processor(self.config.x64).value

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
        array = array.deref()
        if isinstance(t := array.type, TArray):
            self._reserve_variables(t.type, n)
        array.resize(n)

    @external()
    def WizardForm(self) -> object:
        return self._form()

    @external()
    def MainForm(self) -> object:
        """
        The function of Inno Setup 5 that gives Setup's main form; before Setup created the form,
        it raises an internal error.
        """
        if (main := self.wizard_form.main) is None:
            raise InternalError('An attempt was made to access MainForm before it has been created')
        return main

    def _form(self) -> WizardForm:
        """
        The wizard form, for a function that Setup runs through `GetWizardForm`.
        """
        form = self.wizard_form
        form.require()
        return form

    @external()
    def CreateCustomPage(self, after: int, caption: str, description: str) -> object:
        return self._form().add_page(after)

    @external()
    def CreateInputQueryPage(self, after: int, caption: str, description: str, subcaption: str) -> object:
        return self._form().add_page(after)

    @external()
    def CreateInputOptionPage(
        self,
        after: int,
        caption: str,
        description: str,
        subcaption: str,
        exclusive: bool,
        listbox: bool,
    ) -> object:
        return self._form().add_page(after)

    @external()
    def CreateInputDirPage(
        self,
        after: int,
        caption: str,
        description: str,
        subcaption: str,
        append: bool,
        folder: str,
    ) -> object:
        return self._form().add_page(after)

    @external()
    def CreateInputFilePage(self, after: int, caption: str, description: str, subcaption: str) -> object:
        return self._form().add_page(after)

    @external()
    def CreateOutputMsgPage(self, after: int, caption: str, description: str, message: str) -> object:
        return self._form().add_page(after)

    @external()
    def CreateOutputMsgMemoPage(
        self,
        after: int,
        caption: str,
        description: str,
        subcaption: str,
        message: str,
    ) -> object:
        return self._form().add_page(after)

    @external(alias='CreateOutputMarqueeProgressPage')
    def CreateOutputProgressPage(self, caption: str, description: str) -> object:
        return self._form().add_page(-1, PageStyle.AlwaysSkip | PageStyle.NoButtons)

    @external(alias='CreateExtractionPage')
    def CreateDownloadPage(self, caption: str, description: str, progress: object) -> object:
        return self._form().add_page(-1, PageStyle.AlwaysSkip | PageStyle.NoButtons)

    @external()
    def TWizardPage__GetID(self, this: object) -> int:
        return _wizard_page(this).id

    @external()
    def Class__SetNil(self, value: object) -> object:
        """
        Pascal Script's assignment of nil to a variable of a class.
        """
        return None

    @external()
    def Class__CastToType(self, source: object) -> object:
        """
        A cast of an object to a class; the emulator's objects do not record the classes that the
        script knows, and the cast keeps the object.
        """
        return source

    @external()
    def GetWizardForm(self) -> object:
        return self._form()

    @external()
    def PageFromID(self, id: int) -> object:
        return self._form().page(id)

    @external()
    def PageIndexFromID(self, id: int) -> int:
        return self._form().page_index(id)

    @external()
    def WizardDirValue(self) -> str:
        return self.setup.path_func.remove_backslash_unless_root(self._form().dir_edit.text)

    @external()
    def WizardGroupValue(self) -> str:
        return self.setup.path_func.remove_backslash_unless_root(self._form().group_edit.text)

    @external()
    def IsAdminInstallMode(self) -> bool:
        return self.setup.admin_install_mode

    @external(caller=True)
    def GetPreviousData(self, name: str, default: str, caller: _ScriptRun | None = None) -> Generator[Any, Any, str]:
        app_id = '' if (info := self.setup_info) is None else info.Header.text(TextDirective.AppId) or ''
        yield from self.constants.expand(app_id, self.code_runner(caller))
        return default

    @external()
    def TWizardForm__GetCurPageID(self, this: object) -> int:
        return self.wizard_form.current

    def _set_page_handler(self, this: object, event: PageEvent, handler: object):
        page = _wizard_page(this)
        if isinstance(handler, Function):
            page.handlers[event] = handler
        else:
            page.handlers.pop(event, None)

    @external()
    def TWizardPage__SetOnActivate(self, this: object, handler: object):
        self._set_page_handler(this, PageEvent.OnActivate, handler)

    @external()
    def TWizardPage__SetOnShouldSkipPage(self, this: object, handler: object):
        self._set_page_handler(this, PageEvent.OnShouldSkipPage, handler)

    @external()
    def TWizardPage__SetOnNextButtonClick(self, this: object, handler: object):
        self._set_page_handler(this, PageEvent.OnNextButtonClick, handler)

    @external()
    def TWizardPage__SetOnBackButtonClick(self, this: object, handler: object):
        self._set_page_handler(this, PageEvent.OnBackButtonClick, handler)

    @external()
    def TWizardPage__SetOnCancelButtonClick(self, this: object, handler: object):
        self._set_page_handler(this, PageEvent.OnCancelButtonClick, handler)

    @external()
    def Unassigned(self) -> Variant:
        return variants.EMPTY

    @external()
    def Null(self) -> Variant:
        return variants.NULL

    @external()
    def VarType(self, v: Variant) -> int:
        return v.type

    @external()
    def VarIsNull(self, v: Variant) -> bool:
        return v.type == VarType.Null

    @external()
    def VarIsEmpty(self, v: Variant) -> bool:
        return v.type == VarType.Empty

    @external()
    def VarIsClear(self, v: Variant) -> bool:
        return v.type == VarType.Empty or v.type in (VarType.Dispatch, VarType.Unknown) and v.value is None

    @external()
    def Set8087CW(self, cw: int):
        self.runtime.control_word = cw & 0xFFFF

    @external()
    def Get8087CW(self) -> int:
        return self.runtime.control_word | x87.RESERVED_BIT

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

    @external(alias='Replicate')
    def StringOfChar(self, c: str, count: int) -> str:
        self._reserve_text(count, wide=False)
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
        self._reserve_text(len(haystack) + count * (len(new) - len(old)))
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
        return strings.trim(string)

    @external()
    def TrimLeft(self, string: str) -> str:
        return strings.trim_left(string)

    @external()
    def TrimRight(self, string: str) -> str:
        return strings.trim_right(string)

    @external()
    def StringJoin(self, sep: str, values: list[str]) -> str:
        self._reserve_text(sum(map(len, values)) + len(sep) * max(len(values) - 1, 0))
        return sep.join(values)

    @external()
    def StringSplitEx(self, string: str, separators: list[str], quote: str, how: TSplitType) -> list[str]:
        def spans():
            found = _split_spans(string, separators, quote)
            if how == TSplitType.stExcludeEmpty:
                return (span for span in found if span[0] < span[1])
            if how == TSplitType.stExcludeLastEmpty:
                return _without_empty_last(found)
            return found
        self._reserve_variables(_StringType, sum(1 for _ in spans()))
        return [string[start:end] for start, end in spans()]

    @external()
    def StringSplit(self, string: str, separators: list[str], how: TSplitType) -> list[str]:
        return self.StringSplitEx(string, separators, '', how)

    @external()
    def StrToInt(self, s: str) -> int:
        value, error = numbers.val_integer(s, 32)
        return -1 if error else value

    @external()
    def StrToIntDef(self, s: str, d: int) -> int:
        value, error = numbers.val_integer(s, 32)
        return d if error else value

    @external()
    def StrToInt64(self, s: str) -> int:
        return numbers.str_to_int64(s)

    @external()
    def StrToInt64Def(self, s: str, d: int) -> int:
        return numbers.str_to_int64_default(s, d)

    @external()
    def StrToFloat(self, s: str) -> x87.Real:
        runtime = self.runtime
        value, error = numbers.val_float(s, runtime.library)
        if error or value is None:
            raise IFPSException(_INVALID_FLOAT)
        return runtime.fpu.store(value, x87.Format.Extended)

    @external()
    def FloatToStr(self, e: x87.Real) -> str:
        if self.dialect is Dialect.Inno6:
            return numbers.str_fixed(e, 12, self.runtime.library)
        return numbers.float_to_str(e, self.runtime)

    @external()
    def StrToUInt64(self, s: str) -> int:
        return numbers.str_to_uint64(s)

    @external()
    def StrToUInt64Def(self, s: str, d: int) -> int:
        return numbers.str_to_uint64_default(s, d)

    @external(alias='UInt64ToStr')
    def UIntToStr(self, i: int) -> str:
        return str(i & 0xFFFFFFFFFFFFFFFF)

    @external(alias='Int64ToStr')
    def IntToStr(self, i: int) -> str:
        return str(i)

    @external()
    def PadL(self, s: str, n: int) -> str:
        self._reserve_text(n)
        return s.rjust(n)

    @external()
    def PadR(self, s: str, n: int) -> str:
        self._reserve_text(n)
        return s.ljust(n)

    @external()
    def PadZ(self, s: str, n: int) -> str:
        self._reserve_text(n)
        return s.rjust(n, '0')

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
        return self.setup.path_func.add_backslash(string)

    @external()
    def AddPeriod(self, string: str) -> str:
        if string and string[~0] != '.':
            string = F'{string}.'
        return string

    @external()
    def RemoveBackslashUnlessRoot(self, string: str) -> str:
        return self.setup.path_func.remove_backslash_unless_root(string)

    @external()
    def RemoveBackslash(self, string: str) -> str:
        return self.setup.path_func.remove_backslash(string)

    @external()
    def ChangeFileExt(self, name: str, ext: str) -> str:
        return self.setup.path_func.change_ext(name, ext)

    @external()
    def ExtractFileExt(self, name: str) -> str:
        return self.setup.path_func.extract_ext(name)

    @external()
    def ExtractFileDir(self, name: str) -> str:
        return self.setup.path_func.extract_dir(name)

    @external()
    def ExtractFilePath(self, name: str) -> str:
        return self.setup.path_func.extract_path(name)

    @external()
    def ExtractFileName(self, name: str) -> str:
        return self.setup.path_func.extract_name(name)

    @external()
    def ExtractFileDrive(self, name: str) -> str:
        return self.setup.path_func.extract_drive(name)

    @external()
    def ExtractRelativePath(self, base: str, dst: str) -> str:
        return self.setup.path_func.extract_relative_path(base, dst)

    @external()
    def ExpandFileName(self, name: str) -> str:
        try:
            return self.setup.path_func.expand(name, self.current_folder.path)
        except PathFuncError as error:
            raise DelphiException(str(error)) from error

    @external()
    def ExpandUNCFileName(self, name: str) -> str:
        return expand_file_name(name, self.current_folder.path)

    @external()
    def GetCurrentDir(self) -> str:
        return self.current_folder.path

    @external()
    def SetLength(self, target: Variable, size: int):
        target = target.deref()
        if target.container:
            self.SetArrayLength(target, size)
            return
        size = max(size, 0)
        self._reserve_text(size, wide=target.type.code not in (TC.AnsiString, TC.PChar))
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
    def IDispatchInvoke(self, ole: OleObject | None, prop_set: bool, name: str, value: Any) -> Variant:
        if ole is None:
            raise IFPSException(_NIL_INVOKE)
        return variants.EMPTY

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
    def WizardNoIcons(self) -> bool:
        return self._form().icons_off

    @external()
    def WizardSetupType(self, descriptions: bool) -> str:
        form = self._form()
        if (setup_type := form.setup_type) is None:
            return ''
        return form.type_description(setup_type) if descriptions else setup_type.Name

    def _field_expander(self, caller: _ScriptRun | None) -> Expander:
        """
        Expands the fields of the entries in the lists of the wizard for a support function that the
        script calls: a code constant runs inside the run of the caller, as in `ExpandConstant`.
        """
        def expand(entry: object, field: EntryField, text: str) -> Generator[Any, Any, str]:
            return self.constants.expand(text, self.code_runner(caller))
        return expand

    @external(caller=True)
    def WizardSelectedComponents(self, descriptions: bool, caller: _ScriptRun | None = None) -> Generator[Any, Any, str]:
        expand = self._field_expander(caller)
        return comma_text((yield from self._form().selected_components(descriptions, False, expand)))

    @external(caller=True)
    def WizardSelectedTasks(self, descriptions: bool, caller: _ScriptRun | None = None) -> Generator[Any, Any, str]:
        expand = self._field_expander(caller)
        return comma_text((yield from self._form().selected_tasks(descriptions, False, False, expand)))

    @external(alias=['IsComponentSelected'])
    def WizardIsComponentSelected(self, components: str) -> bool:
        return _selected(self._form().selection().components, components)

    @external(alias=['IsTaskSelected'])
    def WizardIsTaskSelected(self, tasks: str) -> bool:
        return _selected(self._form().selection().tasks, tasks)

    @external()
    def WizardSelectComponents(self, components: str):
        self._form().select_components(comma_strings(components.replace('/', '\\')))

    @external()
    def WizardSelectTasks(self, tasks: str):
        self._form().select_tasks(comma_strings(tasks.replace('/', '\\')))

    @external()
    def TWizardForm__GetComponentsList(self, this: object) -> object:
        return self.wizard_form.components

    @external()
    def TWizardForm__GetTasksList(self, this: object) -> object:
        return self.wizard_form.tasks

    @external()
    def TWizardForm__GetRunList(self, this: object) -> object:
        return self.wizard_form.run_list

    @external()
    def TWizardForm__GetTypesCombo(self, this: object) -> object:
        return self.wizard_form.types_combo

    @external()
    def TWizardForm__GetNoIconsCheck(self, this: object) -> object:
        return self.wizard_form.no_icons_check

    @external()
    def TNewCheckListBox__GetChecked(self, this: object, index: int) -> bool:
        if isinstance(this, CheckList):
            return this.checked(index)
        return True

    @external()
    def TNewCheckListBox__SetChecked(self, this: object, index: int, checked: bool):
        if isinstance(this, CheckList):
            this.set_checked(index, checked)

    @external()
    def TNewCheckListBox__GetState(self, this: object, index: int) -> int:
        if isinstance(this, CheckList):
            return this.state(index)
        return 1

    @external()
    def TNewCheckListBox__GetItemEnabled(self, this: object, index: int) -> bool:
        if isinstance(this, CheckList):
            return this.enabled(index)
        return True

    @external()
    def TNewCheckListBox__CheckItem(self, this: object, index: int, operation: int) -> bool:
        if isinstance(this, CheckList):
            return this.check(index, CheckOperation(operation))
        return True

    @external()
    def CurrentFilename(self) -> str:
        if (file := self.current_file) is None or not file.destination:
            raise _outside_file_entry('CurrentFilename')
        return file.destination

    @external()
    def CurrentSourceFilename(self) -> str:
        if (file := self.current_file) is None or not file.source:
            raise _outside_file_entry('CurrentSourceFilename', ' with flag "external"')
        return file.source

    def expand(self, text: str, custom: Mapping[str, str] | None = None) -> Generator[Any, Any, str]:
        """
        Expands the constants in a text of the setup where Setup expands it, with the custom
        constants that Setup passes for it; each code constant runs in a new run of the script.
        """
        return self.constants.expand(text, self.code_runner(None), custom)

    def registry_key_exists(self, key: str) -> bool:
        """
        Whether a key of the emulated registry exists.
        """
        return self.constants.registry('', None, key)

    @property
    def temporary_directory(self) -> str:
        """
        The temporary directory of Setup, the value of `{tmp}`.
        """
        return self.constants.temporary_directory

    def check_time(self):
        """
        Ends the emulation when its time is up.
        """
        if (watch := self._stopwatch) is not None and watch.expired():
            raise EmulatorTimeout

    def _setup_codes(self) -> dict[ArgumentKind, TC]:
        """
        The type codes of the variables that Setup creates for the values that it passes to the
        functions of the script and for the results that it takes from them.
        """
        return {
            ArgumentKind.String  : TC.UnicodeString if self.ifps.unicode else TC.AnsiString,
            ArgumentKind.Integer : TC.S32,
            ArgumentKind.Boolean : TC.U08,
            ArgumentKind.Step    : TC.U08,
            ArgumentKind.Page    : TC.Class,
            ArgumentKind.Object  : TC.Class,
        }

    def _fits(self, function: Function, call: SetupCall) -> bool:
        """
        Whether the declaration of a function of the script takes the call that Setup makes: the
        same number of parameters, each passed the same way and of the type that Setup passes, and
        a result of the type that Setup takes. A parameter or a result whose type the script does
        not record is taken to fit, as Pascal Script records none for a support function that Inno
        Setup does not document, such as `UsingWinNT`.
        """
        if (decl := function.decl) is None or len(decl.parameters) != len(call.parameters):
            return False
        codes = self._setup_codes()
        for parameter, (kind, by_value) in zip(decl.parameters, call.parameters):
            if parameter.const != by_value:
                return False
            if parameter.type is not None and parameter.type.code != codes[kind]:
                return False
        if call.result is None:
            return decl.void
        if decl.void:
            return False
        return (result := decl.return_type) is None or result.code == codes[call.result]

    def call_from_setup(
        self,
        function: Function,
        arguments: Sequence,
        call: SetupCall,
        caller: _ScriptRun | None = None,
    ) -> Generator[Any, Any, Any]:
        """
        Calls a function of the script as Setup does: Pascal Script runs a function whose
        declaration does not take the call on a stack that does not fit it, and the emulation ends
        there. Setup creates the variables of the values that it passes and of the result that it
        takes.
        """
        if not self._fits(function, call):
            raise EmulatorUndefined(F'Setup calls {function.name} as {call}, which its declaration does not take.')
        codes = self._setup_codes()
        types = [TPrimitive(codes[kind]) for kind, _ in call.parameters]
        result = None if call.result is None else TPrimitive(codes[call.result])
        run = _ScriptRun(self.dialect, caller)
        return (yield from self._execute(run, function, arguments, types, result))

    def call_by_name(
        self,
        name: str,
        arguments: list,
        call: SetupCall,
        caller: _ScriptRun | None = None,
    ) -> Generator[Any, Any, Any]:
        """
        Calls a function of the script by name as Setup's `CodeRunner` finds it: a function of the
        script or a support function that the script imports.
        """
        if (function := self.symbols.get(name)) is None:
            raise DelphiException('Script error: Could not call proc')
        return (yield from self.call_from_setup(function, arguments, call, caller))

    @external()
    def Low(self, var: Variable) -> int:
        return self._bound(var.deref(), False)

    @external()
    def High(self, var: Variable) -> int:
        return self._bound(var.deref(), True)

    def _bound(self, var: Variable, high: bool) -> int:
        t = var.type
        code = t.code
        if code is TC.Array:
            return len(var) - 1 if high else 0
        if isinstance(t, TStaticArray):
            start = t.offset or 0
            return start + t.size - 1 if high else start
        if code is TC.AnsiString:
            return len(var.get()) if high else 1
        if (valid := code.integer_range) is not None:
            return valid.stop - 1 if high else valid.start
        raise IFPSException(kind=PSError.CouldNotCallProc)

    @external()
    def SizeOf(self, var: Variable) -> int:
        return pascal.size_of(var.type, self.runtime)

    del external


_FORM_CLASSES = frozenset({
    'TWizardForm',
    'TMainForm',
    'TUninstallProgressForm',
})
"""
The classes of Setup's forms, which the emulator holds itself: a member of one called on an empty
variable fails as Pascal Script fails it, twice, so that the innermost except block does not end
the error.
"""

_FORM_VARIABLES = frozenset({
    'WIZARDFORM',
    'MAINFORM',
    'UNINSTALLPROGRESSFORM',
})
"""
The global variables of a script of Inno Setup 6 or later that hold Setup's forms.
"""

_NOTIFY_CALL = SetupCall.of(parse_function('procedure OnChange(Sender: TObject)'))

_EDIT_CHAR_CASES = frozenset(TEditCharCase)

_LAYOUT_CLASSES = frozenset({
    'TObject',
    'TPersistent',
    'TComponent',
    'TControl',
    'TWinControl',
    'TCustomControl',
    'TGraphicControl',
})
"""
The classes whose members every control of the wizard has, such as its position and visibility.
"""

_APPEARANCE = frozenset({
    'anchors',
    'borderstyle',
    'color',
    'ctl3d',
    'cursor',
    'flat',
    'font',
    'hint',
    'itemcaption',
    'itemfontstyle',
    'itemlevel',
    'itemsubitem',
    'minitemheight',
    'offset',
    'parentcolor',
    'parentfont',
    'showhint',
    'showlines',
    'subitemfontstyle',
    'taborder',
    'tabstop',
    'wanttabs',
})
"""
The properties of the lists, combo boxes and check boxes of the wizard that only change how they
look.
"""


def _changes_choices(function: Function) -> bool:
    """
    Whether a member of a control of the wizard that the emulator does not model may change the
    choices that the control holds: any member but those of every control, those that only change
    how it looks, and the casts of Pascal Script, whose class is `Class`.
    """
    classname = function.decl.classname if function.decl is not None else None
    name = function.name
    if not classname:
        classname, dot, name = name.partition('.')
        if not dot:
            return False
    if classname == 'Class' or classname in _LAYOUT_CLASSES:
        return False
    if name[:3].lower() in ('get', 'set') and name[3:].lower() in _APPEARANCE:
        return False
    return True


class InnoSetupEmulator(IFPSEmulator):
    """
    A specialized `IFPSEmulator` that can emulate the InnoSetup installation with a focus on
    continuing execution as much as possible.
    """

    def __init__(
        self,
        archive: InnoArchive | IFPSFile,
        options: IFPSEmulatorConfig | None = None,
        **more,
    ):
        super().__init__(archive, options, **more)
        cfg = self.config
        self.entries: SetupEntries | None = None
        if (info := self.setup_info) is not None:
            self.entries = SetupEntries.of(info, cfg.windows_os_version, cfg.windows_sp_version)

    def emulate_installation(
        self,
        password: str = '',
        max_seconds: float | None = None,
        password_test: Callable[[str], bool] | None = None,
    ):
        """
        Emulates the calls into the script that Setup makes during an installation in which the user
        clicks Next on every page until Setup finishes; a silent installation when the configuration
        says so. Each installation starts the script over. The given password is typed into the box
        on the password page. An event or entry that ends with a script error is reported as a
        `refinery.lib.inno.emulation.NewScriptError` and the installation goes on, as described
        for `refinery.lib.inno.installation.Installation`. Any other exception ends the emulation.
        A call of an emulated function that fails is reported as a
        `refinery.lib.inno.emulation.NewEmulationError`, also when the script handles its error.
        The time limit counts for the whole installation; the given number of seconds replaces the
        one of the configuration. Setup tests a password against its own before it asks the
        script; the caller can give that test as `password_test`, without it the test fails.
        """
        self.reset(walked=True)
        self.wizard_form.needs_restart = self.setup.always_restart
        installation = Installation(self, self.entries, password, password_test)
        return (yield from self._timed(installation.run(), max_seconds))

    def unimplemented(self, function: Function, arguments: list[Variable], result: Variable | None):
        """
        Any unimplemented function is essentially skipped. Any arguments passed by reference and
        all return values that are of type integer are set to `1` in an attempt to indicate success
        wherever possible. When the function is a member of a control of the wizard that holds
        choices of the installation, called on that control, the emulator no longer knows those
        choices, unless the member belongs to every control, such as its position, or only changes
        how the control looks.
        """
        if arguments and _changes_choices(function):
            self.wizard_form.touched(arguments[0].deref().data)
        if result is not None and not result.container and _holds_integer(result.type):
            result.set(1)
        for ptr in arguments:
            if not ptr.pointer:
                continue
            var = ptr.deref()
            if not var.container and _holds_integer(var.type):
                var.set(1)
