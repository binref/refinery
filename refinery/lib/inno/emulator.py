#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
An emulator for Inno Setup executables.
"""
from __future__ import annotations

from typing import (
    get_origin,
    Callable,
    ClassVar,
    Dict,
    Generic,
    List,
    NamedTuple,
    Optional,
    Sequence,
    TypeVar,
    Union,
)

from dataclasses import dataclass, field
from time import process_time
from enum import auto, Enum

from refinery.lib.types import CaseInsensitiveDict
from refinery.lib.inno.archive import InnoArchive
from refinery.lib.types import AST, INF, NoMask
from refinery.lib.patterns import formats

from refinery.lib.inno.ifps import (
    AOp,
    COp,
    EHType,
    Function,
    IFPSFile,
    IFPSType,
    Op,
    Operand,
    OperandType,
    TArray,
    TC,
    TRecord,
    TStaticArray,
    Value,
    VariableBase,
    Variant,
    VariantType,
)

import operator
import inspect
import re
import struct


_T = TypeVar('_T')


class InvalidIndex(TypeError):
    def __init__(self, v: Variable, key):
        super().__init__(F'Assigning to {v.spec}[{key!r}]; type {v.type} does not support indexing.')


class NullPointer(RuntimeError):
    def __init__(self, v: Variable):
        super().__init__(F'Trying to access uninitialized pointer value {v.spec}.')


class OleObject:
    def __init__(self, name):
        self.name = name


class Variable(VariableBase, Generic[_T]):
    type: IFPSType
    spec: Optional[Variant]
    data: Optional[Union[List[Variable[_T]], _T]]
    path: tuple[int]

    @property
    def container(self):
        return self.type.container

    @property
    def pointer(self):
        return self.type.code == TC.Pointer

    def __len__(self):
        return len(self.data)

    def __bool__(self):
        return True

    def __getitem__(self, key: int):
        return self.get(key)

    def __setitem__(self, key: int, v: _T):
        self.set(v, key)

    def __index__(self):
        data = self.data
        if isinstance(data, str) and len(data) == 1:
            data = ord(data)
        return data

    def at(self, k: int):
        return self.deref().data[k]

    def deref(var):
        while True:
            val = var.data
            if not isinstance(val, Variable):
                return var
            var = val

    def __init__(
        self,
        type: IFPSType,
        spec: Optional[Variant] = None,
        path: tuple[int] = (),
        data: Optional[Union[_T, List[_T]]] = None
    ):
        super().__init__(type, spec)
        self.path = path

        self._int_size = _size = {
            TC.U08: +1,
            TC.U16: +1,
            TC.U32: +1,
            TC.S08: -1,
            TC.S16: -1,
            TC.S32: -1,
            TC.S64: -1,
        }.get((code := type.code), 0) * code.width
        if _size:
            bits = abs(_size) * 8
            umax = (1 << bits)
            self._int_bits = bits
            self._int_mask = umax - 1
            if _size < 0:
                self._int_good = range(-(umax >> 1), (umax >> 1))
            else:
                self._int_good = range(umax)
        else:
            self._int_mask = NoMask
            self._int_bits = INF
            self._int_good = AST

        if data is None:
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
                else:
                    return type.default()
            self.data = default(type)
        else:
            self.set(data)

    def _wrap(self, value: Union[Value, _T], key: Optional[int] = None) -> _T:
        if (t := self.type.py_type(key)) and not isinstance(value, t):
            if issubclass(t, int):
                if isinstance(value, str) and len(value) == 1:
                    return ord(value[0])
                if isinstance(value, float):
                    return int(value)
            elif isinstance(value, int):
                if issubclass(t, str):
                    return chr(value)
                if issubclass(t, float):
                    return float(value)
            raise TypeError(F'Assigning value {value!r} to variable of type {self.type}.')
        if s := self._int_size and value not in self._int_good:
            mask = self._int_mask
            value &= mask
            if s < 0 and (value >> (self._int_bits - 1)):
                value = -(-value & mask)
        return value

    def resize(self, n: int):
        t = self.type
        m = n - len(self.data)
        if t.code != TC.Array:
            if t.code not in (TC.StaticArray, TC.Record):
                raise TypeError
            if n == t.size:
                return
            raise ValueError(F'Attempt to resize {t} of size {t.size} to {n}.')
        if m <= 0:
            del self.data[n:]
            return
        for k in range(m):
            self.data.append(Variable(t.type, self.spec, (*self.path, k)))

    def setptr(self, var: Variable, copy: bool = False):
        if not self.pointer:
            raise TypeError
        if not isinstance(var, Variable):
            raise TypeError
        if copy:
            var = Variable(var.type, data=var.get())
        self.data = var

    def set(
        self,
        value: Union[_T, Sequence[_T]],
        key: Optional[int] = None,
    ) -> None:
        if isinstance(value, (Enum, Value)):
            value = value.value
        if self.pointer:
            ptr: Variable = self.data
            if ptr is None:
                raise NullPointer(self)
            return ptr.set(value, key)
        elif self.container:
            if key is None:
                if not isinstance(value, (list, tuple)):
                    raise TypeError
                self.resize(len(value))
                for k, v in enumerate(value):
                    self.data[k].set(v)
            elif not isinstance(key, int):
                raise TypeError(key)
            else:
                self.data[key].set(value)
        elif key is not None:
            if self.type.code == TC.Set:
                if not isinstance(key, int):
                    raise TypeError(key)
                if not isinstance(value, bool):
                    raise TypeError(value)
                if key not in range(self.type.size):
                    raise IndexError
                if value is True:
                    self.data |= 1 << key
                elif self.data >> key & 1:
                    self.data ^= 1 << key
            else:
                raise InvalidIndex(self, key)
        else:
            self.data = self._wrap(value)

    def get(self, key: Optional[int] = None) -> Union[_T, List[_T]]:
        if self.pointer:
            ptr: Variable = self.data
            if ptr is None:
                raise NullPointer(self)
            return ptr.get(key)
        elif self.container:
            data: List[Variable[_T]] = self.data
            if key is None:
                return [v.get() for v in data]
            if not isinstance(key, int):
                raise TypeError(key)
            return data[key].get()
        elif key is None:
            return self.data
        try:
            return self.data[key]
        except Exception as E:
            raise InvalidIndex(self, key) from E

    @property
    def name(self):
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
    pass


class OpCodeNotImplemented(NotImplementedError):
    pass


class EmulatorException(RuntimeError):
    pass


class AbortEmulation(Exception):
    pass


class IFPSException(RuntimeError):
    pass


class EmulatorTimeout(TimeoutError):
    pass


class EmulatorExecutionLimit(TimeoutError):
    pass


class EmulatorMaxStack(MemoryError):
    pass


class EmulatorMaxCalls(MemoryError):
    pass


class IFPS_NotAnArray(RuntimeError):
    def __init__(self, v: Variable):
        super().__init__(F'Attempting an array operation on non-array variable {v}.')


@dataclass
class ExceptionHandler:
    finally_one: Optional[int]
    catch_error: Optional[int]
    finally_two: Optional[int]
    handler_end: int
    current: EHType = EHType.Try


class IFPSEmulatedFunction(NamedTuple):
    call: Callable
    spec: List[bool]
    static: bool
    void: bool = False

    @property
    def argc(self):
        return len(self.spec)


@dataclass
class IFPSEmulatorConfig:
    x64: bool = True
    windows_os_version: tuple[int, int, int] = (10, 0, 10240)
    windows_sp_version: tuple[int, int] = (2, 0)
    throw_abort: bool = False
    trace_calls: bool = False
    log_passwords: bool = True
    max_opcodes: int = 0
    max_seconds: int = 60
    max_data_stack: int = 1_000_000
    max_call_stack: int = 4096
    environment: dict[str, str] = field(default_factory=dict)
    user_name: str = '%USERNAME%'
    host_name: str = '%COMPUTERNAME%'
    lcid: int = 0x0409


class TSetupStep(int, Enum):
    ssPreInstall = 0
    ssInstall = auto()
    ssPostInstall = auto()
    ssDone = auto()


class TUninstallStep(int, Enum):
    usAppMutexCheck = 0
    usUninstall = auto()
    usPostUninstall = auto()
    usDone = auto()


class TSetupProcessorArchitecture(int, Enum):
    paUnknown = 0
    paX86 = auto()
    paX64 = auto()
    paArm32 = auto()
    paArm64 = auto()


class PageID(int, Enum):
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


class IFPSCall(NamedTuple):
    name: str
    args: tuple


class IFPSEmulator:

    def __init__(
        self,
        archive: Union[InnoArchive, IFPSFile],
        options: Optional[IFPSEmulatorConfig] = None,
        **more
    ):
        if isinstance(archive, InnoArchive):
            self.inno = archive
            self.ifps = ifps = archive.ifps
        else:
            self.inno = None
            self.ifps = archive
        self.config = options or IFPSEmulatorConfig(**more)
        self.globals = [Variable(v.type, v.spec) for v in ifps.globals]
        self.stack: List[Variable] = []
        self.trace: List[IFPSCall] = []
        self.passwords: set[str] = set()
        self.jumpflag = False
        self.mutexes: set[str] = set()
        self.symbols: dict[str, Function] = CaseInsensitiveDict()
        for pfn in ifps.functions:
            self.symbols[pfn.name] = pfn

    def unimplemented(self, function: Function):
        raise NeedSymbol(function.name)

    def emulate_function(self, function: Function, *args):
        self.stack.clear()
        decl = function.decl
        if decl is None:
            raise NotImplementedError(F'Do not know how to call {function!s}.')
        if (n := len(decl.parameters)) != (m := len(args)):
            raise ValueError(
                F'Function {function!s} expects {n} arguments, only {m} were given.')
        for index, (argument, parameter) in enumerate(zip(args, decl.parameters), 1):
            variable = Variable(parameter.type, Variant(index, VariantType.Local))
            variable.set(argument)
            self.stack.append(variable)
        self.stack.reverse()
        if not decl.void:
            result = Variable(decl.return_type, Variant(0, VariantType.Argument))
            self.stack.append(result)
        self.call(function)
        self.stack.clear()
        if not decl.void:
            return result.get()

    def call(self, function: Function):
        def operator_div(a, b):
            return a // b if isinstance(a, int) and isinstance(b, int) else a / b

        def operator_in(a, b):
            return a in b

        def getvar(op: Union[Variant, Operand]) -> Variable:
            if not isinstance(op, Operand):
                v = op
                k = None
            elif op.type is OperandType.Value:
                raise TypeError('Attempting to retrieve variable for an immediate operand.')
            else:
                v = op.variant
                k = op.index
                if op.type is OperandType.IndexedByVar:
                    k = getvar(k).get()
            t, i = v.type, v.index
            if t is VariantType.Argument:
                if function.decl.void:
                    i -= 1
                var = self.stack[sp - i]
            elif t is VariantType.Global:
                var = self.globals[i]
            elif t is VariantType.Local:
                var = self.stack[sp + i]
            else:
                raise TypeError
            if k is not None:
                var = var.at(k)
            return var

        def access(op: Operand, new=None):
            if op.type is OperandType.Value:
                if new is not None:
                    raise RuntimeError('attempt to assign to an immediate')
                return op.value.value
            i = op.index
            v = getvar(op.variant)
            if op.type is OperandType.IndexedByVar:
                i = getvar(i).get()
                if not isinstance(i, int):
                    raise RuntimeError(F'Variable {op} accessed with non-integer {i!r} as index.')
            return v.get(i) if new is None else v.set(new, i)

        def getval(op: Operand):
            return access(op)

        def setval(op: Operand, new):
            return access(op, new=new)

        class CallState(NamedTuple):
            fn: Function
            ip: int
            sp: int
            eh: List[ExceptionHandler]

        callstack: List[CallState] = []

        cycle = 0
        exec_start = process_time()

        ip: int = 0
        sp: int = len(self.stack) - 1
        exceptions = []

        while True:
            if 0 < self.config.max_data_stack < len(callstack):
                raise EmulatorMaxCalls

            if function.body is None:
                decl = function.decl
                name = function.name
                tcls = decl.classname if decl else None
                tcls = tcls or ''
                registry: dict[str, IFPSEmulatedFunction] = self.external_symbols.get(tcls, {})
                handler = registry.get(name)

                if handler:
                    void = handler.void
                    argc = handler.argc
                elif decl:
                    void = decl.void
                    argc = decl.argc
                else:
                    void = True
                    argc = 0

                rpos = 0 if void else 1
                args = [self.stack[~k] for k in range(rpos, argc + rpos)]

                if self.config.trace_calls:
                    self.trace.append(IFPSCall(str(function), tuple(a.get() for a in args)))

                if handler is None:
                    self.unimplemented(function)
                else:
                    if decl and (decl.void != handler.void or decl.argc != handler.argc):
                        raise RuntimeError(F'Handler for {function!s} does not match the declaration.')
                    for k, (var, byref) in enumerate(zip(args, handler.spec)):
                        if not byref:
                            args[k] = var.get()
                    if not handler.static:
                        args.insert(0, self)
                    return_value = handler.call(*args)
                    if not handler.void:
                        self.stack[-1].set(return_value)
                if not callstack:
                    return
                function, ip, sp, exceptions = callstack.pop()
                continue

            while insn := function.code.get(ip, None):
                opc = insn.opcode
                ip += insn.size
                cycle += 1

                if 0 < self.config.max_seconds < process_time() - exec_start:
                    raise EmulatorTimeout
                if 0 < self.config.max_opcodes < cycle:
                    raise EmulatorExecutionLimit
                if 0 < self.config.max_data_stack < len(self.stack):
                    raise EmulatorMaxStack

                try:
                    if opc == Op.Nop:
                        continue
                    elif opc == Op.Assign:
                        setval(insn.op(0), getval(insn.op(1)))
                    elif opc == Op.Calculate:
                        calculate = {
                            AOp.Add: operator.add,
                            AOp.Sub: operator.sub,
                            AOp.Mul: operator.mul,
                            AOp.Div: operator_div,
                            AOp.Mod: operator.mod,
                            AOp.Shl: operator.lshift,
                            AOp.Shr: operator.rshift,
                            AOp.And: operator.and_,
                            AOp.BOr: operator.or_,
                            AOp.Xor: operator.xor,
                        }[insn.operator]
                        src = insn.op(1)
                        dst = insn.op(0)
                        try:
                            setval(dst, calculate(getval(dst), getval(src)))
                        except ArithmeticError as AE:
                            raise IFPSException from AE
                    elif opc == Op.Push:
                        # TODO: I do not actually know how this works
                        self.stack.append(getval(insn.op(0)))
                    elif opc == Op.PushVar:
                        self.stack.append(getvar(insn.op(0)))
                    elif opc == Op.Pop:
                        self.temp = self.stack.pop()
                    elif opc == Op.Call:
                        callstack.append(CallState(function, ip, sp, exceptions))
                        function = insn.operands[0]
                        ip = 0
                        sp = len(self.stack) - 1
                        exceptions = []
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
                        del self.stack[sp + 1:]
                        if not callstack:
                            return
                        function, ip, sp, exceptions = callstack.pop()
                        break
                    elif opc == Op.StackType:
                        raise OpCodeNotImplemented(str(opc))
                    elif opc == Op.PushType:
                        self.stack.append(Variable(
                            insn.operands[0],
                            Variant(len(self.stack) - sp, VariantType.Local)
                        ))
                    elif opc == Op.Compare:
                        compare = {
                            COp.GE: operator.ge,
                            COp.LE: operator.le,
                            COp.GT: operator.gt,
                            COp.LT: operator.lt,
                            COp.NE: operator.ne,
                            COp.EQ: operator.eq,
                            COp.IN: operator_in,
                            COp.IS: operator.is_,
                        }[insn.operator]
                        d = insn.op(0)
                        a = insn.op(1)
                        b = insn.op(2)
                        setval(d, compare(getval(a), getval(b)))
                    elif opc == Op.CallVar:
                        pfn = getval(insn.op(0))
                        if isinstance(pfn, int):
                            pfn = self.ifps.functions[pfn]
                        if isinstance(pfn, Function):
                            self.call(pfn)
                    elif opc in (Op.SetPtr, Op.SetPtrToCopy):
                        copy = False
                        if opc == Op.SetPtrToCopy:
                            copy = True
                        dst = getvar(insn.op(0))
                        src = getvar(insn.op(1))
                        dst.setptr(src, copy=copy)
                    elif opc == Op.BooleanNot:
                        setval(a := insn.op(0), not getval(a))
                    elif opc == Op.IntegerNot:
                        setval(a := insn.op(0), ~getval(a))
                    elif opc == Op.Neg:
                        setval(a := insn.op(0), -getval(a))
                    elif opc == Op.SetFlag:
                        condition, negated = insn.operands
                        self.jumpflag = getval(condition) ^ negated
                    elif opc == Op.JumpFlag:
                        if self.jumpflag:
                            ip = insn.operands[0]
                    elif opc == Op.PushEH:
                        exceptions.append(ExceptionHandler(*insn.operands))
                    elif opc == Op.PopEH:
                        tp = None
                        et = EHType(insn.operands[0])
                        eh = exceptions[-1]
                        if eh.current != et:
                            raise RuntimeError(F'Expected {eh.current} block to end, but {et} was ended instead.')
                        while tp is None:
                            if et is None:
                                raise RuntimeError
                            tp, et = {
                                EHType.Catch         : (eh.finally_one, EHType.Finally),
                                EHType.Try           : (eh.finally_one, EHType.Finally),
                                EHType.Finally       : (eh.finally_two, EHType.SecondFinally),
                                EHType.SecondFinally : (eh.handler_end, None),
                            }[et]
                        eh.current = et
                        ip = tp
                        if et is None:
                            exceptions.pop()
                    elif opc == Op.Inc:
                        setval(a := insn.op(0), getval(a) + 1)
                    elif opc == Op.Dec:
                        setval(a := insn.op(0), getval(a) - 1)
                    elif opc == Op.JumpPop1:
                        self.stack.pop()
                        ip = insn.operands[0]
                    elif opc == Op.JumpPop2:
                        self.stack.pop()
                        self.stack.pop()
                        ip = insn.operands[0]
                    else:
                        raise RuntimeError(F'Function contains invalid opcode at 0x{ip:X}.')
                except IFPSException as EE:
                    try:
                        eh = exceptions[-1]
                    except IndexError:
                        raise EE
                    et = EHType.Try
                    tp = None
                    while tp is None:
                        if et is None:
                            raise RuntimeError
                        tp, et = {
                            EHType.Try           : (eh.catch_error, EHType.Catch),
                            EHType.Catch         : (eh.finally_one, EHType.Finally),
                            EHType.Finally       : (eh.finally_two, EHType.SecondFinally),
                            EHType.SecondFinally : (eh.handler_end, None),
                        }[et]
                    if et is None:
                        raise EE
                    eh.current = et
                    ip = tp
                except AbortEmulation:
                    raise
                except EmulatorException:
                    raise
                # except Exception as RE:
                #     raise EmulatorException(
                #         F'In {function.symbol} at 0x{insn.offset:X} (cycle {cycle}), '
                #         F'emulation of {insn!r} failed: {RE!s}')
            if ip is None:
                raise RuntimeError(F'Instruction pointer moved out of bounds to 0x{ip:X}.')

    external_symbols: ClassVar[
        Dict[str,                        # class name for methods or empty string for functions
        Dict[str, IFPSEmulatedFunction]] # method or function name to emulation info
    ] = CaseInsensitiveDict()

    def external(*args, static=True, __reg: dict = external_symbols, **kwargs):
        def decorator(pfn):
            signature = inspect.signature(pfn)
            name: str = kwargs.get('name', pfn.__name__)
            csep: str = '.'
            if csep not in name:
                csep = '__'
            classname, _, name = name.rpartition(csep)
            if (registry := __reg.get(classname)) is None:
                registry = __reg[classname] = CaseInsensitiveDict()
            void = kwargs.get('void', signature.return_annotation in (signature.empty, None, 'None'))
            parameters: List[bool] = []
            specs = iter(signature.parameters.values())
            if not static:
                next(specs)
            for spec in specs:
                hint = eval(spec.annotation)
                if not isinstance(hint, type):
                    hint = get_origin(hint)
                parameters.append(issubclass(hint, Variable))
            registry[name] = e = IFPSEmulatedFunction(pfn, parameters, static, void)
            aliases = kwargs.get('alias', [])
            if isinstance(aliases, str):
                aliases = [aliases]
            for name in aliases:
                registry[name] = e
            if static:
                pfn = staticmethod(pfn)
            return pfn
        return decorator(args[0]) if args else decorator

    @external(static=False)
    def TPasswordEdit__Text(self, value: str) -> str:
        if value:
            self.passwords.add(value)
        return value

    @external
    def IsX86Compatible() -> bool:
        return True

    @external(alias=[
        'sArm64',
        'IsArm32Compatible',
        'Debugging',
        'IsUninstaller',
    ])
    def Terminated() -> bool:
        return False

    @external
    def Length(string: Variable[str]) -> int:
        return len(string)

    @external
    def WStrGet(string: Variable[str], index: int) -> str:
        if index <= 0:
            raise ValueError
        return string[index - 1:index]

    @external(static=False)
    def GetEnv(self, name: str) -> str:
        return self.config.environment.get(name, F'%{name}%')

    @external
    def AddBackslash(string: str) -> str:
        return string.rstrip('\\') + '\\'

    @external
    def Beep():
        pass

    @external(static=False)
    def Abort(self):
        if self.config.throw_abort:
            raise AbortEmulation

    @external
    def DirExists(path: str) -> bool:
        return True

    @external
    def ForceDirectories(path: str) -> bool:
        return True

    @external(alias='LoadStringFromLockedFile')
    def LoadStringFromFile(path: str, out: Variable[str]) -> bool:
        return True

    @external(alias='LoadStringsFromLockedFile')
    def LoadStringsFromFile(path: str, out: Variable[str]) -> bool:
        return True

    @external
    def ExpandConstant(string: str) -> str:
        return string

    @external
    def ExpandConstantEx(string: str, custom_var: str, custom_val: str) -> str:
        return string

    @external
    def DeleteFile(path: str) -> bool:
        return True

    @external
    def GetSpaceOnDisk(
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

    @external
    def GetSpaceOnDisk64(
        path: str,
        avail: int,
        space: int,
    ) -> bool:
        avail.set(3_000_000_000)
        space.set(5_000_000_000)
        return True

    @external
    def Exec(
        exe: str,
        cmd: str,
        cwd: str,
        show: int,
        wait: int,
        out: Variable[int],
    ) -> bool:
        out.set(0)
        return True

    @external(alias='StrToInt64')
    def StrToInt(s: str) -> int:
        return int(s)

    @external(alias='StrToInt64Def')
    def StrToIntDef(s: str, d: int) -> int:
        try:
            return int(s)
        except Exception:
            return d

    @external
    def StrToFloat(s: str) -> float:
        return float(s)

    @external(alias='FloatToStr')
    def IntToStr(i: int) -> str:
        return str(i)

    @external
    def StrToVersion(s: str, v: Variable[int]) -> bool:
        try:
            packed = bytes(map(int, s.split('.')))
        except Exception:
            return False
        if len(packed) != 4:
            return False
        v.set(int.from_bytes(packed, 'little'))
        return True

    @external
    def GetCmdTail() -> str:
        return ''

    @external
    def ParamCount() -> int:
        return 0

    @external
    def ParamStr(index: int) -> str:
        return ''

    @external
    def ActiveLanguage() -> str:
        return 'en'

    @external(static=False)
    def CustomMessage(self, msg_name: str) -> str:
        for msg in self.inno.setup_info.Messages:
            if msg.EncodedName == msg_name:
                return msg.Value
        raise IFPSException(F'Custom message with name {msg_name} not found.')

    @external
    def FmtMessage(fmt: str, args: list[str]) -> str:
        fmt = fmt.replace('{', '{{')
        fmt = fmt.replace('}', '}}')
        fmt = '%'.join(re.sub('%(\\d+)', '{\\1}', p) for p in fmt.split('%%'))
        return fmt.format(*args)

    @external(static=False)
    def SetupMessage(self, id: int) -> str:
        try:
            return self.inno.setup_info.Messages[id].Value
        except (AttributeError, IndexError):
            return ''

    @external(static=False, alias=['Is64BitInstallMode', 'IsX64Compatible', 'IsX64OS'])
    def IsWin64(self) -> bool:
        return self.config.x64

    @external(static=False)
    def IsX86OS(self) -> bool:
        return not self.config.x64

    @external
    def RaiseException(msg: str) -> None:
        raise IFPSException(msg)

    @external(static=False)
    def ProcessorArchitecture(self) -> int:
        if self.config.x64:
            return TSetupProcessorArchitecture.paX64.value
        else:
            return TSetupProcessorArchitecture.paX86.value

    @external(static=False)
    def GetUserNameString(self) -> str:
        return self.config.user_name

    @external(static=False)
    def GetComputerNameString(self) -> str:
        return self.config.host_name

    @external(static=False)
    def GetUILanguage(self) -> str:
        return self.config.lcid

    @external
    def GetArrayLength(array: Variable) -> int:
        array = array.deref()
        return len(array)

    @external
    def SetArrayLength(array: Variable, n: int):
        a = array.deref()
        a.resize(n)

    @external(static=False)
    def WizardForm(self) -> object:
        return self

    @external
    def GetDateTimeString(
        fmt: str,
        date_separator: str,
        time_separator: str,
    ) -> str:
        from datetime import datetime
        now = datetime.now()
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
                return now.date.isoformat()
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
            if spec == 'n':
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
            split[k] = re.sub('([dmyhnst]+)((?:[aA][mM]?/[pP][mM]?)?)', dt, split[k])
        for k in range(1, len(split), 2):
            split[k] = split[k][1:-1]
        return ''.join(split)

    @external(static=False)
    def CheckForMutexes(self, mutexes: str) -> bool:
        return any(m in self.mutexes for m in mutexes.split(','))

    @external(static=False)
    def CreateMutex(self, name: str):
        self.mutexes.add(name)

    @external(static=False)
    def GetWindowsVersion(self) -> int:
        version = int.from_bytes(struct.pack('>BBH', *self.config.windows_os_version))
        return version

    @external(static=False)
    def GetWindowsVersionEx(self, tv: Variable[Union[int, bool]]):
        tv[0], tv[1], tv[2] = self.config.windows_os_version # noqa
        tv[3], tv[4]        = self.config.windows_sp_version # noqa
        tv[5], tv[6], tv[7] = True, 0, 0

    @external(static=False)
    def GetWindowsVersionString(self) -> str:
        return '{0}.{1:02d}.{2:04d}'.format(*self.config.windows_os_version)

    @external
    def CreateOleObject(name: str) -> OleObject:
        return OleObject(name)

    @external
    def FindWindowByClassName(name: str) -> int:
        return 0

    del external


class InnoSetupEmulator(IFPSEmulator):

    def emulate_installation(self, password=''):

        class SetupDispatcher:

            InitializeSetup: Callable
            InitializeWizard: Callable
            CurStepChanged: Callable
            ShouldSkipPage: Callable
            CurPageChanged: Callable
            PrepareToInstall: Callable
            CheckPassword: Callable
            NextButtonClick: Callable
            DeinitializeSetup: Callable

            def __getattr__(_, name):
                return (lambda *a: self.emulate_function(pfn, *a)) if (
                    pfn := self.symbols.get(name)
                ) else (lambda *_: False)

        Setup = SetupDispatcher()

        Setup.InitializeSetup()
        Setup.InitializeWizard()
        Setup.CurStepChanged(TSetupStep.ssPreInstall)

        for page in PageID:

            if not Setup.ShouldSkipPage(page):
                Setup.CurPageChanged(page)
                if page == PageID.wpPreparing:
                    Setup.PrepareToInstall(False)
                if page == PageID.wpPassword:
                    Setup.CheckPassword(password)

            Setup.NextButtonClick(page)

            if page == PageID.wpPreparing:
                Setup.CurStepChanged(TSetupStep.ssInstall)
            if page == PageID.wpInfoAfter:
                Setup.CurStepChanged(TSetupStep.ssPostInstall)

        Setup.CurStepChanged(TSetupStep.ssDone)
        Setup.DeinitializeSetup()

    def unimplemented(self, function: Function):
        decl = function.decl
        if decl is None:
            return
        if not decl.void:
            rc = 1
            rv = self.stack[-1]
            if not rv.container:
                rt = rv.type.py_type()
                if isinstance(rt, type) and issubclass(rt, int):
                    rv.set(1)
        else:
            rc = 0
        for k in range(rc, rc + len(decl.parameters)):
            ptr: Variable[Variable] = self.stack[-k]
            if not ptr.pointer:
                continue
            var = ptr.deref()
            if var.container:
                continue
            vt = var.type.py_type()
            if isinstance(vt, type) and issubclass(vt, int):
                var.set(1)
