#!/usr/bin/env python3
from __future__ import annotations

import re
import struct

from argparse import ArgumentTypeError
from dataclasses import dataclass
from typing import TypeVar

from refinery.lib.argformats import DelayedArgument, multibin, number
from refinery.lib.emulator import CC, Emulator, EmulationTimeout, Hook
from refinery.lib.structures import StructReader
from refinery.lib.types import buf, Param
from refinery.units import Arg, Chunk
from refinery.units.formats.exe import Arch, EmulatingUnit, Engine

T = TypeVar('T', bound=type[Emulator])


@dataclass(frozen=True)
class Literal:
    text: str


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class LengthOf:
    name: str


@dataclass(frozen=True)
class StructSpec:
    spec: str


@dataclass(frozen=True)
class StructType:
    spec: str


@dataclass(frozen=True)
class BytesType:
    count: Literal | Ref | LengthOf


@dataclass(frozen=True)
class ValueBase:
    multibin: str


@dataclass(frozen=True)
class AllocBase:
    size: Literal | Ref | LengthOf | StructSpec


@dataclass(frozen=True)
class LengthBase:
    name: str


@dataclass(frozen=True)
class ArgSlot:
    boxes: int
    name: str | None
    base: ValueBase | AllocBase | LengthBase
    readback: StructType | BytesType | None


@dataclass(frozen=True)
class RV:
    pass


@dataclass(frozen=True)
class ArgRef:
    index: int


@dataclass(frozen=True)
class Deref:
    addr: RV | ArgRef | Ref | Literal | Deref


@dataclass(frozen=True)
class OutBinding:
    name: str
    src: RV | ArgRef | Ref | Literal | Deref
    readback: StructType | BytesType | None


_IDENTIFIER = re.compile(r'[A-Za-z_]\w*')
_ARGUMENT_N = re.compile(r'a(\d+)')

_SIZEOF_SPEC = re.compile(r'(?:\d*[xcbB?hHiIlLqQefdspP])+')
_DECODE_SPEC = re.compile(r'(?:\d*[xcbB?hHiIlLqQefdspPauwgk])+')


def _ident(text: str) -> str:
    if not _IDENTIFIER.fullmatch(text):
        raise ValueError(F'expected an identifier, got {text!r}')
    return text


def _struct_spec(spec: str, decode: bool) -> str:
    if not spec:
        raise ValueError('the struct specification after # is empty')
    pattern = _DECODE_SPEC if decode else _SIZEOF_SPEC
    if not pattern.fullmatch(spec):
        raise ValueError(F'invalid struct specification: #{spec}')
    return spec


def _count(text: str) -> Literal | Ref | LengthOf:
    if not text:
        raise ValueError('empty count expression')
    if text[0] == '.':
        return LengthOf(_ident(text[1:]))
    if _IDENTIFIER.fullmatch(text):
        return Ref(text)
    return Literal(text)


def _size(text: str) -> Literal | Ref | LengthOf | StructSpec:
    if text[:1] == '#':
        return StructSpec(_struct_spec(text[1:], False))
    return _count(text)


def _readback(text: str) -> StructType | BytesType:
    if not text:
        raise ValueError('empty read-back type after :')
    if text[0] == '#':
        return StructType(_struct_spec(text[1:], True))
    return BytesType(_count(text))


def _split_bracket(text: str) -> tuple[str, str]:
    depth = 0
    for k, character in enumerate(text):
        if character == '[':
            depth += 1
        elif character == ']':
            depth -= 1
            if depth == 0:
                return text[1:k], text[k + 1:]
    raise ValueError(F'unbalanced brackets: {text!r}')


def _arg_base(token: str) -> tuple[ValueBase | AllocBase | LengthBase, StructType | BytesType | None]:
    if not token:
        raise ValueError('empty argument specification')
    if token[0] == '[':
        inside, rest = _split_bracket(token)
        base = AllocBase(_size(inside))
        if not rest:
            return base, None
        if rest[0] != ':':
            raise ValueError(F'unexpected text after allocation: {rest!r}')
        return base, _readback(rest[1:])
    if token[0] == '.':
        name, sep, kind = token[1:].partition(':')
        return LengthBase(_ident(name)), (_readback(kind) if sep else None)
    return ValueBase(token), None


def parse_arg_slot(token: str) -> ArgSlot:
    boxes = 0
    while token[:1] == '@':
        boxes += 1
        token = token[1:]
    name = None
    head, sep, tail = token.partition('=')
    if sep and _IDENTIFIER.fullmatch(head):
        name, token = head, tail
    base, readback = _arg_base(token)
    return ArgSlot(boxes, name, base, readback)


def _parse_addr(text: str) -> RV | ArgRef | Ref | Literal | Deref:
    if not text:
        raise ValueError('empty address or source')
    if text[0] == '[':
        inside, rest = _split_bracket(text)
        if rest:
            raise ValueError(F'unexpected text after dereference: {rest!r}')
        return Deref(_parse_addr(inside))
    if text == 'rv':
        return RV()
    if m := _ARGUMENT_N.fullmatch(text):
        return ArgRef(int(m[1]))
    if _IDENTIFIER.fullmatch(text):
        return Ref(text)
    return Literal(text)


def _place(text: str) -> tuple[RV | ArgRef | Ref | Literal | Deref, StructType | BytesType | None]:
    if not text:
        raise ValueError('empty output place')
    if text[0] == '[':
        inside, rest = _split_bracket(text)
        src = Deref(_parse_addr(inside))
        if not rest:
            return src, None
        if rest[0] != ':':
            raise ValueError(F'unexpected text after dereference: {rest!r}')
        return src, _readback(rest[1:])
    head, sep, kind = text.partition(':')
    return _parse_addr(head), (_readback(kind) if sep else None)


def parse_out_binding(token: str) -> OutBinding:
    head, sep, tail = token.partition('=')
    if not sep or not _IDENTIFIER.fullmatch(head):
        raise ValueError(F'output binding must be NAME=PLACE: {token!r}')
    src, readback = _place(tail)
    return OutBinding(head, src, readback)


@dataclass
class Binding:
    address: int | None
    value: int | None
    length: int
    readback: StructType | BytesType | None
    default_spec: str | None


@dataclass
class _Core:
    scalar: int | None
    addr: int | None
    length: int
    default_spec: str | None = None


class Evaluator:
    _CUSTOM = frozenset('auwgk')

    def __init__(self, emu: Emulator, data: Chunk, cc: CC, max_read: int = 0x1000):
        self.emu = emu
        self.data = data
        self.cc = cc
        self.max_read = max_read
        self.passed: list[int] = []
        self.bindings: dict[str, Binding] = {}
        self._presize: dict[str, tuple[str, int]] = {}
        self._inputs: dict[int, _Core] = {}
        self._extracted: dict[str, object] = {}
        self._pending: set[str] = set()
        self._outmap: dict[str, OutBinding] = {}

    @property
    def _ptr(self) -> int:
        return self.emu.exe.pointer_size_in_bytes

    @property
    def _order(self) -> str:
        return self.emu.exe.byte_order().value

    @property
    def _bigendian(self) -> bool:
        return self._order == 'big'

    def _value(self, expression: str) -> int | buf:
        try:
            scalar = number(expression)
            if isinstance(scalar, DelayedArgument):
                scalar = scalar(self.data)
        except ArgumentTypeError:
            scalar = None
        if isinstance(scalar, int):
            return scalar
        buffer = multibin(expression)
        if isinstance(buffer, DelayedArgument):
            buffer = buffer(self.data)
        return buffer

    def _number(self, expression: str) -> int:
        scalar = number(expression)
        if isinstance(scalar, DelayedArgument):
            scalar = scalar(self.data)
        return int(scalar)

    def _translate(self, spec: str) -> str:
        word = 'Q' if self._ptr == 8 else 'I'
        return spec.replace('p', word).replace('P', word)

    def _calcsize(self, spec: str) -> int:
        return struct.calcsize(F'<{self._translate(spec)}')

    def _lookup(self, name: str) -> tuple[str, int]:
        try:
            return self._presize[name]
        except KeyError:
            raise ValueError(F'reference to undefined binding {name!r}')

    def _length_of(self, name: str) -> int:
        kind, value = self._lookup(name)
        if kind != 'buffer':
            raise ValueError(F'cannot take the length of scalar binding {name!r}')
        return value

    def _eval_size(self, size: Literal | Ref | LengthOf | StructSpec) -> int:
        if isinstance(size, StructSpec):
            return self._calcsize(size.spec)
        if isinstance(size, LengthOf):
            return self._length_of(size.name)
        if isinstance(size, Ref):
            return self._lookup(size.name)[1]
        return self._number(size.text)

    def setup(self, slots: list[ArgSlot]):
        for k, slot in enumerate(slots):
            base = slot.base
            if not isinstance(base, ValueBase):
                continue
            value = self._value(base.multibin)
            if isinstance(value, int):
                self._inputs[k] = _Core(value, None, 0)
                presize = ('scalar', value)
            else:
                addr = self.emu.malloc(len(value))
                self.emu.mem_write(addr, bytes(value))
                self._inputs[k] = _Core(None, addr, len(value))
                presize = ('buffer', len(value))
            if slot.name:
                self._presize[slot.name] = presize
        for k, slot in enumerate(slots):
            self.passed.append(self._build(k, slot))

    def _build(self, index: int, slot: ArgSlot) -> int:
        base = slot.base
        if isinstance(base, ValueBase):
            core = self._inputs[index]
        elif isinstance(base, AllocBase):
            size = self._eval_size(base.size)
            addr = self.emu.malloc(size)
            spec = base.size.spec if isinstance(base.size, StructSpec) else None
            core = _Core(None, addr, size, spec)
            if slot.name:
                self._presize[slot.name] = ('buffer', size)
        else:
            length = self._length_of(base.name)
            core = _Core(length, None, 0)
            if slot.name:
                self._presize[slot.name] = ('scalar', length)
        return self._box(slot, core)

    def _box(self, slot: ArgSlot, core: _Core) -> int:
        if core.addr is None:
            value = core.scalar
            assert value is not None
            passed = value
            anchor_addr = None
            anchor_len = 0
            for level in range(slot.boxes):
                cell = self.emu.malloc(self._ptr)
                self.emu.mem_write_int(cell, passed, self._ptr)
                if level == 0:
                    anchor_addr, anchor_len = cell, self._ptr
                passed = cell
        else:
            passed = core.addr
            anchor_addr, anchor_len = core.addr, core.length
            for _ in range(slot.boxes):
                cell = self.emu.malloc(self._ptr)
                self.emu.mem_write_int(cell, passed, self._ptr)
                passed = cell
        if slot.name:
            if anchor_addr is None:
                self.bindings[slot.name] = Binding(None, core.scalar, 0, slot.readback, None)
            else:
                self.bindings[slot.name] = Binding(anchor_addr, None, anchor_len, slot.readback, core.default_spec)
        return passed

    def invoke(self, start: int, stop: int | None, timeout: int) -> int:
        return self.emu.call(start, *self.passed, until=stop, cc=self.cc, timeout=timeout)

    def extract(self, outputs: list[OutBinding]) -> dict[str, object]:
        self._outmap = {output.name: output for output in outputs}
        names = list(self.bindings)
        names.extend(output.name for output in outputs)
        return {name: self._get(name) for name in names}

    def _get(self, name: str) -> object:
        try:
            return self._extracted[name]
        except KeyError:
            pass
        if name in self._pending:
            raise ValueError(F'cyclic reference involving {name!r}')
        self._pending.add(name)
        if name in self.bindings:
            value = self._extract_binding(self.bindings[name])
        elif name in self._outmap:
            value = self._extract_place(self._outmap[name])
        else:
            raise ValueError(F'reference to undefined output {name!r}')
        self._pending.discard(name)
        self._extracted[name] = value
        return value

    def _arg(self, index: int) -> int:
        try:
            return self.passed[index]
        except IndexError:
            raise ValueError(F'argument index a{index} is out of range')

    def _decode(self, address: int, spec: str) -> object:
        spec = self._translate(spec)
        if any(letter in self._CUSTOM for letter in spec):
            data = self._read_window(address)
        else:
            data = self.emu.mem_read(address, struct.calcsize(F'<{spec}'))
        reader = StructReader(data, bigendian=self._bigendian)
        values = reader.read_struct(spec)
        if not values:
            return B''
        return values[0] if len(values) == 1 else list(values)

    def _read_window(self, address: int) -> buf:
        cap = self.max_read
        while cap > 0:
            try:
                return self.emu.mem_read(address, cap)
            except Exception:
                cap //= 2
        return B''

    def _count(self, count: Literal | Ref | LengthOf) -> int:
        if isinstance(count, LengthOf):
            return self._post_length(count.name)
        if isinstance(count, Ref):
            value = self._get(count.name)
            if isinstance(value, int):
                return value
            if isinstance(value, (bytes, bytearray, memoryview)):
                return len(value)
            raise ValueError(F'cannot use {count.name!r} as a count')
        return self._number(count.text)

    def _post_length(self, name: str) -> int:
        binding = self.bindings.get(name)
        if binding is not None and binding.address is not None:
            return binding.length
        value = self._get(name)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return len(value)
        raise ValueError(F'cannot take the length of {name!r}')

    def _extract_binding(self, binding: Binding) -> object:
        if binding.address is None:
            return binding.value
        readback = binding.readback
        if readback is None and binding.default_spec is not None:
            readback = StructType(binding.default_spec)
        if readback is None:
            return self.emu.mem_read(binding.address, binding.length)
        if isinstance(readback, StructType):
            return self._decode(binding.address, readback.spec)
        return self.emu.mem_read(binding.address, self._count(readback.count))

    def _extract_place(self, output: OutBinding) -> object:
        src = output.src
        if isinstance(src, Deref):
            return self._read_at(self._addr(src.addr), output.readback)
        value = self._src_value(src)
        if output.readback is None:
            return value
        return self._reinterpret(value, output.readback)

    def _src_value(self, src: RV | ArgRef | Ref | Literal) -> object:
        if isinstance(src, RV):
            return self.emu.rv
        if isinstance(src, ArgRef):
            return self._arg(src.index)
        if isinstance(src, Ref):
            return self._get(src.name)
        return self._number(src.text)

    def _addr(self, addr: RV | ArgRef | Ref | Literal | Deref) -> int:
        if isinstance(addr, RV):
            return self.emu.rv
        if isinstance(addr, ArgRef):
            return self._arg(addr.index)
        if isinstance(addr, Deref):
            return self.emu.mem_read_int(self._addr(addr.addr), self._ptr)
        if isinstance(addr, Ref):
            value = self._get(addr.name)
            if not isinstance(value, int):
                raise ValueError(F'binding {addr.name!r} is not usable as an address')
            return value
        return self._number(addr.text)

    def _read_at(self, address: int, readback: StructType | BytesType | None) -> object:
        if readback is None:
            return self.emu.mem_read_int(address, self._ptr)
        if isinstance(readback, StructType):
            return self._decode(address, readback.spec)
        return self.emu.mem_read(address, self._count(readback.count))

    def _reinterpret(self, value: object, readback: StructType | BytesType) -> object:
        if not isinstance(value, int):
            raise ValueError('cannot reinterpret a non-integer source value')
        if isinstance(readback, StructType):
            spec = self._translate(readback.spec)
            size = struct.calcsize(F'<{spec}')
        else:
            spec = None
            size = self._count(readback.count)
        raw = (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'big' if self._bigendian else 'little')
        if spec is None:
            return raw
        reader = StructReader(memoryview(raw), bigendian=self._bigendian)
        values = reader.read_struct(spec)
        return values[0] if len(values) == 1 else list(values)


def _show_disassembly(base: T) -> T:
    class VCallEmulator(base):
        def disassemble(self, address: int):
            try:
                return self.disassemble_instruction(address)
            except Exception:
                return None

        def hook_code_execute(self, emu, address: int, size: int, state=None):
            instruction = self.disassemble(address)
            if instruction:
                vcall.log_always(F'0x{address:08X} {instruction.mnemonic} {instruction.op_str}')
            else:
                self.halt()
            return False

    return VCallEmulator # type:ignore


class vcall(EmulatingUnit):
    """
    Call a single function inside an input executable with one of the emulator backends and capture
    its results as meta variables

    Every positional argument is a binding that describes one function argument. Giving a binding a
    name additionally captures its value after the call. The unit emits the input chunk, enriched
    with each captured value as a meta variable.

    An argument binding has the form `[name=][@...]base[:type]`. The `base` can be:

    - A multibin value: Scalars are passed by value, byte strings are put into an allocated buffer
      and passed as pointers.
    - An expression `[n]` where `n` is an integer. It allocates a zero-filled buffer of size `n`
      and passes a pointer to it.
    - The expression `.name` is the byte length of the binding `name`, passed as an integer.

    A leading `@` adds one level of pointer indirection and may be repeated. The `:type` modifier
    overrides how a named binding is read back after the call.

    For `[n]` and `:n`, the expression `n` can be a literal number, the name of another binding
    the expression `.name` for a binding's length, or `#spec` for the size of a struct field. A
    read-back `type` is `#spec` to decode a struct field, or a plain count to read that many raw
    bytes. The `spec` is a Python struct format string with refinery extensions:

    - `a` reads a C string
    - `u` and `w` read wide strings as bytes and as text
    - `g` reads a GUID
    - `k` reads a 7-bit encoded integer
    - `p` denotes a pointer-sized integer

    Non-argument outputs are added with `--out NAME=PLACE`. A `PLACE` is `rv` for the return value,
    the name of another binding, an absolute address, `aN` for the `N`th argument value, or any of
    these wrapped in `[...]` to dereference it; this can be nested.

    Examples:

    - <this> getLength data=H:0011 .data -r length
    - <this> decryptString 7 -o text=[rv]:#a
    - <this> decompress 0x401000 src=H:0011 .src dst=[0x1000]:n n=[#I] -o status=rv:#i
    """

    def __init__(
        self,
        address: Param[str, Arg.String(help='Address or name of the function to call.')],
        *argument: Param[str, Arg.String(metavar='arg', help='An argument binding; see above.')],
        out: Param[list | None, Arg('-o', '--out', type=str, action='append', metavar='OUT', help=(
            'Capture an additional output as NAME=PLACE; may be given more than once.'))] = None,
        ret: Param[str, Arg.String('-r', '--ret', metavar='NAME', help=(
            'A shortcut for --out NAME=rv.'))] = '',
        cc: Param[str | CC, Arg.Option('-c', metavar='CC', choices=CC, help=(
            'Specify the calling convention, default is {default}; pick from {choices}.'))] = CC.StdCall,
        timeout: Param[int, Arg.Number('-t', help='Optionally stop emulating after a given number of instructions.')] = 0,
        max_read: Param[int, Arg.Number('-m', '--max-read', metavar='N', help=(
            'Byte cap for reading variable-length outputs such as strings; the default is {default}.'))] = 0x1000,
        base=None, arch=Arch.X32, engine=Engine.unicorn, se=False, ic=False, uc=False,
    ):
        super().__init__(
            address=address,
            argument=argument,
            out=out,
            ret=ret,
            cc=Arg.AsOption(cc, CC),
            timeout=timeout,
            max_read=max_read,
            base=base,
            arch=arch,
            engine=engine,
            se=se,
            ic=ic,
            uc=uc,
        )

    def process(self, data: Chunk):
        engine = self._engine().cls
        hook = Hook.Errors

        if self.log_info():
            engine = _show_disassembly(engine)
            hook |= Hook.CodeExecute

        emu = engine(data, self.args.base, self.args.arch, hook).reset()
        address = self._parse_address(data, emu.exe, self.args.address)

        outputs = [parse_out_binding(token) for token in (self.args.out or ())]
        if self.args.ret:
            outputs.append(OutBinding(self.args.ret, RV(), None))

        evaluator = Evaluator(emu, data, self.args.cc, self.args.max_read)
        evaluator.setup([parse_arg_slot(token) for token in self.args.argument])
        try:
            evaluator.invoke(
                emu.base_exe_to_emu(address.start),
                emu.base_exe_to_emu(address.stop),
                timeout=self.args.timeout
            )
        except EmulationTimeout:
            pass
        data.meta.update(evaluator.extract(outputs))
        return data
