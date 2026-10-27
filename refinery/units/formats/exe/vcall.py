#!/usr/bin/env python3
from __future__ import annotations

import re
import struct

from argparse import ArgumentTypeError
from dataclasses import dataclass

from refinery.lib.argformats import DelayedArgument, multibin, number
from refinery.lib.emulator import CC, EmulationTimeout, Emulator, Hook
from refinery.lib.meta import check_variable_name
from refinery.lib.structures import StructReader, UnpackType
from refinery.lib.tools import mixed_class
from refinery.lib.types import Param, buf, isbuffer
from refinery.units import Arg, Chunk
from refinery.units.formats.exe import Arch, EmulatingUnit, Engine


ExtractType = UnpackType | list[UnpackType] | None


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
    deref: bool = False


@dataclass(frozen=True)
class RV:
    pass


@dataclass(frozen=True)
class Deref:
    addr: RV | Ref | Literal | Deref


@dataclass(frozen=True)
class OutBinding:
    name: str
    src: RV | Ref | Literal | Deref
    readback: StructType | BytesType | None


_IDENTIFIER = re.compile(r'[A-Za-z_]\w*')

_SIZEOF_SPEC = re.compile(r'(?:\d*[xcbB?hHiIlLqQefdspP])+')
_DECODE_SPEC = re.compile(r'(?:\d*[xcbB?hHiIlLqQefdspPauwgk])+')

_BODY_CONTENT_VARIABLE = 'B'
_RETURN_VALUE_VARIABLE = 'R'


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
    deref = False
    head, sep, tail = token.partition('=')
    if sep and head[:1] == '@' and _IDENTIFIER.fullmatch(head[1:]):
        deref = True
        head = head[1:]
    if sep and _IDENTIFIER.fullmatch(head):
        name, token = head, tail
    else:
        name = None
    check_variable_name(name)
    boxes = 0
    while token[:1] == '@':
        boxes += 1
        token = token[1:]
    base, readback = _arg_base(token)
    if readback is not None and not deref:
        raise ValueError('a :type read-back requires a named binding with a leading @')
    return ArgSlot(boxes, name, base, readback, deref)


def _parse_addr(text: str) -> RV | Ref | Literal | Deref:
    if not text:
        raise ValueError('empty address or source')
    if text[0] == '[':
        inside, rest = _split_bracket(text)
        if rest:
            raise ValueError(F'unexpected text after dereference: {rest!r}')
        return Deref(_parse_addr(inside))
    if text == _RETURN_VALUE_VARIABLE:
        return RV()
    if _IDENTIFIER.fullmatch(text):
        return Ref(text)
    return Literal(text)


def _place(text: str) -> tuple[RV | Ref | Literal | Deref, StructType | BytesType | None]:
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
    check_variable_name(head)
    src, readback = _place(tail)
    return OutBinding(head, src, readback)


@dataclass
class Binding:
    address: int | None
    value: int | None
    length: int
    readback: StructType | BytesType | None
    default_spec: str | None
    deref: bool = False


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
        self._extracted: dict[str, ExtractType] = {}
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
                self.bindings[slot.name] = Binding(None, core.scalar, 0, slot.readback, None, slot.deref)
            else:
                self.bindings[slot.name] = Binding(anchor_addr, None, anchor_len, slot.readback, core.default_spec, slot.deref)
        return passed

    def invoke(self, start: int, stop: int | None, timeout: int) -> int:
        return self.emu.call(start, *self.passed, until=stop, cc=self.cc, timeout=timeout)

    def extract(self, outputs: list[OutBinding]) -> dict[str, ExtractType]:
        self._outmap = {output.name: output for output in outputs}
        names = list(self.bindings)
        names.extend(output.name for output in outputs)
        return {name: self._get(name) for name in names}

    def _get(self, name: str) -> ExtractType:
        try:
            return self._extracted[name]
        except KeyError:
            pass
        if name in self._pending:
            raise ValueError(F'cyclic reference involving {name!r}')
        self._pending.add(name)
        if name in self.bindings:
            value = self._extract_binding(name, self.bindings[name])
        elif name in self._outmap:
            value = self._extract_place(self._outmap[name])
        else:
            raise ValueError(F'reference to undefined output {name!r}')
        self._pending.discard(name)
        self._extracted[name] = value
        return value

    def _decode(self, address: int, spec: str) -> ExtractType:
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
            binding = self.bindings.get(count.name)
            if binding is not None and binding.address is not None and not binding.deref:
                raise ValueError(
                    F'cannot use the pointer of {count.name!r} as a count; use .{count.name} for its length')
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

    def _natural_readback(self, binding: Binding) -> StructType | BytesType:
        if binding.readback is not None:
            return binding.readback
        if binding.default_spec is not None:
            return StructType(binding.default_spec)
        return BytesType(Literal(F'{binding.length}'))

    def _extract_binding(self, name: str, binding: Binding) -> ExtractType:
        if binding.address is None:
            if binding.deref:
                raise ValueError(F'cannot capture the contents of scalar binding {name!r}')
            return binding.value
        if not binding.deref:
            return binding.address
        readback = self._natural_readback(binding)
        if isinstance(readback, StructType):
            return self._decode(binding.address, readback.spec)
        return self.emu.mem_read(binding.address, self._count(readback.count))

    def _extract_place(self, output: OutBinding) -> ExtractType:
        src = output.src
        if isinstance(src, Deref):
            readback = output.readback
            if readback is None and isinstance(src.addr, Ref):
                binding = self.bindings.get(src.addr.name)
                if binding is not None and binding.address is not None and not binding.deref:
                    readback = self._natural_readback(binding)
            return self._read_at(self._addr(src.addr), readback)
        value = self._src_value(src)
        if output.readback is None:
            return value
        return self._reinterpret(value, output.readback)

    def _src_value(self, src: RV | Ref | Literal) -> ExtractType:
        if isinstance(src, RV):
            return self.emu.rv
        if isinstance(src, Ref):
            return self._get(src.name)
        return self._number(src.text)

    def _addr(self, src: RV | Ref | Literal | Deref) -> int:
        if isinstance(src, RV):
            return self.emu.rv
        if isinstance(src, Deref):
            return self.emu.mem_read_int(self._addr(src.addr), self._ptr)
        if isinstance(src, Ref):
            value = self._get(src.name)
            if not isinstance(value, int):
                raise ValueError(F'binding {src.name!r} is not usable as an address')
            return value
        return self._number(src.text)

    def _read_at(self, address: int, readback: StructType | BytesType | None) -> ExtractType:
        if readback is None:
            return self.emu.mem_read_int(address, self._ptr)
        if isinstance(readback, StructType):
            return self._decode(address, readback.spec)
        return self.emu.mem_read(address, self._count(readback.count))

    def _reinterpret(self, value: object, readback: StructType | BytesType) -> ExtractType:
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


class _DisassemblingEmulator(Emulator):
    """
    Logs each instruction that the emulator executes; the unit adds it to an emulator backend when
    asked to show the disassembly.
    """
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


class vcall(EmulatingUnit):
    """
    Call a single function inside an input executable with one of the emulator backends and capture
    its results as meta variables.

    Every positional argument is a binding that describes one function argument. Giving a binding a
    name additionally captures its value after the call. The unit emits the input chunk, enriched
    with each captured value as a meta variable.

    An argument binding has the form `[@]name=[@...]base[:type]`; the name and all `@` modifiers
    are optional. The `base` can be:

    - A multibin value: Scalars are passed by value, byte strings are put into an allocated buffer
      and passed as pointers.
    - An expression `[n]` where `n` is an integer. It allocates a zero-filled buffer of size `n`
      and passes a pointer to it.
    - The expression `.name` is the byte length of the binding `name`, passed as an integer.

    Each `@` after the name adds one level of pointer indirection to the value that is passed;
    this can be repeated. By default, a named binding captures the value that was passed to the
    function: the scalar itself, or the address of the buffer. A `@` before the name instead
    binds the name to the contents of the buffer, decoded according to the `:type` read-back;
    a read-back is only valid on such a binding.

    For `[n]` and `:n`, the expression `n` can be a literal number, the name of a number-valued
    binding, the expression `.name` for a binding's length, or `#spec` for the size of a struct
    field. A read-back `type` is `#spec` to decode a struct field, or a plain count to read that
    many raw bytes. The `spec` is a Python struct format string with refinery extensions:

    - `a` reads a C string
    - `u` and `w` read wide strings as bytes and as text
    - `g` reads a GUID
    - `k` reads a 7-bit encoded integer
    - `p` denotes a pointer-sized integer

    Non-argument outputs are captured with `--put NAME=PLACE`. A `PLACE` is `R` for the return
    value, the name of another binding (yielding whatever that binding captures), an absolute
    address, or any of these wrapped in `[...]` to read the memory at the resulting address;
    this can be nested. A `[name]` without a read-back type reads the memory using the natural
    size of the binding `name` when it captures a pointer: its read-back if one was declared,
    the size of its allocated struct, or the full length of its buffer. Use `--out=PLACE` to
    parse a `PLACE` and replace the chunk body with the output read from it instead of capturing
    it as a meta variable.

    Examples:

    - <this> getLength data=H:0011 .data -p length=R
    - <this> decryptString 7 -p text=[R]:#a
    - <this> decryptString 7 -o [R]:#a
    - <this> decompress 0x401000 src=H:0011 .src dst=[0x1000] @n=[#I] -p status=R:#i -o[dst]
    """

    def __init__(
        self,
        address: Param[str, Arg.String(help='Address or name of the function to call.')],
        *argument: Param[str, Arg.String(metavar='arg', help='An argument binding; see above.')],
        put: Param[list | None, Arg('-p', '--put', type=str, action='append', metavar='NAME=PLACE', help=(
            'Capture an additional output as the meta variable NAME=PLACE; may be given more than once.'))] = None,
        out: Param[str | None, Arg('-o', '--out', type=str, metavar='PLACE', help=(
            'Parse PLACE and replace the chunk body with the output read from it.'))] = None,
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
            put=put,
            out=out,
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
            engine = mixed_class(_DisassemblingEmulator, engine, F'Disassembling{engine.__name__}')
            hook |= Hook.CodeExecute

        emu = engine(data, self.args.base, self.args.arch, hook).reset()
        address = self._parse_address(data, emu.exe, self.args.address)

        outputs = [parse_out_binding(token) for token in (self.args.put or ())]
        if self.args.out is not None:
            src, readback = _place(self.args.out)
            outputs.append(OutBinding(_BODY_CONTENT_VARIABLE, src, readback))

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
        extracted = evaluator.extract(outputs)
        if self.args.out is not None:
            body = extracted.pop(_BODY_CONTENT_VARIABLE)
            if isinstance(body, int):
                body = str(body).encode(self.codec)
            elif isinstance(body, str):
                body = body.encode(self.codec)
            elif not isbuffer(body):
                body = bytearray(body)
            data[:] = body
        data.meta.update(extracted)
        return data
