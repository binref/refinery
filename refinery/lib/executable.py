#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This module implements an abstraction layer executable loader for PE, ELF, and MachO files.
The provided interface is the same for all executables. It powers the following units:

- `refinery.vsnip`
- `refinery.vsect`
- `refinery.vaddr`
- `refinery.vmemref`
"""
from __future__ import annotations

import sys
import itertools

from typing import NamedTuple, TYPE_CHECKING

from abc import ABC, abstractmethod
from enum import Enum
from uuid import uuid4

from refinery.lib import lief
from refinery.lib.types import INF, ByteStr

if TYPE_CHECKING:
    from lief.ELF import Binary as ELFBinary
    from lief.MachO import Binary as MachOBinary
    from lief.MachO import FatBinary as MachOFatBinary
    from lief.PE import Binary as PEBinary

    from typing import (
        ClassVar,
        Generator,
        Iterable,
        List,
        Optional,
        ParamSpec,
        Type,
        TypeVar,
        Union,
    )

    _T = TypeVar('_T')
    _P = ParamSpec('_P')

    AnyLIEF = Union[
        MachOBinary,
        MachOFatBinary,
        ELFBinary,
        PEBinary,
    ]


class ParsingFailure(ValueError):
    """
    Exception generated for parsing errors of an input `refinery.lib.executable.Executable`.
    """
    def __init__(self, kind):
        super().__init__(F'unable to parse input as {kind} file')


def align(alignment: int, value: int, down=False) -> int:
    """
    Given an alignment size and an integer value, compute the byte boundary to where this value
    would be aligned. By default, the next higher address that satisfies the alignment is computed;
    The optional parameter `down` can be set to `True` to instead return the next lower one.
    """
    if alignment >= 2:
        incomplete_chunk_count = value % alignment
        if incomplete_chunk_count > 0:
            if not down:
                value += alignment - incomplete_chunk_count
            else:
                value -= incomplete_chunk_count
    return value


class Range(NamedTuple):
    """
    A range of bytes specified by a lower and an upper bound. A `refinery.lib.executable.Range`
    can be subtracted from another one to return a list of ranges that are the result of
    removing the former from the latter. This operation is the only reason for using a custom
    class over the builtin `range` object, which does not support this.
    """
    lower: int
    upper: int

    def range(self):
        """
        Convertsion to a `range` object.
        """
        return range(self.lower, self.upper)

    def slice(self):
        """
        Conversion to a `slice` object.
        """
        return slice(self.lower, self.upper)

    def __len__(self):
        return self.upper - self.lower

    def __contains__(self, addr: int):
        return self.lower <= addr < self.upper

    def __str__(self):
        return F'0x{self.lower:X}:0x{self.upper:X}'

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self!s}>'

    def __sub__(self, them: Range) -> List[Range]:
        pieces = []
        if self.lower < them.lower:
            pieces.append(Range(self.lower, min(them.lower, self.upper)))
        if them.upper < self.upper:
            pieces.append(Range(max(self.lower, them.upper), self.upper))
        return pieces


class BoxedOffset(NamedTuple):
    """
    An offset together with a range of available bytes at that location.
    """
    box: Range
    position: int

    def __str__(self):
        return F'0x{self.position:X} in {self.box!s}'

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self!s}>'


class Location(NamedTuple):
    """
    A location in an `refinery.lib.executable.Executable`. Contains `refinery.lib.executable.BoxedOffset`
    for both its physical and virtual range of bytes.
    """
    physical: BoxedOffset
    virtual: BoxedOffset

    def __str__(self):
        return F'V={self.virtual!s}; P={self.physical!s}'

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self!s}>'


class ArchItem(NamedTuple):
    """
    An item of the `refinery.lib.executable.Arch` enumeration. It is used to store the register
    size in bits for a given architecture.
    """
    id: int
    pointer_size: int

    @classmethod
    def New(cls, pointer_size: int):
        return cls(uuid4(), pointer_size)


class Arch(ArchItem, Enum):
    """
    An enumeration of supported architectures and their register sizes.
    """
    X32 = ArchItem.New(32)
    X64 = ArchItem.New(64)
    ARM32 = ArchItem.New(32)
    ARM64 = ArchItem.New(64)
    MIPS16 = ArchItem.New(16)
    MIPS32 = ArchItem.New(32)
    MIPS64 = ArchItem.New(64)
    PPC32 = ArchItem.New(32)
    PPC64 = ArchItem.New(64)
    SPARC32 = ArchItem.New(32)
    SPARC64 = ArchItem.New(64)


class LT(str, Enum):
    """
    An enumeration to distinguish between physical and virtual address types.
    """
    PHYSICAL = 'offset'
    VIRTUAL = 'address'


class ET(str, Enum):
    """
    An enumeration to distinguish various executable types.
    """
    ELF = 'ELF'
    MachO = 'MachO'
    PE = 'PE'
    BLOB = 'BLOB'


class BO(str, Enum):
    """
    An enumeration to distinguish big and little endian.
    """
    BE = 'big'
    LE = 'little'


class Section(NamedTuple):
    """
    An abstract representation of a section inside an `refinery.lib.executable.Executable`.
    """
    name: str
    physical: Range
    virtual: Range
    synthetic: bool

    def as_segment(self, populate_sections=False) -> Segment:
        sections = [self] if populate_sections else None
        return Segment(self.physical, self.virtual, sections, self.name)

    def __str__(self):
        return str(self.as_segment())

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self!s}>'


class Symbol(NamedTuple):
    address: int
    name: Optional[str] = None
    code: bool = True
    exported: bool = True
    is_entry: bool = False
    size: Optional[int] = None
    tls_index: Optional[int] = None
    type_name: Optional[str] = None
    bind_name: Optional[str] = None

    def get_name(self):
        name = self.name
        if name is not None:
            return name
        if self.is_entry:
            return 'entry'
        if self.code:
            return F'sub_{self.address:08X}'
        else:
            return F'sym_{self.address:08X}'


class Segment(NamedTuple):
    """
    An abstract representation of a segment inside an `refinery.lib.executable.Executable`.
    """
    physical: Range
    virtual: Range
    sections: Optional[List[Section]]
    name: Optional[str] = None

    def as_section(self) -> Section:
        if self.name is None:
            raise ValueError('Unable to convert nameless segment to section.')
        return Section(self.name, self.physical, self.virtual, False)

    def __str__(self):
        msg = F'P=[{self.physical!s}];V=[{self.virtual!s}]'
        if self.name is not None:
            msg = F'{self.name}:{msg}'
        return msg

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self!s}>'


class CompartmentNotFound(LookupError):
    """
    This exception is raised when `refinery.lib.executable.Executable.lookup_location` fails to
    find a `refinery.lib.executable.Segment` that contains the given location.
    """
    def __init__(self, lt: LT, location: int):
        super().__init__(F'Unable to find a segment that contains the {lt.value} 0x{location:X}.')
        self.location_type = lt
        self.location = location


class Executable(ABC):
    """
    An abstract representation of a parsed executable in memory.
    """

    _data: ByteStr
    _head: AnyLIEF
    _base: Optional[int]
    _type: ET

    blob: ClassVar[bool] = False

    @classmethod
    def Load(cls: Type[_T], data: ByteStr, base: Optional[int] = None) -> _T:
        """
        Uses the `refinery.lib.executable.exeroute` function to parse the input data with one of
        the following specializations of this class:

        - `refinery.lib.executable.ExecutableELF`
        - `refinery.lib.executable.ExecutableMachO`
        - `refinery.lib.executable.ExecutablePE`
        """
        if (parsed := lief.load(data)) is None:
            raise ValueError('LIEF was unable to parse the input.')
        return LIEF(parsed, data, base)

    def __init__(self, head: AnyLIEF, data: ByteStr, base: Optional[int] = None):
        self._data = data
        self._head = head
        self._base = base

    @property
    def head(self):
        """
        Return the internal object representing the parsed file format header.
        """
        return self._head

    @property
    def type(self):
        """
        Returns the `refinery.lib.executable.ET` instance that identifies the executable type.
        """
        return self._type

    def __getitem__(self, key: Union[int, slice, Range]):
        return self.read(key)

    def __contains__(self, key: Union[int, slice, Range]):
        try:
            self.read(key)
        except LookupError:
            return False
        else:
            return True

    def read(self, key: Union[int, slice, Range]) -> memoryview:
        """
        Read data from the binary based on a given address. If the input `key` is a single integer,
        the function reads a single byte from the given address.
        """
        if isinstance(key, Range):
            key = slice(key.lower, key.upper)
        elif isinstance(key, int):
            key = slice(key, key + 1, 1)
        if key.start is None:
            raise LookupError(R'Slice indices with unspecified start are not supported.')
        if key.stop is not None and key.stop < key.start:
            raise LookupError(R'The slice end must lie after the slice start.')

        box = self.location_from_address(key.start)

        if key.stop is None:
            end = box.physical.box.upper
        elif key.stop <= box.virtual.box.upper:
            end = box.physical.position + (key.stop - key.start)
        else:
            raise LookupError(F'The end address 0x{key.stop:X} is beyond the section end 0x{box.virtual.box.upper:X}.')

        return self.data[box.physical.position:end]

    @staticmethod
    def ascii(string: Union[str, ByteStr]) -> str:
        """
        If the input `string` is a `str` instance, the function returns the input value. Byte
        strings are truncated to the first occurrence of a null byte and then decoded using
        the `latin-1` codec.
        """
        if isinstance(string, str):
            return string
        for k, b in enumerate(string):
            if b == 0:
                string = string[:k]
                break
        return string.decode('latin-1')

    def rebase_usr_to_img(self, addr: int) -> int:
        return addr - self.base + self.image_defined_base()

    def rebase_img_to_usr(self, addr: int) -> int:
        return addr - self.image_defined_base() + self.base

    @property
    def base(self) -> int:
        """
        Return the base address when mapped to memory. This is either the value passed to the
        constructor, or `refinery.lib.exectuable.Executable.image_defined_base`.
        """
        if self._base is None:
            return self.image_defined_base()
        return self._base

    @base.setter
    def base(self, value: int):
        self._base = value

    @property
    def data(self) -> memoryview:
        """
        Return a (readonly) view to the raw bytes of the executable image.
        """
        view = memoryview(self._data)
        if sys.version_info >= (3, 8):
            view = view.toreadonly()
        return view

    @property
    def pointer_size(self) -> int:
        """
        Return the size of a pointer in bits. Depends on `refinery.lib.executable.Executable.arch`.
        """
        return self.arch().pointer_size

    def location_from_address(self, address: int) -> Location:
        """
        Return a `refinery.lib.executable.Location` from the given address.
        """
        return self.lookup_location(address, LT.VIRTUAL)

    def location_from_offset(self, offset: int) -> Location:
        """
        Return a `refinery.lib.executable.Location` from the given file offset.
        """
        return self.lookup_location(offset, LT.PHYSICAL)

    def image_defined_size(self) -> int:
        """
        Returns the size of the executable on disk.
        """
        size = 0
        for segment in self.segments():
            size = max(size, segment.physical.upper)
        for section in self.sections():
            size = max(size, section.physical.upper)
        return size

    def image_defined_address_space(self) -> Range:
        """
        Returns the size of the executalbe in memory.
        """
        upper = 0
        lower = INF
        for segment in self.segments():
            upper = max(upper, segment.virtual.upper)
            lower = min(lower, segment.virtual.lower)
        for section in self.sections():
            upper = max(upper, section.virtual.upper)
            lower = min(lower, section.virtual.lower)
        if upper < lower:
            raise RuntimeError(F'The computed address space upper bound 0x{upper:X} is less than the computed lower bound 0x{lower:X}.')
        return Range(lower, upper)

    def lookup_location(self, location: int, lt: LT) -> Location:
        """
        For a address or file offset, compute the corresponding `refinery.lib.executable.Location`.
        """
        for part in itertools.chain(self.sections(), self.segments()):
            phys = part.physical
            virt = part.virtual
            if lt is LT.PHYSICAL and location in phys:
                return Location(
                    BoxedOffset(phys, location),
                    BoxedOffset(virt, virt.lower + location - phys.lower)
                )
            if lt is LT.VIRTUAL and location in virt:
                return Location(
                    BoxedOffset(phys, phys.lower + location - virt.lower),
                    BoxedOffset(virt, location)
                )
        else:
            raise CompartmentNotFound(lt, location)

    @abstractmethod
    def _symbols(self) -> Generator[Symbol, None, None]:
        ...

    def symbols(self) -> Generator[Symbol, None, None]:
        """
        Generates a list of symbols in the executable.
        """
        for symbol in self._symbols():
            if symbol.address in self:
                yield symbol

    @abstractmethod
    def byte_order(self) -> BO:
        """
        The byte order used by the architecture of this executable.
        """
        ...

    @abstractmethod
    def image_defined_base(self) -> int:
        """
        The image defined base address when mapped to memory.
        """
        ...

    @abstractmethod
    def arch(self) -> Arch:
        """
        The architecture for which this executable was built.
        """
        ...

    @abstractmethod
    def _sections(self) -> Generator[Section, None, None]:
        ...

    @abstractmethod
    def _segments(self, populate_sections=False) -> Generator[Segment, None, None]:
        ...

    def segments(self, populate_sections=False) -> Generator[Segment, None, None]:
        """
        An iterable of all `refinery.lib.executable.Segment`s in this executable.
        """
        yield from self._segments(populate_sections=populate_sections)

    def sections(self) -> Generator[Section, None, None]:
        """
        An iterable of all `refinery.lib.executable.Section`s in this executable.
        """
        ib = self.image_defined_base()
        missing = [Range(0, len(self._data))]
        offsets = {}
        for section in self._sections():
            missing = [piece for patch in missing for piece in patch - section.physical]
            offsets[section.physical.lower] = section.virtual.lower
            yield section
        if not missing:
            return
        offsets.setdefault(0, ib)
        for gap in missing:
            p_floor = min((k for k in offsets if k <= gap.lower), key=lambda p: p - gap.lower)
            v_floor = offsets[p_floor]
            v_lower = v_floor + (gap.lower - p_floor)
            v_upper = v_lower + len(gap)
            if gap.lower == 0:
                name = R'synthesized/.header'
            elif gap.upper == len(self._data):
                name = R'synthesized/.overlay'
            elif any(self._data[gap.slice()]):
                name = F'synthesized/.gap-{gap.lower:08X}-{gap.upper:08X}'
            else:
                name = F'synthesized/.zeros-{gap.lower:08X}'
            yield Section(name, gap, Range(v_lower, v_upper), True)


class ExecutableCodeBlob(Executable):
    """
    A dummy specialization of `refinery.lib.executable.Executable` that represents an unstructured
    blob of (shell)code. All information that would usually be obtained from a file header must be
    provided in the constructor for this object.
    """

    _head: Type[None] = None
    _type = ET.BLOB
    _byte_order: BO
    _arch: Arch

    blob = True

    def __init__(self, data, base=None, arch: Arch = Arch.X32, byte_order: BO = BO.LE):
        super().__init__(None, data, base)
        self._byte_order = byte_order
        self._arch = arch

    def image_defined_base(self) -> int:
        return 0

    def byte_order(self) -> BO:
        return self._byte_order

    def arch(self) -> Arch:
        return self._arch

    def _symbols(self) -> Generator[Symbol, None, None]:
        yield Symbol(0, is_entry=True)

    def _sections(self) -> Generator[Section, None, None]:
        v = Range(self.base, self.base + len(self.data))
        p = Range(0, len(self.data))
        yield Section('blob', p, v, False)

    def _segments(self, populate_sections=False) -> Generator[Segment, None, None]:
        for s in self.sections():
            yield s.as_segment(populate_sections=populate_sections)


class LIEF(Executable):

    _head: AnyLIEF
    _type: Union[ET.PE, ET.ELF, ET.MachO]

    @property
    def _lh(self) -> lief.Binary:
        return self._first_header.abstract

    @property
    def _first_header(self) -> Union[MachOBinary, ELFBinary, PEBinary]:
        head = self._head
        if isinstance(self._head, lief.MachO.FatBinary):
            head = head.at(0)
        return head

    @property
    def _type(self):
        EF = lief.Binary.FORMATS
        HF = self._lh.format
        if HF is EF.UNKNOWN:
            raise AttributeError('Unknown executable type.')
        return {EF.MACHO: ET.MachO, EF.PE: ET.PE, EF.ELF: ET.ELF}[HF]

    def image_defined_base(self) -> int:
        return self._lh.imagebase

    def byte_order(self) -> BO:
        LE = lief.Header.ENDIANNESS
        return {
            LE.BIG    : BO.BE,
            LE.LITTLE : BO.LE,
        }.get(self._lh.header.endianness, BO.LE)

    def arch(self) -> Arch:
        LA = lief.Header.ARCHITECTURES
        LM = lief.Header.MODES
        arch = self._lh.header.architecture
        mode = self._lh.header.modes
        if arch == LA.UNKNOWN:
            raise ValueError('No architecture set.')
        elif arch == LA.ARM:
            return Arch.ARM32
        elif arch == LA.ARM64:
            return Arch.ARM64
        elif arch == LA.MIPS:
            if LM.BITS_16 == mode:
                return Arch.MIPS16
            if LM.BITS_32 == mode:
                return Arch.MIPS32
            if LM.BITS_64 == mode:
                return Arch.MIPS64
        elif arch == LA.PPC:
            if LM.BITS_32 == mode:
                return Arch.PPC32
            if LM.BITS_64 == mode:
                return Arch.PPC64
        elif arch == LA.SPARC:
            if LM.BITS_32 == mode:
                return Arch.SPARC32
            if LM.BITS_64 == mode:
                return Arch.SPARC64
        elif arch == LA.X86_64:
            assert LM.BITS_64 == mode
            return Arch.X64
        elif arch == LA.X86:
            if LM.BITS_32 == mode:
                return Arch.X32
            if LM.BITS_64 == mode:
                return Arch.X64
        raise NotImplementedError

    def _symbols(self) -> Generator[Symbol, None, None]:
        yield Symbol(self._lh.entrypoint, is_entry=True)
        it: Iterable[lief.Symbol] = self._lh.symbols
        for symbol in it:
            yield Symbol(symbol.value, symbol.name, size=symbol.size)

    def _convert_section(self, section: lief.Section, segment_name: Optional[str] = None) -> Section:
        p_lower = section.offset
        p_upper = p_lower + section.size

        v_lower = section.virtual_address
        if self._type == ET.PE:
            v_lower += self.image_defined_base()
        v_lower = self.rebase_img_to_usr(v_lower)
        try:
            alignment = section.alignment
        except AttributeError:
            v_upper = v_lower + section.size
        else:
            v_upper = v_lower + align(alignment, section.size)
        name = self.ascii(section.name)
        if segment_name is not None:
            name = F'{segment_name}/{name}'
        return Section(
            name,
            Range(p_lower, p_upper),
            Range(v_lower, v_upper),
            synthetic=False,
        )

    @property
    def is_pe(self):
        return isinstance(self._head, lief.PE.Binary)

    @property
    def is_elf(self):
        return isinstance(self._head, lief.ELF.Binary)

    @property
    def is_macho(self):
        return isinstance(self._head, (lief.MachO.Binary, lief.MachO.FatBinary))

    def _sections(self) -> Generator[Section, None, None]:
        if self.is_pe:
            it: Iterable[lief.Section] = self._lh.sections
            for section in it:
                if section.size == 0:
                    continue
                yield self._convert_section(section)
            return
        if self.is_elf:
            for section in self._lh.sections:
                if section.size > 0:
                    yield self._convert_section(section)
            return
        for segment in self.segments(populate_sections=True):
            if segment.name:
                yield segment.as_section()
            if self.is_pe:
                return
            yield from segment.sections

    def _segments(self, populate_sections=False) -> Generator[Segment, None, None]:
        if self.is_pe:
            for section in self.sections():
                yield section.as_segment(populate_sections)
        else:
            it: Iterable[Union[
                lief.ELF.Segment,
                lief.MachO.SegmentCommand
            ]] = self._first_header.segments
            for segment in it:
                p_lower = segment.file_offset
                try:
                    p_upper = p_lower + segment.file_size
                except AttributeError:
                    p_upper = p_lower + segment.physical_size
                v_lower = segment.virtual_address
                v_lower = self.rebase_usr_to_img(v_lower)
                v_upper = v_lower + segment.virtual_size
                try:
                    name = segment.name
                except AttributeError:
                    name = None
                else:
                    name = self.ascii(name)
                if not populate_sections:
                    sections = None
                else:
                    sections = [self._convert_section(section, name) for section in segment.sections]
                yield Segment(Range(p_lower, p_upper), Range(v_lower, v_upper), sections, name)
