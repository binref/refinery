"""
Parser for .NET metadata blob signatures per ECMA-335 II.23.2.
"""
from __future__ import annotations

import enum

from refinery.lib.dotnet.header import DotNetStructReader


class ElementType(enum.IntEnum):
    Void        = 0x01 # noqa
    Boolean     = 0x02 # noqa
    Char        = 0x03 # noqa
    I1          = 0x04 # noqa
    U1          = 0x05 # noqa
    I2          = 0x06 # noqa
    U2          = 0x07 # noqa
    I4          = 0x08 # noqa
    U4          = 0x09 # noqa
    I8          = 0x0A # noqa
    U8          = 0x0B # noqa
    R4          = 0x0C # noqa
    R8          = 0x0D # noqa
    String      = 0x0E # noqa
    Ptr         = 0x0F # noqa
    ByRef       = 0x10 # noqa
    ValueType   = 0x11 # noqa
    Class       = 0x12 # noqa
    Var         = 0x13 # noqa
    Array       = 0x14 # noqa
    GenericInst = 0x15 # noqa
    TypedByRef  = 0x16 # noqa
    I           = 0x18 # noqa
    U           = 0x19 # noqa
    FnPtr       = 0x1B # noqa
    Object      = 0x1C # noqa
    SzArray     = 0x1D # noqa
    MVar        = 0x1E # noqa
    CModReqD    = 0x1F # noqa
    CModOpt     = 0x20 # noqa
    Internal    = 0x21 # noqa
    Sentinel    = 0x41 # noqa
    Pinned      = 0x45 # noqa


_PRIMITIVE_INFO: dict[int, tuple[str, int | None]] = {
    ElementType.Void       : ('Void', 0),
    ElementType.Boolean    : ('Boolean', 1),
    ElementType.Char       : ('Char', 2),
    ElementType.I1         : ('SByte', 1),
    ElementType.U1         : ('Byte', 1),
    ElementType.I2         : ('Int16', 2),
    ElementType.U2         : ('UInt16', 2),
    ElementType.I4         : ('Int32', 4),
    ElementType.U4         : ('UInt32', 4),
    ElementType.I8         : ('Int64', 8),
    ElementType.U8         : ('UInt64', 8),
    ElementType.R4         : ('Single', 4),
    ElementType.R8         : ('Double', 8),
    ElementType.String     : ('String', None),
    ElementType.TypedByRef : ('TypedByRef', None),
    ElementType.I          : ('IntPtr', None),
    ElementType.U          : ('UIntPtr', None),
    ElementType.Object     : ('Object', None),
}


class SignatureKind(enum.IntEnum):
    Default      = 0x0 # noqa
    C            = 0x1 # noqa
    StdCall      = 0x2 # noqa
    ThisCall     = 0x3 # noqa
    FastCall     = 0x4 # noqa
    VarArg       = 0x5 # noqa
    Field        = 0x6 # noqa
    Local        = 0x7 # noqa
    Property     = 0x8 # noqa
    Unmanaged    = 0x9 # noqa
    GenericInst  = 0xA # noqa
    NativeVarArg = 0xB # noqa


GENERIC_FLAG    = 0x10 # noqa
HAS_THIS_FLAG   = 0x20 # noqa
EXPLICIT_THIS   = 0x40 # noqa


class TypeSig:
    element_type: ElementType

    @property
    def name(self) -> str:
        return ''

    @property
    def byte_size(self) -> int | None:
        return None


class PrimitiveTypeSig(TypeSig):
    def __init__(self, element_type: ElementType):
        info = _PRIMITIVE_INFO.get(element_type)
        self.element_type = element_type
        self._name = info[0] if info else element_type.name
        self._byte_size = info[1] if info else None

    @property
    def name(self) -> str:
        return self._name

    @property
    def byte_size(self) -> int | None:
        return self._byte_size


class TypeDefOrRefSig(TypeSig):
    def __init__(
        self,
        element_type: ElementType,
        table_id: int,
        row_index: int,
    ):
        self.element_type = element_type
        self.table_id = table_id
        self.row_index = row_index
        self.is_value_type = element_type == ElementType.ValueType

    @property
    def name(self) -> str:
        prefix = 'valuetype' if self.is_value_type else 'class'
        return F'{prefix}({self.table_id}:{self.row_index})'

    @property
    def byte_size(self) -> int | None:
        return None


class SzArrayTypeSig(TypeSig):
    element_type = ElementType.SzArray

    def __init__(self, element: TypeSig):
        self.element = element

    @property
    def name(self) -> str:
        return F'{self.element.name}[]'

    @property
    def byte_size(self) -> int | None:
        return None


class ArrayTypeSig(TypeSig):
    element_type = ElementType.Array

    def __init__(
        self,
        element: TypeSig,
        rank: int,
        sizes: list[int],
        lower_bounds: list[int],
    ):
        self.element = element
        self.rank = rank
        self.sizes = sizes
        self.lower_bounds = lower_bounds

    @property
    def name(self) -> str:
        dims = ','.join([''] * (self.rank - 1))
        return F'{self.element.name}[{dims}]'

    @property
    def byte_size(self) -> int | None:
        return None


class GenericInstTypeSig(TypeSig):
    element_type = ElementType.GenericInst

    def __init__(self, generic_type: TypeSig, type_arguments: list[TypeSig]):
        self.generic_type = generic_type
        self.type_arguments = type_arguments

    @property
    def name(self) -> str:
        args = ', '.join(a.name for a in self.type_arguments)
        return F'{self.generic_type.name}<{args}>'

    @property
    def byte_size(self) -> int | None:
        return None


class PointerTypeSig(TypeSig):
    element_type = ElementType.Ptr

    def __init__(self, element: TypeSig):
        self.element = element

    @property
    def name(self) -> str:
        return F'{self.element.name}*'

    @property
    def byte_size(self) -> int | None:
        return None


class ByRefTypeSig(TypeSig):
    element_type = ElementType.ByRef

    def __init__(self, element: TypeSig):
        self.element = element

    @property
    def name(self) -> str:
        return F'{self.element.name}&'

    @property
    def byte_size(self) -> int | None:
        return None


class GenericVarSig(TypeSig):
    element_type = ElementType.Var

    def __init__(self, index: int):
        self.index = index

    @property
    def name(self) -> str:
        return F'!{self.index}'

    @property
    def byte_size(self) -> int | None:
        return None


class GenericMVarSig(TypeSig):
    element_type = ElementType.MVar

    def __init__(self, index: int):
        self.index = index

    @property
    def name(self) -> str:
        return F'!!{self.index}'

    @property
    def byte_size(self) -> int | None:
        return None


class CustomModTypeSig(TypeSig):
    def __init__(
        self,
        modifier: TypeDefOrRefSig,
        required: bool,
        inner: TypeSig,
    ):
        self.element_type = (
            ElementType.CModReqD if required else ElementType.CModOpt
        )
        self.modifier = modifier
        self.required = required
        self.inner = inner

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def byte_size(self) -> int | None:
        return self.inner.byte_size


class PinnedTypeSig(TypeSig):
    element_type = ElementType.Pinned

    def __init__(self, element: TypeSig):
        self.element = element

    @property
    def name(self) -> str:
        return self.element.name

    @property
    def byte_size(self) -> int | None:
        return self.element.byte_size


class FnPtrTypeSig(TypeSig):
    element_type = ElementType.FnPtr

    def __init__(self, method: MethodSig):
        self.method = method

    @property
    def name(self) -> str:
        return 'method_ptr'

    @property
    def byte_size(self) -> int | None:
        return None


class SentinelTypeSig(TypeSig):
    element_type = ElementType.Sentinel

    @property
    def name(self) -> str:
        return '...'

    @property
    def byte_size(self) -> int | None:
        return None


class CallingConventionSig:
    def __init__(self, attributes: int):
        self.attributes = attributes


class FieldSig(CallingConventionSig):
    def __init__(self, attributes: int, field_type: TypeSig):
        super().__init__(attributes)
        self.field_type = field_type


class MethodSig(CallingConventionSig):
    def __init__(
        self,
        attributes: int,
        return_type: TypeSig,
        param_types: list[TypeSig],
        generic_param_count: int = 0,
    ):
        super().__init__(attributes)
        self.return_type = return_type
        self.param_types = param_types
        self.generic_param_count = generic_param_count


class PropertySig(CallingConventionSig):
    def __init__(
        self,
        attributes: int,
        property_type: TypeSig,
        param_types: list[TypeSig],
    ):
        super().__init__(attributes)
        self.property_type = property_type
        self.param_types = param_types


class LocalVarSig(CallingConventionSig):
    def __init__(self, attributes: int, variable_types: list[TypeSig]):
        super().__init__(attributes)
        self.variable_types = variable_types


class GenericInstMethodSig(CallingConventionSig):
    def __init__(self, attributes: int, type_arguments: list[TypeSig]):
        super().__init__(attributes)
        self.type_arguments = type_arguments


def _read_type_def_or_ref_coded(reader: DotNetStructReader) -> tuple[int, int]:
    coded = reader.read_dn_length_prefix()
    tag = coded & 0x3
    row = coded >> 2
    return tag, row


def _read_type(reader: DotNetStructReader) -> TypeSig:
    et = reader.u8fast()

    while et in (ElementType.CModReqD, ElementType.CModOpt):
        required = et == ElementType.CModReqD
        tag, row = _read_type_def_or_ref_coded(reader)
        modifier = TypeDefOrRefSig(ElementType(et), tag, row)
        inner = _read_type(reader)
        return CustomModTypeSig(modifier, required, inner)

    if et == ElementType.Pinned:
        return PinnedTypeSig(_read_type(reader))

    if et in _PRIMITIVE_INFO:
        return PrimitiveTypeSig(ElementType(et))

    if et in (ElementType.ValueType, ElementType.Class):
        tag, row = _read_type_def_or_ref_coded(reader)
        return TypeDefOrRefSig(ElementType(et), tag, row)

    if et == ElementType.SzArray:
        return SzArrayTypeSig(_read_type(reader))

    if et == ElementType.Array:
        element = _read_type(reader)
        rank = reader.read_dn_length_prefix()
        num_sizes = reader.read_dn_length_prefix()
        sizes = [reader.read_dn_length_prefix() for _ in range(num_sizes)]
        num_lo = reader.read_dn_length_prefix()
        lower_bounds = [
            reader.read_dn_length_prefix() for _ in range(num_lo)
        ]
        return ArrayTypeSig(element, rank, sizes, lower_bounds)

    if et == ElementType.GenericInst:
        generic_type = _read_type(reader)
        count = reader.read_dn_length_prefix()
        type_args = [_read_type(reader) for _ in range(count)]
        return GenericInstTypeSig(generic_type, type_args)

    if et == ElementType.Ptr:
        return PointerTypeSig(_read_type(reader))

    if et == ElementType.ByRef:
        return ByRefTypeSig(_read_type(reader))

    if et == ElementType.Var:
        return GenericVarSig(reader.read_dn_length_prefix())

    if et == ElementType.MVar:
        return GenericMVarSig(reader.read_dn_length_prefix())

    if et == ElementType.FnPtr:
        method = _read_method_sig(reader)
        return FnPtrTypeSig(method)

    if et == ElementType.Sentinel:
        return SentinelTypeSig()

    return PrimitiveTypeSig(ElementType(et))


def _read_field_sig(reader: DotNetStructReader) -> FieldSig:
    attributes = reader.u8fast()
    field_type = _read_type(reader)
    return FieldSig(attributes, field_type)


def _read_method_sig(reader: DotNetStructReader) -> MethodSig:
    attributes = reader.u8fast()
    generic_param_count = 0
    if attributes & GENERIC_FLAG:
        generic_param_count = reader.read_dn_length_prefix()
    param_count = reader.read_dn_length_prefix()
    return_type = _read_type(reader)
    param_types = [_read_type(reader) for _ in range(param_count)]
    return MethodSig(attributes, return_type, param_types, generic_param_count)


def _read_property_sig(reader: DotNetStructReader) -> PropertySig:
    attributes = reader.u8fast()
    param_count = reader.read_dn_length_prefix()
    property_type = _read_type(reader)
    param_types = [_read_type(reader) for _ in range(param_count)]
    return PropertySig(attributes, property_type, param_types)


def _read_local_var_sig(reader: DotNetStructReader) -> LocalVarSig:
    attributes = reader.u8fast()
    count = reader.read_dn_length_prefix()
    variable_types = [_read_type(reader) for _ in range(count)]
    return LocalVarSig(attributes, variable_types)


def _read_generic_inst_method_sig(
    reader: DotNetStructReader,
) -> GenericInstMethodSig:
    attributes = reader.u8fast()
    count = reader.read_dn_length_prefix()
    type_args = [_read_type(reader) for _ in range(count)]
    return GenericInstMethodSig(attributes, type_args)


def parse_signature(
    data: bytes | bytearray | memoryview,
) -> CallingConventionSig:
    """
    Parse a .NET metadata blob signature. The first byte determines the signature kind (field,
    method, property, local variables, etc.) and the remaining bytes encode type information
    per ECMA-335 II.23.2.
    """
    reader = DotNetStructReader(memoryview(bytearray(data)))
    first = data[0]
    kind = first & 0x0F
    if kind == SignatureKind.Field:
        return _read_field_sig(reader)
    if kind == SignatureKind.Local:
        return _read_local_var_sig(reader)
    if kind == SignatureKind.Property:
        return _read_property_sig(reader)
    if kind == SignatureKind.GenericInst:
        return _read_generic_inst_method_sig(reader)
    return _read_method_sig(reader)
