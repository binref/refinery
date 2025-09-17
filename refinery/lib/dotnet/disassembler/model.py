from __future__ import annotations

import abc
import enum

from struct import unpack


class OpArgument(abc.ABC):
    def __init__(
        self,
        size: int = 4,
        has_target: bool = False,
        is_num: bool = False,
        is_idx: bool = False,
        is_arg_num: bool = False,
        is_casecnt: bool = False,
        is_caseargs: bool = False,
    ):
        self._size = size
        self.has_target = has_target
        self.is_num = is_num
        self.is_idx = is_idx
        self.is_arg_num = is_arg_num
        self.is_casecnt = is_casecnt
        self.is_caseargs = is_caseargs

    def __len__(self):
        return self._size

    def __repr__(self):
        bool_args = []
        if self.has_target:
            bool_args.append('has_target')
        if self.is_num:
            bool_args.append('is_num')
        if self.is_idx:
            bool_args.append('is_idx')
        if self.is_arg_num:
            bool_args.append('is_arg_num')
        if self.is_casecnt:
            bool_args.append('is_casecnt')
        if self.is_caseargs:
            bool_args.append('is_caseargs')
        bool_str = '' if len(bool_args) == 0 else f" {','.join(bool_args)}"

        return f"<{self.__class__.__name__} size={self._size}{bool_str}>"

    def unpack(self, value) -> int:
        return unpack('<I', value)[0]


class Int8(OpArgument):
    def __init__(self, has_target: bool = False, is_num: bool = False):
        super().__init__(1, has_target=has_target, is_num=is_num)

    def unpack(self, value: bytes) -> int:
        return unpack('<b', value)[0]


class Int32(OpArgument):
    def __init__(
        self, has_target: bool = False, is_num: bool = False, is_caseargs: bool = False
    ):
        super().__init__(4, has_target, is_num=is_num, is_caseargs=is_caseargs)

    def unpack(self, value: bytes) -> int:
        return unpack('<i', value)[0]


class Int64(OpArgument):
    def __init__(self, is_num: bool = False):
        super().__init__(8, is_num=is_num)

    def unpack(self, value: bytes) -> int:
        return unpack('<q', value)[0]


class UInt8(OpArgument):
    def __init__(self, is_num: bool = False, is_idx: bool = False, is_arg_num=True):
        super().__init__(1, is_num=is_num, is_idx=is_idx, is_arg_num=is_arg_num)

    def unpack(self, value: bytes) -> int:
        return unpack('<B', value)[0]


class UInt16(OpArgument):
    def __init__(
        self, is_num: bool = False, is_idx: bool = False, is_arg_num: bool = False
    ):
        super().__init__(2, is_num=is_num, is_idx=is_idx, is_arg_num=is_arg_num)

    def unpack(self, value: bytes) -> int:
        return unpack('<H', value)[0]


class UInt32(OpArgument):
    def __init__(self, is_casecnt: bool = False):
        super().__init__(4, is_casecnt=is_casecnt)


class Float32(OpArgument):
    def __init__(self, is_num: bool = False):
        super().__init__(4, is_num=is_num)


class Float64(OpArgument):
    def __init__(self, is_num: bool = False):
        super().__init__(8, is_num=is_num)


class String(OpArgument):
    def unpack(self, value) -> int:
        return unpack('<I', value[:-1] + b'\0')[0]


class TypeTok(OpArgument):
    pass


class Field(OpArgument):
    pass


class Class(OpArgument):
    pass


class Method(OpArgument):
    pass


class ValueType(OpArgument):
    pass


class ThisType(OpArgument):
    pass


class CallSiteDescr(OpArgument):
    pass


class Token(OpArgument):
    pass


class Etype(OpArgument):
    pass


class Ctor(OpArgument):
    pass


class Type(OpArgument):
    pass


class TokenLabel:
    def __init__(self, tid: int, value: str):
        self._tid = tid
        self._value = value


class OpType(str, enum.Enum):
    BASE = 'Base'
    OBJECT_MODEL = 'ObjectModel'
    PREFIX_TO = 'PrefixTo'


class Op(abc.ABC):
    """
    Specifier for a Common Intermediate Language (CIL) instruction. It is used to specify a complete list of all
    available instructions in the OpRepository. Instances of this class do not represent concrete instructions during
    disassembly, that what the Instruction class is for.
    """

    def __init__(
        self,
        op_type: OpType,
        code: bytes,
        mnemonic: str,
        arguments: list[OpArgument],
        description: str,
        is_switch: bool = False,
        is_alias: bool = False,
    ):
        self.op_type = op_type
        self.code = code
        self.mnemonic = mnemonic
        self.arguments = arguments
        self.description = description
        self.is_switch = is_switch
        self.is_alias = is_alias

    def __len__(self):
        return len(self.code) + sum(len(argument) for argument in self.arguments)

    def __repr__(self):
        return f"<Op{self.op_type.value} {self.mnemonic} arguments={self.arguments}>"

    @property
    def fixed_length(self):
        return not self.is_switch


class Argument:
    """
    Represents a concrete argument including value during dissassembly. Refer to `OpArgument` for the abstract
    description of an argument.
    """

    def __init__(self, data: bytes, op_argument: OpArgument):
        self._data = data
        self._op_argument = op_argument

    @property
    def value(self):
        return self._op_argument.unpack(self._data)

    def __repr__(self):
        return f"<Argument {self._op_argument.__class__.__name__}=0x{self.value:x}>"


class Instruction:
    """
    Represent a concrete instruction in memory. The `op` field carries the corresponding abstract `Op` instance
    describing the data in memory.
    """

    def __init__(self, data: bytes, offset: int, op: Op, arguments: list[Argument]):
        self.data = data
        self.offset = offset
        self.op = op
        self.arguments = arguments

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return f"<Instruction op={self.op} offset={self.offset} arguments={self.arguments}>"


class UnknownInstruction(Exception):
    pass


class DisassemblerException(Exception):
    pass
