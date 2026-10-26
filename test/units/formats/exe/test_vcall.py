from refinery.units.formats.exe.vcall import (
    AllocBase,
    ArgRef,
    ArgSlot,
    BytesType,
    Deref,
    LengthBase,
    LengthOf,
    Literal,
    OutBinding,
    Ref,
    RV,
    StructSpec,
    StructType,
    ValueBase,
    Evaluator,
    parse_arg_slot,
    parse_out_binding,
)

import hashlib
import struct

from refinery.lib.emulator import Arch, CC, Engine, Hook
from refinery.units import Chunk

from ... import TestUnitBase


def _minimal_pe64(code: bytes, image_base: int = 0x140000000) -> bytes:
    """
    Hand-craft the smallest PE32+ that both LIEF and speakeasy accept.
    """
    align_s = 0x1000
    align_f = 0x200
    text_rva = 0x1000
    raw_size = (len(code) + align_f - 1) // align_f * align_f

    dos = B'MZ' + bytes(0x3A) + struct.pack('<I', 0x40)
    coff = struct.pack('<HHIIIHH',
        0x8664,            # Machine: AMD64
        1,                 # NumberOfSections
        0, 0, 0,           # TimeDateStamp, symbol table, symbol count
        0xF0,              # SizeOfOptionalHeader
        0x0023,            # Characteristics: RELOCS_STRIPPED | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    opt = struct.pack('<HBB', 0x20B, 1, 0)                            # magic, linker version
    opt += struct.pack('<III', raw_size, 0, 0)                        # code, initialized, uninitialized
    opt += struct.pack('<II', text_rva, text_rva)                     # entry point, base of code
    opt += struct.pack('<Q', image_base)                              # ImageBase
    opt += struct.pack('<II', align_s, align_f)                       # alignments
    opt += struct.pack('<HHHHHH', 6, 0, 0, 0, 6, 0)                   # OS, image, subsystem versions
    opt += struct.pack('<I', 0)                                       # Win32VersionValue
    opt += struct.pack('<II', text_rva + align_s, align_f)            # SizeOfImage, SizeOfHeaders
    opt += struct.pack('<I', 0)                                       # CheckSum
    opt += struct.pack('<HH', 3, 0)                                   # Subsystem: console, DllCharacteristics
    opt += struct.pack('<QQQQ', 0x100000, 0x1000, 0x100000, 0x1000)   # stack and heap, reserve and commit
    opt += struct.pack('<II', 0, 16)                                  # LoaderFlags, NumberOfRvaAndSizes
    opt += bytes(16 * 8)                                              # data directories, all empty
    assert len(opt) == 0xF0
    sect = struct.pack('<8sIIIIIIHHI',
        B'.text\0\0\0',    # Name
        len(code),         # VirtualSize
        text_rva,          # VirtualAddress
        raw_size,          # SizeOfRawData
        align_f,           # PointerToRawData
        0, 0, 0, 0,        # relocation and line number bookkeeping
        0x60000020,        # Characteristics: CODE | EXECUTE | READ
    )
    header = dos + B'PE\0\0' + coff + opt + sect
    assert len(header) <= align_f
    return header.ljust(align_f, B'\0') + code.ljust(raw_size, B'\0')


class TestVCallSpec(TestUnitBase):

    def test_arg_scalar_value(self):
        self.assertEqual(
            parse_arg_slot('0x40'),
            ArgSlot(0, None, ValueBase('0x40'), None))

    def test_arg_named_scalar_echo(self):
        self.assertEqual(
            parse_arg_slot('len=0x20'),
            ArgSlot(0, 'len', ValueBase('0x20'), None))

    def test_arg_named_inbuffer(self):
        self.assertEqual(
            parse_arg_slot('data=H:deadbeef'),
            ArgSlot(0, 'data', ValueBase('H:deadbeef'), None))

    def test_arg_value_with_equals_in_multibin(self):
        self.assertEqual(
            parse_arg_slot('b64:SGVsbG8='),
            ArgSlot(0, None, ValueBase('b64:SGVsbG8='), None))

    def test_arg_out_int(self):
        self.assertEqual(
            parse_arg_slot('n=[#I]'),
            ArgSlot(0, 'n', AllocBase(StructSpec('I')), None))

    def test_arg_out_buffer_literal_size(self):
        self.assertEqual(
            parse_arg_slot('key=[16]'),
            ArgSlot(0, 'key', AllocBase(Literal('16')), None))

    def test_arg_out_buffer_readback_length(self):
        self.assertEqual(
            parse_arg_slot('data=[0x1000]:n'),
            ArgSlot(0, 'data', AllocBase(Literal('0x1000')), BytesType(Ref('n'))))

    def test_arg_out_buffer_pointer_size(self):
        self.assertEqual(
            parse_arg_slot('p=[#p]'),
            ArgSlot(0, 'p', AllocBase(StructSpec('p')), None))

    def test_arg_alloc_size_struct_multifield(self):
        self.assertEqual(
            parse_arg_slot('hdr=[#IIH]'),
            ArgSlot(0, 'hdr', AllocBase(StructSpec('IIH')), None))

    def test_arg_boxed_pointer_to_pointer(self):
        self.assertEqual(
            parse_arg_slot('@n=[#I]'),
            ArgSlot(1, 'n', AllocBase(StructSpec('I')), None))

    def test_arg_double_boxed(self):
        self.assertEqual(
            parse_arg_slot('@@k=[16]'),
            ArgSlot(2, 'k', AllocBase(Literal('16')), None))

    def test_arg_boxed_scalar(self):
        self.assertEqual(
            parse_arg_slot('@0x40'),
            ArgSlot(1, None, ValueBase('0x40'), None))

    def test_arg_length_of_binding(self):
        self.assertEqual(
            parse_arg_slot('.src'),
            ArgSlot(0, None, LengthBase('src'), None))

    def test_arg_alloc_same_size_as_binding(self):
        self.assertEqual(
            parse_arg_slot('out=[.data]'),
            ArgSlot(0, 'out', AllocBase(LengthOf('data')), None))

    def test_out_return_value_typed(self):
        self.assertEqual(
            parse_out_binding('rc=rv:#i'),
            OutBinding('rc', RV(), StructType('i')))

    def test_out_return_value_default(self):
        self.assertEqual(
            parse_out_binding('r=rv'),
            OutBinding('r', RV(), None))

    def test_out_pointer_return_cstring(self):
        self.assertEqual(
            parse_out_binding('s=[rv]:#a'),
            OutBinding('s', Deref(RV()), StructType('a')))

    def test_out_global_bytes(self):
        self.assertEqual(
            parse_out_binding('table=[0x402000]:256'),
            OutBinding('table', Deref(Literal('0x402000')), BytesType(Literal('256'))))

    def test_out_arg_ref_default(self):
        self.assertEqual(
            parse_out_binding('p=a2'),
            OutBinding('p', ArgRef(2), None))

    def test_out_double_deref_arg(self):
        self.assertEqual(
            parse_out_binding('n=[[a0]]:#I'),
            OutBinding('n', Deref(Deref(ArgRef(0))), StructType('I')))

    def test_reject_variable_length_alloc(self):
        with self.assertRaises(ValueError):
            parse_arg_slot('s=[#a]')

    def test_reject_unknown_struct_letter(self):
        with self.assertRaises(ValueError):
            parse_arg_slot('x=[#Z]')

    def test_reject_out_binding_without_name(self):
        with self.assertRaises(ValueError):
            parse_out_binding('rv:#i')

    def test_reject_unbalanced_brackets(self):
        with self.assertRaises(ValueError):
            parse_arg_slot('x=[16')


class TestVCallSetup(TestUnitBase):

    def _rv(self, code: bytes, *tokens: str, cc=CC.StdCall, arch=Arch.X64) -> int:
        emu = Engine.unicorn.cls(code, None, arch, Hook.Errors).reset()
        evaluator = Evaluator(emu, Chunk(code), cc)
        evaluator.setup([parse_arg_slot(token) for token in tokens])
        return evaluator.invoke(emu.base_exe_to_emu(0), None, 0)

    def test_int_return(self):
        code = bytes.fromhex('B82A000000C3')  # mov eax, 0x2A ; ret
        self.assertEqual(self._rv(code), 0x2A)

    def test_scalar_arguments_are_added(self):
        code = bytes.fromhex('89C801D0C3')  # mov eax, ecx ; add eax, edx ; ret
        self.assertEqual(self._rv(code, '3', '4'), 7)

    def test_input_buffer_is_passed_by_pointer(self):
        code = bytes.fromhex('0FB601C3')  # movzx eax, byte ptr [rcx] ; ret
        self.assertEqual(self._rv(code, 'H:41'), 0x41)

    def test_boxed_scalar_is_passed_by_pointer(self):
        code = bytes.fromhex('8B01C3')  # mov eax, dword ptr [rcx] ; ret
        self.assertEqual(self._rv(code, '@0x40'), 0x40)


class TestVCallExtract(TestUnitBase):

    def _meta(self, code: bytes, tokens=(), outs=(), cc=CC.StdCall, arch=Arch.X64) -> dict:
        emu = Engine.unicorn.cls(code, None, arch, Hook.Errors).reset()
        evaluator = Evaluator(emu, Chunk(code), cc)
        evaluator.setup([parse_arg_slot(token) for token in tokens])
        evaluator.invoke(emu.base_exe_to_emu(0), None, 0)
        return evaluator.extract([parse_out_binding(out) for out in outs])

    def test_out_int_parameter(self):
        code = bytes.fromhex('C70134120000C3')  # mov dword ptr [rcx], 0x1234 ; ret
        self.assertEqual(self._meta(code, ['n=[#I]'])['n'], 0x1234)

    def test_out_buffer(self):
        code = bytes.fromhex('C70141424344C3')  # mov dword ptr [rcx], 0x44434241 ; ret
        self.assertEqual(self._meta(code, ['out=[4]'])['out'], B'ABCD')

    def test_in_place_buffer(self):
        code = bytes.fromhex('830101C3')  # add dword ptr [rcx], 1 ; ret
        self.assertEqual(self._meta(code, ['data=H:41424344'])['data'], bytes.fromhex('42424344'))

    def test_pointer_return_cstring(self):
        code = bytes.fromhex('4889C8C3')  # mov rax, rcx ; ret
        self.assertEqual(self._meta(code, ['H:48656C6C6F00'], ['s=[rv]:#a'])['s'], B'Hello')

    def test_length_dependent_output(self):
        code = bytes.fromhex('C70141424344C70204000000C3')  # [rcx]=ABCD ; [rdx]=4 ; ret
        meta = self._meta(code, ['data=[0x40]:n', 'n=[#I]'])
        self.assertEqual(meta['n'], 4)
        self.assertEqual(meta['data'], B'ABCD')

    def test_pointer_to_pointer_inner_int(self):
        code = bytes.fromhex('488B01C70099000000C3')  # rax=[rcx] ; [rax]=0x99 ; ret
        self.assertEqual(self._meta(code, ['@n=[#I]'])['n'], 0x99)

    def test_multifield_struct_readback(self):
        code = bytes.fromhex('C70101000000C7410402000000C3')  # [rcx]=1 ; [rcx+4]=2 ; ret
        self.assertEqual(self._meta(code, ['hdr=[#II]'])['hdr'], [1, 2])


class TestVCallUnit(TestUnitBase):

    def _run(self, code: bytes, *args, **kwargs) -> Chunk:
        result = next(code | self.load(*args, **kwargs))
        assert isinstance(result, Chunk)
        return result

    def test_return_value_via_ret(self):
        code = bytes.fromhex('B82A000000C3')  # mov eax, 0x2A ; ret
        result = self._run(code, '0', arch='x64', ret='retval')
        self.assertEqual(result.meta['retval'], 0x2A)
        self.assertEqual(bytes(result), code)

    def test_named_out_int_argument(self):
        code = bytes.fromhex('C70134120000C3')  # mov dword ptr [rcx], 0x1234 ; ret
        result = self._run(code, '0', 'n=[#I]', arch='x64')
        self.assertEqual(result.meta['n'], 0x1234)

    def test_out_binding_cstring(self):
        code = bytes.fromhex('4889C8C3')  # mov rax, rcx ; ret
        result = self._run(code, '0', 'H:48656C6C6F00', out=['s=[rv]:#a'], arch='x64')
        self.assertEqual(result.meta['s'], B'Hello')

    def test_buffer_and_length_arguments(self):
        code = bytes.fromhex('C70141424344C70204000000C3')  # [rcx]=ABCD ; [rdx]=4 ; ret
        result = self._run(code, '0', 'data=[0x40]:n', 'n=[#I]', arch='x64')
        self.assertEqual(result.meta['n'], 4)
        self.assertEqual(result.meta['data'], B'ABCD')

    def test_aplib_extraction(self):
        """
        aplib-decompress the malicious payload with the shellcode's own aplib implementation
        """
        data = self.download_sample('ad320839e01df160c5feb0e89131521719a65ab11c952f33e03d802ecee3f51f')
        test = data | self.load_pipeline(
            'push [['
            '| vsnip 0x01011240:0x1e348'
            '| rex ..(..) {1} []'
            '| xor -B4 0x26FE'
            '| rotl -B4 4'
            '| add -B4 0x77777778'
            '| pop d ]'
            '| vsnip 0x01010648:0xbf4'
            '| alu -B4 L(B@0x10a1,4)+0x77777778'
            '| vcall 0x940 v:d p=[2M]'
            '| eat p'
            '| pestrip ]'
        ) | bytearray
        self.assertEqual(
            hashlib.sha256(test).hexdigest(),
            'f31468c95437a0c99be5551536b64576e21eeacfd43b0c63b020cdc10465a01b'
        )


class TestVCallX64StackArguments(TestUnitBase):
    FIFTH = 0xA5A5A5A5
    SIXTH = 0x5A5A5A5A

    SHELLCODE = bytes.fromhex(
        '488b442428c39090'                           # 0x00: mov rax, [rsp+0x28] ; ret
        '488b442430c39090'                           # 0x08: mov rax, [rsp+0x30] ; ret
        '4889e04883e00fc3'                           # 0x10: mov rax, rsp ; and rax, 0xF ; ret
        '488b4424284803442430c3' + '90' * 5          # 0x18: mov rax, [rsp+0x28] ; add rax, [rsp+0x30] ; ret
    )

    def _call(self, engine: Engine, offset: int, *tokens: str) -> int:
        pe = engine is Engine.speakeasy
        data = _minimal_pe64(self.SHELLCODE) if pe else self.SHELLCODE
        emu = engine.cls(data, None, Arch.X64, Hook.Errors).reset()
        evaluator = Evaluator(emu, Chunk(data), CC.StdCall)
        evaluator.setup([parse_arg_slot(token) for token in tokens])
        va = (0x140001000 if pe else 0) + offset
        return evaluator.invoke(emu.base_exe_to_emu(va), None, 0)

    def _arguments(self, stack_arguments: int = 2) -> tuple[str, ...]:
        return ('0', '0', '0', '0', hex(self.FIFTH), hex(self.SIXTH))[:4 + stack_arguments]

    def test_fifth_and_sixth_stack_arguments_are_delivered(self):
        for engine in (Engine.unicorn, Engine.speakeasy):
            for offset, expected in ((0x00, self.FIFTH), (0x08, self.SIXTH)):
                test = self._call(engine, offset, *self._arguments())
                self.assertEqual(test, expected, F'{engine.name} at shellcode offset 0x{offset:02X}')

    def test_stack_arguments_are_usable_together(self):
        for engine in (Engine.unicorn, Engine.speakeasy):
            test = self._call(engine, 0x18, *self._arguments())
            self.assertEqual(test, self.FIFTH + self.SIXTH, engine.name)

    def test_stack_is_16_byte_aligned_at_function_entry(self):
        for engine in (Engine.unicorn, Engine.speakeasy):
            for stack_arguments in (0, 1, 2):
                test = self._call(engine, 0x10, *self._arguments(stack_arguments))
                self.assertEqual(test, 8, F'{engine.name} with {stack_arguments} stack arguments')

    def test_zero_timeout_means_unlimited_instruction_budget(self):
        for engine in (Engine.unicorn, Engine.icicle, Engine.speakeasy):
            test = self._call(engine, 0x00, *self._arguments())
            self.assertEqual(test, self.FIFTH, engine.name)

    def test_pe_module_call_with_stack_arguments_through_the_unit(self):
        data = _minimal_pe64(self.SHELLCODE)
        result = next(data | self.load(
            '0x140001000', *self._arguments(), engine='speakeasy', ret='rv'))
        self.assertEqual(result.meta['rv'], self.FIFTH)
