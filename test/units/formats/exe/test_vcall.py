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

from refinery.lib.emulator import Arch, CC, Engine, Hook
from refinery.units import Chunk

from ... import TestUnitBase


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
