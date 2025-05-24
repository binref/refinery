#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest
from collections import defaultdict
from typing import List, Tuple

from refinery.lib.dotnet.disassembler import Disassembler, Instruction, OpRepository
from refinery.lib.dotnet.disassembler.factory import OutputFactory
from .. import TestBase


class TestRepository(unittest.TestCase):
    def test_endfinally_endfault(self):
        rep = OpRepository()
        by_opcode = defaultdict(list)
        for op in rep.INSTRUCTIONS:
            if op.is_alias:
                continue
            by_opcode[op.code].append(op)

        aliases = [lst for lst in by_opcode.values() if len(lst) != 1]
        self.assertEqual(1, len(aliases))
        self.assertEqual(2, len(aliases[0]))
        self.assertTrue('endfault' in [op.mnemonic for op in aliases[0]])
        self.assertTrue('endfinally' in [op.mnemonic for op in aliases[0]])

    def test_has_code_offsets(self):
        rep = OpRepository()
        for op in rep.INSTRUCTIONS:
            if op.mnemonic[0:2] != 'br' or op.mnemonic == 'break':
                continue
            self.assertEqual(1, len(op.arguments))
            self.assertTrue(op.arguments[0].has_target)

    def test_has_at_most_one_argument(self):
        rep = OpRepository()
        for op in rep.INSTRUCTIONS:
            if not op.arguments:
                continue
            if not op.fixed_length:  # for the 'switch' Op
                continue
            self.assertEqual(1, len(op.arguments))


class TestDotNetDisassembler(TestBase):
    OBFUSCATED_ASM = '''7E290000048E3A29000000735200000A8006000004735300000A801B0000047E2200000472140300706F2B00000A0228240000067E050000041F4B3C9800000017735400000A6F5500000A0A7E22000004066F3B00000A6F1400000A285600000A3966000000160B066F3B00000A6F1400000A6F5700000A6F5800000A0C7E220000046F5900000A0D16130438250000000911049A13050811056F5800000A285A00000A3907000000170B38100000001104175813041104098E693FD1FFFFFF073A06000000735B00000A7A7E05000004175880050000047E25000004130616130711061207282900000A7E2900000402285C00000A130811087E1B0000046F5D00000A3C250000007E1B00000411086F5E00000A0240130000007E0600000411086F5F00000A1309DD8D00000000288400000611088D23000001130A7E29000004021A58110A161108281C00000A286000000A110A16110A8E696F6100000A130B7E06000004110B6F6200000A7E1B000004026F6300000A7E060000046F6400000A1759286500000A167E29000004021A281C00000A110B1309DD1B00000026DD0F000000110739070000001106283200000ADC72600300702A11092A'''
    STEAM_GRABBER = '''7280640070289800000A0A068E39E700000006169A6F6101000A6F6201000A728C640070727D4E00706F6301000A289200000A7251290070286A00000A7E42000004289200000A729E640070286A00000A0B25286B00000A2572B4640070286401000A0C2572C0640070286401000A0D72E8640070286401000A13040809281300002B1104281300002B13050717284C01000A130611056F0900000A1307381500000011076F0800000A1308110611081108285001000A2611076F0400000A3ADFFFFFFFDD1E0000001107390700000011076F0300000ADC1106390700000011066F0300000ADC07725462007028730100060728A700000A2A7208650070726E19007028740100062A'''

    def assertSimilarDnSpyOutput(self, dn_str: str):
        asm, dn_lines = self._parse_dn_spy_putput(dn_str)
        lst = list(Disassembler().disasm(asm))
        self.assertEqual(len(lst), len(dn_lines))
        for ins, dn_line in zip(lst, dn_lines):
            # print('---')
            # print(dn_line)
            # print(ins)
            self.assertTrue(ins.op.mnemonic in dn_line)
            self.assertTrue(ins.data.hex().upper() in dn_line)
            self.assertTrue('IL_' in dn_line)
            self.assertTrue(F"{ins.offset:X}" in dn_line)

    @staticmethod
    def _parse_dn_spy_putput(dn_str: str) -> Tuple[bytes, List[str]]:
        asm = ''
        dn_lines = []
        for line in dn_str.splitlines():
            line = line.strip()
            if not line:
                continue
            dn_lines.append(line)
            asm += line.split(' ')[2]
        return bytes.fromhex(asm), dn_lines

    def assertInstructionCount(self, expected_cnt: int, hex_encoded_asm: str):
        cnt = 0
        for ins in Disassembler().disasm(bytes.fromhex(hex_encoded_asm)):
            self.assertTrue(isinstance(ins, Instruction))
            cnt += 1
        self.assertEqual(expected_cnt, cnt)

    def test_hello_world_asm(self):
        self.assertInstructionCount(5, '007201000070280700000A002A')

    def test_loop_asm(self):
        asm = '00028E16FE030A062C0B0002169A280700000A0000160B2B28007211000070078C0B000001280800000A007233000070078C0B000001280800000A00000717580B071F0AFE040C082DCF2A'
        self.assertInstructionCount(41, asm)

    def test_steam_grabber(self):
        self.assertInstructionCount(81, self.STEAM_GRABBER)

    def test_steam_grabber_output(self):
        of = OutputFactory(il_refs=True)
        il_reference_found = False
        for ins in Disassembler().disasm(bytes.fromhex(self.STEAM_GRABBER)):
            p = of.instruction(ins)
            if ' -> IL_00F9' in p:
                il_reference_found = True
        self.assertTrue(il_reference_found)

    def test_obfuscated(self):
        self.assertInstructionCount(144, self.OBFUSCATED_ASM)

    def test_output(self):
        dn_spy_output = '''
		/* 0x00005674 7E2F000004   */ IL_0000: ldsfld    bool WFvT84mYy0ls1dobk9.mlJ2B5EJ2bwgyDPhBV::oyid7sovw8
		/* 0x00005679 3A3D000000   */ IL_0005: brtrue    IL_0047

		/* 0x0000567E 17           */ IL_000A: ldc.i4.1
		/* 0x0000567F 802F000004   */ IL_000B: stsfld    bool WFvT84mYy0ls1dobk9.mlJ2B5EJ2bwgyDPhBV::oyid7sovw8
		/* 0x00005684 280400000A   */ IL_0010: call      valuetype [mscorlib]System.DateTime [mscorlib]System.DateTime::get_Now()
		/* 0x00005689 20E8070000   */ IL_0015: ldc.i4    2024
		/* 0x0000568E 1F02         */ IL_001A: ldc.i4.s  2
		/* 0x00005690 1F06         */ IL_001C: ldc.i4.s  6
		/* 0x00005692 730500000A   */ IL_001E: newobj    instance void [mscorlib]System.DateTime::.ctor(int32, int32, int32)
		/* 0x00005697 280600000A   */ IL_0023: call      valuetype [mscorlib]System.TimeSpan [mscorlib]System.DateTime::op_Subtraction(valuetype [mscorlib]System.DateTime, valuetype [mscorlib]System.DateTime)
		/* 0x0000569C 0A           */ IL_0028: stloc.0
		/* 0x0000569D 1200         */ IL_0029: ldloca.s  V_0
		/* 0x0000569F 280700000A   */ IL_002B: call      instance int32 [mscorlib]System.TimeSpan::get_Days()
		/* 0x000056A4 288B00000A   */ IL_0030: call      int32 [mscorlib]System.Math::Abs(int32)
		/* 0x000056A9 1F0E         */ IL_0035: ldc.i4.s  14
		/* 0x000056AB 3F0B000000   */ IL_0037: blt       IL_0047

		/* 0x000056B0 7201000070   */ IL_003C: ldstr     "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"! This assembly won't further work."
		/* 0x000056B5 730800000A   */ IL_0041: newobj    instance void [mscorlib]System.Exception::.ctor(string)
		/* 0x000056BA 7A           */ IL_0046: throw

		/* 0x000056BB 2A           */ IL_0047: ret
        '''
        self.assertSimilarDnSpyOutput(dn_spy_output)
        asm = ''.join(line.strip()[14:24].strip() for line in dn_spy_output.splitlines())
        of = OutputFactory()
        line_found = False
        for ins in Disassembler().disasm(bytes.fromhex(asm)):
            p = of.instruction(ins)
            if '/* 730500000a   */ IL_001E: newobj(0xA000005)' in p:
                line_found = True
        self.assertTrue(line_found)

    def test_nested_if(self):
        asm = '''0002179A281000000A0A060C080B07163207071F64300F2B1A7201000070281100000A002B3C7225000070281100000A002B2F12031F0917281200000A12037247000070281300000A00120306280100002B001203281500000A281100000A002B002A'''
        token_labels = {
            0x1: "Value is negative",
            0x25: "Value is too big",
            0x47: "Value is ",
            0xA000010: "System.Convert::ToInt32",
            0xA000011: "System.Console::WriteLine",
            0xA000012: "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::.ctor",
            0xA000013: "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendLiteral",
            0x2B000001: "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::AppendFormatted",
            0xA000015: "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler::ToStringAndClear",
        }
        of = OutputFactory(token_labels=token_labels)
        seen_tokens = set()
        for ins in Disassembler().disasm(bytes.fromhex(asm)):
            p = of.instruction(ins)
            for token, token_label in token_labels.items():
                if token_label in p:
                    seen_tokens.add(token)
        self.assertEqual(set(token_labels.keys()), seen_tokens)

    def test_switch(self):
        asm = '''0002179A280D00000A0A060C080B074503000000020000000F0000001C0000002B277201000070280E00000A002B49721D000070280E00000A002B3C7237000070280E00000A002B2F12031F0917280F00000A12037251000070281000000A00120306280100002B001203281200000A280E00000A002B002A'''
        of = OutputFactory(il_refs=True)
        lst = list(Disassembler().disasm(bytes.fromhex(asm)))

        # check if switch is directly followed by br.s and also if pretty print "looks good"
        state = 0
        found = False
        for ins in lst:
            if state == 0:
                if ins.op.mnemonic == 'switch':
                    self.assertEqual(4, len(ins.arguments))
                    state = 1
            elif state == 1:
                self.assertEqual('br.s', ins.op.mnemonic)
                state = 2

            p = of.instruction(ins)
            if '/* 4503000000020000000f0000001c000000 */ ' in p:
                found = True
                self.assertTrue('IL_0022, IL_002F, IL_003C' in p)
        self.assertEqual(2, state)
        self.assertTrue(found)

    def test_refanyval(self):
        self.assertSimilarDnSpyOutput('''
/* 0x0000025C 00           */ IL_0000: nop
/* 0x0000025D 7201000070   */ IL_0001: ldstr     "1"
/* 0x00000262 0A           */ IL_0006: stloc.0
/* 0x00000263 16           */ IL_0007: ldc.i4.0
/* 0x00000264 0B           */ IL_0008: stloc.1
/* 0x00000265 1201         */ IL_0009: ldloca.s  b
/* 0x00000267 C610000001   */ IL_000B: mkrefany  [System.Runtime]System.Int32
/* 0x0000026C 0C           */ IL_0010: stloc.2
/* 0x0000026D 06           */ IL_0011: ldloc.0
/* 0x0000026E 08           */ IL_0012: ldloc.2
/* 0x0000026F C210000001   */ IL_0013: refanyval [System.Runtime]System.Int32
/* 0x00000274 280D00000A   */ IL_0018: call      bool [System.Runtime]System.Int32::TryParse(string, int32&)
/* 0x00000279 26           */ IL_001D: pop
/* 0x0000027A 2A           */ IL_001E: ret
''')

    def test_unbox(self):
        self.assertSimilarDnSpyOutput('''
/* 0x00000284 00           */ IL_0000: nop
/* 0x00000285 1202         */ IL_0001: ldloca.s  V_2
/* 0x00000287 FE1503000002 */ IL_0003: initobj   HelloClass/MyStruct
/* 0x0000028D 08           */ IL_0009: ldloc.2
/* 0x0000028E 8C03000002   */ IL_000A: box       HelloClass/MyStruct
/* 0x00000293 0A           */ IL_000F: stloc.0
/* 0x00000294 06           */ IL_0010: ldloc.0
/* 0x00000295 7903000002   */ IL_0011: unbox     HelloClass/MyStruct
/* 0x0000029A 7B01000004   */ IL_0016: ldfld     int32 HelloClass/MyStruct::A
/* 0x0000029F 0B           */ IL_001B: stloc.1
/* 0x000002A0 07           */ IL_001C: ldloc.1
/* 0x000002A1 0D           */ IL_001D: stloc.3
/* 0x000002A2 2B00         */ IL_001E: br.s      IL_0020
/* 0x000002A4 09           */ IL_0020: ldloc.3
/* 0x000002A5 2A           */ IL_0021: ret
		''')


if __name__ == '__main__':
    unittest.main()
