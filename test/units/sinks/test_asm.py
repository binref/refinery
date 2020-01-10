#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import TestUnitBase


class TestASM(TestUnitBase):

    def test_x64_shellcode(self):
        asm = self.load('x64')
        data = bytes.fromhex('4831C948F7E1043B48BB0A2F62696E2F2F736852530A545F5257545E0F05')
        result = asm(data)
        pattern = B'.*'.join([RB'\b%s\b' % oc for oc in [
            B'xor',
            B'mul',
            B'add',
            B'mov(abs)?',
            B'push',
            B'pop',
            B'push',
            B'push',
            B'push',
            B'pop',
            B'syscall'
        ]])
        self.assertIsNotNone(re.search(pattern, result, flags=re.DOTALL))

    def test_x32_shellcode(self):
        asm = self.load('x32')
        data = bytes.fromhex('31C050682F2F7368682F62696E89E350545350B03BCD80')
        result = asm(data)
        pattern = B'.*'.join([RB'\b%s\b' % oc for oc in [
            B'xor',
            B'push',
            B'push',
            B'push',
            B'mov',
            B'push',
            B'push',
            B'push',
            B'push',
            B'mov',
            B'int'
        ]])
        self.assertIsNotNone(re.search(pattern, result, flags=re.DOTALL))