#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestJavaDisassembler(TestUnitBase):

    def test_keylogger_sample(self):
        unit = self.load(join=True)
        data = self.download_from_malshare('31055a528f9a139104a0ce8f4da6b4b89a37a800715292ae7f8f190b2a7b6582')
        dasm = unit(data)

        self.assertIn(B'lookupswitch    defaultjmp => 0x00000054', dasm)
        self.assertIn(B'tableswitch     defaultjmp => 0x00000058', dasm)
        self.assertIn(B'invokestatic    org/jnativehook/keyboard/NativeKeyEvent::getKeyText', dasm)
