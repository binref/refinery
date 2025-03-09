#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from ... import TestUnitBase


class TestInnoExtractor(TestUnitBase):

    def test_mw_script_01(self):
        data = self.download_sample('441094a1a29f4ff248f289e19ae6c8c15abe1ff8bd440aefe85a0e5817482e92')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'7@8#3%5819((4f-=/72\~c0d``a221fdefc6bd&208fe1808d49606<:c89f')

    def test_mw_script_02(self):
        data = self.download_sample('453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'NFfB5qf2o1EJOkmBRrMvFcmj4QmKfwyNE5yoMOMRmFE4yfEEEMImIyyEYIQYFiO0')

    def test_mw_script_03(self):
        data = self.download_sample('922aaca70e288f7fd9ee31ac4db98d0fc90fb7bb92b056d18f69b328cbacc043')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'Zet0')

    def test_mw_script_04(self):
        data = self.download_sample('a3c40be74f061bd25a3e4b264602f4ace5652eed0ca020362a6d56d336bc650f')
        unit = self.load()
        code = self.load_pipeline('recode utf8 latin1 | recode cp1251')
        pwds = data | unit | code | {str}
        self.assertContains(pwds, r'kj2678лоkjfv89цкs75345в00р\5(*&Y&&^^^%##832984ол1мвырам~`ёЁ<>xhvрлджэ^(UJ<:')

    def test_mw_script_05(self):
        data = self.download_sample('c47352571fb7ac45bd994f4b057ffec15898df4724f2a4cd0d9213e3eedfca29')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'02b60c12469a674bf')

    def test_mw_script_06(self):
        data = self.download_sample('d290117343b7e76b971c7b9eb618e60322af6cd74bd70296dbc00a06ca30d565')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'5D97BF9AEC584AAF4B7C0AEDF46CF882A5B1645392F958545AB2A7FC8FF8963F8')
 
