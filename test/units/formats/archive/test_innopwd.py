#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from ... import TestUnitBase


class TestInnoExtractor(TestUnitBase):

    def test_mw_script_01(self):
        # fabd429204db75e2ff9fe7fae5dc981b8c392be42a936273c99dcc41eeb0730d
        data = self.download_sample('441094a1a29f4ff248f289e19ae6c8c15abe1ff8bd440aefe85a0e5817482e92')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'7@8#3%5819((4f-=/72\~c0d``a221fdefc6bd&208fe1808d49606<:c89f')

    def test_mw_script_02(self):
        # 3785065d6ba8a07f248ed63deadbf04f5e35918224d414afe19f0de1bfcb0e84
        data = self.download_sample('453b14ee0451b92f390ddacc93d6c4d24fcb8268baf94efa823387a1dba4eedc')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'NFfB5qf2o1EJOkmBRrMvFcmj4QmKfwyNE5yoMOMRmFE4yfEEEMImIyyEYIQYFiO0')

    def test_mw_script_03(self):
        # aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42
        data = self.download_sample('922aaca70e288f7fd9ee31ac4db98d0fc90fb7bb92b056d18f69b328cbacc043')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'Zet0')

    def test_mw_script_04(self):
        # f72106284904a0033fa877df21151bbb84b632163fab55789422916ed85b43a1
        data = self.download_sample('a3c40be74f061bd25a3e4b264602f4ace5652eed0ca020362a6d56d336bc650f')
        unit = self.load()
        code = self.load_pipeline('recode utf8 latin1 | recode cp1251')
        pwds = data | unit | code | {str}
        self.assertContains(pwds, r'kj2678лоkjfv89цкs75345в00р\5(*&Y&&^^^%##832984ол1мвырам~`ёЁ<>xhvрлджэ^(UJ<:')

    def test_mw_script_05(self):
        # 15f9eca216f9eb92dd70f86b65e4f6b19081113c5675d04c6008d216d54ed7e0
        data = self.download_sample('c47352571fb7ac45bd994f4b057ffec15898df4724f2a4cd0d9213e3eedfca29')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'02b60c12469a674bf')

    def test_mw_script_06(self):
        # f09c25c1b868baf93b77a7cbb3d57a2848355e495bca470db6dab70adcf73273
        data = self.download_sample('d290117343b7e76b971c7b9eb618e60322af6cd74bd70296dbc00a06ca30d565')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'5D97BF9AEC584AAF4B7C0AEDF46CF882A5B1645392F958545AB2A7FC8FF8963F8')
 
    def test_mw_script_07(self):
        # 258ecd1cb153a2a450ad5404f7c55a7dea44edb54da650ffa1165d7158dee94b
        data = self.download_sample('fb0fc2e3c2059e6159540920a4ff7f75f92212639b318da7eb7fadece4a46ecc')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'A1ADB8BE8E677894E')
 
    def test_mw_script_08(self):
        # 73f5eee95f0d5250f5d2f7a29702700537ebe6c08861d4ddfefc09d485f0f65e
        data = self.download_sample('5589c0d2de0efdc59eb7325497f18a9a01c095b5cc4859774f75cc91bbdb2757')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'Zet0')

    def test_double_curly_brace_regression(self):
        # 89f37f929f8c75c2a851f1d331bd5872cfe41d14c73d722fb5db5f0f3e016e85
        data = self.download_sample('a30a12d725e20c7ec403676710b3a2df41bb395fcc80539a28c0da09f5906ee6')
        unit = self.load()
        pwds = data | unit | {str}
        self.assertContains(pwds, r'LD6DQAUT2FQRBGKMXKET7K6PBBBP6TMDUKQ6K4S995HKIGIYFUDCFLU')