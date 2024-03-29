#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestGOST(TestUnitBase):

    def test_reversible(self):
        data = bytes(range(0x100))
        for mode in ('CBC', 'CFB', 'OFB', 'PCBC'):
            encrypter = -self.load(range(32), iv=range(8), mode=mode)
            decrypter = self.load(range(32), iv=range(8), mode=mode)
            self.assertEqual(data, bytes(data | encrypter | decrypter), F'error for {mode}')

    def test_kryptografie_de(self):
        skey = B'SchokoladentorteSchokoladentorte'
        data = B'Beispielklartext'
        unit = self.load(skey, sbox='r34', raw=True)
        self.assertEqual(unit.encrypt(data).hex(), 'e05f62ba0ca8d8d9d1000602a37c6d32')

    def test_cryptopp_vectors(self):
        vectors = [
            ('BE5EC2006CFF9DCF52354959F1FF0CBFE95061B5A648C10387069C25997C0672', '0DF82802B741A292', '07F9027DF7F7DF89'),
            ('B385272AC8D72A5A8B344BC80363AC4D09BF58F41F540624CBCB8FDCF55307D7', '1354EE9C0A11CD4C', '4FB50536F960A7B1'),
            ('AEE02F609A35660E4097E546FD3026B032CD107C7D459977ADF489BEF2652262', '6693D492C4B0CC39', '670034AC0FA811B5'),
            ('320E9D8422165D58911DFC7D8BBB1F81B0ECD924023BF94D9DF7DCF7801240E0', '99E2D13080928D79', '8118FF9D3B3CFE7D'),
            ('C9F703BBBFC63691BFA3B7B87EA8FD5E8E8EF384EF733F1A61AEF68C8FFA265F', 'D1E787749C72814C', 'A083826A790D3E0C'),
            ('728FEE32F04B4C654AD7F607D71C660C2C2670D7C999713233149A1C0C17A1F0', 'D4C05323A4F7A7B5', '4D1F2E6B0D9DE2CE'),
            ('35FC96402209500FCFDEF5352D1ABB038FE33FC0D9D58512E56370B22BAA133B', '8742D9A05F6A3AF6', '2F3BB84879D11E52'),
            ('D416F630BE65B7FE150656183370E07018234EE5DA3D89C4CE9152A03E5BFB77', 'F86506DA04E41CB8', '96F0A5C77A04F5CE'),
        ]
        for K, M, C in vectors:
            M = bytes.fromhex(M)
            C = bytes.fromhex(C)
            K = bytes.fromhex(K)
            U = self.load(K, sbox='cbr', raw=True, reverse=True)
            self.assertEqual(C, M | U | bytearray)
