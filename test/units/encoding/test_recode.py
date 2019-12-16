#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from functools import reduce

from .. import TestUnitBase


class TestRecode(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.zalgo = U'ţ͔̮̼̦̀̐̾̈̓͟0̷̧̦͙̹̫̹̪̟͚̍̉͂̑͡͠0̷̢͙̱̮̻̗͂̀͗̉͐̇̇͘ M̡͖̹̹̦̭̜͈̿͆̎́̒̏͛͟Ư̡̡̥͖͇̤̪̅̂̋́̆̚͡c̸̺͇̠̯̩͚̱͖͆͒͂̌̏̾͢͞Ḫ̛̘͙̦̩̝̼͈͓̝̐̀̐̈́͠ t̢̳͚̟̘̝̼̠͐̒̐͗̀̎̈̂̃͠3̨͔̪̰͆͗͌̔̆̊͘͟͡C͎̭̼͉͕̭̰͒̄͌̕͝H̷̡̬̙̮͙̝̭͖̝̖͒̈̍͋͘͞ṋ̨̨̘̟̼̗̪̼̊̿̌͐́̄0̶͔͈̙̲̏͋̓̍͆̀̚͜͢l̡̢̰̫̹̦̳͔͌̽̌͐̈́̃͒̕͠o̸̡͕̮̫͖̱̿́́͋͌͝G̪̖̥̫̰̗͇̦͉͂͑̂̉́̋̈́ͅy̛̛̭̦͍̳̞̋̑͋̽̄͒̾̋'.encode('UTF8')

    def test_circular_encoding(self):
        codecs = ['UTF8', 'UNICODE_ESCAPE', 'UTF-16LE', 'UTF-32', 'UTF8']
        units = [self.load(a, b) for a, b in zip(codecs[:-1], codecs[1:])]
        self.assertEqual(self.zalgo, reduce(lambda t, u: u(t), units, self.zalgo))

    def test_impossible_encoding(self):
        unit = self.load('UTF8', 'cp1252')
        self.assertRaises(UnicodeEncodeError, unit, self.zalgo)

    def test_ascii_encoding(self):
        data = U'Hände weg vom Crêpe!'
        unit = self.load('cp1252', 'UTF8')
        self.assertEqual(unit(data.encode('cp1252')).decode('UTF8'), data)
