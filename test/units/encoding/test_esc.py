#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.encoding.esc import esc
from .. import TestUnitBase


class TestEscaping(TestUnitBase):

    def test_quoted_string_01(self):
        unit = esc(quoted=True)
        self.assertEqual(unit.process(RB'"r\x65\x66\x69\x6ee\x72\x79"'), B'refinery')

    def test_quoted_string_02(self):
        unit = esc(quoted=True, hex=True)
        result = unit.reverse(RB'refinery')
        self.assertEqual(result, BR'"\x72\x65\x66\x69\x6e\x65\x72\x79"')

    def test_quoted_string_03(self):
        unit = esc(quoted=True, hex=False)
        result = unit.reverse(B'binary\n\a\t.."refinery"!')
        self.assertEqual(result, BR'"binary\n\a\t..\"refinery\"!"')

    def test_quoted_string_04(self):
        unit = esc(quoted=True)
        data = RB'"r\x65\x66\x69\x6ee\x72\x79'
        goal = B'"r\x65\x66\x69\x6ee\x72\x79'
        self.assertEqual(bytes(data | unit), goal)

    def test_inversion_simple(self):
        unit = self.load()
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_unicode(self):
        unit = self.load(unicode=True)
        data = u'refinery is all about the パイプライン.'.encode('UTF8')
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_reverse(self):
        unit = self.load(reverse=True)
        data = B'FOO\tBAR\nBAZ\tBOF.\a\a'
        self.assertEqual(BR'FOO\tBAR\nBAZ\tBOF.\a\a', unit(data))

    def test_escape_not_greedy(self):
        unit = self.load()
        data = B'H\\x\\y\\x20\\u\\u0020!'
        self.assertEqual(unit(data), B'H\\xy \\u !')

    def test_escape_greedy(self):
        unit = self.load(greedy=True)
        data = B'H\\x\\y\\x20\\u\\u0020!'
        self.assertEqual(unit(data), B'Hxy u !')

    def test_zalgo_text(self):

        zalgo_unicode = U'B̘̥̦̣͇̩̱͎̱͑̿̇̅͂ì̢̬̲̪̯̼̠̉͂̾͋͢͢ṋ̷̡̯̰͖͎̲̋̄͌̒͊̍͑̽͛ą̶̮̗̱̗̥̜̙̞̋̑́̀͐̓͋́̇̆r̶̟͇̬̺̙̝̻̪̥̙̽͊͋̔̍̾̒̄y̗̞̠̬̭̖̼̠̣͐̆͂͗͗̀͞ R̻͍̭͚͍̭̤̜̽̿̄́͡é͕̝͚̻̙̤͌̊̇͆͆̆̊͠f̷̨͓̜̣̜͐͛̿̌̉̋̎͜͜ḯ͚̩͈̮̫́̃͂̀͞ǹ̢̫͔̞̝̝̯̼̊̍͗͗̽̽́̿͜͜ẻ̸͚̮̝͎͖̜̻̙̀̔̆̅̆̔̊͞r̸̢̢̻̣̠̈́̂͛̓͋̍̾̌̕͟y̥̖͖̦̼̱̼̜͍͛́́͊͆̐̍̚͠͞'.encode('UTF8')

        zalgo_encoded = B''.join([
            BR'B\u0351\u033f\u0307\u0305\u0342\u0318\u0325\u0326\u0323\u0347\u0329\u0331\u034e\u0331',
            BR'i\u0300\u0309\u0342\u033e\u034b\u032c\u0362\u0332\u032a\u0322\u032f\u033c\u0320\u0362',
            BR'n\u030b\u0304\u034c\u0312\u034a\u030d\u0351\u033d\u035b\u032d\u032f\u0321\u0330\u0356\u034e\u0332\u0337',
            BR'a\u030b\u0311\u0341\u0340\u0350\u0343\u034b\u0301\u0307\u0306\u0328\u032e\u0317\u0331\u0317\u0325\u031c\u0319\u031e\u0336',
            BR'r\u033d\u034a\u034b\u0314\u030d\u033e\u0312\u0304\u031f\u0347\u032c\u033a\u0319\u031d\u033b\u032a\u0325\u0319\u0336',
            BR'y\u0350\u035e\u0306\u0342\u0357\u0357\u0300\u0317\u031e\u0320\u032c\u032d\u0316\u033c\u0320\u0323 ',
            BR'R\u0361\u033d\u033f\u0304\u0301\u033b\u034d\u032d\u035a\u034d\u032d\u0324\u031c',
            BR'e\u0360\u0301\u034c\u030a\u0307\u0346\u0346\u0306\u030a\u0355\u031d\u035a\u033b\u0319\u0324',
            BR'f\u0350\u035b\u033f\u030c\u0309\u030b\u030e\u0328\u0353\u035c\u031c\u035c\u0323\u031c\u0337',
            BR'i\u0344\u0341\u0303\u0342\u035e\u0300\u035a\u0329\u0348\u032e\u032b',
            BR'n\u0300\u030a\u030d\u0357\u0357\u033d\u033d\u0301\u033f\u032b\u0354\u031e\u035c\u031d\u031d\u035c\u0322\u032f\u033c',
            BR'e\u0309\u0300\u0314\u0306\u035e\u0305\u0306\u0314\u030a\u035a\u032e\u031d\u034e\u0356\u031c\u033b\u0319\u0338',
            BR'r\u0344\u0302\u0315\u035b\u0343\u034b\u030d\u033e\u030c\u033b\u0322\u0322\u0323\u035f\u0320\u0338',
            BR'y\u035b\u0301\u031a\u0301\u034a\u0360\u0346\u0310\u030d\u035e\u0325\u0316\u0356\u0326\u033c\u0331\u033c\u031c\u034d'
        ])
        unit = self.load(unicode=True)
        self.assertEqual(zalgo_unicode, unit(zalgo_encoded))

    def test_octal_escape_sequences(self):
        data = R'\154\225\151\067\135\111\073\307\033\173\004\154\273\222\301\242'
        wish = B'\154\225\151\067\135\111\073\307\033\173\004\154\273\222\301\242'
        unit = self.load()
        self.assertEqual(bytes(data | unit), wish)

    def test_java_single_digit_hex_escapes(self):
        data = R'\x1\x2\x03\x04'
        wish = bytes((1, 2, 3, 4))
        unit = self.load()
        self.assertEqual(bytes(data | unit), wish)

    def test_obfuscated_unicode_strings(self):
        data = r'࡙ࠣࡨࡰࡨࡵ\u086dࡦ\u082eࠣࡴࡱ\u086bࡡࡴࡧࠣࡩࡳࡺࡥࡳࠢࡼࡳࡺࡸࠠ\u086fࡣࡰࡩ\u083fࠨࠄ'.encode('utf8')
        unit = self.load(unicode=True)[
            self.load_pipeline('u16 -R | put b le:x:~1: | alu -B2 B-0x800-((K+b)%7) | u16 | esc -q ]')]
        self.assertEqual(data | unit | str, 'Welcome, please enter your name:')

    def test_autoquotes_01(self):
        self.assertEqual(B'BINARY REFINERY!', B'"BINARY\\x20REFINERY!"' | self.load() | bytes)
        self.assertEqual(B"BINARY REFINERY!", B"'BINARY\\x20REFINERY!'" | self.load() | bytes)

    def test_autoquotes_02(self):
        self.assertEqual(B'"BINARY REFINERY!"', B'"BINARY\\x20REFINERY!"' | self.load(unquoted=True) | bytes)
        self.assertEqual(B"'BINARY REFINERY!'", B"'BINARY\\x20REFINERY!'" | self.load(unquoted=True) | bytes)

    def test_autoquotes_03(self):
        self.assertEqual(B'BINARY REFINERY!"', B'BINARY\\x20REFINERY!"' | self.load() | bytes)
        self.assertEqual(B"'BINARY REFINERY!", B"'BINARY\\x20REFINERY!" | self.load() | bytes)
