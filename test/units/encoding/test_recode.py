from functools import reduce
from base64 import b64decode

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

    def test_auto_decode_01(self):
        data = b64decode('08nT2uSvwMDG97XEyejWw8/e1sajrMXk1sO5pL7fzt63qNaxvdPUy9DQo6zH68rWtq/PwtTYsaO05rW9sb67+rrz1NnUy9DQIQ==')
        unit = self.load()
        self.assertEqual(unit(data).decode(unit.codec),
            U'由于浏览器的设置限制，配置工具无法直接运行，请手动下载保存到本机后再运行!')

    def test_auto_decode_02(self):
        data = B'H\0e\0l\0l\0o\0 \0W\0o\0r\0l\0d\0'
        unit = self.load()
        self.assertEqual(unit(data).decode(unit.codec), U'Hello World')
