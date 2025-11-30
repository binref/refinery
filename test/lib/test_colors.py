from refinery.lib import colors


from .. import TestBase


class TestColorFunctions(TestBase):

    def test_01(self):
        data = (
            '\x1b[39m\x1b[38;5;7mExecute\x1b[39m\x1b[38;5;7m(\x1b[39m\x1b[38;5;7mVOCATIONALFDA'
            '\x1b[39m\x1b[38;5;7m(\x1b[39m\x1b[38;5;153m"\x1b[39m\x1b[38;5;153m77N123N114N127N'
            '110N80N110N125N92N110N123N114N106N117N49N48N122N98N94N94N97N116N80N91N94N79N74N96'
            'N48N50\x1b[39m\x1b[38;5;153m"\x1b[39m\x1b[38;5;7m,\x1b[39m\x1b[38;5;243m \x1b[39m'
            '\x1b[38;5;153m10\x1b[39m\x1b[38;5;243m \x1b[39m\x1b[38;5;209;01m-\x1b[39;00m\x1b['
            '38;5;243m \x1b[39m\x1b[38;5;153m1\x1b[39m\x1b[38;5;7m)\x1b[39m\x1b[38;5;7m)'
        )
        self.assertEqual(colors.colored_text_length(data), 136)
        self.assertEqual(colors.colored_text_bleach(data), (
            'Execute(VOCATIONALFDA("77N123N114N127N110N80N110N125N92N110N123N114N106N117N49N48'
            'N122N98N94N94N97N116N80N91N94N79N74N96N48N50", 10 - 1))'
        ))
        self.assertEqual(colors.colored_text_truncate(data, 70), (
            '\x1b[39m\x1b[38;5;7mExecute\x1b[39m\x1b[38;5;7m(\x1b[39m\x1b[38;5;7mVOCATIONALFDA'
            '\x1b[39m\x1b[38;5;7m(\x1b[39m\x1b[38;5;153m"\x1b[39m\x1b[38;5;153m77N123N114N127N'
            '110N80N110N125N92N110N123N114N10'))
