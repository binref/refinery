from ... import TestUnitBase


class TestChmExtractor(TestUnitBase):

    def test_chm_normal_document(self):
        data = self.download_sample('b329740e3729487b4475985ec4348da58c880d812c76a39b445c39c9fc57c5c8')
        unit = self.load('9.html')
        self.assertTrue(unit.handles(data))
        test = data | unit | str
        self.assertIn('http://api.farmanager.com/ru/service_functions/panelcontrol.html', test)

    def test_offset_count_regression(self):
        data = self.download_sample('7584ece3f33b66ef69d111d0c7104d8d033e0d8c3ee918261cfac57768d30f1d')
        unit = self.load('html/NoHelp1.htm')
        self.assertTrue(unit.handles(data))
        test = data | unit | self.ldu('recode') | str
        self.assertIn('CONTENT="HP05206873"', test)
