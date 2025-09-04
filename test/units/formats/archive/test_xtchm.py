from ... import TestUnitBase


class TestChmExtractor(TestUnitBase):

    def test_chm_normal_document(self):
        data = self.download_sample('b329740e3729487b4475985ec4348da58c880d812c76a39b445c39c9fc57c5c8')
        unit = self.load('9.html')
        self.assertTrue(unit.handles(data))
        test = data | unit | str
        self.assertIn('http://api.farmanager.com/ru/service_functions/panelcontrol.html', test)
