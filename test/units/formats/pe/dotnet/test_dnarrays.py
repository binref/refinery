from .... import TestUnitBase

import json


class TestDotNetArrayExtractor(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('2579bc4cd0d5f76d1a2937a0e0eb0256f2a9f2f8a30c1da694be66bfa04dc740')
        test = data | self.load() | json.loads
        self.assertDictEqual(test['B6541265123.Properties::Settings.[cctor]'], {'v1': [
            '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.pdf ', '.cd', '.jpg', '.png', '.csv',
            '.sql', '.mdb', '.sln', '.php', '.asp', '.aspx', '.html', '.xml', '.psd', '.ps', '.lock', '.rtf', '.wav',
            '.wmp', '.mp4', '.avi', '.wmv', '.mp3', '.xaml', 'htm', '.html', '.hta', '.vbs', '.zip', '.7z', '.rar',
            '.bit', '.png', '.jpg', '.bmp', '.jfif', '.gif', '.tif', '.tiff', '.wncry', '.cert', '.log', '.id', '.md5',
            '.hash', 'pkg', '.asar', '.curl', '.device', '.done']})
