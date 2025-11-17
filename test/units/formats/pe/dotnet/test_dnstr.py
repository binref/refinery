from .... import TestUnitBase


class TestDotNetHeaderParser(TestUnitBase):

    def test_require_one_mode(self):
        with self.assertRaises(ValueError):
            self.load(user=False, meta=False)

    def test_sample_with_data_directory_issue(self):
        data = self.download_sample('b3b7376c5046be978b5558e91a515c1bf57c13a1151d225745c2bdc3183e0a8f')
        unit = self.load()
        strings = data | unit | {bytes}
        self.assertIn(B'NoLm3cQQRvqHXtIBud.T6U9wFFbHKIsgklbGQ', strings)
        self.assertIn(B'{11111-22222-50001-00000}', strings)

    def test_hawkeye(self):
        unit_both = self.load()
        unit_meta = self.load(user=False)
        unit_user = self.load(meta=False)
        data = self.download_sample('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')

        data_both = unit_both(data)
        data_meta = unit_meta(data)
        data_user = unit_user(data)

        sample_meta = B'System.Runtime.Serialization.Formatters.Binary'
        sample_user = B'HawkEye Keylogger - Reborn v9'

        self.assertIn(sample_meta, data_meta)
        self.assertIn(sample_user, data_user)
        self.assertIn(sample_meta, data_both)
        self.assertIn(sample_user, data_both)

        self.assertNotIn(sample_meta, data_user)
        self.assertNotIn(sample_user, data_meta)
