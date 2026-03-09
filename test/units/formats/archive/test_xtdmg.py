import hashlib

import pytest

from test.units import TestUnitBase
from test.units.compression import KADATH1, KADATH2


@pytest.mark.cythonized
class TestDMGExtractor(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('f5d76324cb8fcae7f00b6825e4c110ddfd6b32db452f1eca0f4cff958316869c')
        files = data | self.load() | {'path': bytes}
        self.assertSetEqual({str(p) for p in files}, {
            'Player/.DS_Store',
            'Player/dmgbg.png',
            'Player/Installer.app/Contents/Info.plist',
            'Player/Installer.app/Contents/_CodeSignature/CodeResources',
            'Player/Installer.app/Contents/Frameworks/libcurl.4.dylib',
            'Player/Installer.app/Contents/MacOS/mac',
            'Player/Installer.app/Contents/Resources/install.icns',
            'Player/Installer.app/Contents/Resources/Html/ErrorPage.html',
            'Player/.fseventsd/0000000004c39db4',
            'Player/.fseventsd/0000000004c39db5',
            'Player/.fseventsd/fseventsd-uuid',
        })
        self.assertEqual(hashlib.sha256(files['Player/Installer.app/Contents/MacOS/mac']).hexdigest(),
            '9c4f74feff131fa93dd04175795f334649ee91ad7fce11dc661231254e1ebd84')

    def test_flare_dmg(self):
        data = self.download_sample('57940959104d80cdeee3d430d45c9500e5c43491a67778004faba38be9a96555')
        files = data | self.load() | {'path': bytes}
        for path in (
            'Flare/logo.gif',
            'Flare/flare.html',
            'Flare/classic.css',
        ):
            self.assertIn(path, files)
        self.assertIn(b'Flare is a free ActionScript decompiler.', files['Flare/flare.html'])

    def _test_artificial_sample(self, sha256hash: str):
        data = self.download_sample(sha256hash)
        results = data | self.load() | {'path': bytearray}
        k1 = results['TestVol/kadath1.txt']
        k2 = results['TestVol/kadath2.txt']
        k1.append(0)
        k2.append(0)
        self.assertEqual(k1.decode('latin1'), KADATH1)
        self.assertEqual(k2.decode('latin1'), KADATH2)

    def test_sample_bz2(self):
        self._test_artificial_sample('44e6d55b2364141dd1a79a3189147e1daa388a1b5f613ec08b9080799b3ba12c')

    def test_sample_lzfse(self):
        self._test_artificial_sample('06a764a6895f72f34fcddbb5002f63ed94241c67f2c3c6dd732583bc31bb83d3')

    def test_sample_lzma(self):
        self._test_artificial_sample('482bf764b9bce292cff93914bd831f0bb15b07f44fc668b8924c964a88f55ccd')

    def test_sample_empty(self):
        data = self.download_sample('8ca6b68d7799e25a47d0555b83d900219fa5623326e51c27665573e7e20f9956')
        results = data | self.load() | []
        self.assertListEqual(results, [])

    def test_sample_zlib(self):
        self._test_artificial_sample('0f6c189d7e6a17b29a1e281bbecc9f4b545d18e9ade28a19869083150378949a')

    def test_sample_decmpfs(self):
        self._test_artificial_sample('e7b1d7282c86af32e114e9cb4cafe6daa4833323b57e46d979e03682c719d16d')

    def test_sample_front_koly(self):
        self._test_artificial_sample('a2f3d66825746ab6f5421efd9dc55616818f2b581e6456fb3b8632516a2f8225')
