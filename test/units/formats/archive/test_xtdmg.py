import hashlib

from ... import TestUnitBase


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
