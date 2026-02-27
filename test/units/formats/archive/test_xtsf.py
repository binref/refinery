import pytest

from ... import TestUnitBase


class TestSetupFactoryUnpacker(TestUnitBase):

    def test_sf6(self):
        data = self.download_sample('1511edf42bcaed5580ef8632aee6ceb9af23d3b1ca9bb2aba8e71fa2331dfe87')
        test = data | self.load(list=True) | [str]
        self.assertListEqual(test, [
            'irsetup.exe',
            'irsetup.uni',
            'irsetup.dat',
            'irsetup.lng',
            'irsetup.avi',
            'IRIMG1.BMP',
            'IRIMG2.BMP',
            'IRIMG3.BMP',
            'IRIMG4.BMP',
            'IRIMG5.BMP',
            'IRIMG6.BMP',
            'IRIMG7.BMP',
            'IRIMG8.BMP',
            '%AppDir%/ReadMe.htm',
            '%SysDir%/VB40032.DLL',
            '%SysDir%/ven2232.olb',
            '%SysDir%/olepro32.dll',
            '%SysDir%/msvcrt20.dll',
            '%SysDir%/msvcrt40.dll',
            '%SysDir%/CTL3D32.DLL',
            '%SysDir%/oleaut32.dll',
            '%SysDir%/msvcrt.dll',
            '%AppDir%/RCT acCeSS.exe',
        ])
        test = data | self.load('readme.htm') | str
        self.assertIn('RCT acCeSS Backup', test)
        test = data | self.load('access.exe') | self.ldu('sha256', text=True) | str
        self.assertEqual(test,
            '2c43cc4ce352a228e2fbcfd94116b738ec21e866f6fbb1d4d35b380d3ace4aa1')

    def test_sf_9_5(self):
        data = self.download_sample('4e94a9d15f7697288c360a89f15dca2c51c12389665258264300cf15c8a40ae0')
        test = data | self.load() [ self.ldu('sha256', text=True) ]| {'path': str}
        self.assertDictEqual(test, {
            'irsetup.exe' : '566a66e5a5a02ad894d13c48fe0b46aff92bc92bd892cba30e1ddb149be5e8ba',
            'lua5.1.dll'  : 'c572a6103af1526f97e708a229a532fd02100a52b949f721052107f1f55e0c59',
            'irsetup.dat' : '94cf2e2234c66ae80583766faae150f82ec0c7373b191cf514850b0af54297e3',
            'IRIMG1.JPG'  : '988cf422cbf400d41c48fbe491b425a827a1b70691f483679c1df02fb9352765',
            'IRIMG2.JPG'  : 'f35985fe1e46a767be7dcea35f8614e1edd60c523442e6c2c2397d1e23dbd3ea',
        })

    def test_sf_8_0(self):
        data = self.download_sample('c228fc953dd755827ac96ade2b7b5ce379d8809ac89fec0af8d184a30bedaced')
        test = data | self.load('WTP*.EXE') [ self.ldu('sha256', text=True) ]| {'path': str}
        self.assertDictEqual(test, {
            '%AppFolder%/WTPAgent.exe' : 'aa6dc64b016593f3d66bda2f3e81b0c285d4c5b71101b4d8599dcf6e395df927',
            '%AppFolder%/WTPLock.exe'  : 'd1bc7610d2f79c303bb950ba087279d820e8977231c02864cc72e09a096e2351',
            '%AppFolder%/WTPSvc.exe'   : '744d93e0d6246206cc8403e3463181d2319e8aa27f0efa57888963b6869594e6',
        })
