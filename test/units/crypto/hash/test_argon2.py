from ... import TestUnitBase

import pytest


@pytest.mark.cythonized
class TestAgainstCyberchef(TestUnitBase):

    def _run(self, _i: bool = False, _d: bool = False) -> str:
        return B'The Binary Refinery refines the Finest Binaries.' | self.load(
            size=32,
            salt=b'somesalt',
            iter=5,
            jobs=1,
            cost=4096,
            resist_tmto=_i,
            resist_side=_d,
        ) | self.ldu('hex', reverse=True) | str

    def test_i(self):
        self.assertEqual(self._run(_i=True), '2E890442303CDB48F3A74655088CA7C5032DCE93D326E2BE90F05E0BC78F615C')

    def test_d(self):
        self.assertEqual(self._run(_d=True), 'CE3A5F6599587DD0EC531C5B359D052FA3F27E0F29AA0190D9452A18BAFB798F')

    def test_id(self):
        self.assertEqual(self._run(), 'FB6B3F9C1F584210ED8E289EB0B658D697A91BCA274D2F3336B9D8BAC8064C4C')
