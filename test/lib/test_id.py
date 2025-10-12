from .. import TestBase


class TestIDLib(TestBase):

    def test_all_pyc_magics(self):
        from refinery.lib.shared import xdis
        from refinery.lib.id import PycMagicPattern
        for magic, version in xdis.magics.versions.items():
            self.assertIsNotNone(PycMagicPattern.fullmatch(magic),
                msg=F'pattern does not match magic {magic.hex()} for version {version}')
