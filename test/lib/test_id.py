from .. import TestBase


class TestIDLib(TestBase):

    def test_all_pyc_magics(self):
        from refinery.lib.shared import xdis
        from refinery.lib.id import PycMagicPattern
        mismatches = [
            (magic, version) for magic, version in xdis.magics.versions.items()
            if PycMagicPattern.fullmatch(magic) is None
        ]
        errors = '\n'.join([
            F'- {magic.hex().upper()} for version {version}' for magic, version in mismatches
        ])
        self.assertListEqual(mismatches, [],
            msg=F'the following pyc magics were not matches:\n{errors}')
