from refinery.lib.inno.archive import InnoArchive
from refinery.lib.inno.emulator import IFPSEmulatorConfig, InnoSetupEmulator
from refinery.lib.inno.release import SetupRelease

from .. import TestBase

_RELEASES = {
    '0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642': (5, 2, 1),
    '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314': (5, 5, 9),
    'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42': (5, 5, 3),
    'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c': (5, 5, 3),
    'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73': (5, 5, 1),
    '0c05247e69030e6c1678d5c1a4cb05e6cc323b79e428d3fe014cb12adf8f502c': (6, 5, 0),
    'd1a18cc03c1ca8901a2521e448acb5074fca2511e51044a028989ecb116a332b': (6, 5, 0),
    'eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e': (6, 3, 3),
}
"""
Installers and the release that the text `Inno Setup version` in their setup programs names;
c6bb1662 names `5.5.1.ee2`, a build of 5.5.1 by another party.
"""

_RELEASE_5_5_1 = 'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'
_RELEASE_5_5_3 = 'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42'
_RELEASE_6_3_3 = 'eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e'


class TestTheReleaseThatBuiltAnInstaller(TestBase):

    def installer(self, sha256: str, readable: bool = True) -> InnoArchive:
        """
        The installer; unless its setup program is readable, a byte of the program's first block is
        changed in memory, so that the block fails its check.
        """
        data = self.download_sample(sha256)
        archive = InnoArchive(data)
        if not readable:
            data[archive.meta.exe_offset + 0x100] ^= 0xFF
            archive = InnoArchive(data)
        return archive

    def test_the_setup_program_of_each_installer_names_the_release_that_built_it(self):
        for sha256, release in _RELEASES.items():
            with self.subTest(installer=sha256[:8]):
                self.assertEqual(self.installer(sha256).setup_program_release, release)

    def test_the_release_of_each_installer_is_the_one_that_its_setup_program_names(self):
        for sha256, (major, minor, patch) in _RELEASES.items():
            release = self.installer(sha256).release
            with self.subTest(installer=sha256[:8]):
                self.assertTrue(release.since((major, minor, patch)))
                self.assertFalse(release.since((major, minor, patch + 1)))

    def test_a_setup_program_that_cannot_be_read_names_no_release(self):
        self.assertIsNone(self.installer(_RELEASE_5_5_1, readable=False).setup_program_release)

    def test_the_setup_program_decides_what_the_version_of_the_data_leaves_open(self):
        """
        The data of c6bb1662 has the version 5.5.0, which the releases from 5.5.0 up to 5.5.2
        write; the restart manager's scan calls `RegisterExtraCloseApplicationsResources` from
        5.5.2 on.
        """
        release = self.installer(_RELEASE_5_5_1).release
        self.assertTrue(release.since((5, 5, 1)))
        self.assertFalse(release.since((5, 5, 2)))
        self.assertEqual(release.exact, (5, 5, 1))

    def test_without_the_setup_program_a_question_that_the_data_leaves_open_fails(self):
        release = self.installer(_RELEASE_5_5_1, readable=False).release
        self.assertTrue(release.since((5, 5, 0)))
        self.assertFalse(release.since((5, 5, 6)))
        with self.assertRaises(NotImplementedError):
            release.since((5, 5, 2))

    def test_a_part_of_the_installer_that_contradicts_the_version_of_its_data_is_ignored(self):
        def setup_program():
            return (6, 0, 0), (6, 0, 1)
        release = SetupRelease((5, 5, 0), (5, 5, 6), setup_program)
        with self.assertRaises(NotImplementedError):
            release.since((5, 5, 2))

    def test_an_installer_whose_data_decides_every_rule_runs_without_its_setup_program(self):
        """
        The data of eeafd3fe has the version 6.3.0, which the releases from 6.3.0 up to 6.3.3
        write; no behavior of Setup that the emulator follows changed between them.
        """
        def installation(readable: bool):
            emulator = InnoSetupEmulator(self.installer(_RELEASE_6_3_3, readable), IFPSEmulatorConfig())
            return [str(event) for event in emulator.emulate_installation()]
        self.assertEqual(installation(readable=False), installation(readable=True))

    def test_each_installer_behaves_as_the_release_that_built_it(self):
        """
        The preparing page passes the selection to its scans from 5.5.1 on, and the restart
        manager's scan calls `RegisterExtraCloseApplicationsResources` from 5.5.2 on.
        """
        for sha256 in (_RELEASE_5_5_1, _RELEASE_5_5_3):
            release = _RELEASES[sha256]
            setup = InnoSetupEmulator(self.installer(sha256), IFPSEmulatorConfig()).setup
            with self.subTest(installer=sha256[:8]):
                self.assertEqual(
                    (setup.prepares_with_selection, setup.registers_close_applications_resources),
                    (release >= (5, 5, 1), release >= (5, 5, 2)),
                )
