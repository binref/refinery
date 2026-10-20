from refinery.lib.inno.archive import InnoArchive, SetupMessageName, TextDirective

from .. import TestBase

_INSTALLERS = [
    '0c05247e69030e6c1678d5c1a4cb05e6cc323b79e428d3fe014cb12adf8f502c',
    '0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642',
    '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314',
    'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42',
    'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73',
    'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c',
    'd1a18cc03c1ca8901a2521e448acb5074fca2511e51044a028989ecb116a332b',
    'eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e',
]

_ANSI_INSTALLER = '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314'
_LANGUAGES_OUTSIDE_THE_CODE_PAGE_OF_THE_SCRIPT = frozenset({'cz', 'yu', 'jp', 'sk', 'mk', 'ir'})
"""
The languages of the ANSI installer 9271acdc whose messages hold bytes that code page 1252, in which
its script's strings are written, does not define.
"""

_ENGLISH = {
    SetupMessageName.ButtonBack          : '< &Back',
    SetupMessageName.ButtonNext          : '&Next >',
    SetupMessageName.FullInstallation    : 'Full installation',
    SetupMessageName.CompactInstallation : 'Compact installation',
    SetupMessageName.CustomInstallation  : 'Custom installation',
    SetupMessageName.ReadyMemoComponents : 'Selected components:',
    SetupMessageName.ReadyMemoDir        : 'Destination location:',
    SetupMessageName.ReadyMemoGroup      : 'Start Menu folder:',
    SetupMessageName.ReadyMemoTasks      : 'Additional tasks:',
    SetupMessageName.ReadyMemoType       : 'Setup type:',
    SetupMessageName.ReadyMemoUserInfo   : 'User information:',
    SetupMessageName.ErrorInternal2      : 'Internal error: %1',
}
"""
The texts of the named messages in `Default.isl` of Inno Setup, the same from 5.1.11 to 6.5.0.
"""

_ENGLISH_INSTALLERS = {
    '0c05247e69030e6c1678d5c1a4cb05e6cc323b79e428d3fe014cb12adf8f502c': 'default',
    '0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642': 'default',
    '9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314': 'en',
    'c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73': 'en',
    'cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c': 'en',
    'd1a18cc03c1ca8901a2521e448acb5074fca2511e51044a028989ecb116a332b': 'default',
    'eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e': 'default',
}
"""
The installers with an English language, by the name of that language. Their messages are those of
five lists: Inno Setup 5.1.11, 5.5.0, 5.5.3, 6.1.0 and 6.5.0.
"""


class TestTheMessagesOfSetup(TestBase):

    def installer(self, sha256: str) -> InnoArchive:
        return InnoArchive(self.download_sample(sha256))

    def test_every_block_of_messages_passes_the_checks_of_setup(self):
        for sha256 in _INSTALLERS:
            info = self.installer(sha256).setup_info
            for index, language in enumerate(info.Languages):
                with self.subTest(installer=sha256[:8], language=language.Name):
                    if sha256 == _ANSI_INSTALLER and language.Name in _LANGUAGES_OUTSIDE_THE_CODE_PAGE_OF_THE_SCRIPT:
                        with self.assertRaisesRegex(ValueError, 'cannot be decoded'):
                            info.messages(index)
                    else:
                        self.assertGreater(len(info.messages(index)), 200)

    def test_the_named_messages_of_an_english_language_are_the_texts_of_inno_setup(self):
        """
        The installer c6bb1662 names its button Next `Accept`.
        """
        for sha256, name in _ENGLISH_INSTALLERS.items():
            info = self.installer(sha256).setup_info
            index = [language.Name for language in info.Languages].index(name)
            messages = info.messages(index)
            named = {name: messages.named(name) for name in SetupMessageName}
            english = dict(_ENGLISH)
            if sha256.startswith('c6bb1662'):
                english[SetupMessageName.ButtonNext] = 'Accept'
            with self.subTest(installer=sha256[:8]):
                self.assertEqual(named, english)

    def test_a_message_of_an_ansi_installer_is_the_text_of_its_bytes_in_the_code_page_of_the_script(self):
        """
        An ANSI Setup holds messages and the strings of its script as bytes; the Russian `&Далее >`
        of code page 1251 has the bytes that code page 1252 reads as `&Äàëåå >`, and the strings of
        the script of 9271acdc are written in code page 1252.
        """
        archive = self.installer(_ANSI_INSTALLER)
        info = archive.setup_info
        index = [language.Name for language in info.Languages].index('ru')
        self.assertEqual(archive.script_codec, 'cp1252')
        self.assertEqual(info.messages(index).named(SetupMessageName.ButtonNext), '&Äàëåå >')

    def test_a_block_that_fails_its_crc_has_no_messages(self):
        info = self.installer(_INSTALLERS[0]).setup_info
        language = info.Languages[0]
        broken = bytearray(language._compiled_messages)
        broken[-3] ^= 1
        language._compiled_messages = broken
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'CRC'):
                info.messages(0)


class TestTheTextsOfTheSetupHeader(TestBase):

    def test_every_text_directive_has_a_text_unless_the_installer_is_older_than_the_directive(self):
        """
        Inno Setup 5.5.6 added the directive `SetupMutex`.
        """
        for sha256 in _INSTALLERS:
            archive = InnoArchive(self.download_sample(sha256))
            header = archive.setup_info.Header
            missing = {directive for directive in TextDirective if header.text(directive) is None}
            with self.subTest(installer=sha256[:8]):
                self.assertEqual(missing, {TextDirective.SetupMutex} if archive.version < (5, 5, 6) else set())
