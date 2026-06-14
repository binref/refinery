from __future__ import annotations

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation.securestring import _find_key_argument
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1SecureString(TestPs1):

    def test_securestring_key_argument_matched(self):
        # The -Key parameter is stored with its leading dash; the matcher must still find it.
        script = Ps1Parser("ConvertTo-SecureString 'AAAA' -Key (1..16)").parse()
        cmd = next(n for n in script.walk() if isinstance(n, Ps1CommandInvocation))
        key = _find_key_argument(cmd)
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 16)
