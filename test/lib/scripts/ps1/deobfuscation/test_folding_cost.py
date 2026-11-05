from __future__ import annotations

import unittest.mock

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis import values
from refinery.lib.scripts.ps1.deobfuscation import Ps1ConstantFolding
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _chain(links: int) -> str:
    return '$a = $x' + ' -and 1' * links


class TestPs1FoldingAChainCostsOneDerivationPerLink(TestPs1):

    SHORT = 20
    LONG = 80

    def _derivations(self, links: int) -> int:
        derived = 0
        uncached = values._evaluated

        def counted(*args, **kwargs):
            nonlocal derived
            derived += 1
            return uncached(*args, **kwargs)

        script = Ps1Parser(_chain(links)).parse()
        with unittest.mock.patch.object(values, '_evaluated', counted):
            Ps1ConstantFolding().visit(script)
        return derived

    def test_a_chain_over_an_unknown_variable_folds_to_itself(self):
        self._assertUnchanged(_chain(self.SHORT), Ps1ConstantFolding)
        self._assertUnchanged(_chain(self.LONG), Ps1ConstantFolding)

    def test_a_chain_four_times_as_long_is_not_derived_sixteen_times_as_often(self):
        derived = {links: self._derivations(links) for links in (self.SHORT, self.LONG)}
        self.assertGreater(derived[self.SHORT], 0)
        linear_growth = self.LONG / self.SHORT
        self.assertLess(derived[self.LONG] / derived[self.SHORT], 2 * linear_growth)
