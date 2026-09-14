from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


class TestCleanupRunsAgainAfterAFoldItEnabled(TestJsDeobfuscator):

    def test_a_finder_freed_by_removing_its_only_other_writer_is_gone_after_one_run(self):
        source = inspect.cleandoc(
            """
            var w;
            w = function () { return globalThis; };
            function unused() { w = null; }
            w().console.log(1);
            """
        )
        self.assertEqual('globalThis.console.log(1);', self._deobfuscate(source))
