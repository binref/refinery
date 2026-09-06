import marshal
import sys

from refinery.lib.py import code_header, decompile_buffer

from .. import TestBase


def _a_trivial_code_object() -> bytes:
    def refined():
        print('refine your binaries!')
    return bytes(code_header()) + marshal.dumps(refined.__code__)


class TestDecompileBuffer(TestBase):
    """
    `decompyle3` and `uncompyle6` each raise the interpreter's recursion limit to 5000 as a side
    effect of being imported and never restore it, so importing either one leaves every later
    caller in the same process with a wider recursion budget than it asked for. A caller relying
    on the ambient limit to fail loudly on unreasonably deep input loses that guard the moment
    anything in the same process has decompiled a `.pyc` before it, which is silent and depends on
    unrelated import order.
    """

    def test_the_ambient_recursion_limit_survives_a_decompile(self):
        sentinel = 123
        ambient = sys.getrecursionlimit()
        sys.setrecursionlimit(sentinel)
        try:
            decompile_buffer(_a_trivial_code_object())
            self.assertEqual(sys.getrecursionlimit(), sentinel)
        finally:
            sys.setrecursionlimit(ambient)
