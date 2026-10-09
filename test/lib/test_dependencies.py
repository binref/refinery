import traceback

from refinery.lib.dependencies import MissingModule
from refinery.lib.exceptions import RefineryImportError

from .. import TestBase


class TestMissingModule(TestBase):

    def test_each_access_raises_an_error_with_a_traceback_of_its_own(self):
        missing = MissingModule('module', error=RefineryImportError('the module is not installed'))
        depths = []
        for _ in range(3):
            try:
                missing.attribute
            except RefineryImportError as error:
                depths.append(len(traceback.extract_tb(error.__traceback__)))
        self.assertEqual(depths, depths[:1] * 3)
