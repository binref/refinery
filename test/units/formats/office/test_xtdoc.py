
# flake8: noqa
from ... import TestUnitBase
from refinery.lib.loader import load as L


class TestDocExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('969ff75448ea54feccc0d5f652e00172af8e1848352e9a5877d705fc97fa0238')
        pipeline = self.load_pipeline(
            'xtdoc WordDoc | push [| drp | pop junk | repl var:junk | carve -ds b64 | u16 | deob-ps1 | repl var:junk http | xtp url ]')
        c2s = pipeline(data)
        self.assertIn(B'http://depannage-vehicule-maroc'B'.com/wp-admin/c/', c2s)
