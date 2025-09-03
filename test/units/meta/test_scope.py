from . import TestMetaBase
from refinery.lib.loader import load_detached as L


class TestScope(TestMetaBase):

    def test_only_local_scope(self):
        pipeline = L('rep') [ L('scope 1') | L('rep') [ L('scope 0') | L('cca .') ]] # noqa
        self.assertEqual(pipeline(B'FOO'), B'FOOFOO.FOO')

    def test_layer1_rescope(self):
        pipeline = L('rep') [ L('scope 0') | L('cca ,') | L('scope 1') | L('cca .') ] # noqa
        self.assertEqual(pipeline(B'FOO'), B'FOO,FOO.')

    def test_layer2_rescope(self):
        pipeline = L('rep 6') [ L('scope 4:') | L('chop 1') [ L('scope 1:') | L('cca A') | L('scope 0') | L('ccp -') ]] # noqa
        self.assertEqual(pipeline(B'NA'), B'NANANANA-NAA-NAA')

    def test_scope_in_frame_regression(self):
        pipeline = self.load_pipeline('emit FOO BAR BAZ [| scope 0 [| rex O [| scope 1 | cca F ]| ccp B ]| sep : ]')
        self.assertEqual(pipeline(), B'BOOF:BAR:BAZ')
