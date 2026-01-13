import itertools

from refinery.lib import id as idlib

from .. import TestBase


class TestIDLib(TestBase):

    def test_detect_unicode(self):
        data = B'H\0e\0l\0l\0o\0,\0\x20\0W\0r\0l\0d\0!\0\0\0'
        enc = idlib.guess_text_encoding(data)
        self.assertIsNotNone(enc)
        self.assertEqual(enc.step, 2)

    def test_all_pyc_magics(self):
        from refinery.lib.shared import xdis
        mismatches = [
            (magic, version) for magic, version in xdis.magics.versions.items()
            if idlib.PycMagicPattern.fullmatch(magic) is None
        ]
        errors = '\n'.join([
            F'- {magic.hex().upper()} for version {version}' for magic, version in mismatches
        ])
        self.assertListEqual(mismatches, [],
            msg=F'the following pyc magics were not matches:\n{errors}')

    def test_buffer_containment(self):
        base = bytearray(range(20, 100))
        view = memoryview(base)

        for hl, hx, hs in itertools.product(range(10), range(10), (1, 2, 3)):
            hu = hl + hx
            for nl, nx, ns in itertools.product(range(10), range(10), (1, 2, 3)):
                nu = nl + nx
                h_slice = slice(hl, hu, hs)
                n_slice = slice(nl, nu, ns)
                n_view = view[n_slice]
                h_view = view[h_slice]
                n_base = base[n_slice]
                h_base = base[h_slice]
                goal = h_base.find(n_base)
                msg = F'offset of [{nl}:{nu}:{ns}] in [{hl}:{hu}:{hs}] was {{}}, should be {goal}'
                test = idlib.buffer_offset(h_view, n_view)
                self.assertEqual(goal, test, F'buffer {msg}'.format(test))
                if (test := idlib.slice_offset(h_slice, n_slice)) is not None:
                    self.assertEqual(goal, test, F'sliced {msg}'.format(test))

    def test_comparison(self):
        self.assertLessEqual(idlib.Fmt.PE, idlib.Fmt.PE32CUI)
        self.assertLessEqual(idlib.Fmt.MACHO, idlib.Fmt.MACHO32BE)
        self.assertNotEqual(idlib.Fmt.PE, idlib.Fmt.ELF)
        self.assertNotEqual(idlib.Fmt.PE32DLL, idlib.Fmt.PE32CUI)
        self.assertNotEqual(idlib.Fmt.JSON, idlib.Fmt.REG)
        self.assertLessEqual(idlib.Fmt.ZIP, idlib.Fmt.DOCX)

    def test_not_json_regression(self):
        a = B'Acceptance of the QuoVadis Root CA 3 Certificate'
        self.assertNotEqual(idlib.get_structured_data_type(a), idlib.Fmt.JSON)
